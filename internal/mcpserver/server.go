// Package mcpserver is interstellar's north side: it presents the loaded
// wormholes' tools to AI agents as a standard MCP server, with the policy
// engine deciding what is exposed and the audit log seeing every call.
package mcpserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	wormholev1 "github.com/talhaHavadar/interstellar/gen/wormhole/v1"
	"github.com/talhaHavadar/interstellar/internal/audit"
	"github.com/talhaHavadar/interstellar/internal/policy"
	"github.com/talhaHavadar/interstellar/internal/registry"
	"github.com/talhaHavadar/interstellar/pkg/wormhole"
)

// New builds the MCP server over the loaded wormholes. Tools denied by
// policy are not registered at all; they appear, with the denial reason, in
// the interstellar__status tool so the omission is discoverable.
func New(version string, reg *registry.Registry, pol *policy.Engine, aud *audit.Log, logger *slog.Logger) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{
		Name:    "interstellar",
		Title:   "Interstellar",
		Version: version,
	}, nil)

	status := buildStatus(version, reg, pol)
	mcp.AddTool(s, &mcp.Tool{
		Name: "interstellar__status",
		Description: "Describe this interstellar gateway: loaded wormholes, " +
			"their tools (including tools hidden by policy and why), and their ports.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		return nil, status, nil
	})

	for _, w := range reg.All() {
		for _, t := range w.Manifest.Tools {
			if dec := pol.CheckTool(w.Manifest.Name, t); !dec.Allow {
				logger.Info("tool hidden by policy",
					"wormhole", w.Manifest.Name, "tool", t.Name, "reason", dec.Reason)
				continue
			}
			s.AddTool(&mcp.Tool{
				Name:        toolName(w.Manifest.Name, t.Name),
				Description: t.Description,
				InputSchema: json.RawMessage(t.InputSchemaJson),
				Annotations: annotationsFor(t),
			}, callHandler(w, t, pol, aud, logger))
		}
	}
	return s
}

// toolName builds the agent-facing name: "<wormhole>__<tool>", using only
// characters every MCP host accepts.
func toolName(wormholeName, tool string) string {
	return wormholeName + "__" + tool
}

func annotationsFor(t *wormholev1.ToolSpec) *mcp.ToolAnnotations {
	readOnly := true
	network := false
	for _, pc := range t.Capabilities {
		c, err := wormhole.CapabilityFromProto(pc)
		if err != nil {
			continue
		}
		if c != wormhole.CapRead {
			readOnly = false
		}
		if c == wormhole.CapNetwork {
			network = true
		}
	}
	a := &mcp.ToolAnnotations{ReadOnlyHint: readOnly}
	if network {
		open := true
		a.OpenWorldHint = &open
	}
	return a
}

// callHandler routes one tool call south: policy check, audit, gRPC stream
// to the wormhole, result back to the agent.
func callHandler(w *registry.Wormhole, t *wormholev1.ToolSpec, pol *policy.Engine, aud *audit.Log, logger *slog.Logger) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		callID := newCallID()
		start := time.Now()
		args := req.Params.Arguments

		record := audit.Record{
			Time:     start,
			CallID:   callID,
			Wormhole: w.Manifest.Name,
			Tool:     t.Name,
			Args:     args,
		}

		// Policy is checked again per call: registration-time filtering keeps
		// the surface clean, this keeps execution correct even if the two
		// ever disagree.
		if dec := pol.CheckTool(w.Manifest.Name, t); !dec.Allow {
			record.Decision = "deny"
			record.Reason = dec.Reason
			aud.Write(record)
			return toolError(dec.Reason), nil
		}
		record.Decision = "allow"

		if len(t.RequiresPorts) > 0 {
			// Link resolution (the capability graph) is not implemented yet;
			// refuse loudly rather than running a tool without its links.
			msg := fmt.Sprintf("tool %q requires linked ports %v; link resolution is not implemented yet", t.Name, t.RequiresPorts)
			record.IsError = true
			record.Error = msg
			record.Duration = time.Since(start)
			aud.Write(record)
			return toolError(msg), nil
		}

		stream, err := w.Client.CallTool(ctx, &wormholev1.CallToolRequest{
			CallId:        callID,
			Tool:          t.Name,
			ArgumentsJson: string(args),
		})
		if err != nil {
			record.IsError = true
			record.Error = err.Error()
			record.Duration = time.Since(start)
			aud.Write(record)
			return nil, fmt.Errorf("calling wormhole %q: %w", w.Manifest.Name, err)
		}

		var result *wormholev1.ToolResult
		for result == nil {
			ev, err := stream.Recv()
			if err == io.EOF {
				err = fmt.Errorf("wormhole %q closed the stream without a result", w.Manifest.Name)
			}
			if err != nil {
				record.IsError = true
				record.Error = err.Error()
				record.Duration = time.Since(start)
				aud.Write(record)
				return nil, err
			}
			switch e := ev.Event.(type) {
			case *wormholev1.CallToolResponse_Log:
				logger.Info("wormhole log",
					"wormhole", w.Manifest.Name, "tool", t.Name, "call_id", callID,
					"level", e.Log.Level, "message", e.Log.Message)
			case *wormholev1.CallToolResponse_Progress:
				logger.Debug("wormhole progress",
					"wormhole", w.Manifest.Name, "tool", t.Name, "call_id", callID,
					"fraction", e.Progress.Fraction, "message", e.Progress.Message)
			case *wormholev1.CallToolResponse_Result:
				result = e.Result
			}
		}

		record.IsError = result.IsError
		record.Duration = time.Since(start)
		aud.Write(record)

		return &mcp.CallToolResult{
			IsError: result.IsError,
			Content: []mcp.Content{&mcp.TextContent{Text: result.ContentJson}},
		}, nil
	}
}

func toolError(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}
}

func newCallID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return hex.EncodeToString(b[:])
}

// status types are the payload of interstellar__status.
type statusPayload struct {
	Version   string           `json:"version"`
	Wormholes []wormholeStatus `json:"wormholes"`
}

type wormholeStatus struct {
	Name        string       `json:"name"`
	Version     string       `json:"version"`
	Description string       `json:"description,omitempty"`
	Tools       []toolStatus `json:"tools"`
	Provides    []portStatus `json:"provides,omitempty"`
	Requires    []portStatus `json:"requires,omitempty"`
}

type toolStatus struct {
	Name string `json:"name"`
	// Exposed is false when policy hides the tool from agents.
	Exposed bool   `json:"exposed"`
	Reason  string `json:"reason,omitempty"`
}

type portStatus struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Optional bool   `json:"optional,omitempty"`
}

func buildStatus(version string, reg *registry.Registry, pol *policy.Engine) statusPayload {
	payload := statusPayload{Version: version, Wormholes: []wormholeStatus{}}
	for _, w := range reg.All() {
		ws := wormholeStatus{
			Name:        w.Manifest.Name,
			Version:     w.Manifest.Version,
			Description: w.Manifest.Description,
			Tools:       []toolStatus{},
		}
		for _, t := range w.Manifest.Tools {
			dec := pol.CheckTool(w.Manifest.Name, t)
			ws.Tools = append(ws.Tools, toolStatus{
				Name:    toolName(w.Manifest.Name, t.Name),
				Exposed: dec.Allow,
				Reason:  dec.Reason,
			})
		}
		for _, p := range w.Manifest.Provides {
			ws.Provides = append(ws.Provides, portStatus{Name: p.Name, Type: p.Type, Optional: p.Optional})
		}
		for _, p := range w.Manifest.Requires {
			ws.Requires = append(ws.Requires, portStatus{Name: p.Name, Type: p.Type, Optional: p.Optional})
		}
		payload.Wormholes = append(payload.Wormholes, ws)
	}
	return payload
}
