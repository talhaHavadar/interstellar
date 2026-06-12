// Package mcpserver is interstellar's north side: it presents the loaded
// wormholes' tools to AI agents as a standard MCP server, with the policy
// engine deciding what is exposed and the session manager resolving the
// links a tool needs.
package mcpserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	wormholev1 "github.com/talhaHavadar/interstellar/gen/wormhole/v1"
	"github.com/talhaHavadar/interstellar/internal/audit"
	"github.com/talhaHavadar/interstellar/internal/policy"
	"github.com/talhaHavadar/interstellar/internal/registry"
	"github.com/talhaHavadar/interstellar/internal/session"
	"github.com/talhaHavadar/interstellar/pkg/wormhole"
)

// portArg describes a required port surfaced to the agent as a target
// argument on the tool.
type portArg struct {
	port     string // the tool's required port name
	argName  string // the argument the agent sets, "<port>_target"
	portType string
	optional bool
	targets  []string // compatible target names
}

// New builds the MCP server over the loaded wormholes. Tools are hidden when
// policy denies them or when a non-optional required port has no compatible
// target; either way the omission and its reason show up in
// interstellar__status.
func New(version string, reg *registry.Registry, pol *policy.Engine, sess *session.Manager, aud *audit.Log, logger *slog.Logger) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{
		Name:    "interstellar",
		Title:   "Interstellar",
		Version: version,
	}, nil)

	byType := targetsByType(reg, sess)

	mcp.AddTool(s, &mcp.Tool{
		Name: "interstellar__status",
		Description: "Describe this interstellar gateway: loaded wormholes, their tools " +
			"(including tools hidden by policy or for lack of a target, and why), their " +
			"ports, and the configured targets a tool can be routed to.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		return nil, buildStatus(version, reg, pol, sess, byType), nil
	})

	for _, w := range reg.All() {
		for _, t := range w.Manifest.Tools {
			if dec := pol.CheckTool(w.Manifest.Name, t); !dec.Allow {
				logger.Info("tool hidden by policy", "wormhole", w.Manifest.Name, "tool", t.Name, "reason", dec.Reason)
				continue
			}
			ports, reason := portArgsFor(w, t, byType)
			if reason != "" {
				logger.Info("tool hidden", "wormhole", w.Manifest.Name, "tool", t.Name, "reason", reason)
				continue
			}
			schema, err := augmentSchema(t.InputSchemaJson, ports)
			if err != nil {
				logger.Error("tool schema augmentation failed; hiding tool",
					"wormhole", w.Manifest.Name, "tool", t.Name, "error", err)
				continue
			}
			s.AddTool(&mcp.Tool{
				Name:        toolName(w.Manifest.Name, t.Name),
				Description: t.Description,
				InputSchema: schema,
				Annotations: annotationsFor(t),
			}, callHandler(w, t, ports, pol, sess, aud, logger))
		}
	}
	return s
}

func toolName(wormholeName, tool string) string { return wormholeName + "__" + tool }

// targetsByType groups configured target names by the port type they
// provide, so a tool's required port can be offered the targets that fit it.
func targetsByType(reg *registry.Registry, sess *session.Manager) map[string][]string {
	byType := map[string][]string{}
	if sess == nil {
		return byType
	}
	for name, t := range sess.Targets() {
		wh, ok := reg.Get(t.Wormhole)
		if !ok {
			continue
		}
		for _, p := range wh.Manifest.Provides {
			if p.Name == t.Port {
				byType[p.Type] = append(byType[p.Type], name)
			}
		}
	}
	for _, names := range byType {
		sort.Strings(names)
	}
	return byType
}

// portArgsFor resolves a tool's required ports to target arguments. It
// returns a non-empty reason when the tool must be hidden (a non-optional
// port has no compatible target).
func portArgsFor(w *registry.Wormhole, t *wormholev1.ToolSpec, byType map[string][]string) (args []portArg, hideReason string) {
	for _, portName := range t.RequiresPorts {
		spec := findPort(w.Manifest.Requires, portName)
		if spec == nil {
			// Validation should prevent this; fail closed.
			return nil, fmt.Sprintf("required port %q is not declared in the manifest", portName)
		}
		targets := byType[spec.Type]
		if len(targets) == 0 && !spec.Optional {
			return nil, fmt.Sprintf("no configured target provides %q for required port %q", spec.Type, portName)
		}
		args = append(args, portArg{
			port:     portName,
			argName:  portName + "_target",
			portType: spec.Type,
			optional: spec.Optional,
			targets:  targets,
		})
	}
	return args, ""
}

// augmentSchema adds a target argument per required port to the tool's input
// schema. Required (non-optional) ports add a required string argument whose
// enum is the compatible targets.
func augmentSchema(schemaJSON string, ports []portArg) (json.RawMessage, error) {
	if len(ports) == 0 {
		return json.RawMessage(schemaJSON), nil
	}
	var schema map[string]any
	if err := json.Unmarshal([]byte(schemaJSON), &schema); err != nil {
		return nil, fmt.Errorf("parsing input schema: %w", err)
	}
	props, _ := schema["properties"].(map[string]any)
	if props == nil {
		props = map[string]any{}
		schema["properties"] = props
	}
	required, _ := schema["required"].([]any)

	for _, p := range ports {
		desc := fmt.Sprintf("Interstellar target to route the %q connection (%s) through.", p.port, p.portType)
		if p.optional {
			desc += " Optional."
		}
		prop := map[string]any{"type": "string", "description": desc}
		if len(p.targets) > 0 {
			enum := make([]any, len(p.targets))
			for i, name := range p.targets {
				enum[i] = name
			}
			prop["enum"] = enum
		}
		props[p.argName] = prop
		if !p.optional {
			required = append(required, p.argName)
		}
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return json.Marshal(schema)
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

func findPort(ports []*wormholev1.PortSpec, name string) *wormholev1.PortSpec {
	for _, p := range ports {
		if p.Name == name {
			return p
		}
	}
	return nil
}

// callHandler routes one tool call south: policy check, link resolution,
// audit, gRPC stream to the wormhole, result back to the agent.
func callHandler(w *registry.Wormhole, t *wormholev1.ToolSpec, ports []portArg, pol *policy.Engine, sess *session.Manager, aud *audit.Log, logger *slog.Logger) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		callID := newCallID()
		start := time.Now()

		record := audit.Record{
			Time: start, CallID: callID,
			Wormhole: w.Manifest.Name, Tool: t.Name,
			Args: req.Params.Arguments,
		}
		finish := func(res *mcp.CallToolResult, err error) (*mcp.CallToolResult, error) {
			record.Duration = time.Since(start)
			if res != nil {
				record.IsError = res.IsError
			}
			if err != nil {
				record.IsError = true
				record.Error = err.Error()
			}
			aud.Write(record)
			return res, err
		}

		if dec := pol.CheckTool(w.Manifest.Name, t); !dec.Allow {
			record.Decision = "deny"
			record.Reason = dec.Reason
			return finish(toolError(dec.Reason), nil)
		}
		record.Decision = "allow"

		// Resolve the links the tool needs, peeling the target arguments out
		// of the arguments forwarded to the wormhole.
		args := map[string]json.RawMessage{}
		if len(req.Params.Arguments) > 0 {
			if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
				return finish(toolError(fmt.Sprintf("invalid arguments: %v", err)), nil)
			}
		}

		var links []*wormholev1.Link
		var leases []*session.Lease
		releaseAll := func() {
			for _, l := range leases {
				l.Release()
			}
		}
		for _, p := range ports {
			raw, present := args[p.argName]
			delete(args, p.argName)
			var targetName string
			if present {
				if err := json.Unmarshal(raw, &targetName); err != nil {
					releaseAll()
					return finish(toolError(fmt.Sprintf("argument %q must be a target name string", p.argName)), nil)
				}
			}
			if targetName == "" {
				if p.optional {
					continue
				}
				releaseAll()
				return finish(toolError(fmt.Sprintf("argument %q is required: choose one of %v", p.argName, p.targets)), nil)
			}
			if !contains(p.targets, targetName) {
				releaseAll()
				return finish(toolError(fmt.Sprintf("unknown target %q for %q; choose one of %v", targetName, p.argName, p.targets)), nil)
			}
			lease, err := sess.Acquire(ctx, targetName)
			if err != nil {
				releaseAll()
				return finish(toolError(fmt.Sprintf("connecting target %q: %v", targetName, err)), nil)
			}
			leases = append(leases, lease)
			if record.Targets == nil {
				record.Targets = map[string]string{}
			}
			record.Targets[p.port] = targetName
			// The wormhole knows this link by its own required port name.
			links = append(links, &wormholev1.Link{
				LinkId:         lease.Link.LinkId,
				PortName:       p.port,
				Type:           lease.Link.Type,
				DescriptorJson: lease.Link.DescriptorJson,
			})
		}
		defer releaseAll()

		forwardArgs, err := json.Marshal(args)
		if err != nil {
			return finish(nil, fmt.Errorf("re-encoding arguments: %w", err))
		}

		stream, err := w.Client.CallTool(ctx, &wormholev1.CallToolRequest{
			CallId:        callID,
			Tool:          t.Name,
			ArgumentsJson: string(forwardArgs),
			Links:         links,
		})
		if err != nil {
			return finish(nil, fmt.Errorf("calling wormhole %q: %w", w.Manifest.Name, err))
		}

		var result *wormholev1.ToolResult
		for result == nil {
			ev, err := stream.Recv()
			if err == io.EOF {
				err = fmt.Errorf("wormhole %q closed the stream without a result", w.Manifest.Name)
			}
			if err != nil {
				return finish(nil, err)
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

		return finish(&mcp.CallToolResult{
			IsError: result.IsError,
			Content: []mcp.Content{&mcp.TextContent{Text: result.ContentJson}},
		}, nil)
	}
}

func toolError(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: msg}}}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func newCallID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
