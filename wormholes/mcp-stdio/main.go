// Command mcp-stdio is a generic provider wormhole: it spawns a third-party
// MCP server as a subprocess, speaks MCP to it over stdio, and offers that live
// session as an "mcp-endpoint" port for purpose-built consumer wormholes to
// build on. It exposes no agent-facing tools — agents never reach the upstream
// server directly; a consumer wormhole holds the link and chooses exactly which
// upstream tools to call and how to present them.
//
// The upstream server's own credentials (a GitHub token, an API key, ...) are
// supplied as ambient environment to this process and inherited by the spawned
// subprocess — never as agent arguments.
//
// Configure a target that binds its "server" port:
//
//	targets:
//	  github-mcp:
//	    wormhole: mcp-stdio
//	    port: server
//	    config:
//	      command: github-mcp-server
//	      args: ["stdio"]
//	      env:
//	        GITHUB_PERSONAL_ACCESS_TOKEN_ENV: GITHUB_TOKEN  # see notes below
//
// By default the subprocess inherits this process's full environment; `env`
// adds or overrides individual variables.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/talhaHavadar/interstellar/pkg/wormhole"
)

// serverConfig is the admin-supplied config for an upstream MCP server.
type serverConfig struct {
	// Command is the executable to spawn (looked up on PATH).
	Command string `json:"command"`
	// Args are passed to the command.
	Args []string `json:"args,omitempty"`
	// Env adds or overrides environment variables for the subprocess, on top of
	// this process's inherited environment.
	Env map[string]string `json:"env,omitempty"`
}

func main() {
	w := wormhole.New("mcp-stdio", "0.1.0",
		"Provides an mcp-endpoint backed by a third-party MCP server run over stdio.")

	w.Provide(
		wormhole.Port{
			Name:        "server",
			Type:        wormhole.PortTypeMCPEndpoint,
			Description: "a third-party MCP server spawned and spoken to over stdio",
		},
		openServer,
	)

	w.Serve()
}

func openServer(ctx context.Context, req *wormhole.LinkRequest) (*wormhole.ActiveLink, error) {
	var cfg serverConfig
	if len(req.Config) > 0 {
		if err := json.Unmarshal(req.Config, &cfg); err != nil {
			return nil, fmt.Errorf("mcp-stdio config: %w", err)
		}
	}
	if cfg.Command == "" {
		return nil, fmt.Errorf("mcp-stdio config: command is required")
	}

	cmd := exec.Command(cfg.Command, cfg.Args...)
	if len(cfg.Env) > 0 {
		env := os.Environ()
		for k, v := range cfg.Env {
			env = append(env, k+"="+v)
		}
		cmd.Env = env
	}
	// Surface the subprocess's stderr for operator debugging; its stdout is the
	// MCP transport and must not be touched.
	cmd.Stderr = os.Stderr

	// No sampling/elicitation handlers are registered, so this client does not
	// advertise those capabilities and the upstream cannot call back into the
	// agent — sampling and elicitation are out of scope (see ADR 0001).
	client := mcp.NewClient(&mcp.Implementation{Name: "interstellar-mcp-stdio", Version: "0.1.0"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		return nil, fmt.Errorf("connecting to upstream MCP server %q: %w", cfg.Command, err)
	}

	desc, stop, err := wormhole.ServeMCPEndpoint(
		wormhole.LinkSocketDir(req.LinkID), &sessionBackend{session: session})
	if err != nil {
		_ = session.Close()
		return nil, err
	}

	return &wormhole.ActiveLink{
		Descriptor: desc,
		Close: func() error {
			_ = stop()
			return session.Close()
		},
	}, nil
}

// sessionBackend adapts a live MCP client session to the SDK's MCPBackend.
type sessionBackend struct {
	session *mcp.ClientSession
}

func (b *sessionBackend) ListTools(ctx context.Context) ([]wormhole.MCPToolInfo, error) {
	var out []wormhole.MCPToolInfo
	params := &mcp.ListToolsParams{}
	for {
		res, err := b.session.ListTools(ctx, params)
		if err != nil {
			return nil, err
		}
		for _, t := range res.Tools {
			var schema []byte
			if t.InputSchema != nil {
				if b, err := json.Marshal(t.InputSchema); err == nil {
					schema = b
				}
			}
			out = append(out, wormhole.MCPToolInfo{
				Name:            t.Name,
				Description:     t.Description,
				InputSchemaJSON: schema,
			})
		}
		if res.NextCursor == "" {
			return out, nil
		}
		params.Cursor = res.NextCursor
	}
}

func (b *sessionBackend) CallTool(ctx context.Context, name string, argsJSON []byte) (*wormhole.MCPCallResult, error) {
	params := &mcp.CallToolParams{Name: name}
	if len(argsJSON) > 0 {
		params.Arguments = json.RawMessage(argsJSON)
	}
	res, err := b.session.CallTool(ctx, params)
	if err != nil {
		return nil, err
	}
	out := &wormhole.MCPCallResult{IsError: res.IsError}
	if len(res.Content) > 0 {
		if b, err := json.Marshal(res.Content); err == nil {
			out.ContentJSON = b
		}
	}
	if res.StructuredContent != nil {
		if b, err := json.Marshal(res.StructuredContent); err == nil {
			out.StructuredJSON = b
		}
	}
	return out, nil
}
