// Command mcp-client-greeter is a test-fixture consumer wormhole for the
// mcp-endpoint path. It is NOT shipped as a core wormhole — the
// reference/example version lives in the separate wormholes repo. It exists
// here only so the core e2e can exercise the mcp-stdio provider end to end: it
// requires an mcp-endpoint and exposes one curated tool, proving the agent
// reaches only what the consumer authors, never the upstream's raw tools.
package main

import (
	"context"
	"fmt"

	"github.com/talhaHavadar/interstellar/pkg/wormhole"
)

type greetInput struct {
	Name string `json:"name" jsonschema:"the name to greet"`
}

type greetOutput struct {
	Greeting string `json:"greeting"`
}

func main() {
	w := wormhole.New("mcp-client-greeter", "0.1.0",
		"Reference example: greets a person, backed by an upstream MCP server.")

	w.Require(wormhole.Port{
		Name:        "upstream",
		Type:        wormhole.PortTypeMCPEndpoint,
		Description: "the MCP server that performs the greeting",
	})

	wormhole.AddTool(w, wormhole.Tool[greetInput]{
		Name:          "greet",
		Description:   "Greet a person by name.",
		Capabilities:  []wormhole.Capability{wormhole.CapRead},
		RequiresPorts: []string{"upstream"},
		Handler:       greet,
	})

	w.Serve()
}

func greet(ctx context.Context, call *wormhole.Call, in greetInput) (any, error) {
	if in.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	link, ok := call.Link("upstream")
	if !ok {
		return nil, fmt.Errorf("no mcp endpoint linked")
	}
	var ep wormhole.MCPEndpointDescriptor
	if err := link.DecodeDescriptor(&ep); err != nil {
		return nil, fmt.Errorf("decoding mcp endpoint: %w", err)
	}
	proxy, err := wormhole.DialMCPEndpoint(ep)
	if err != nil {
		return nil, err
	}
	defer proxy.Close()

	res, err := proxy.CallTool(ctx, "greet", map[string]any{"name": in.Name})
	if err != nil {
		return nil, fmt.Errorf("calling upstream greet: %w", err)
	}
	if res.IsError {
		return nil, fmt.Errorf("upstream greet failed: %s", res.Text())
	}
	return greetOutput{Greeting: res.Text()}, nil
}
