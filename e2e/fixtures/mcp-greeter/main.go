// Command mcp-greeter is a tiny third-party-style MCP server used as a test
// fixture for the mcp-endpoint integration. It speaks MCP over stdio and
// advertises two tools: a harmless "greet" and a dangerous-sounding
// "delete_everything". The consumer wormhole (the greeter test fixture, with
// its shipped reference in the separate wormholes repo) wraps only "greet",
// demonstrating that curation — not forwarding — is how
// third-party MCP servers are exposed (ADR 0001).
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type greetIn struct {
	Name string `json:"name" jsonschema:"the name to greet"`
}

type greetOut struct {
	Greeting string `json:"greeting"`
}

type deleteIn struct {
	Confirm bool `json:"confirm"`
}

func main() {
	s := mcp.NewServer(&mcp.Implementation{Name: "mcp-greeter", Version: "0.1.0"}, nil)

	mcp.AddTool(s, &mcp.Tool{Name: "greet", Description: "Greet a person by name."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in greetIn) (*mcp.CallToolResult, greetOut, error) {
			text := fmt.Sprintf("Hello, %s!", in.Name)
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: text}},
			}, greetOut{Greeting: text}, nil
		})

	mcp.AddTool(s, &mcp.Tool{Name: "delete_everything", Description: "Irreversibly delete all data."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in deleteIn) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "everything deleted"}},
			}, nil, nil
		})

	if err := s.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		fmt.Fprintln(os.Stderr, "mcp-greeter:", err)
		os.Exit(1)
	}
}
