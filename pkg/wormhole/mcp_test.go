package wormhole

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

// fakeBackend is a minimal MCPBackend standing in for an upstream MCP server.
type fakeBackend struct{}

func (fakeBackend) ListTools(ctx context.Context) ([]MCPToolInfo, error) {
	return []MCPToolInfo{
		{Name: "greet", Description: "Greet a person.", InputSchemaJSON: []byte(`{"type":"object"}`)},
	}, nil
}

func (fakeBackend) CallTool(ctx context.Context, name string, argsJSON []byte) (*MCPCallResult, error) {
	if name != "greet" {
		return &MCPCallResult{IsError: true, ContentJSON: []byte(`[{"type":"text","text":"unknown tool"}]`)}, nil
	}
	var in struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(argsJSON, &in)
	text := fmt.Sprintf("Hello, %s!", in.Name)
	return &MCPCallResult{
		ContentJSON: []byte(fmt.Sprintf(`[{"type":"text","text":%q}]`, text)),
	}, nil
}

// TestMCPEndpointRoundTrip exercises ServeMCPEndpoint and DialMCPEndpoint over a
// real unix socket, without spawning a subprocess.
func TestMCPEndpointRoundTrip(t *testing.T) {
	desc, stop, err := ServeMCPEndpoint(LinkSocketDir("mcptest"), fakeBackend{})
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	defer stop()

	proxy, err := DialMCPEndpoint(desc)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer proxy.Close()

	ctx := context.Background()

	tools, err := proxy.ListTools(ctx)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "greet" {
		t.Fatalf("unexpected tools: %+v", tools)
	}

	res, err := proxy.CallTool(ctx, "greet", map[string]any{"name": "Ada"})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", res.Text())
	}
	if got := res.Text(); got != "Hello, Ada!" {
		t.Errorf("Text() = %q, want %q", got, "Hello, Ada!")
	}
}
