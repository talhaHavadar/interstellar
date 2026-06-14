package e2e

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestMCPCompositionThroughConsumer drives the full mcp-endpoint path: an
// upstream MCP server (the mcp-greeter fixture) is held by the mcp-stdio
// provider and offered as an mcp-endpoint; a purpose-built consumer (the
// mcp-client-greeter fixture) requires it and exposes one curated tool. The
// agent reaches only the consumer's tool — never the upstream surface.
func TestMCPCompositionThroughConsumer(t *testing.T) {
	if testing.Short() {
		t.Skip("builds binaries")
	}

	tmp := t.TempDir()
	wormholeDir := filepath.Join(tmp, "wormholes")
	if err := os.Mkdir(wormholeDir, 0o755); err != nil {
		t.Fatal(err)
	}

	daemon := build(t, tmp, "interstellard", "./cmd/interstellard")
	build(t, wormholeDir, "mcp-stdio", "./wormholes/mcp-stdio")
	// The consumer is a test fixture, not a shipped core wormhole; the
	// reference version lives in the separate wormholes repo.
	build(t, wormholeDir, "mcp-client-greeter", "./e2e/fixtures/mcp-client-greeter")
	// The upstream MCP server is an ordinary binary, not a wormhole; build it
	// outside the wormhole dir so the gateway does not try to load it.
	upstream := build(t, tmp, "mcp-greeter", "./e2e/fixtures/mcp-greeter")

	auditPath := filepath.Join(tmp, "audit.jsonl")
	configPath := filepath.Join(tmp, "config.yaml")
	config := "" +
		"audit_log: " + auditPath + "\n" +
		"targets:\n" +
		"  greeter-backend:\n" +
		"    wormhole: mcp-stdio\n" +
		"    port: server\n" +
		"    config:\n" +
		"      command: " + upstream + "\n"
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "e2e-agent", Version: "0.0.0"}, nil)
	cmd := exec.Command(daemon, "--stdio", "--config", configPath, "--wormhole-dir", wormholeDir)
	cmd.Stderr = os.Stderr
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer session.Close()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	names := toolNames(tools.Tools)

	// The consumer's curated tool is exposed and carries the injected target arg.
	var greeter *mcp.Tool
	for _, tool := range tools.Tools {
		if tool.Name == "mcp-client-greeter__greet" {
			greeter = tool
		}
		// The upstream's tools must never leak through as agent tools.
		if strings.Contains(tool.Name, "delete_everything") {
			t.Errorf("upstream tool leaked to the agent: %q", tool.Name)
		}
	}
	if greeter == nil {
		t.Fatalf("mcp-client-greeter__greet not exposed; got %v", names)
	}
	assertTargetArg(t, greeter, "upstream_target", "greeter-backend")

	// The full chain: agent -> mcp-client-greeter -> mcp-stdio -> upstream greet.
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "mcp-client-greeter__greet",
		Arguments: map[string]any{"name": "Ada", "upstream_target": "greeter-backend"},
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if result.IsError {
		t.Fatalf("greeter call errored: %s", text(result))
	}
	var out struct {
		Greeting string `json:"greeting"`
	}
	if err := json.Unmarshal([]byte(text(result)), &out); err != nil {
		t.Fatalf("result not greeter JSON: %v (%q)", err, text(result))
	}
	if out.Greeting != "Hello, Ada!" {
		t.Errorf("greeting = %q, want %q", out.Greeting, "Hello, Ada!")
	}

	session.Close()

	auditData, _ := os.ReadFile(auditPath)
	if !strings.Contains(string(auditData), `"tool":"greet"`) ||
		!strings.Contains(string(auditData), `"upstream":"greeter-backend"`) {
		t.Errorf("audit log missing the routed call: %s", auditData)
	}
}
