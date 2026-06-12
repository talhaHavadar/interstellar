// Package e2e proves the full vertical slice: an MCP client (standing in
// for an AI agent) connects to interstellard over stdio, discovers tools
// forwarded from a real wormhole plugin process, and calls one.
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

// build compiles a package into dir and returns the binary path.
func build(t *testing.T, dir, name, pkg string) string {
	t.Helper()
	bin := filepath.Join(dir, name)
	cmd := exec.Command("go", "build", "-o", bin, pkg)
	cmd.Dir = ".." // module root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building %s: %v\n%s", pkg, err, out)
	}
	return bin
}

func TestAgentToWormholeRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("builds binaries")
	}

	tmp := t.TempDir()
	wormholeDir := filepath.Join(tmp, "wormholes")
	if err := os.Mkdir(wormholeDir, 0o755); err != nil {
		t.Fatal(err)
	}

	daemon := build(t, tmp, "interstellard", "./cmd/interstellard")
	build(t, wormholeDir, "echo", "./wormholes/echo")
	auditPath := filepath.Join(tmp, "audit.jsonl")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "e2e-agent", Version: "0.0.0"}, nil)
	cmd := exec.Command(daemon, "--stdio", "--wormhole-dir", wormholeDir, "--audit-log", auditPath)
	cmd.Stderr = os.Stderr
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connecting to interstellard: %v", err)
	}
	defer session.Close()

	// The agent should see the wormhole's tool and the built-in status tool.
	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("listing tools: %v", err)
	}
	names := map[string]*mcp.Tool{}
	for _, tool := range tools.Tools {
		names[tool.Name] = tool
	}
	if names["interstellar__status"] == nil {
		t.Error("missing interstellar__status tool")
	}
	say := names["echo__say"]
	if say == nil {
		t.Fatalf("missing echo__say tool; got %v", keys(names))
	}
	if say.Annotations == nil || !say.Annotations.ReadOnlyHint {
		t.Error("read-capability tool should carry readOnlyHint")
	}

	// Call the wormhole tool through the gateway.
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "echo__say",
		Arguments: map[string]any{"message": "hello, universe", "repeat": 2},
	})
	if err != nil {
		t.Fatalf("calling echo__say: %v", err)
	}
	if result.IsError {
		t.Fatalf("tool call errored: %v", result.Content)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	var out struct {
		Echo  string `json:"echo"`
		Times int    `json:"times"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("result is not the wormhole's JSON payload: %v (%q)", err, text)
	}
	if out.Echo != "hello, universe hello, universe" || out.Times != 2 {
		t.Errorf("unexpected result: %+v", out)
	}

	// The status tool reports the loaded wormhole.
	status, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "interstellar__status"})
	if err != nil {
		t.Fatalf("calling status: %v", err)
	}
	statusText := status.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(statusText, `"echo"`) {
		t.Errorf("status should list the echo wormhole: %s", statusText)
	}

	session.Close()

	// Every call must have left an audit record.
	auditData, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	if !strings.Contains(string(auditData), `"tool":"say"`) {
		t.Errorf("audit log missing the echo__say call: %s", auditData)
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
