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

// TestCompositionThroughExecEndpoint drives the full composition path: a
// consumer wormhole (sysinfo) requiring an exec-endpoint, routed by the
// session manager to a provider wormhole (local-exec) via a configured
// target, all reached by an MCP client standing in for the agent.
func TestCompositionThroughExecEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("builds binaries")
	}

	tmp := t.TempDir()
	wormholeDir := filepath.Join(tmp, "wormholes")
	if err := os.Mkdir(wormholeDir, 0o755); err != nil {
		t.Fatal(err)
	}

	daemon := build(t, tmp, "interstellard", "./cmd/interstellard")
	build(t, wormholeDir, "local-exec", "./wormholes/local-exec")
	build(t, wormholeDir, "sysinfo", "./wormholes/sysinfo")

	auditPath := filepath.Join(tmp, "audit.jsonl")
	configPath := filepath.Join(tmp, "config.yaml")
	config := "" +
		"audit_log: " + auditPath + "\n" +
		"targets:\n" +
		"  localhost:\n" +
		"    wormhole: local-exec\n" +
		"    port: host\n"
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

	// The consumer tool must be exposed, and its schema must carry the
	// injected target argument with localhost as a choice.
	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var sysinfo *mcp.Tool
	for _, tool := range tools.Tools {
		if tool.Name == "sysinfo__get_system_info" {
			sysinfo = tool
		}
	}
	if sysinfo == nil {
		t.Fatalf("sysinfo__get_system_info not exposed; got %v", toolNames(tools.Tools))
	}
	assertTargetArg(t, sysinfo, "shell_target", "localhost")

	// Calling without the target argument must be refused.
	noTarget, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "sysinfo__get_system_info",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !noTarget.IsError {
		t.Error("call without a target should be a tool error")
	}

	// With the target, the chain runs end to end and returns real data.
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "sysinfo__get_system_info",
		Arguments: map[string]any{"shell_target": "localhost"},
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if result.IsError {
		t.Fatalf("composition call errored: %s", text(result))
	}
	var info struct {
		Hostname string            `json:"hostname"`
		Kernel   string            `json:"kernel"`
		Errors   map[string]string `json:"errors"`
	}
	if err := json.Unmarshal([]byte(text(result)), &info); err != nil {
		t.Fatalf("result not sysinfo JSON: %v (%q)", err, text(result))
	}
	if info.Hostname == "" {
		t.Errorf("expected a hostname from the host, got errors=%v", info.Errors)
	}
	if info.Kernel == "" {
		t.Errorf("expected a kernel string, got errors=%v", info.Errors)
	}

	session.Close()

	// The audit record must capture the routed target.
	auditData, _ := os.ReadFile(auditPath)
	if !strings.Contains(string(auditData), `"get_system_info"`) ||
		!strings.Contains(string(auditData), `"shell":"localhost"`) {
		t.Errorf("audit log missing the routed call: %s", auditData)
	}
}

func assertTargetArg(t *testing.T, tool *mcp.Tool, arg, wantTarget string) {
	t.Helper()
	raw, err := json.Marshal(tool.InputSchema)
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties map[string]struct {
			Enum []string `json:"enum"`
		} `json:"properties"`
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	prop, ok := schema.Properties[arg]
	if !ok {
		t.Fatalf("tool schema missing %q argument: %s", arg, raw)
	}
	found := false
	for _, e := range prop.Enum {
		if e == wantTarget {
			found = true
		}
	}
	if !found {
		t.Errorf("%q enum %v does not include %q", arg, prop.Enum, wantTarget)
	}
	req := false
	for _, r := range schema.Required {
		if r == arg {
			req = true
		}
	}
	if !req {
		t.Errorf("%q should be required", arg)
	}
}

func text(r *mcp.CallToolResult) string {
	if len(r.Content) == 0 {
		return ""
	}
	tc, ok := r.Content[0].(*mcp.TextContent)
	if !ok {
		return ""
	}
	return tc.Text
}

func toolNames(tools []*mcp.Tool) []string {
	out := make([]string, len(tools))
	for i, tool := range tools {
		out[i] = tool.Name
	}
	return out
}
