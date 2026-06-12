package wormhole

import (
	"context"
	"encoding/json"
	"testing"

	wormholev1 "github.com/talhaHavadar/interstellar/gen/wormhole/v1"
)

type buildInput struct {
	Distro string `json:"distro" jsonschema:"target distribution"`
	Arch   string `json:"arch,omitempty" jsonschema:"target architecture"`
}

func TestManifestAndSchemaGeneration(t *testing.T) {
	w := New("deb-builder", "0.1.0", "Builds Debian packages.")
	w.Require(Port{Name: "target", Type: PortTypeExecEndpoint, Description: "where to build"})
	AddTool(w, Tool[buildInput]{
		Name:          "build_source_package",
		Description:   "Build a Debian source package.",
		Capabilities:  []Capability{CapExecScoped},
		RequiresPorts: []string{"target"},
		Handler: func(ctx context.Context, call *Call, in buildInput) (any, error) {
			return nil, nil
		},
	})

	m := w.manifest()
	if m.Name != "deb-builder" || len(m.Tools) != 1 || len(m.Requires) != 1 {
		t.Fatalf("unexpected manifest: %+v", m)
	}

	tool := m.Tools[0]
	if got := tool.Capabilities; len(got) != 1 || got[0] != wormholev1.Capability_CAPABILITY_EXEC_SCOPED {
		t.Errorf("capabilities = %v, want [EXEC_SCOPED]", got)
	}

	var schema map[string]any
	if err := json.Unmarshal([]byte(tool.InputSchemaJson), &schema); err != nil {
		t.Fatalf("input schema is not valid JSON: %v", err)
	}
	props, _ := schema["properties"].(map[string]any)
	distro, _ := props["distro"].(map[string]any)
	if distro == nil {
		t.Fatalf("schema missing distro property: %s", tool.InputSchemaJson)
	}
	if distro["description"] != "target distribution" {
		t.Errorf("jsonschema tag not reflected as description: %v", distro)
	}
}

func TestAddToolRejectsBadDefinitions(t *testing.T) {
	handler := func(ctx context.Context, call *Call, in buildInput) (any, error) { return nil, nil }

	tests := []struct {
		name string
		tool Tool[buildInput]
	}{
		{"bad name", Tool[buildInput]{Name: "Bad-Name", Capabilities: []Capability{CapRead}, Handler: handler}},
		{"no capabilities", Tool[buildInput]{Name: "ok_name", Handler: handler}},
		{"invalid capability", Tool[buildInput]{Name: "ok_name", Capabilities: []Capability{Capability(42)}, Handler: handler}},
		{"nil handler", Tool[buildInput]{Name: "ok_name", Capabilities: []Capability{CapRead}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("want panic")
				}
			}()
			AddTool(New("x", "0.1.0", ""), tt.tool)
		})
	}
}

func TestCapabilityRoundTrip(t *testing.T) {
	for _, name := range KnownCapabilityNames() {
		c, err := ParseCapability(name)
		if err != nil {
			t.Fatalf("ParseCapability(%q): %v", name, err)
		}
		if c.String() != name {
			t.Errorf("round trip %q -> %v", name, c)
		}
		if rt, err := CapabilityFromProto(c.Proto()); err != nil || rt != c {
			t.Errorf("proto round trip failed for %q", name)
		}
	}
	if _, err := ParseCapability("exec.anything"); err == nil {
		t.Error("unknown name should not parse")
	}
}
