package registry

import (
	"strings"
	"testing"

	wormholev1 "github.com/talhaHavadar/interstellar/gen/wormhole/v1"
)

func validManifest() *wormholev1.Manifest {
	return &wormholev1.Manifest{
		Name:    "deb-builder",
		Version: "0.1.0",
		Tools: []*wormholev1.ToolSpec{{
			Name:            "build_source_package",
			Description:     "Build a Debian source package.",
			InputSchemaJson: `{"type":"object","properties":{"distro":{"type":"string"}}}`,
			Capabilities:    []wormholev1.Capability{wormholev1.Capability_CAPABILITY_EXEC_SCOPED},
			RequiresPorts:   []string{"target"},
		}},
		Requires: []*wormholev1.PortSpec{{
			Name: "target",
			Type: "exec-endpoint",
		}},
	}
}

func TestValidManifestPasses(t *testing.T) {
	if err := ValidateManifest(validManifest()); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
}

func TestValidateManifest(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*wormholev1.Manifest)
		wantErr string
	}{
		{"nil manifest is rejected", nil, "missing"},
		{"bad wormhole name", func(m *wormholev1.Manifest) { m.Name = "DebBuilder" }, "kebab-case"},
		{"empty version", func(m *wormholev1.Manifest) { m.Version = "" }, "version"},
		{"bad tool name", func(m *wormholev1.Manifest) { m.Tools[0].Name = "Build-It" }, "snake_case"},
		{"no capabilities", func(m *wormholev1.Manifest) { m.Tools[0].Capabilities = nil }, "no capabilities"},
		{"unspecified capability", func(m *wormholev1.Manifest) {
			m.Tools[0].Capabilities = []wormholev1.Capability{wormholev1.Capability_CAPABILITY_UNSPECIFIED}
		}, "unknown capability"},
		{"out-of-range capability", func(m *wormholev1.Manifest) {
			m.Tools[0].Capabilities = []wormholev1.Capability{wormholev1.Capability(42)}
		}, "unknown capability"},
		{"schema not json", func(m *wormholev1.Manifest) { m.Tools[0].InputSchemaJson = "{nope" }, "schema"},
		{"undeclared required port", func(m *wormholev1.Manifest) { m.Tools[0].RequiresPorts = []string{"ghost"} }, "ghost"},
		{"duplicate tool", func(m *wormholev1.Manifest) { m.Tools = append(m.Tools, m.Tools[0]) }, "duplicate tool"},
		{"duplicate port", func(m *wormholev1.Manifest) { m.Requires = append(m.Requires, m.Requires[0]) }, "duplicate port"},
		{"bad port type", func(m *wormholev1.Manifest) { m.Requires[0].Type = "Exec Endpoint" }, "invalid type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m *wormholev1.Manifest
			if tt.mutate != nil {
				m = validManifest()
				tt.mutate(m)
			}
			err := ValidateManifest(m)
			if err == nil {
				t.Fatal("want error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestAllErrorsReportedTogether(t *testing.T) {
	m := validManifest()
	m.Name = "Bad Name"
	m.Version = ""
	m.Tools[0].Capabilities = nil
	err := ValidateManifest(m)
	if err == nil {
		t.Fatal("want error")
	}
	for _, want := range []string{"kebab-case", "version", "no capabilities"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("joined error should mention %q, got: %v", want, err)
		}
	}
}
