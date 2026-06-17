package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadRejectsViaNestedUnderConfig(t *testing.T) {
	// The exact footgun: via indented under config instead of at target level.
	path := writeConfig(t, `
targets:
  remote:
    wormhole: ssh
    port: target
    config:
      host: h
      via:
        net: tailnet
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("want error for via nested under config")
	}
	if !strings.Contains(err.Error(), "via") || !strings.Contains(err.Error(), "indentation") {
		t.Errorf("error should explain the misindentation, got: %v", err)
	}
}

func TestLoadAcceptsViaAtTargetLevel(t *testing.T) {
	path := writeConfig(t, `
targets:
  tailnet:
    wormhole: tailscale
    port: tailnet
  remote:
    wormhole: ssh
    port: target
    via:
      net: tailnet
    config:
      host: h
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if got := cfg.Targets["remote"].Via["net"]; got != "tailnet" {
		t.Errorf("via not parsed: %q", got)
	}
}

func TestTargetVisibilityDefaultAndOverride(t *testing.T) {
	path := writeConfig(t, `
targets:
  shown:
    wormhole: ssh
    port: target
  hidden:
    wormhole: ssh
    port: target
    visible: false
  explicit-true:
    wormhole: ssh
    port: target
    visible: true
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if !cfg.Targets["shown"].IsVisible() {
		t.Error("missing visible field should default to true")
	}
	if cfg.Targets["hidden"].IsVisible() {
		t.Error("visible: false should hide the target")
	}
	if !cfg.Targets["explicit-true"].IsVisible() {
		t.Error("visible: true should keep the target visible")
	}
}

func TestLoadRejectsVisibleNestedUnderConfig(t *testing.T) {
	path := writeConfig(t, `
targets:
  remote:
    wormhole: ssh
    port: target
    config:
      host: h
      visible: false
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("want error for visible nested under config")
	}
	if !strings.Contains(err.Error(), "visible") {
		t.Errorf("error should mention visible, got: %v", err)
	}
}

func TestLoadRejectsUnknownTopLevelField(t *testing.T) {
	path := writeConfig(t, "listen: :8420\nbogus_field: x\n")
	if _, err := Load(path); err == nil {
		t.Error("unknown field should be rejected by KnownFields")
	}
}
