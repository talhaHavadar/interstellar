// Package config loads the interstellar server configuration.
package config

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/talhaHavadar/interstellar/internal/policy"
)

// Config is the interstellard configuration file (YAML).
type Config struct {
	// Listen is the HTTP address for the streamable MCP endpoint. Defaults
	// to loopback; bind a routable address deliberately (and put auth in
	// front of it) when exposing the gateway beyond the host.
	Listen string `yaml:"listen"`
	// WormholeDir is scanned for wormhole plugin executables at startup.
	WormholeDir string `yaml:"wormhole_dir"`
	// AuditLog is the JSONL file every tool call is appended to.
	AuditLog string        `yaml:"audit_log"`
	Policy   policy.Config `yaml:"policy"`
}

// Default returns the configuration used when no file is given.
func Default() *Config {
	return &Config{
		Listen:   "127.0.0.1:8420",
		AuditLog: "interstellar-audit.jsonl",
	}
}

// Load reads the YAML file at path over the defaults. Unknown fields are
// rejected so a typo in the config fails at startup instead of being
// silently ignored.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	return cfg, nil
}
