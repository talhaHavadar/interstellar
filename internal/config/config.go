// Package config loads the interstellar server configuration.
package config

import (
	"bytes"
	"fmt"
	"os"
	"time"

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
	AuditLog string `yaml:"audit_log"`
	// Targets are admin-defined endpoints a tool can be pointed at: each
	// binds a wormhole's provided port to a configuration, optionally
	// routed through other targets. Keyed by target name.
	Targets map[string]Target `yaml:"targets"`
	Policy  policy.Config     `yaml:"policy"`
}

// Target binds a wormhole's provided port to admin configuration. Agents
// reference targets by name when calling a tool that needs a linked port;
// they never supply the configuration themselves.
type Target struct {
	// Wormhole providing the port.
	Wormhole string `yaml:"wormhole"`
	// Port is the name of the provided port on that wormhole.
	Port string `yaml:"port"`
	// Config is opaque admin configuration passed to the wormhole when the
	// link is opened (e.g. SSH host/user/key, VPN profile path).
	Config map[string]any `yaml:"config"`
	// Via routes this target's link through other targets: it maps a
	// required port name on the providing wormhole to the target name that
	// satisfies it (e.g. ssh's "net" port -> a vpn target).
	Via map[string]string `yaml:"via"`
	// IdleTimeout is how long the link is kept warm after its last release,
	// for reuse across calls. Zero uses the server default.
	IdleTimeout time.Duration `yaml:"idle_timeout"`
}

// Default returns the configuration used when no file is given.
func Default() *Config {
	return &Config{
		Listen:   "127.0.0.1:8420",
		AuditLog: "interstellar-audit.jsonl",
		Targets:  map[string]Target{},
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
