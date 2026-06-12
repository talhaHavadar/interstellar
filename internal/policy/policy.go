// Package policy decides which wormhole tools the gateway exposes and
// executes. Decisions are based on the capability classes each tool declares
// in its manifest, plus per-wormhole rules from server configuration.
//
// The default posture denies the "exec.arbitrary" class: a tool that runs
// caller-supplied commands is unavailable until the server admin explicitly
// opts that wormhole in.
package policy

import (
	"fmt"
	"path"

	wormholev1 "github.com/talhaHavadar/interstellar/gen/wormhole/v1"
	"github.com/talhaHavadar/interstellar/pkg/wormhole"
)

// Config is the policy section of the server configuration. Capability
// names are validated when the engine is built, so a typo fails at startup
// with the list of valid names.
type Config struct {
	// DenyCapabilities lists capability classes denied for every wormhole
	// unless a per-wormhole rule allows them. When the field is absent from
	// the configuration it defaults to ["exec.arbitrary"]; set it to an
	// explicit empty list to deny nothing.
	DenyCapabilities []string `yaml:"deny_capabilities"`
	// Wormholes holds per-wormhole overrides, keyed by wormhole name.
	Wormholes map[string]WormholeRules `yaml:"wormholes"`
}

// WormholeRules are per-wormhole policy overrides.
type WormholeRules struct {
	// AllowCapabilities re-allows globally denied classes for this wormhole.
	AllowCapabilities []string `yaml:"allow_capabilities"`
	// DenyTools blocks individual tools by name; glob patterns allowed.
	DenyTools []string `yaml:"deny_tools"`
}

// DefaultDenied is applied when deny_capabilities is absent.
var DefaultDenied = []string{wormhole.CapExecArbitrary.String()}

// Decision is the outcome of a policy check.
type Decision struct {
	Allow  bool
	Reason string // set when denied
}

// Engine evaluates tool calls against the configured policy.
type Engine struct {
	denied map[wormhole.Capability]bool
	rules  map[string]compiledRules
}

type compiledRules struct {
	allowed   map[wormhole.Capability]bool
	denyTools []string
}

// New compiles a policy configuration, validating every capability name.
func New(cfg Config) (*Engine, error) {
	e := &Engine{denied: map[wormhole.Capability]bool{}, rules: map[string]compiledRules{}}

	denyNames := cfg.DenyCapabilities
	if denyNames == nil {
		denyNames = DefaultDenied
	}
	for _, name := range denyNames {
		c, err := wormhole.ParseCapability(name)
		if err != nil {
			return nil, fmt.Errorf("policy deny_capabilities: %w", err)
		}
		e.denied[c] = true
	}

	for wname, r := range cfg.Wormholes {
		cr := compiledRules{allowed: map[wormhole.Capability]bool{}, denyTools: r.DenyTools}
		for _, name := range r.AllowCapabilities {
			c, err := wormhole.ParseCapability(name)
			if err != nil {
				return nil, fmt.Errorf("policy wormholes.%s.allow_capabilities: %w", wname, err)
			}
			cr.allowed[c] = true
		}
		for _, pattern := range r.DenyTools {
			if _, err := path.Match(pattern, ""); err != nil {
				return nil, fmt.Errorf("policy wormholes.%s.deny_tools: bad pattern %q: %v", wname, pattern, err)
			}
		}
		e.rules[wname] = cr
	}
	return e, nil
}

// CheckTool decides whether the named wormhole's tool may be exposed and
// executed.
func (e *Engine) CheckTool(wormholeName string, t *wormholev1.ToolSpec) Decision {
	rules := e.rules[wormholeName]

	for _, pattern := range rules.denyTools {
		if ok, _ := path.Match(pattern, t.Name); ok {
			return Decision{Reason: fmt.Sprintf("tool %q is denied by policy for wormhole %q", t.Name, wormholeName)}
		}
	}

	for _, pc := range t.Capabilities {
		c, err := wormhole.CapabilityFromProto(pc)
		if err != nil {
			// Unknown classes never pass validation, but fail closed anyway.
			return Decision{Reason: fmt.Sprintf("tool %q declares an unknown capability", t.Name)}
		}
		if e.denied[c] && !rules.allowed[c] {
			return Decision{Reason: fmt.Sprintf(
				"tool %q requires capability %q which is denied by policy; allow it for wormhole %q in the server config to enable",
				t.Name, c, wormholeName)}
		}
	}
	return Decision{Allow: true}
}
