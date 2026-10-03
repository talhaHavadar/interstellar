// Package policy decides which wormhole tools the gateway exposes and
// executes. Decisions are based on the capability classes each tool declares
// in its manifest, plus per-wormhole rules from server configuration.
//
// The default posture denies the "exec.arbitrary" class: a tool that runs
// caller-supplied commands is unavailable until the server admin explicitly
// opts that wormhole in.
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"

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
	// Engine configures the external semantic policy engine (e.g. Jev) that
	// backs semantic_checks. When absent, semantic checks are disabled and
	// configuring any is a startup error. It carries connection data only;
	// the policy package never builds or calls the HTTP client (that lives in
	// package jev, wired in by main via WithSemanticEngine).
	Engine *EngineConfig `yaml:"engine"`
	// SemanticChecks are global checks applied to every tool of every wormhole,
	// on top of any per-wormhole checks.
	SemanticChecks []SemanticCheck `yaml:"semantic_checks"`
	// SemanticResultChecks are the result-time counterpart of SemanticChecks:
	// global checks run against each tool's OUTPUT before it is returned to the
	// agent, on top of any per-wormhole result checks.
	SemanticResultChecks []SemanticCheck `yaml:"semantic_result_checks"`
}

// EngineConfig is the connection to the external semantic policy engine.
// Named EngineConfig (not Engine) to avoid colliding with the policy
// evaluator type below.
type EngineConfig struct {
	// Type selects the engine implementation. Defaults to "jev"; only "jev"
	// is supported today.
	Type string `yaml:"type"`
	// APIKey is the engine credential inline. Prefer APIKeyEnv.
	APIKey string `yaml:"api_key"`
	// APIKeyEnv names an environment variable holding the credential; it wins
	// over APIKey when set.
	APIKeyEnv string `yaml:"api_key_env"`
	// BaseURL overrides the engine endpoint (e.g. for a self-hosted proxy).
	BaseURL string `yaml:"base_url"`
	// Model selects the engine model (e.g. "jev-latest").
	Model string `yaml:"model"`
	// Timeout bounds each engine call; exceeding it fails closed (deny).
	Timeout time.Duration `yaml:"timeout"`
}

// WormholeRules are per-wormhole policy overrides.
type WormholeRules struct {
	// AllowCapabilities re-allows globally denied classes for this wormhole.
	AllowCapabilities []string `yaml:"allow_capabilities"`
	// DenyTools blocks individual tools by name; glob patterns allowed.
	DenyTools []string `yaml:"deny_tools"`
	// SemanticChecks are checks applied only to this wormhole's tools.
	SemanticChecks []SemanticCheck `yaml:"semantic_checks"`
	// SemanticResultChecks are result-time checks applied only to this
	// wormhole's tool outputs.
	SemanticResultChecks []SemanticCheck `yaml:"semantic_result_checks"`
}

// SemanticCheck attaches natural-language deny conditions to a set of tools.
// The gateway asks the engine whether any of DenyRules matches; a probability
// at or above the threshold denies. The same shape drives both call-time
// checks (judging the arguments) and result-time checks (judging the output) —
// which one is decided by the config list the check lives in.
type SemanticCheck struct {
	// Tools are glob patterns matched against the (unqualified) tool name.
	// Empty means every tool ("*").
	Tools []string `yaml:"tools"`
	// DenyRules are prohibited conditions, in plain language. Required.
	DenyRules []string `yaml:"deny_rules"`
	// DenyThreshold is the violation-probability cutoff in [0,1]. A nil value
	// (field absent) defaults to 0.5; an explicit 0 is honored.
	DenyThreshold *float64 `yaml:"deny_threshold"`
}

// SemanticEngine evaluates whether a tool call matches natural-language rules.
// It is implemented outside this package (package jev) and injected via
// WithSemanticEngine, so the policy package stays free of net/http.
type SemanticEngine interface {
	// Evaluate returns one Verdict per rule, in the same order as rules. A
	// non-nil error means the gateway must fail closed (deny).
	Evaluate(ctx context.Context, call CallDescription, rules []string) ([]Verdict, error)
}

// CallDescription is the tool call handed to the semantic engine. For a
// call-time check Args is set and Result is nil; for a result-time check
// Result carries the tool's output and Args is left empty.
type CallDescription struct {
	Wormhole string
	Tool     string
	Args     json.RawMessage
	Result   json.RawMessage
}

// Verdict is the engine's judgment for one rule.
type Verdict struct {
	// Probability is the likelihood (0..1) that the rule is matched/violated.
	Probability float64
	// Model is the engine model version that produced the verdict, for audit.
	Model string
}

// SemanticVerdict is the decided semantic check, surfaced for the audit log.
// On a fail-closed engine error, Err is set and the numeric fields are zero.
type SemanticVerdict struct {
	Rule        string
	Probability float64
	Threshold   float64
	Model       string
	Err         string
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
	denied             map[wormhole.Capability]bool
	rules              map[string]compiledRules
	globalChecks       []compiledCheck
	globalResultChecks []compiledCheck
	semantic           SemanticEngine
}

type compiledRules struct {
	allowed      map[wormhole.Capability]bool
	denyTools    []string
	checks       []compiledCheck
	resultChecks []compiledCheck
}

// compiledCheck is a SemanticCheck with its threshold resolved and tool globs
// defaulted.
type compiledCheck struct {
	tools     []string // glob patterns; defaulted to {"*"}
	denyRules []string
	threshold float64
}

// Option configures an Engine at construction.
type Option func(*Engine)

// WithSemanticEngine injects the backend used to evaluate semantic_checks.
// Without it, any configured semantic_checks are a startup error.
func WithSemanticEngine(se SemanticEngine) Option {
	return func(e *Engine) { e.semantic = se }
}

// New compiles a policy configuration, validating every capability name and
// semantic check.
func New(cfg Config, opts ...Option) (*Engine, error) {
	e := &Engine{denied: map[wormhole.Capability]bool{}, rules: map[string]compiledRules{}}
	for _, o := range opts {
		o(e)
	}

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

	hasChecks := false

	global, err := compileChecks(cfg.SemanticChecks, "semantic_checks")
	if err != nil {
		return nil, err
	}
	e.globalChecks = global
	hasChecks = hasChecks || len(global) > 0

	globalResult, err := compileChecks(cfg.SemanticResultChecks, "semantic_result_checks")
	if err != nil {
		return nil, err
	}
	e.globalResultChecks = globalResult
	hasChecks = hasChecks || len(globalResult) > 0

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
		checks, err := compileChecks(r.SemanticChecks, fmt.Sprintf("wormholes.%s.semantic_checks", wname))
		if err != nil {
			return nil, err
		}
		cr.checks = checks
		hasChecks = hasChecks || len(checks) > 0

		resultChecks, err := compileChecks(r.SemanticResultChecks, fmt.Sprintf("wormholes.%s.semantic_result_checks", wname))
		if err != nil {
			return nil, err
		}
		cr.resultChecks = resultChecks
		hasChecks = hasChecks || len(resultChecks) > 0
		e.rules[wname] = cr
	}

	if hasChecks && e.semantic == nil {
		return nil, fmt.Errorf("policy: semantic_checks are configured but no policy.engine is defined")
	}
	return e, nil
}

// compileChecks validates a slice of semantic checks and resolves defaults.
// ctx is the config path used in error messages (e.g. "semantic_checks").
func compileChecks(checks []SemanticCheck, ctx string) ([]compiledCheck, error) {
	var out []compiledCheck
	for i, c := range checks {
		if len(c.DenyRules) == 0 {
			return nil, fmt.Errorf("policy %s[%d]: deny_rules must not be empty", ctx, i)
		}
		for j, rule := range c.DenyRules {
			if strings.TrimSpace(rule) == "" {
				return nil, fmt.Errorf("policy %s[%d].deny_rules[%d]: rule must not be empty", ctx, i, j)
			}
		}
		tools := c.Tools
		if len(tools) == 0 {
			tools = []string{"*"}
		}
		for _, pattern := range tools {
			if _, err := path.Match(pattern, ""); err != nil {
				return nil, fmt.Errorf("policy %s[%d].tools: bad pattern %q: %v", ctx, i, pattern, err)
			}
		}
		threshold := 0.5
		if c.DenyThreshold != nil {
			threshold = *c.DenyThreshold
			if threshold < 0 || threshold > 1 {
				return nil, fmt.Errorf("policy %s[%d].deny_threshold: must be in [0,1], got %v", ctx, i, threshold)
			}
		}
		out = append(out, compiledCheck{tools: tools, denyRules: c.DenyRules, threshold: threshold})
	}
	return out, nil
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

// CheckCall applies call-time semantic checks to an already-capability-allowed
// tool call: it judges the wormhole/tool/arguments against the matching
// semantic_checks and denies a match before the tool runs. See evalChecks for
// the decision rules.
func (e *Engine) CheckCall(ctx context.Context, wormholeName, toolName string, args json.RawMessage) (Decision, *SemanticVerdict) {
	return e.evalChecks(ctx, toolName,
		[][]compiledCheck{e.globalChecks, e.rules[wormholeName].checks},
		CallDescription{Wormhole: wormholeName, Tool: toolName, Args: args})
}

// CheckResult applies result-time semantic checks to a tool's output before it
// is returned to the agent: it judges the wormhole/tool/output against the
// matching semantic_result_checks and denies a match, withholding the output.
// Unlike CheckCall the tool has ALREADY run, so this gates egress of the output
// to the agent, not the side effect. See evalChecks for the decision rules.
func (e *Engine) CheckResult(ctx context.Context, wormholeName, toolName string, result json.RawMessage) (Decision, *SemanticVerdict) {
	return e.evalChecks(ctx, toolName,
		[][]compiledCheck{e.globalResultChecks, e.rules[wormholeName].resultChecks},
		CallDescription{Wormhole: wormholeName, Tool: toolName, Result: result})
}

// evalChecks is the shared core of CheckCall and CheckResult. It gathers the
// deny rules from every check group whose tool globs match toolName, asks the
// semantic engine (with desc as the state) whether any rule matches, and
// denies on the first verdict at or above its threshold.
//
// It only ever narrows: with no engine, no matching checks, or an all-clear
// verdict it allows. A nil error from the engine is required to allow — any
// engine error or malformed result fails closed (deny). The returned
// *SemanticVerdict (nil when no check ran) is for the audit log: the deciding
// rule on a deny, or the highest-scoring rule on an allow.
func (e *Engine) evalChecks(ctx context.Context, toolName string, groups [][]compiledCheck, desc CallDescription) (Decision, *SemanticVerdict) {
	if e.semantic == nil {
		return Decision{Allow: true}, nil
	}

	type ruleRef struct {
		rule      string
		threshold float64
	}
	var refs []ruleRef
	for _, checks := range groups {
		for _, c := range checks {
			if !matchAny(c.tools, toolName) {
				continue
			}
			for _, rule := range c.denyRules {
				refs = append(refs, ruleRef{rule: rule, threshold: c.threshold})
			}
		}
	}
	if len(refs) == 0 {
		return Decision{Allow: true}, nil
	}

	rules := make([]string, len(refs))
	for i, r := range refs {
		rules[i] = r.rule
	}

	verdicts, err := e.semantic.Evaluate(ctx, desc, rules)
	if err != nil {
		reason := fmt.Sprintf("denied: semantic policy engine error: %v", err)
		return Decision{Reason: reason}, &SemanticVerdict{Err: err.Error()}
	}
	if len(verdicts) != len(refs) {
		reason := fmt.Sprintf("denied: semantic policy engine returned %d verdicts for %d rules", len(verdicts), len(refs))
		return Decision{Reason: reason}, &SemanticVerdict{Err: "verdict count mismatch"}
	}

	var best *SemanticVerdict
	for i, v := range verdicts {
		sv := &SemanticVerdict{Rule: refs[i].rule, Probability: v.Probability, Threshold: refs[i].threshold, Model: v.Model}
		if v.Probability >= refs[i].threshold {
			reason := fmt.Sprintf("denied by semantic policy: %q (p=%.2f >= %.2f)", refs[i].rule, v.Probability, refs[i].threshold)
			return Decision{Reason: reason}, sv
		}
		if best == nil || v.Probability > best.Probability {
			best = sv
		}
	}
	return Decision{Allow: true}, best
}

// SemanticChecksFor returns the call-time deny rules (global + per-wormhole)
// whose tool globs match toolName, for display in interstellar__status.
func (e *Engine) SemanticChecksFor(wormholeName, toolName string) []string {
	return rulesFor([][]compiledCheck{e.globalChecks, e.rules[wormholeName].checks}, toolName)
}

// SemanticResultChecksFor returns the result-time deny rules (global +
// per-wormhole) whose tool globs match toolName, for interstellar__status.
func (e *Engine) SemanticResultChecksFor(wormholeName, toolName string) []string {
	return rulesFor([][]compiledCheck{e.globalResultChecks, e.rules[wormholeName].resultChecks}, toolName)
}

// rulesFor flattens the deny rules of every check whose tool globs match.
func rulesFor(groups [][]compiledCheck, toolName string) []string {
	var rules []string
	for _, checks := range groups {
		for _, c := range checks {
			if matchAny(c.tools, toolName) {
				rules = append(rules, c.denyRules...)
			}
		}
	}
	return rules
}

// matchAny reports whether name matches any of the glob patterns.
func matchAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
}
