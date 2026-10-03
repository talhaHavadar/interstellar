package policy

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func f64(v float64) *float64 { return &v }

// fakeEngine is a scripted SemanticEngine for tests.
type fakeEngine struct {
	probs    map[string]float64 // rule -> probability
	err      error
	badCount bool // return a mismatched number of verdicts

	gotRules []string
	gotCall  CallDescription
}

func (f *fakeEngine) Evaluate(_ context.Context, call CallDescription, rules []string) ([]Verdict, error) {
	f.gotRules = rules
	f.gotCall = call
	if f.err != nil {
		return nil, f.err
	}
	n := len(rules)
	if f.badCount {
		n++
	}
	out := make([]Verdict, n)
	for i := range out {
		if i < len(rules) {
			out[i] = Verdict{Probability: f.probs[rules[i]], Model: "jev-test"}
		}
	}
	return out, nil
}

func TestCheckCallNoEngineNoChecks(t *testing.T) {
	e, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if dec, v := e.CheckCall(context.Background(), "w", "t", nil); !dec.Allow || v != nil {
		t.Errorf("no engine and no checks should allow with nil verdict, got %+v / %+v", dec, v)
	}
}

func TestSemanticChecksWithoutEngineFails(t *testing.T) {
	_, err := New(Config{SemanticChecks: []SemanticCheck{{DenyRules: []string{"r"}}}})
	if err == nil {
		t.Fatal("semantic_checks without an engine must fail at startup")
	}
	if !strings.Contains(err.Error(), "policy.engine") {
		t.Errorf("error should point at policy.engine, got %q", err)
	}
}

func TestCheckCallGlobalDeny(t *testing.T) {
	fe := &fakeEngine{probs: map[string]float64{"leaks secrets": 0.9}}
	e, err := New(Config{
		SemanticChecks: []SemanticCheck{{DenyRules: []string{"leaks secrets"}, DenyThreshold: f64(0.5)}},
	}, WithSemanticEngine(fe))
	if err != nil {
		t.Fatal(err)
	}
	dec, v := e.CheckCall(context.Background(), "any", "post", json.RawMessage(`{"x":1}`))
	if dec.Allow {
		t.Fatal("prob >= threshold must deny")
	}
	if v == nil || v.Rule != "leaks secrets" {
		t.Fatalf("verdict should name the deciding rule, got %+v", v)
	}
	if !strings.Contains(dec.Reason, "leaks secrets") {
		t.Errorf("reason should name the rule, got %q", dec.Reason)
	}
	if string(fe.gotCall.Args) != `{"x":1}` {
		t.Errorf("args should reach the engine verbatim, got %s", fe.gotCall.Args)
	}
}

func TestCheckCallAllowBelowThresholdBatchesRules(t *testing.T) {
	fe := &fakeEngine{probs: map[string]float64{"a": 0.1, "b": 0.3}}
	e, err := New(Config{
		SemanticChecks: []SemanticCheck{{DenyRules: []string{"a", "b"}}}, // default threshold 0.5
	}, WithSemanticEngine(fe))
	if err != nil {
		t.Fatal(err)
	}
	dec, v := e.CheckCall(context.Background(), "w", "t", nil)
	if !dec.Allow {
		t.Fatalf("all below threshold should allow, got %q", dec.Reason)
	}
	if len(fe.gotRules) != 2 {
		t.Errorf("both rules should batch into one call, got %v", fe.gotRules)
	}
	if v == nil || v.Rule != "b" {
		t.Errorf("allow verdict should be the highest-scoring rule, got %+v", v)
	}
}

func TestCheckCallDefaultThresholdBoundary(t *testing.T) {
	fe := &fakeEngine{probs: map[string]float64{"r": 0.5}}
	e, err := New(Config{SemanticChecks: []SemanticCheck{{DenyRules: []string{"r"}}}}, WithSemanticEngine(fe))
	if err != nil {
		t.Fatal(err)
	}
	if dec, _ := e.CheckCall(context.Background(), "w", "t", nil); dec.Allow {
		t.Error("probability exactly at the default 0.5 threshold should deny")
	}
}

func TestCheckCallScoping(t *testing.T) {
	fe := &fakeEngine{probs: map[string]float64{"r": 0.9}}
	e, err := New(Config{
		Wormholes: map[string]WormholeRules{
			"mattermost": {SemanticChecks: []SemanticCheck{{Tools: []string{"post_*"}, DenyRules: []string{"r"}}}},
		},
	}, WithSemanticEngine(fe))
	if err != nil {
		t.Fatal(err)
	}
	if dec, _ := e.CheckCall(context.Background(), "mattermost", "post_message", nil); dec.Allow {
		t.Error("matching wormhole+tool check should fire")
	}
	if dec, v := e.CheckCall(context.Background(), "mattermost", "get_channel", nil); !dec.Allow || v != nil {
		t.Error("non-matching tool glob should have no check")
	}
	if dec, _ := e.CheckCall(context.Background(), "other", "post_message", nil); !dec.Allow {
		t.Error("per-wormhole check must not leak to another wormhole")
	}
}

func TestCheckCallFailsClosedOnError(t *testing.T) {
	fe := &fakeEngine{err: errors.New("boom")}
	e, err := New(Config{SemanticChecks: []SemanticCheck{{DenyRules: []string{"r"}}}}, WithSemanticEngine(fe))
	if err != nil {
		t.Fatal(err)
	}
	dec, v := e.CheckCall(context.Background(), "w", "t", nil)
	if dec.Allow {
		t.Fatal("engine error must fail closed")
	}
	if v == nil || v.Err == "" {
		t.Errorf("verdict should record the engine error, got %+v", v)
	}
}

func TestCheckCallFailsClosedOnCountMismatch(t *testing.T) {
	fe := &fakeEngine{badCount: true, probs: map[string]float64{"r": 0}}
	e, err := New(Config{SemanticChecks: []SemanticCheck{{DenyRules: []string{"r"}}}}, WithSemanticEngine(fe))
	if err != nil {
		t.Fatal(err)
	}
	if dec, _ := e.CheckCall(context.Background(), "w", "t", nil); dec.Allow {
		t.Fatal("a mismatched verdict count must fail closed")
	}
}

func TestSemanticCheckValidation(t *testing.T) {
	fe := &fakeEngine{}
	cases := []struct {
		name string
		cfg  Config
	}{
		{"empty deny_rules", Config{SemanticChecks: []SemanticCheck{{}}}},
		{"blank rule", Config{SemanticChecks: []SemanticCheck{{DenyRules: []string{"  "}}}}},
		{"threshold too high", Config{SemanticChecks: []SemanticCheck{{DenyRules: []string{"r"}, DenyThreshold: f64(1.5)}}}},
		{"threshold negative", Config{SemanticChecks: []SemanticCheck{{DenyRules: []string{"r"}, DenyThreshold: f64(-0.1)}}}},
		{"bad glob", Config{SemanticChecks: []SemanticCheck{{Tools: []string{"["}, DenyRules: []string{"r"}}}}},
	}
	for _, c := range cases {
		if _, err := New(c.cfg, WithSemanticEngine(fe)); err == nil {
			t.Errorf("%s: expected a validation error", c.name)
		}
	}
}

func TestSemanticChecksForMergesGlobalAndWormhole(t *testing.T) {
	fe := &fakeEngine{}
	e, err := New(Config{
		SemanticChecks: []SemanticCheck{{DenyRules: []string{"global-rule"}}},
		Wormholes: map[string]WormholeRules{
			"mm": {SemanticChecks: []SemanticCheck{{Tools: []string{"post_*"}, DenyRules: []string{"wh-rule"}}}},
		},
	}, WithSemanticEngine(fe))
	if err != nil {
		t.Fatal(err)
	}
	got := e.SemanticChecksFor("mm", "post_message")
	if len(got) != 2 {
		t.Fatalf("want global + per-wormhole rules, got %v", got)
	}
	if e.SemanticChecksFor("mm", "get_channel")[0] != "global-rule" {
		t.Error("non-matching tool should still get the global rule")
	}
}

// ── result-time checks (CheckResult) ──────────────────────────────────────

func TestCheckResultGlobalDeny(t *testing.T) {
	fe := &fakeEngine{probs: map[string]float64{"output leaks secrets": 0.9}}
	e, err := New(Config{
		SemanticResultChecks: []SemanticCheck{{DenyRules: []string{"output leaks secrets"}, DenyThreshold: f64(0.5)}},
	}, WithSemanticEngine(fe))
	if err != nil {
		t.Fatal(err)
	}
	dec, v := e.CheckResult(context.Background(), "any", "read", json.RawMessage(`{"secret":"x"}`))
	if dec.Allow {
		t.Fatal("prob >= threshold must deny")
	}
	if v == nil || v.Rule != "output leaks secrets" {
		t.Fatalf("verdict should name the deciding rule, got %+v", v)
	}
	if string(fe.gotCall.Result) != `{"secret":"x"}` {
		t.Errorf("result should reach the engine verbatim, got %s", fe.gotCall.Result)
	}
	if len(fe.gotCall.Args) != 0 {
		t.Errorf("a result check should not send call args, got %s", fe.gotCall.Args)
	}
}

func TestResultAndCallChecksAreIndependent(t *testing.T) {
	fe := &fakeEngine{probs: map[string]float64{"call-rule": 0.9, "result-rule": 0.9}}
	e, err := New(Config{
		SemanticChecks:       []SemanticCheck{{DenyRules: []string{"call-rule"}}},
		SemanticResultChecks: []SemanticCheck{{DenyRules: []string{"result-rule"}}},
	}, WithSemanticEngine(fe))
	if err != nil {
		t.Fatal(err)
	}
	if dec, _ := e.CheckCall(context.Background(), "w", "t", nil); dec.Allow {
		t.Fatal("call check should fire")
	}
	if len(fe.gotRules) != 1 || fe.gotRules[0] != "call-rule" {
		t.Errorf("CheckCall should evaluate only call rules, got %v", fe.gotRules)
	}
	if dec, _ := e.CheckResult(context.Background(), "w", "t", json.RawMessage(`{}`)); dec.Allow {
		t.Fatal("result check should fire")
	}
	if len(fe.gotRules) != 1 || fe.gotRules[0] != "result-rule" {
		t.Errorf("CheckResult should evaluate only result rules, got %v", fe.gotRules)
	}
}

func TestCheckResultScoping(t *testing.T) {
	fe := &fakeEngine{probs: map[string]float64{"r": 0.9}}
	e, err := New(Config{
		Wormholes: map[string]WormholeRules{
			"vault": {SemanticResultChecks: []SemanticCheck{{Tools: []string{"read_*"}, DenyRules: []string{"r"}}}},
		},
	}, WithSemanticEngine(fe))
	if err != nil {
		t.Fatal(err)
	}
	if dec, _ := e.CheckResult(context.Background(), "vault", "read_secret", json.RawMessage(`{}`)); dec.Allow {
		t.Error("matching wormhole+tool result check should fire")
	}
	if dec, v := e.CheckResult(context.Background(), "vault", "list_keys", json.RawMessage(`{}`)); !dec.Allow || v != nil {
		t.Error("non-matching tool glob should have no result check")
	}
	if dec, _ := e.CheckResult(context.Background(), "other", "read_secret", json.RawMessage(`{}`)); !dec.Allow {
		t.Error("per-wormhole result check must not leak to another wormhole")
	}
}

func TestSemanticResultChecksWithoutEngineFails(t *testing.T) {
	_, err := New(Config{SemanticResultChecks: []SemanticCheck{{DenyRules: []string{"r"}}}})
	if err == nil {
		t.Fatal("semantic_result_checks without an engine must fail at startup")
	}
	if !strings.Contains(err.Error(), "policy.engine") {
		t.Errorf("error should point at policy.engine, got %q", err)
	}
}

func TestCheckResultFailsClosedOnError(t *testing.T) {
	fe := &fakeEngine{err: errors.New("boom")}
	e, err := New(Config{SemanticResultChecks: []SemanticCheck{{DenyRules: []string{"r"}}}}, WithSemanticEngine(fe))
	if err != nil {
		t.Fatal(err)
	}
	dec, v := e.CheckResult(context.Background(), "w", "t", json.RawMessage(`{}`))
	if dec.Allow {
		t.Fatal("engine error must fail closed")
	}
	if v == nil || v.Err == "" {
		t.Errorf("verdict should record the engine error, got %+v", v)
	}
}

func TestSemanticResultChecksForMergesGlobalAndWormhole(t *testing.T) {
	fe := &fakeEngine{}
	e, err := New(Config{
		SemanticResultChecks: []SemanticCheck{{DenyRules: []string{"global-out"}}},
		Wormholes: map[string]WormholeRules{
			"vault": {SemanticResultChecks: []SemanticCheck{{Tools: []string{"read_*"}, DenyRules: []string{"wh-out"}}}},
		},
	}, WithSemanticEngine(fe))
	if err != nil {
		t.Fatal(err)
	}
	if got := e.SemanticResultChecksFor("vault", "read_secret"); len(got) != 2 {
		t.Fatalf("want global + per-wormhole result rules, got %v", got)
	}
	if e.SemanticResultChecksFor("vault", "other")[0] != "global-out" {
		t.Error("non-matching tool should still get the global result rule")
	}
	// Result rules must not surface under the call-check accessor.
	if got := e.SemanticChecksFor("vault", "read_secret"); len(got) != 0 {
		t.Errorf("call-check accessor should not return result rules, got %v", got)
	}
}
