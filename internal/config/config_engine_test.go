package config

import (
	"testing"
	"time"
)

func TestLoadParsesPolicyEngineAndSemanticChecks(t *testing.T) {
	path := writeConfig(t, `
policy:
  engine:
    type: jev
    api_key_env: TYPESAFE_API_KEY
    base_url: https://example.test
    model: jev-latest
    timeout: 3s
  semantic_checks:
    - deny_rules: ["no secrets"]
      deny_threshold: 0.7
  wormholes:
    mattermost:
      semantic_checks:
        - tools: ["post_*"]
          deny_rules: ["no PII"]
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	eng := cfg.Policy.Engine
	if eng == nil || eng.Type != "jev" {
		t.Fatalf("engine not parsed: %+v", eng)
	}
	if eng.Timeout != 3*time.Second {
		t.Errorf("timeout = %v, want 3s", eng.Timeout)
	}
	if eng.APIKeyEnv != "TYPESAFE_API_KEY" {
		t.Errorf("api_key_env = %q", eng.APIKeyEnv)
	}
	if len(cfg.Policy.SemanticChecks) != 1 || len(cfg.Policy.SemanticChecks[0].DenyRules) != 1 {
		t.Fatalf("global semantic_checks not parsed: %+v", cfg.Policy.SemanticChecks)
	}
	if th := cfg.Policy.SemanticChecks[0].DenyThreshold; th == nil || *th != 0.7 {
		t.Errorf("deny_threshold not parsed: %v", th)
	}
	wc := cfg.Policy.Wormholes["mattermost"].SemanticChecks
	if len(wc) != 1 || len(wc[0].Tools) != 1 || wc[0].Tools[0] != "post_*" {
		t.Errorf("per-wormhole semantic_checks not parsed: %+v", wc)
	}
}

func TestLoadRejectsUnknownEngineField(t *testing.T) {
	path := writeConfig(t, `
policy:
  engine:
    type: jev
    bogus: x
`)
	if _, err := Load(path); err == nil {
		t.Error("unknown policy.engine field should be rejected by KnownFields")
	}
}
