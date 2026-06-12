package policy

import (
	"strings"
	"testing"

	wormholev1 "github.com/talhaHavadar/interstellar/gen/wormhole/v1"
)

func tool(name string, caps ...wormholev1.Capability) *wormholev1.ToolSpec {
	return &wormholev1.ToolSpec{Name: name, Capabilities: caps}
}

func TestDefaultDeniesArbitraryExec(t *testing.T) {
	e, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}

	dec := e.CheckTool("shell", tool("run", wormholev1.Capability_CAPABILITY_EXEC_ARBITRARY))
	if dec.Allow {
		t.Fatal("exec.arbitrary should be denied by default")
	}
	if !strings.Contains(dec.Reason, "exec.arbitrary") {
		t.Errorf("reason should name the denied capability, got %q", dec.Reason)
	}

	if dec := e.CheckTool("deb-builder", tool("build", wormholev1.Capability_CAPABILITY_EXEC_SCOPED)); !dec.Allow {
		t.Errorf("exec.scoped should be allowed by default, got %q", dec.Reason)
	}
	if dec := e.CheckTool("echo", tool("say", wormholev1.Capability_CAPABILITY_READ)); !dec.Allow {
		t.Errorf("read should be allowed by default, got %q", dec.Reason)
	}
}

func TestPerWormholeOptIn(t *testing.T) {
	e, err := New(Config{
		Wormholes: map[string]WormholeRules{
			"trusted-shell": {AllowCapabilities: []string{"exec.arbitrary"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if dec := e.CheckTool("trusted-shell", tool("run", wormholev1.Capability_CAPABILITY_EXEC_ARBITRARY)); !dec.Allow {
		t.Errorf("opted-in wormhole should be allowed, got %q", dec.Reason)
	}
	if dec := e.CheckTool("other-shell", tool("run", wormholev1.Capability_CAPABILITY_EXEC_ARBITRARY)); dec.Allow {
		t.Error("opt-in must not leak to other wormholes")
	}
}

func TestExplicitEmptyDenyListDeniesNothing(t *testing.T) {
	e, err := New(Config{DenyCapabilities: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if dec := e.CheckTool("shell", tool("run", wormholev1.Capability_CAPABILITY_EXEC_ARBITRARY)); !dec.Allow {
		t.Errorf("explicit empty deny list should deny nothing, got %q", dec.Reason)
	}
}

func TestDenyTools(t *testing.T) {
	e, err := New(Config{
		Wormholes: map[string]WormholeRules{
			"deb-builder": {DenyTools: []string{"publish_*"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec := e.CheckTool("deb-builder", tool("publish_package", wormholev1.Capability_CAPABILITY_WRITE)); dec.Allow {
		t.Error("glob-denied tool should be blocked")
	}
	if dec := e.CheckTool("deb-builder", tool("build_source_package", wormholev1.Capability_CAPABILITY_EXEC_SCOPED)); !dec.Allow {
		t.Errorf("other tools should pass, got %q", dec.Reason)
	}
}

func TestTypoInCapabilityNameFailsAtStartup(t *testing.T) {
	_, err := New(Config{DenyCapabilities: []string{"exec.arbitary"}}) // typo
	if err == nil {
		t.Fatal("typo in deny_capabilities must fail config load")
	}
	if !strings.Contains(err.Error(), "exec.arbitrary") {
		t.Errorf("error should list valid names, got %q", err)
	}

	_, err = New(Config{Wormholes: map[string]WormholeRules{
		"x": {AllowCapabilities: []string{"reed"}},
	}})
	if err == nil {
		t.Fatal("typo in allow_capabilities must fail config load")
	}
}

func TestUnknownCapabilityFailsClosed(t *testing.T) {
	e, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if dec := e.CheckTool("x", tool("t", wormholev1.Capability(99))); dec.Allow {
		t.Error("unknown capability value must be denied")
	}
}
