package session

import (
	"errors"
	"fmt"

	wormholev1 "github.com/talhaHavadar/interstellar/gen/wormhole/v1"
)

// Validate checks every target against the loaded wormholes: the wormhole
// exists and provides the named port, every `via` edge matches a required
// port of the right type, all non-optional required ports are routed, and
// the routing graph is acyclic. All problems are reported together.
func Validate(reg Registry, targets map[string]Target) error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	for name, t := range targets {
		if name != t.Name {
			fail("target %q has mismatched name %q", name, t.Name)
		}
		wh, ok := reg.Get(t.Wormhole)
		if !ok {
			fail("target %q: wormhole %q is not loaded", name, t.Wormhole)
			continue
		}

		if findPort(wh.Manifest.Provides, t.Port) == nil {
			fail("target %q: wormhole %q does not provide port %q", name, t.Wormhole, t.Port)
		}

		// Every via edge must name a real required port, and the upstream
		// target must provide a matching type.
		for reqPort, upName := range t.Via {
			req := findPort(wh.Manifest.Requires, reqPort)
			if req == nil {
				fail("target %q: wormhole %q has no required port %q (named in via)", name, t.Wormhole, reqPort)
				continue
			}
			up, ok := targets[upName]
			if !ok {
				fail("target %q: via target %q does not exist", name, upName)
				continue
			}
			if upType := providedType(reg, up); upType != "" && upType != req.Type {
				fail("target %q: via target %q provides %q but port %q needs %q",
					name, upName, upType, reqPort, req.Type)
			}
		}

		// Non-optional required ports must all be routed.
		for _, req := range wh.Manifest.Requires {
			if req.Optional {
				continue
			}
			if _, routed := t.Via[req.Name]; !routed {
				fail("target %q: required port %q is not routed (add it under via)", name, req.Name)
			}
		}
	}

	if err := detectCycles(targets); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func findPort(ports []*wormholev1.PortSpec, name string) *wormholev1.PortSpec {
	for _, p := range ports {
		if p.Name == name {
			return p
		}
	}
	return nil
}

// providedType returns the type of the port a target provides, or "" if it
// cannot be determined (a separate error already covers that case).
func providedType(reg Registry, t Target) string {
	wh, ok := reg.Get(t.Wormhole)
	if !ok {
		return ""
	}
	if p := findPort(wh.Manifest.Provides, t.Port); p != nil {
		return p.Type
	}
	return ""
}

func detectCycles(targets map[string]Target) error {
	const (
		visiting = 1
		done     = 2
	)
	state := map[string]int{}

	var walk func(name string, path []string) error
	walk = func(name string, path []string) error {
		switch state[name] {
		case done:
			return nil
		case visiting:
			return fmt.Errorf("via routing cycle: %v -> %s", path, name)
		}
		t, ok := targets[name]
		if !ok {
			return nil // missing target already reported
		}
		state[name] = visiting
		for _, up := range t.Via {
			if err := walk(up, append(path, name)); err != nil {
				return err
			}
		}
		state[name] = done
		return nil
	}

	for name := range targets {
		if err := walk(name, nil); err != nil {
			return err
		}
	}
	return nil
}
