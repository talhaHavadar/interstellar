package wormhole

import (
	"fmt"
	"sort"
	"strings"

	wormholev1 "github.com/talhaHavadar/interstellar/gen/wormhole/v1"
)

// Capability classifies what a tool is allowed to do. Capabilities are
// enforced by the core's policy engine; they are not advisory hints.
//
// Always use the exported constants. The string forms ("read", "exec.scoped",
// ...) appear in policy configuration and are validated when the core loads
// its config, so a typo there fails at startup rather than silently.
type Capability int32

const (
	// CapRead reads state and has no side effects.
	CapRead = Capability(wormholev1.Capability_CAPABILITY_READ)
	// CapWrite mutates state through a fixed, parameterized procedure.
	CapWrite = Capability(wormholev1.Capability_CAPABILITY_WRITE)
	// CapNetwork establishes or alters network connectivity.
	CapNetwork = Capability(wormholev1.Capability_CAPABILITY_NETWORK)
	// CapExecScoped runs a fixed, purpose-built procedure that happens to
	// execute commands chosen by the wormhole, never by the caller.
	CapExecScoped = Capability(wormholev1.Capability_CAPABILITY_EXEC_SCOPED)
	// CapExecArbitrary executes caller-supplied commands. Denied by default
	// policy; a server admin must explicitly opt a wormhole into this class.
	CapExecArbitrary = Capability(wormholev1.Capability_CAPABILITY_EXEC_ARBITRARY)
)

var capabilityNames = map[Capability]string{
	CapRead:          "read",
	CapWrite:         "write",
	CapNetwork:       "network",
	CapExecScoped:    "exec.scoped",
	CapExecArbitrary: "exec.arbitrary",
}

func (c Capability) String() string {
	if name, ok := capabilityNames[c]; ok {
		return name
	}
	return fmt.Sprintf("capability(%d)", int32(c))
}

// Valid reports whether c is one of the defined capability classes.
func (c Capability) Valid() bool {
	_, ok := capabilityNames[c]
	return ok
}

// Proto converts c to its wire representation.
func (c Capability) Proto() wormholev1.Capability {
	return wormholev1.Capability(c)
}

// CapabilityFromProto converts a wire value, rejecting unknown or
// unspecified values.
func CapabilityFromProto(p wormholev1.Capability) (Capability, error) {
	c := Capability(p)
	if !c.Valid() {
		return 0, fmt.Errorf("unknown capability %d", int32(p))
	}
	return c, nil
}

// ParseCapability parses a capability name as used in policy configuration.
// Unknown names produce an error that lists the valid options.
func ParseCapability(s string) (Capability, error) {
	for c, name := range capabilityNames {
		if name == s {
			return c, nil
		}
	}
	return 0, fmt.Errorf("unknown capability %q (valid: %s)", s, strings.Join(KnownCapabilityNames(), ", "))
}

// KnownCapabilityNames returns all valid capability names, sorted.
func KnownCapabilityNames() []string {
	names := make([]string, 0, len(capabilityNames))
	for _, name := range capabilityNames {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
