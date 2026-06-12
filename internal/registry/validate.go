package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	wormholev1 "github.com/talhaHavadar/interstellar/gen/wormhole/v1"
	"github.com/talhaHavadar/interstellar/pkg/wormhole"
)

var (
	nameRE     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	toolNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	portTypeRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
)

// ValidateManifest checks a wormhole manifest before the wormhole is
// admitted. It returns all problems found, joined, so authors can fix a
// manifest in one round trip.
func ValidateManifest(m *wormholev1.Manifest) error {
	if m == nil {
		return errors.New("manifest is missing")
	}
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	if !nameRE.MatchString(m.Name) {
		fail("name %q must be lowercase kebab-case (max 64 chars)", m.Name)
	}
	if m.Version == "" {
		fail("version must not be empty")
	}

	requiredPorts := map[string]bool{}
	portNames := map[string]bool{}
	for _, p := range m.Requires {
		validatePort(p, "requires", portNames, &errs)
		requiredPorts[p.Name] = true
	}
	for _, p := range m.Provides {
		validatePort(p, "provides", portNames, &errs)
	}

	toolNames := map[string]bool{}
	for _, t := range m.Tools {
		if !toolNameRE.MatchString(t.Name) {
			fail("tool %q must be lowercase snake_case (max 64 chars)", t.Name)
		}
		if toolNames[t.Name] {
			fail("duplicate tool %q", t.Name)
		}
		toolNames[t.Name] = true

		if len(t.Capabilities) == 0 {
			fail("tool %q declares no capabilities", t.Name)
		}
		for _, c := range t.Capabilities {
			if _, err := wormhole.CapabilityFromProto(c); err != nil {
				fail("tool %q: %v", t.Name, err)
			}
		}

		var schema map[string]any
		if err := json.Unmarshal([]byte(t.InputSchemaJson), &schema); err != nil {
			fail("tool %q input schema is not a JSON object: %v", t.Name, err)
		}

		for _, port := range t.RequiresPorts {
			if !requiredPorts[port] {
				fail("tool %q requires port %q which is not declared in the manifest's requires", t.Name, port)
			}
		}
	}

	return errors.Join(errs...)
}

func validatePort(p *wormholev1.PortSpec, section string, seen map[string]bool, errs *[]error) {
	if !nameRE.MatchString(p.Name) {
		*errs = append(*errs, fmt.Errorf("%s port %q must be lowercase kebab-case", section, p.Name))
	}
	if seen[p.Name] {
		*errs = append(*errs, fmt.Errorf("duplicate port name %q", p.Name))
	}
	seen[p.Name] = true
	if !portTypeRE.MatchString(p.Type) {
		*errs = append(*errs, fmt.Errorf("%s port %q has invalid type %q (want lowercase kebab-case)", section, p.Name, p.Type))
	}
}
