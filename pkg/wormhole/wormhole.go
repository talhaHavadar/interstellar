// Package wormhole is the SDK for writing interstellar wormholes in Go.
//
// A wormhole is a purpose-built plugin: it exposes a small set of typed
// tools that perform specific tasks, and optionally typed ports that other
// wormholes can compose with. Define a struct for each tool's input, register
// the tools, and call [Wormhole.Serve] from main:
//
//	func main() {
//		w := wormhole.New("deb-builder", "0.1.0", "Builds Debian packages.")
//		wormhole.AddTool(w, wormhole.Tool[BuildInput]{
//			Name:         "build_source_package",
//			Description:  "Build a Debian source package.",
//			Capabilities: []wormhole.Capability{wormhole.CapExecScoped},
//			Handler:      build,
//		})
//		w.Serve()
//	}
//
// Resist the temptation to expose a generic "run any command" tool. The
// interstellar composition model exists precisely so you don't need one:
// raw execution travels through ports between wormholes, and agents only
// ever see purpose-built, parameterized operations.
package wormhole

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/google/jsonschema-go/jsonschema"
	wormholev1 "github.com/talhaHavadar/interstellar/gen/wormhole/v1"
)

var (
	nameRE     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	toolNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

// Wormhole accumulates the wormhole's identity, tools, and ports, and serves
// them to the interstellar core. Construct with [New].
type Wormhole struct {
	name        string
	version     string
	description string

	tools       map[string]*toolRuntime
	toolOrder   []string
	requires    []Port
	provides    []Port
	linkHandler map[string]LinkHandler
}

type toolRuntime struct {
	spec    *wormholev1.ToolSpec
	handler func(ctx context.Context, call *Call, argsJSON []byte) (any, error)
}

// New creates a wormhole. The name must be lowercase kebab-case; it
// namespaces every tool the wormhole exposes (e.g. "deb-builder" tools
// appear to agents as "deb-builder__<tool>").
func New(name, version, description string) *Wormhole {
	if !nameRE.MatchString(name) {
		panic(fmt.Sprintf("wormhole: invalid name %q (want lowercase kebab-case)", name))
	}
	if version == "" {
		panic("wormhole: version must not be empty")
	}
	return &Wormhole{
		name:        name,
		version:     version,
		description: description,
		tools:       map[string]*toolRuntime{},
		linkHandler: map[string]LinkHandler{},
	}
}

// Tool declares one agent-facing operation. In is the argument struct; its
// JSON Schema is generated from the struct's fields (use `json` tags for
// names and `jsonschema` tags for per-field descriptions).
type Tool[In any] struct {
	// Name in lowercase snake_case, e.g. "build_source_package".
	Name        string
	Description string
	// Capabilities the tool exercises. Required, and enforced by the core's
	// policy engine — declare honestly, the audit log sees everything.
	Capabilities []Capability
	// RequiresPorts names entries of the wormhole's required ports that must
	// be linked before this tool can run. The core resolves and passes the
	// links; the handler retrieves them with Call.Link.
	RequiresPorts []string
	// Handler runs the tool. Returning an error produces a tool error for
	// the agent; the returned value is JSON-marshaled as the result.
	Handler func(ctx context.Context, call *Call, in In) (any, error)
}

// AddTool registers a tool. It panics on invalid definitions (bad name,
// missing capabilities, unschematizable input type) — these are programmer
// errors, caught the first time the wormhole runs.
func AddTool[In any](w *Wormhole, t Tool[In]) {
	if !toolNameRE.MatchString(t.Name) {
		panic(fmt.Sprintf("wormhole: invalid tool name %q (want lowercase snake_case)", t.Name))
	}
	if _, dup := w.tools[t.Name]; dup {
		panic(fmt.Sprintf("wormhole: duplicate tool %q", t.Name))
	}
	if len(t.Capabilities) == 0 {
		panic(fmt.Sprintf("wormhole: tool %q declares no capabilities", t.Name))
	}
	caps := make([]wormholev1.Capability, len(t.Capabilities))
	for i, c := range t.Capabilities {
		if !c.Valid() {
			panic(fmt.Sprintf("wormhole: tool %q has invalid capability %d", t.Name, int32(c)))
		}
		caps[i] = c.Proto()
	}
	if t.Handler == nil {
		panic(fmt.Sprintf("wormhole: tool %q has no handler", t.Name))
	}
	schema, err := jsonschema.For[In](nil)
	if err != nil {
		panic(fmt.Sprintf("wormhole: tool %q input schema: %v", t.Name, err))
	}
	schemaJSON, err := json.Marshal(schema)
	if err != nil {
		panic(fmt.Sprintf("wormhole: tool %q input schema: %v", t.Name, err))
	}

	w.tools[t.Name] = &toolRuntime{
		spec: &wormholev1.ToolSpec{
			Name:            t.Name,
			Description:     t.Description,
			InputSchemaJson: string(schemaJSON),
			Capabilities:    caps,
			RequiresPorts:   t.RequiresPorts,
		},
		handler: func(ctx context.Context, call *Call, argsJSON []byte) (any, error) {
			var in In
			if len(argsJSON) > 0 {
				if err := json.Unmarshal(argsJSON, &in); err != nil {
					return nil, fmt.Errorf("invalid arguments: %w", err)
				}
			}
			return t.Handler(ctx, call, in)
		},
	}
	w.toolOrder = append(w.toolOrder, t.Name)
}

// Require declares a port this wormhole consumes from other wormholes.
func (w *Wormhole) Require(p Port) {
	w.requires = append(w.requires, p)
}

// Provide declares a port this wormhole offers, with the handler that
// brings a link of that port up when the core requests it.
func (w *Wormhole) Provide(p Port, h LinkHandler) {
	if h == nil {
		panic(fmt.Sprintf("wormhole: provided port %q has no link handler", p.Name))
	}
	w.provides = append(w.provides, p)
	w.linkHandler[p.Name] = h
}

func (w *Wormhole) manifest() *wormholev1.Manifest {
	m := &wormholev1.Manifest{
		Name:        w.name,
		Version:     w.version,
		Description: w.description,
	}
	for _, name := range w.toolOrder {
		m.Tools = append(m.Tools, w.tools[name].spec)
	}
	for _, p := range w.provides {
		m.Provides = append(m.Provides, portSpec(p))
	}
	for _, p := range w.requires {
		m.Requires = append(m.Requires, portSpec(p))
	}
	return m
}

func portSpec(p Port) *wormholev1.PortSpec {
	return &wormholev1.PortSpec{
		Name:        p.Name,
		Type:        p.Type,
		Optional:    p.Optional,
		Description: p.Description,
	}
}

// LinkHandler establishes a link on a provided port. It returns the live
// link; the core owns its lifecycle and calls Close when the link is torn
// down.
type LinkHandler func(ctx context.Context, req *LinkRequest) (*ActiveLink, error)

// LinkRequest carries everything needed to bring a provided port up.
type LinkRequest struct {
	// LinkID assigned by the core's session manager.
	LinkID string
	// Config is admin-supplied configuration for this link (e.g. which VPN
	// profile to use), resolved by the core from server config. It never
	// comes from the agent.
	Config json.RawMessage
	// Links are upstream links this link should be established through.
	Links []Link
}

// ActiveLink is a live link on a provided port.
type ActiveLink struct {
	// Descriptor is JSON-marshaled and delivered to the link's consumer.
	// Its schema is defined by the port type (see the descriptor types in
	// this package).
	Descriptor any
	// Close tears the link down. May be nil if there is nothing to release.
	Close func() error
}

// Link is a live connection handle received from the core, satisfying one
// of the wormhole's required ports.
type Link struct {
	ID       string
	PortName string
	Type     string
	// Descriptor is the raw payload; decode it with DecodeDescriptor into
	// the descriptor type for the port type.
	Descriptor json.RawMessage
}

// DecodeDescriptor unmarshals the link's descriptor into v.
func (l Link) DecodeDescriptor(v any) error {
	return json.Unmarshal(l.Descriptor, v)
}

// Call is the per-invocation context handed to tool handlers. It carries
// the resolved links and lets the handler stream logs and progress back to
// the core while running.
type Call struct {
	// ID is the core-assigned correlation id; it appears in the audit log.
	ID string

	links map[string]Link
	emit  func(*wormholev1.CallToolResponse) // nil-safe; serialized by the server
}

// Link returns the live link satisfying the named required port, if any.
func (c *Call) Link(portName string) (Link, bool) {
	l, ok := c.links[portName]
	return l, ok
}

// Logf streams a log line to the core. Level is "debug", "info", "warn" or
// "error".
func (c *Call) Logf(level, format string, args ...any) {
	if c.emit == nil {
		return
	}
	c.emit(&wormholev1.CallToolResponse{
		Event: &wormholev1.CallToolResponse_Log{
			Log: &wormholev1.LogEvent{Level: level, Message: fmt.Sprintf(format, args...)},
		},
	})
}

// Progress streams a progress update. Fraction is in [0,1], or -1 when
// indeterminate.
func (c *Call) Progress(fraction float64, message string) {
	if c.emit == nil {
		return
	}
	c.emit(&wormholev1.CallToolResponse{
		Event: &wormholev1.CallToolResponse_Progress{
			Progress: &wormholev1.ProgressEvent{Fraction: fraction, Message: message},
		},
	})
}
