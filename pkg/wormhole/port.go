package wormhole

// Well-known port types. A port type defines the schema of the descriptor
// carried by links of that type; providers and consumers match on the type
// string and rely on the descriptor schema being stable.
//
// Custom port types are allowed (lowercase kebab-case), but prefer a
// well-known type when one fits so wormholes from different authors compose.
const (
	// PortTypeNetworkContext is a routable network path. Descriptor:
	// NetworkContextDescriptor. The provider (e.g. a VPN wormhole) serves a
	// SOCKS5 dialer on a local unix socket; consumers dial through it
	// without knowing what kind of tunnel is behind it.
	PortTypeNetworkContext = "network-context"

	// PortTypeExecEndpoint is a place to run commands. Descriptor:
	// ExecEndpointDescriptor. The provider (e.g. an SSH wormhole) hosts an
	// execution service for the life of the link.
	PortTypeExecEndpoint = "exec-endpoint"

	// PortTypeMCPEndpoint is a live session to an upstream third-party MCP
	// server. Descriptor: MCPEndpointDescriptor. The provider (e.g. mcp-stdio)
	// holds the upstream session and serves a normalized tool-proxy on a local
	// unix socket; a purpose-built consumer dials it to fulfill its own
	// hand-written tools by calling specific upstream tools. The upstream is
	// never exposed to agents directly.
	PortTypeMCPEndpoint = "mcp-endpoint"
)

// NetworkContextDescriptor is the link descriptor for PortTypeNetworkContext.
type NetworkContextDescriptor struct {
	// DialerSocket is the path of a unix socket speaking SOCKS5. All dials
	// through this socket are routed through the provider's network context.
	DialerSocket string `json:"dialer_socket"`
}

// ExecEndpointDescriptor is the link descriptor for PortTypeExecEndpoint.
type ExecEndpointDescriptor struct {
	// Address of the provider's execution service, in gRPC target syntax
	// (e.g. "unix:///run/interstellar/links/abc.sock").
	Address string `json:"address"`
}

// MCPEndpointDescriptor is the link descriptor for PortTypeMCPEndpoint.
type MCPEndpointDescriptor struct {
	// Address of the provider's tool-proxy service, in gRPC target syntax
	// (e.g. "unix:///run/interstellar/links/abc.sock").
	Address string `json:"address"`
}

// Port declares a typed connection point on a wormhole, used for
// composition with other wormholes. Ports are never visible to agents.
type Port struct {
	// Name is unique within the wormhole's manifest (e.g. "target").
	Name string
	// Type is the port type (e.g. PortTypeExecEndpoint).
	Type string
	// Optional marks a required port that may be left unlinked; the
	// wormhole must then degrade gracefully (e.g. connect directly
	// instead of through a tunnel).
	Optional bool
	// Description is a one-line human explanation.
	Description string
}
