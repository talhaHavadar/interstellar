package wormhole

import (
	"context"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	wormholev1 "github.com/talhaHavadar/interstellar/gen/wormhole/v1"
)

// PluginName is the key under which the wormhole service is registered in
// the go-plugin map.
const PluginName = "wormhole"

// Handshake is shared between the core and every wormhole binary. The
// ProtocolVersion is the wormhole protocol major version: the core refuses
// plugins built against a different version with a clear error instead of
// failing cryptically mid-call.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "INTERSTELLAR_WORMHOLE",
	MagicCookieValue: "interstellar-wormhole-protocol",
}

// GRPCPlugin adapts WormholeService to go-plugin. The same type serves both
// sides: wormholes set Impl and serve; the core leaves Impl nil and uses the
// dispensed client.
type GRPCPlugin struct {
	plugin.NetRPCUnsupportedPlugin
	Impl wormholev1.WormholeServiceServer
}

func (p *GRPCPlugin) GRPCServer(_ *plugin.GRPCBroker, s *grpc.Server) error {
	wormholev1.RegisterWormholeServiceServer(s, p.Impl)
	return nil
}

func (p *GRPCPlugin) GRPCClient(_ context.Context, _ *plugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return wormholev1.NewWormholeServiceClient(c), nil
}

// Serve hands the wormhole over to the interstellar core. It blocks for the
// life of the process; call it last in main. The process must be launched by
// the core (go-plugin handshake) — running the binary directly prints an
// explanatory error.
func (w *Wormhole) Serve() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: Handshake,
		Plugins: map[string]plugin.Plugin{
			PluginName: &GRPCPlugin{Impl: newServer(w)},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
