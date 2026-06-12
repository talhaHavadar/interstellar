// Command local-exec is a wormhole that provides an exec-endpoint port
// running commands on the gateway host itself. It exposes no agent-facing
// tools — only a port other wormholes consume. Agents cannot reach it
// directly; a purpose-built consumer wormhole holds the link and chooses
// exactly what runs.
//
// Configure a target that binds its "host" port:
//
//	targets:
//	  localhost:
//	    wormhole: local-exec
//	    port: host
package main

import (
	"context"

	"github.com/talhaHavadar/interstellar/pkg/wormhole"
)

func main() {
	w := wormhole.New("local-exec", "0.1.0",
		"Provides an exec-endpoint that runs commands on the gateway host.")

	w.Provide(
		wormhole.Port{
			Name:        "host",
			Type:        wormhole.PortTypeExecEndpoint,
			Description: "command execution on the gateway host",
		},
		func(ctx context.Context, req *wormhole.LinkRequest) (*wormhole.ActiveLink, error) {
			desc, stop, err := wormhole.ServeExecEndpoint(
				wormhole.LinkSocketDir(req.LinkID), wormhole.RunLocalCommand)
			if err != nil {
				return nil, err
			}
			return &wormhole.ActiveLink{Descriptor: desc, Close: stop}, nil
		},
	)

	w.Serve()
}
