// Command ssh is a wormhole that provides an exec-endpoint port reaching a
// remote host over SSH. It optionally consumes a network-context port, so
// the SSH connection can be routed through a VPN or other tunnel without the
// SSH wormhole knowing what kind of tunnel it is.
//
// Like local-exec, it exposes no agent-facing tools — only the port. A
// purpose-built consumer wormhole holds the link and decides what runs.
//
// Target configuration (admin-supplied, never from the agent):
//
//	targets:
//	  build-box:
//	    wormhole: ssh
//	    port: target
//	    config:
//	      host: build.internal
//	      user: builder
//	      key_file: /etc/interstellar/keys/builder
//	      known_hosts_file: /etc/interstellar/known_hosts
//	    via:
//	      net: corp-vpn        # optional: route through a network-context target
package main

import (
	"context"
	"fmt"

	"github.com/talhaHavadar/interstellar/pkg/wormhole"
)

func main() {
	w := wormhole.New("ssh", "0.1.0",
		"Provides an exec-endpoint reaching a host over SSH, optionally through a tunnel.")

	w.Require(wormhole.Port{
		Name:        "net",
		Type:        wormhole.PortTypeNetworkContext,
		Optional:    true,
		Description: "network path to reach the SSH host (e.g. a VPN); direct if absent",
	})

	w.Provide(
		wormhole.Port{
			Name:        "target",
			Type:        wormhole.PortTypeExecEndpoint,
			Description: "command execution on the remote host over SSH",
		},
		openSSHLink,
	)

	w.Serve()
}

func openSSHLink(ctx context.Context, req *wormhole.LinkRequest) (*wormhole.ActiveLink, error) {
	cfg, err := parseConfig(req.Config)
	if err != nil {
		return nil, err
	}

	// Route through a network-context link if one was provided.
	dial := directDialer
	if link, ok := findLink(req.Links, wormhole.PortTypeNetworkContext); ok {
		var nc wormhole.NetworkContextDescriptor
		if err := link.DecodeDescriptor(&nc); err != nil {
			return nil, fmt.Errorf("decoding network-context: %w", err)
		}
		dial, err = socksDialer(nc.DialerSocket)
		if err != nil {
			return nil, err
		}
	}

	client, err := connect(ctx, cfg, dial)
	if err != nil {
		return nil, err
	}

	run := func(ctx context.Context, cmd wormhole.Command, sink wormhole.ExecSink) error {
		return runOverSSH(ctx, client, cmd, sink)
	}
	desc, stop, err := wormhole.ServeExecEndpoint(wormhole.LinkSocketDir(req.LinkID), run)
	if err != nil {
		client.Close()
		return nil, err
	}

	return &wormhole.ActiveLink{
		Descriptor: desc,
		Close: func() error {
			_ = stop()
			return client.Close()
		},
	}, nil
}

func findLink(links []wormhole.Link, portType string) (wormhole.Link, bool) {
	for _, l := range links {
		if l.Type == portType {
			return l, true
		}
	}
	return wormhole.Link{}, false
}
