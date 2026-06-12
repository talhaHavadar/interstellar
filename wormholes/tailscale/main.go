// Command tailscale is a wormhole that provides a network-context routed
// through a Tailscale tailnet. It embeds a full Tailscale node in-process via
// tsnet (userspace gVisor stack) — no tailscaled daemon, no root, no
// container. It exposes no agent-facing tools, only a network-context port
// other wormholes route through.
//
//	targets:
//	  tailnet:
//	    wormhole: tailscale
//	    port: tailnet
//	    config:
//	      hostname: interstellar-gw
//	      authkey_env: TS_AUTHKEY      # auth key read from the environment
//	  ts-box:
//	    wormhole: ssh
//	    port: target
//	    config: { host: my-server, user: talha, ... }   # MagicDNS name works
//	    via:
//	      net: tailnet
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"tailscale.com/tsnet"

	"github.com/talhaHavadar/interstellar/pkg/wormhole"
)

type tailnetConfig struct {
	// Hostname is the node name this gateway presents on the tailnet.
	Hostname string `json:"hostname"`
	// AuthKey authenticates the node. Prefer AuthKeyEnv so the secret is not
	// stored in the config file; it names an environment variable.
	AuthKey    string `json:"authkey"`
	AuthKeyEnv string `json:"authkey_env"`
	// StateDir persists node identity so it need not re-auth each start.
	// Defaults to a per-hostname directory under the OS temp dir.
	StateDir string `json:"state_dir"`
	// Ephemeral removes the node from the tailnet when it stops (default true).
	Ephemeral *bool `json:"ephemeral"`
	// ControlURL overrides the coordination server (e.g. for Headscale).
	ControlURL string `json:"control_url"`
}

func main() {
	w := wormhole.New("tailscale", "0.1.0",
		"Provides a network-context routed through a Tailscale tailnet (userspace tsnet).")

	w.Provide(
		wormhole.Port{
			Name:        "tailnet",
			Type:        wormhole.PortTypeNetworkContext,
			Description: "network access through a Tailscale tailnet",
		},
		openTailnet,
	)

	w.Serve()
}

func openTailnet(ctx context.Context, req *wormhole.LinkRequest) (*wormhole.ActiveLink, error) {
	var tc tailnetConfig
	if len(req.Config) > 0 {
		if err := json.Unmarshal(req.Config, &tc); err != nil {
			return nil, fmt.Errorf("tailscale config: %w", err)
		}
	}
	if tc.Hostname == "" {
		return nil, fmt.Errorf("tailscale config: hostname is required")
	}

	authKey := tc.AuthKey
	if tc.AuthKeyEnv != "" {
		if v := os.Getenv(tc.AuthKeyEnv); v != "" {
			authKey = v
		}
	}

	dir := tc.StateDir
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "interstellar-tsnet", tc.Hostname)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating tsnet state dir: %w", err)
	}

	ephemeral := true
	if tc.Ephemeral != nil {
		ephemeral = *tc.Ephemeral
	}

	srv := &tsnet.Server{
		Hostname:   tc.Hostname,
		AuthKey:    authKey,
		Dir:        dir,
		Ephemeral:  ephemeral,
		ControlURL: tc.ControlURL,
		// Keep tsnet's voluminous internal logging out of stderr, but surface
		// user-relevant lines (such as an interactive login URL).
		Logf:     func(string, ...any) {},
		UserLogf: func(format string, args ...any) { fmt.Fprintf(os.Stderr, "tailscale: "+format+"\n", args...) },
	}

	// Block until the node is actually connected so the first dial succeeds.
	upCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if _, err := srv.Up(upCtx); err != nil {
		srv.Close()
		return nil, fmt.Errorf("joining tailnet: %w", err)
	}

	desc, stop, err := wormhole.ServeNetworkContext(wormhole.LinkSocketDir(req.LinkID), srv.Dial)
	if err != nil {
		srv.Close()
		return nil, err
	}

	return &wormhole.ActiveLink{
		Descriptor: desc,
		Close: func() error {
			_ = stop()
			return srv.Close()
		},
	}, nil
}
