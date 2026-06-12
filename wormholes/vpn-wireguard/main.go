// Command vpn-wireguard is a wormhole that provides a network-context routed
// through a WireGuard tunnel, brought up entirely in userspace (wireguard-go
// + gVisor netstack) — no root, no kernel wg interface, no container.
//
// It exposes no agent-facing tools, only a network-context port that other
// wormholes (e.g. ssh) route through via a target's `via`:
//
//	targets:
//	  corp-vpn:
//	    wormhole: vpn-wireguard
//	    port: tunnel
//	    config:
//	      config_file: /etc/interstellar/wg/corp.conf   # a wg-quick file
//	  build-box:
//	    wormhole: ssh
//	    port: target
//	    via:
//	      net: corp-vpn
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/talhaHavadar/interstellar/pkg/wormhole"
)

type tunnelConfig struct {
	// ConfigFile is the path to a wg-quick configuration file (on the
	// gateway host). ConfigText is the same content provided inline.
	ConfigFile string `json:"config_file"`
	ConfigText string `json:"config_text"`
}

func main() {
	w := wormhole.New("vpn-wireguard", "0.1.0",
		"Provides a network-context routed through a userspace WireGuard tunnel.")

	w.Provide(
		wormhole.Port{
			Name:        "tunnel",
			Type:        wormhole.PortTypeNetworkContext,
			Description: "network access through a WireGuard tunnel",
		},
		openTunnel,
	)

	w.Serve()
}

func openTunnel(ctx context.Context, req *wormhole.LinkRequest) (*wormhole.ActiveLink, error) {
	var tc tunnelConfig
	if len(req.Config) > 0 {
		if err := json.Unmarshal(req.Config, &tc); err != nil {
			return nil, fmt.Errorf("vpn-wireguard config: %w", err)
		}
	}

	text := tc.ConfigText
	if text == "" {
		if tc.ConfigFile == "" {
			return nil, fmt.Errorf("vpn-wireguard config: set config_file or config_text")
		}
		b, err := os.ReadFile(tc.ConfigFile)
		if err != nil {
			return nil, fmt.Errorf("reading config_file: %w", err)
		}
		text = string(b)
	}

	cfg, err := parseWgQuick(text)
	if err != nil {
		return nil, err
	}

	tnet, dev, err := bringUp(cfg)
	if err != nil {
		return nil, err
	}

	desc, stop, err := wormhole.ServeNetworkContext(
		wormhole.LinkSocketDir(req.LinkID), dialThrough(tnet))
	if err != nil {
		dev.Close()
		return nil, err
	}

	return &wormhole.ActiveLink{
		Descriptor: desc,
		Close: func() error {
			_ = stop()
			dev.Close()
			return nil
		},
	}, nil
}

// bringUp creates the userspace WireGuard device and returns the netstack Net
// to dial through plus the device (whose Close tears the tunnel down).
func bringUp(cfg *wgConfig) (*netstack.Net, *device.Device, error) {
	tun, tnet, err := netstack.CreateNetTUN(cfg.Address, cfg.DNS, cfg.MTU)
	if err != nil {
		return nil, nil, fmt.Errorf("creating userspace tun: %w", err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wireguard "))

	uapi, err := cfg.uapiConfig()
	if err != nil {
		dev.Close()
		return nil, nil, err
	}
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("configuring device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("bringing device up: %w", err)
	}
	return tnet, dev, nil
}

// dialThrough adapts netstack's typed TCP dialer to the SDK's DialFunc,
// resolving hostnames via the tunnel's DNS when needed.
func dialThrough(tnet *netstack.Net) wormhole.DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, portStr, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q", portStr)
		}

		ip, err := netip.ParseAddr(host)
		if err != nil {
			// A hostname: resolve through the tunnel's DNS.
			addrs, lerr := tnet.LookupHost(host)
			if lerr != nil || len(addrs) == 0 {
				return nil, fmt.Errorf("resolving %q through tunnel: %w", host, lerr)
			}
			ip, err = netip.ParseAddr(addrs[0])
			if err != nil {
				return nil, err
			}
		}
		conn, err := tnet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(ip, uint16(port)))
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
}
