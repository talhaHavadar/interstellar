package wormhole

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
)

// ServeNetworkContext stands up a SOCKS5 server on a unix socket under dir,
// routing every connection through dial, and returns the descriptor plus a
// stop function. Provider wormholes (vpn-wireguard, tailscale, ...) call this
// from a LinkHandler:
//
//	desc, stop, err := wormhole.ServeNetworkContext(wormhole.LinkSocketDir(req.LinkID), tnet.DialContext)
//	return &wormhole.ActiveLink{Descriptor: desc, Close: stop}, err
//
// Consumers reach it transparently: the descriptor's DialerSocket is a
// SOCKS5 endpoint, which is exactly what the ssh wormhole's socksDialer (and
// golang.org/x/net/proxy.SOCKS5) expects.
func ServeNetworkContext(dir string, dial DialFunc) (NetworkContextDescriptor, func() error, error) {
	if dial == nil {
		return NetworkContextDescriptor{}, nil, fmt.Errorf("nil dial function")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return NetworkContextDescriptor{}, nil, fmt.Errorf("creating link dir: %w", err)
	}
	sock := filepath.Join(dir, "socks5.sock")
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return NetworkContextDescriptor{}, nil, fmt.Errorf("listening on link socket: %w", err)
	}

	srv := newSocksServer(ln, dial)
	var once sync.Once
	stop := func() error {
		var err error
		once.Do(func() {
			err = srv.stop()
			_ = os.Remove(sock)
		})
		return err
	}
	return NetworkContextDescriptor{DialerSocket: sock}, stop, nil
}
