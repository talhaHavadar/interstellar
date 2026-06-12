package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLiveTunnel brings up a real WireGuard tunnel from the config file named
// by WG_LIVE_CONF and verifies a handshake with the peer completes. It is
// skipped unless that variable is set, so it never runs in normal test runs:
//
//	WG_LIVE_CONF=~/sandbox/wg1.conf go test ./wormholes/vpn-wireguard/ -run TestLiveTunnel -v
func TestLiveTunnel(t *testing.T) {
	path := os.Getenv("WG_LIVE_CONF")
	if path == "" {
		t.Skip("set WG_LIVE_CONF to a wg-quick file to run the live tunnel test")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parseWgQuick(string(data))
	if err != nil {
		t.Fatal(err)
	}

	tnet, dev, err := bringUp(cfg)
	if err != nil {
		t.Fatalf("bringing up tunnel: %v", err)
	}
	defer dev.Close()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		// Nudge the tunnel into sending its first handshake by dialing the
		// tunnel-side DNS server (best effort; the dial may fail even when
		// the handshake succeeds).
		if len(cfg.DNS) > 0 {
			dctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			if c, derr := dialThrough(tnet)(dctx, "tcp", cfg.DNS[0].String()+":53"); derr == nil {
				c.Close()
			}
			cancel()
		}
		if handshakeComplete(t, dev.IpcGet) {
			t.Log("WireGuard handshake succeeded; tunnel is up")
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatal("no WireGuard handshake within 15s — tunnel did not come up")
}

// handshakeComplete reports whether the device reports a non-zero last
// handshake time for any peer (i.e. the peer answered).
func handshakeComplete(t *testing.T, ipcGet func() (string, error)) bool {
	dump, err := ipcGet()
	if err != nil {
		t.Fatalf("reading device state: %v", err)
	}
	for _, line := range strings.Split(dump, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && key == "last_handshake_time_sec" && value != "0" && value != "" {
			return true
		}
	}
	return false
}
