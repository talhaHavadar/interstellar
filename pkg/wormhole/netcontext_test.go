package wormhole

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// TestNetworkContextRoundTrip proves the SOCKS5 provider end to end: a
// network context backed by a direct dialer, reached through it the same way
// the ssh wormhole reaches a real tunnel (golang.org/x/net/proxy.SOCKS5 over
// a unix socket).
func TestNetworkContextRoundTrip(t *testing.T) {
	// An upstream TCP echo server standing in for "a host behind the tunnel".
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()

	// The provider: a network context whose dialer is a plain net.Dialer.
	var d net.Dialer
	desc, stop, err := ServeNetworkContext(t.TempDir(), d.DialContext)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	// The consumer side: dial the echo server *through* the SOCKS5 socket.
	pd, err := proxy.SOCKS5("unix", desc.DialerSocket, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	cd := pd.(proxy.ContextDialer)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := cd.DialContext(ctx, "tcp", echo.Addr().String())
	if err != nil {
		t.Fatalf("dial through socks5: %v", err)
	}
	defer conn.Close()

	msg := []byte("through the tunnel")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Errorf("echoed %q, want %q", got, msg)
	}
}

func TestServeNetworkContextRejectsNilDial(t *testing.T) {
	if _, _, err := ServeNetworkContext(t.TempDir(), nil); err == nil {
		t.Error("want error for nil dial")
	}
}
