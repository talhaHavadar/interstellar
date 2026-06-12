package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/talhaHavadar/interstellar/pkg/wormhole"
)

func TestParseConfigDefaultsAndValidation(t *testing.T) {
	if _, err := parseConfig(json.RawMessage(`{"user":"x"}`)); err == nil {
		t.Error("missing host should fail")
	}
	if _, err := parseConfig(json.RawMessage(`{"host":"h"}`)); err == nil {
		t.Error("missing user should fail")
	}
	cfg, err := parseConfig(json.RawMessage(`{"host":"h","user":"u"}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 22 {
		t.Errorf("default port = %d, want 22", cfg.Port)
	}
}

func TestHostKeyCallbackRequiresVerification(t *testing.T) {
	if _, err := hostKeyCallback(&sshConfig{}); err == nil {
		t.Error("absent host key config must fail closed")
	}
	if _, err := hostKeyCallback(&sshConfig{InsecureSkipHostKeyCheck: true}); err != nil {
		t.Errorf("explicit insecure opt-out should be allowed: %v", err)
	}
}

func TestAuthMethodsRequireSomething(t *testing.T) {
	_, cleanup, err := authMethods(&sshConfig{})
	cleanup()
	if err == nil {
		t.Error("no auth configured must fail")
	}
}

func TestAuthMethodsAgentNeedsSocket(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	_, cleanup, err := authMethods(&sshConfig{UseAgent: true})
	cleanup()
	if err == nil {
		t.Error("use_agent without a socket must fail")
	}
}

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"plain":     `'plain'`,
		"a b":       `'a b'`,
		"it's":      `'it'\''s'`,
		"$(rm -rf)": `'$(rm -rf)'`,
		"a;b|c&d":   `'a;b|c&d'`,
	}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestQuoteCommandWithDir(t *testing.T) {
	got := quoteCommand([]string{"echo", "hi there"}, "/tmp/x")
	want := `cd '/tmp/x' && 'echo' 'hi there'`
	if got != want {
		t.Errorf("quoteCommand = %q, want %q", got, want)
	}
}

// TestConnectAndRun exercises the real SSH path against an in-process server:
// host-key verification, public-key auth, argv quoting, and exit codes.
func TestConnectAndRun(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("needs a POSIX shell")
	}

	hostSigner, _ := genKey(t)
	clientSigner, clientPEM := genKey(t)

	addr, stop := startSSHServer(t, hostSigner, clientSigner.PublicKey())
	defer stop()

	host, port, _ := net.SplitHostPort(addr)
	cfg := &sshConfig{
		Host:    host,
		User:    "tester",
		KeyData: string(clientPEM),
		HostKey: string(ssh.MarshalAuthorizedKey(hostSigner.PublicKey())),
		Port:    atoi(port),
	}

	client, err := connect(context.Background(), cfg, directDialer)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()

	// Successful command: argv with a space survives quoting intact.
	sink := newCollector()
	if err := runOverSSH(context.Background(), client, wormhole.Command{Argv: []string{"echo", "hello world"}}, sink); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := strings.TrimSpace(string(sink.stdout())); got != "hello world" {
		t.Errorf("stdout = %q", got)
	}
	if sink.exit() != 0 {
		t.Errorf("exit = %d, want 0", sink.exit())
	}

	// Non-zero exit is reported via the code, not as an error.
	sink2 := newCollector()
	if err := runOverSSH(context.Background(), client, wormhole.Command{Argv: []string{"sh", "-c", "exit 7"}}, sink2); err != nil {
		t.Fatalf("run: %v", err)
	}
	if sink2.exit() != 7 {
		t.Errorf("exit = %d, want 7", sink2.exit())
	}
}

// proxyAddrConn simulates the SOCKS5 case: a working TCP connection whose
// RemoteAddr is a unix socket path rather than host:port.
type proxyAddrConn struct {
	net.Conn
}

func (proxyAddrConn) RemoteAddr() net.Addr {
	return tcpLikeAddr("/tmp/interstellar-links/abc/socks5.sock")
}

// TestConnectKnownHostsThroughProxy reproduces the bug where SSH routed
// through a SOCKS5 unix socket fails host-key verification because knownhosts
// receives the socket path instead of the target host:port.
func TestConnectKnownHostsThroughProxy(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("needs a POSIX shell")
	}

	hostSigner, _ := genKey(t)
	clientSigner, clientPEM := genKey(t)
	addr, stop := startSSHServer(t, hostSigner, clientSigner.PublicKey())
	defer stop()

	// A known_hosts file authorizing the server's key for the dialed address.
	khPath := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{knownhosts.Normalize(addr)}, hostSigner.PublicKey())
	if err := os.WriteFile(khPath, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	host, port, _ := net.SplitHostPort(addr)
	cfg := &sshConfig{
		Host:           host,
		Port:           atoi(port),
		User:           "tester",
		KeyData:        string(clientPEM),
		KnownHostsFile: khPath,
	}

	// Dial as the SOCKS5 path would: a real connection reporting a unix-socket
	// RemoteAddr. Without the targetAddrConn fix, knownhosts would fail here.
	proxyDial := func(ctx context.Context, address string) (net.Conn, error) {
		c, err := directDialer(ctx, address)
		if err != nil {
			return nil, err
		}
		return proxyAddrConn{c}, nil
	}

	client, err := connect(context.Background(), cfg, proxyDial)
	if err != nil {
		t.Fatalf("connect through proxy with known_hosts: %v", err)
	}
	client.Close()
}

// --- test helpers: a minimal in-process SSH server ---

// genKey generates an ed25519 key, returning a signer and its OpenSSH PEM.
func genKey(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	return signer, pem.EncodeToMemory(block)
}

func startSSHServer(t *testing.T, hostKey ssh.Signer, authorized ssh.PublicKey) (addr string, stop func()) {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(authorized.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, errUnauthorized
		},
	}
	cfg.AddHostKey(hostKey)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				serveConn(conn, cfg)
			}()
		}
	}()

	return ln.Addr().String(), func() {
		ln.Close()
		wg.Wait()
	}
}

func serveConn(c net.Conn, cfg *ssh.ServerConfig) {
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		c.Close()
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		go handleSession(ch, creqs)
	}
}

func handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	for req := range reqs {
		if req.Type != "exec" {
			req.Reply(false, nil)
			continue
		}
		var payload struct{ Command string }
		_ = ssh.Unmarshal(req.Payload, &payload)
		req.Reply(true, nil)

		cmd := exec.Command("sh", "-c", payload.Command)
		cmd.Stdout = ch
		cmd.Stderr = ch.Stderr()
		code := 0
		if err := cmd.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				code = 1
			}
		}
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
		ch.Close()
		return
	}
}

var errUnauthorized = &authError{}

type authError struct{}

func (*authError) Error() string { return "unauthorized" }

// collector implements wormhole.ExecSink and records output.
type collector struct {
	mu  sync.Mutex
	out []byte
	err []byte
	ex  int
}

func newCollector() *collector { return &collector{ex: -1} }

func (c *collector) Stdout(p []byte)  { c.mu.Lock(); c.out = append(c.out, p...); c.mu.Unlock() }
func (c *collector) Stderr(p []byte)  { c.mu.Lock(); c.err = append(c.err, p...); c.mu.Unlock() }
func (c *collector) SetExit(code int) { c.mu.Lock(); c.ex = code; c.mu.Unlock() }

func (c *collector) stdout() []byte { c.mu.Lock(); defer c.mu.Unlock(); return c.out }
func (c *collector) exit() int      { c.mu.Lock(); defer c.mu.Unlock(); return c.ex }

func atoi(s string) int {
	n := 0
	for _, r := range s {
		n = n*10 + int(r-'0')
	}
	return n
}

var _ io.Writer = sinkWriter{}
