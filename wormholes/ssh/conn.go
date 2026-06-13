package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/net/proxy"

	"github.com/talhaHavadar/interstellar/pkg/wormhole"
)

// sshConfig is the admin-supplied target configuration for an SSH link.
type sshConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	User string `json:"user"`

	// Authentication: a private key (path or inline), a password, and/or an
	// SSH agent. At least one must be configured.
	KeyFile    string `json:"key_file"`
	KeyData    string `json:"key_data"`
	Passphrase string `json:"passphrase"`
	// Password authenticates with a password. Prefer PasswordEnv so the
	// secret is not stored in the config file; PasswordEnv names an
	// environment variable the wormhole reads the password from.
	Password    string `json:"password"`
	PasswordEnv string `json:"password_env"`
	// UseAgent authenticates via an SSH agent (e.g. for smartcard or
	// security-key backed keys that have no key file). AgentSocket overrides
	// the agent socket path; it defaults to $SSH_AUTH_SOCK.
	UseAgent    bool   `json:"use_agent"`
	AgentSocket string `json:"agent_socket"`

	// Host key verification. Provide a known_hosts file or a single
	// authorized host key line. Setting insecure_skip_host_key_check
	// disables verification and must be opted into deliberately.
	KnownHostsFile           string `json:"known_hosts_file"`
	HostKey                  string `json:"host_key"`
	InsecureSkipHostKeyCheck bool   `json:"insecure_skip_host_key_check"`

	ConnectTimeoutMs int64 `json:"connect_timeout_ms"`
}

func parseConfig(raw json.RawMessage) (*sshConfig, error) {
	cfg := &sshConfig{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, cfg); err != nil {
			return nil, fmt.Errorf("ssh target config: %w", err)
		}
	}
	if cfg.Host == "" {
		return nil, fmt.Errorf("ssh target config: host is required")
	}
	if cfg.User == "" {
		return nil, fmt.Errorf("ssh target config: user is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	return cfg, nil
}

// dialer abstracts how the TCP connection to the SSH host is made: directly
// or through a network-context tunnel.
type dialer func(ctx context.Context, addr string) (net.Conn, error)

func directDialer(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

// socksDialer routes connections through a SOCKS5 server on a unix socket,
// as provided by a network-context wormhole.
func socksDialer(socketPath string) (dialer, error) {
	pd, err := proxy.SOCKS5("unix", socketPath, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("creating SOCKS5 dialer: %w", err)
	}
	cd, ok := pd.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("SOCKS5 dialer does not support contexts")
	}
	return func(ctx context.Context, addr string) (net.Conn, error) {
		return cd.DialContext(ctx, "tcp", addr)
	}, nil
}

func connect(ctx context.Context, cfg *sshConfig, dial dialer) (*ssh.Client, error) {
	auth, cleanup, err := authMethods(cfg)
	if err != nil {
		cleanup()
		return nil, err
	}
	// The agent connection (if any) is only needed through the handshake.
	defer cleanup()
	hostKey, err := hostKeyCallback(cfg)
	if err != nil {
		return nil, err
	}

	clientCfg := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            auth,
		HostKeyCallback: hostKey,
		Timeout:         15 * time.Second,
	}

	if cfg.ConnectTimeoutMs > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(cfg.ConnectTimeoutMs)*time.Millisecond)
		defer cancel()
	}

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	conn, err := dial(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("dialing %s: %w", addr, err)
	}
	// When dialing through a network-context (SOCKS5 over a unix socket), the
	// connection's RemoteAddr is the proxy socket path, which the knownhosts
	// host-key callback would choke on (it expects host:port). Report the real
	// target address so verification sees the host we actually reached.
	conn = &targetAddrConn{Conn: conn, target: tcpLikeAddr(addr)}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, clientCfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh handshake with %s: %w", addr, err)
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// authMethods builds the SSH auth methods from the config. It returns a
// cleanup function that releases any agent connection; the caller invokes it
// after the handshake. cleanup is always safe to call, even on error.
func authMethods(cfg *sshConfig) ([]ssh.AuthMethod, func(), error) {
	var methods []ssh.AuthMethod
	var closers []func()
	cleanup := func() {
		for _, c := range closers {
			c()
		}
	}

	var keyPEM []byte
	switch {
	case cfg.KeyData != "":
		keyPEM = []byte(cfg.KeyData)
	case cfg.KeyFile != "":
		b, err := os.ReadFile(cfg.KeyFile)
		if err != nil {
			return nil, cleanup, fmt.Errorf("reading key_file: %w", err)
		}
		keyPEM = b
	}
	if keyPEM != nil {
		var signer ssh.Signer
		var err error
		if cfg.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyPEM, []byte(cfg.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(keyPEM)
		}
		if err != nil {
			return nil, cleanup, fmt.Errorf("parsing private key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	if cfg.UseAgent {
		sock := cfg.AgentSocket
		if sock == "" {
			sock = os.Getenv("SSH_AUTH_SOCK")
		}
		if sock == "" {
			return nil, cleanup, fmt.Errorf("use_agent set but no agent socket (set agent_socket or SSH_AUTH_SOCK)")
		}
		conn, err := net.Dial("unix", sock)
		if err != nil {
			return nil, cleanup, fmt.Errorf("connecting to ssh agent at %s: %w", sock, err)
		}
		closers = append(closers, func() { conn.Close() })
		ag := agent.NewClient(conn)
		methods = append(methods, ssh.PublicKeysCallback(ag.Signers))
	}

	if password := resolvePassword(cfg); password != "" {
		// Offer both the password method and keyboard-interactive: many
		// sshd configs present the password prompt via the latter.
		methods = append(methods, ssh.Password(password))
		methods = append(methods, ssh.KeyboardInteractive(
			func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = password
				}
				return answers, nil
			}))
	}

	if len(methods) == 0 {
		return nil, cleanup, fmt.Errorf("ssh target config: no authentication (set key_file, key_data, use_agent, password, or password_env)")
	}
	return methods, cleanup, nil
}

// resolvePassword returns the configured password, preferring the value from
// PasswordEnv over an inline Password.
func resolvePassword(cfg *sshConfig) string {
	if cfg.PasswordEnv != "" {
		if v := os.Getenv(cfg.PasswordEnv); v != "" {
			return v
		}
	}
	return cfg.Password
}

func hostKeyCallback(cfg *sshConfig) (ssh.HostKeyCallback, error) {
	switch {
	case cfg.InsecureSkipHostKeyCheck:
		// Explicit opt-out; the security trade-off is the admin's.
		return ssh.InsecureIgnoreHostKey(), nil
	case cfg.HostKey != "":
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cfg.HostKey))
		if err != nil {
			return nil, fmt.Errorf("parsing host_key: %w", err)
		}
		return ssh.FixedHostKey(key), nil
	case cfg.KnownHostsFile != "":
		cb, err := knownhosts.New(cfg.KnownHostsFile)
		if err != nil {
			return nil, fmt.Errorf("loading known_hosts_file: %w", err)
		}
		return cb, nil
	default:
		return nil, fmt.Errorf("ssh host-key verification is not configured for this target. " +
			"Set `known_hosts_file` (recommended) or `host_key` to verify the host. " +
			"Quick workaround if you don't want a known_hosts file: add " +
			"`insecure_skip_host_key_check: true` to the target's config to accept any host key " +
			"(safe enough over an already-encrypted tunnel like Tailscale/WireGuard; risky over a direct connection)")
	}
}

// runOverSSH runs one command on the remote host. SSH executes a command
// string through the remote shell, so argv is POSIX-quoted; this is the one
// unavoidable shell boundary and it is the wormhole, not the agent, that
// builds the argv.
func runOverSSH(ctx context.Context, client *ssh.Client, cmd wormhole.Command, sink wormhole.ExecSink) error {
	if len(cmd.Argv) == 0 {
		return fmt.Errorf("empty argv")
	}

	if cmd.TimeoutMs > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(cmd.TimeoutMs)*time.Millisecond)
		defer cancel()
	}

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("opening ssh session: %w", err)
	}
	defer session.Close()

	session.Stdout = sinkWriter{sink.Stdout}
	session.Stderr = sinkWriter{sink.Stderr}
	if len(cmd.Stdin) > 0 {
		session.Stdin = strings.NewReader(string(cmd.Stdin))
	}
	for k, v := range cmd.Env {
		// Best-effort; sshd may reject unlisted env via AcceptEnv.
		_ = session.Setenv(k, v)
	}

	line := quoteCommand(cmd.Argv, cmd.Dir)
	done := make(chan error, 1)
	go func() { done <- session.Run(line) }()

	select {
	case err := <-done:
		var exitErr *ssh.ExitError
		if err == nil {
			sink.SetExit(0)
			return nil
		}
		if asExitError(err, &exitErr) {
			sink.SetExit(exitErr.ExitStatus())
			return nil
		}
		return err
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		session.Close()
		<-done
		return ctx.Err()
	}
}

type sinkWriter struct{ write func([]byte) }

func (w sinkWriter) Write(p []byte) (int, error) {
	w.write(p)
	return len(p), nil
}

func asExitError(err error, target **ssh.ExitError) bool {
	if e, ok := err.(*ssh.ExitError); ok {
		*target = e
		return true
	}
	return false
}

// quoteCommand builds a shell command line from argv, single-quoting each
// element so no argument is re-interpreted by the remote shell. An optional
// working directory is prepended as a cd.
func quoteCommand(argv []string, dir string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		parts[i] = shellQuote(a)
	}
	cmd := strings.Join(parts, " ")
	if dir != "" {
		return "cd " + shellQuote(dir) + " && " + cmd
	}
	return cmd
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// targetAddrConn overrides RemoteAddr so host-key verification sees the real
// target host:port rather than the address of whatever transport carried the
// connection (e.g. a SOCKS5 unix socket).
type targetAddrConn struct {
	net.Conn
	target net.Addr
}

func (c *targetAddrConn) RemoteAddr() net.Addr { return c.target }

// tcpLikeAddr is a net.Addr whose String() is a host:port, for feeding the
// knownhosts callback.
type tcpLikeAddr string

func (a tcpLikeAddr) Network() string { return "tcp" }
func (a tcpLikeAddr) String() string  { return string(a) }
