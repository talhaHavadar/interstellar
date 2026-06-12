// Package session resolves and holds the links between wormholes. It turns
// an admin-defined target into a live link by opening the providing
// wormhole's port — recursively bringing up any targets it routes through —
// and keeps that link warm, reference-counted and idle-expiring, so it can
// be reused across tool calls.
package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	wormholev1 "github.com/talhaHavadar/interstellar/gen/wormhole/v1"
	"github.com/talhaHavadar/interstellar/internal/registry"
)

const (
	// defaultOpenTimeout is a generous backstop for bringing a link up. It is
	// deliberately longer than any wormhole's own connect timeout (e.g.
	// tsnet's ~60s tailnet join) so the wormhole's real error surfaces rather
	// than being masked by this timeout. Tunnels are slow; a fast provider
	// (local-exec) comes up in milliseconds regardless.
	defaultOpenTimeout = 90 * time.Second
	defaultIdleTimeout = 60 * time.Second
	closeTimeout       = 10 * time.Second
)

// Target is a resolved, validated endpoint: a wormhole's provided port plus
// the configuration and upstream routing needed to bring it up.
type Target struct {
	Name        string
	Wormhole    string
	Port        string
	Config      json.RawMessage
	Via         map[string]string // required port name -> upstream target name
	IdleTimeout time.Duration
	// OpenTimeout overrides defaultOpenTimeout for bringing this link up.
	OpenTimeout time.Duration
}

// Registry is the slice of the wormhole registry the session manager needs:
// looking up a loaded wormhole by name.
type Registry interface {
	Get(name string) (*registry.Wormhole, bool)
}

// Manager owns the lifecycle of all links.
type Manager struct {
	reg    Registry
	logger *slog.Logger

	mu      sync.Mutex
	targets map[string]Target
	links   map[string]*linkState // keyed by target name
}

type linkState struct {
	target Target

	ready chan struct{} // closed when setup finishes (success or failure)
	err   error         // setup failure, read after ready is closed
	link  *wormholev1.Link

	refs     int
	cancel   context.CancelFunc // ends the OpenLink stream
	upstream []*Lease           // leases held on `via` targets
	timer    *time.Timer        // idle teardown timer; nil when refs > 0
	dead     bool               // link failed or was torn down
}

// Lease is a hold on a live link. Release it when the work is done; the link
// stays warm for its idle timeout in case it is acquired again.
type Lease struct {
	// Link is the resolved connection handle. Its PortName is the
	// provider's provided port; relabel a clone when handing it to a
	// consumer that knows the port by a different name.
	Link *wormholev1.Link

	mgr      *Manager
	target   string
	released bool
}

// Release returns the lease. Safe to call once; further calls are no-ops.
func (l *Lease) Release() {
	if l == nil || l.released {
		return
	}
	l.released = true
	l.mgr.release(l.target)
}

// New creates a manager over the given targets, which must already be
// validated with Validate.
func New(reg Registry, logger *slog.Logger, targets map[string]Target) *Manager {
	return &Manager{
		reg:     reg,
		logger:  logger,
		targets: targets,
		links:   map[string]*linkState{},
	}
}

// Targets returns the configured targets, for inspection.
func (m *Manager) Targets() map[string]Target { return m.targets }

// IsLive reports whether the named target currently has a live link.
func (m *Manager) IsLive(targetName string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	ls, ok := m.links[targetName]
	return ok && !ls.dead && ls.link != nil
}

// Acquire brings up (or reuses) the named target's link and returns a lease.
// Concurrent acquisitions of the same target share one link.
func (m *Manager) Acquire(ctx context.Context, targetName string) (*Lease, error) {
	for {
		m.mu.Lock()
		ls, ok := m.links[targetName]
		if !ok {
			target, known := m.targets[targetName]
			if !known {
				m.mu.Unlock()
				return nil, fmt.Errorf("unknown target %q", targetName)
			}
			ls = &linkState{target: target, ready: make(chan struct{}), refs: 1}
			m.links[targetName] = ls
			m.mu.Unlock()

			m.setup(ctx, ls)
			<-ls.ready
			if ls.err != nil {
				return nil, ls.err
			}
			return &Lease{Link: ls.link, mgr: m, target: targetName}, nil
		}

		// An existing link: it may still be setting up, live, or dead.
		if ls.dead {
			// A failed/torn-down state lingering in the map; drop and retry.
			delete(m.links, targetName)
			m.mu.Unlock()
			continue
		}
		ls.refs++
		if ls.timer != nil {
			ls.timer.Stop()
			ls.timer = nil
		}
		ready := ls.ready
		m.mu.Unlock()

		<-ready
		m.mu.Lock()
		err := ls.err
		link := ls.link
		dead := ls.dead
		m.mu.Unlock()
		if err != nil || dead {
			// Setup failed after we joined; undo our ref and report.
			m.release(targetName)
			if err == nil {
				err = fmt.Errorf("target %q link is unavailable", targetName)
			}
			return nil, err
		}
		return &Lease{Link: link, mgr: m, target: targetName}, nil
	}
}

// setup establishes the link for ls and closes ls.ready. On failure it marks
// the state dead so Acquire reports the error and the entry is dropped.
func (m *Manager) setup(ctx context.Context, ls *linkState) {
	link, cancel, upstream, err := m.open(ctx, ls.target)

	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		ls.err = err
		ls.dead = true
		delete(m.links, ls.target.Name)
	} else {
		ls.link = link
		ls.cancel = cancel
		ls.upstream = upstream
	}
	close(ls.ready)
}

// open brings a target's link up: it acquires upstream `via` leases, calls
// OpenLink on the providing wormhole, and waits for the link to come up.
func (m *Manager) open(ctx context.Context, target Target) (*wormholev1.Link, context.CancelFunc, []*Lease, error) {
	wh, ok := m.reg.Get(target.Wormhole)
	if !ok {
		return nil, nil, nil, fmt.Errorf("target %q: wormhole %q is not loaded", target.Name, target.Wormhole)
	}

	var upstream []*Lease
	var upstreamLinks []*wormholev1.Link
	release := func() {
		for _, l := range upstream {
			l.Release()
		}
	}
	for reqPort, upTarget := range target.Via {
		lease, err := m.Acquire(ctx, upTarget)
		if err != nil {
			release()
			return nil, nil, nil, fmt.Errorf("target %q via %q: %w", target.Name, upTarget, err)
		}
		upstream = append(upstream, lease)
		// Relabel for the consumer: the providing wormhole knows this link
		// by its own required port name.
		l := proto.Clone(lease.Link).(*wormholev1.Link)
		l.PortName = reqPort
		upstreamLinks = append(upstreamLinks, l)
	}

	linkID := newLinkID()
	linkCtx, cancel := context.WithCancel(context.Background())

	stream, err := wh.Client.OpenLink(linkCtx, &wormholev1.OpenLinkRequest{
		LinkId:     linkID,
		PortName:   target.Port,
		ConfigJson: string(target.Config),
		Links:      upstreamLinks,
	})
	if err != nil {
		cancel()
		release()
		return nil, nil, nil, fmt.Errorf("target %q: opening link: %w", target.Name, err)
	}

	ready := make(chan openResult, 1)
	go m.runLink(target.Name, stream, ready)

	openTimeout := target.OpenTimeout
	if openTimeout <= 0 {
		openTimeout = defaultOpenTimeout
	}
	select {
	case res := <-ready:
		if res.err != nil {
			cancel()
			release()
			return nil, nil, nil, fmt.Errorf("target %q: %w", target.Name, res.err)
		}
		m.logger.Info("link up", "target", target.Name, "wormhole", target.Wormhole, "port", target.Port, "link_id", linkID)
		return res.link, cancel, upstream, nil
	case <-time.After(openTimeout):
		cancel()
		release()
		return nil, nil, nil, fmt.Errorf("target %q: timed out after %s waiting for link to come up", target.Name, openTimeout)
	case <-ctx.Done():
		cancel()
		release()
		return nil, nil, nil, ctx.Err()
	}
}

type openResult struct {
	link *wormholev1.Link
	err  error
}

// runLink reads the OpenLink stream: it reports the first LinkUp via ready,
// then watches for the link closing or the stream ending.
func (m *Manager) runLink(targetName string, stream grpc_OpenLinkClient, ready chan<- openResult) {
	up := false
	for {
		ev, err := stream.Recv()
		if err != nil {
			if !up {
				ready <- openResult{err: err}
			} else {
				m.linkDied(targetName, err)
			}
			return
		}
		switch e := ev.Event.(type) {
		case *wormholev1.OpenLinkResponse_Up:
			up = true
			ready <- openResult{link: e.Up.Link}
		case *wormholev1.OpenLinkResponse_State:
			if e.State.State == "closed" {
				if up {
					m.linkDied(targetName, nil)
				}
				return
			}
		case *wormholev1.OpenLinkResponse_Log:
			m.logger.Info("link log", "target", targetName, "level", e.Log.Level, "message", e.Log.Message)
		}
	}
}

// grpc_OpenLinkClient is the receive side of the OpenLink stream.
type grpc_OpenLinkClient interface {
	Recv() (*wormholev1.OpenLinkResponse, error)
}

// release decrements the target's refcount and, when it reaches zero, starts
// the idle teardown timer.
func (m *Manager) release(targetName string) {
	m.mu.Lock()
	ls, ok := m.links[targetName]
	if !ok {
		m.mu.Unlock()
		return
	}
	ls.refs--
	if ls.refs > 0 || ls.dead {
		m.mu.Unlock()
		return
	}
	idle := ls.target.IdleTimeout
	if idle <= 0 {
		idle = defaultIdleTimeout
	}
	ls.timer = time.AfterFunc(idle, func() { m.idleTeardown(targetName) })
	m.mu.Unlock()
}

func (m *Manager) idleTeardown(targetName string) {
	m.mu.Lock()
	ls, ok := m.links[targetName]
	if !ok || ls.refs > 0 || ls.dead {
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()
	m.destroy(targetName, "idle timeout")
}

// linkDied handles a link that failed or was closed by its wormhole. When the
// link was already torn down deliberately (idle timeout, shutdown), the
// monitor goroutine also lands here as its stream ends; that case is silent.
func (m *Manager) linkDied(targetName string, cause error) {
	m.mu.Lock()
	ls, ok := m.links[targetName]
	alive := ok && !ls.dead
	m.mu.Unlock()
	if !alive {
		return
	}
	m.logger.Warn("link died", "target", targetName, "cause", cause)
	m.destroy(targetName, "link closed by wormhole")
}

// destroy tears a link down: cancels its stream, asks the wormhole to close
// it, and releases the upstream leases. Idempotent per target generation.
func (m *Manager) destroy(targetName, reason string) {
	m.mu.Lock()
	ls, ok := m.links[targetName]
	if !ok || ls.dead {
		m.mu.Unlock()
		return
	}
	ls.dead = true
	delete(m.links, targetName)
	if ls.timer != nil {
		ls.timer.Stop()
	}
	cancel := ls.cancel
	link := ls.link
	upstream := ls.upstream
	target := ls.target
	m.mu.Unlock()

	m.logger.Info("link down", "target", targetName, "reason", reason)
	if link != nil {
		if wh, ok := m.reg.Get(target.Wormhole); ok {
			cctx, cc := context.WithTimeout(context.Background(), closeTimeout)
			_, _ = wh.Client.CloseLink(cctx, &wormholev1.CloseLinkRequest{LinkId: link.LinkId})
			cc()
		}
	}
	if cancel != nil {
		cancel()
	}
	for _, l := range upstream {
		l.Release()
	}
}

// Close tears down every link. Call on shutdown.
func (m *Manager) Close() {
	m.mu.Lock()
	names := make([]string, 0, len(m.links))
	for name := range m.links {
		names = append(names, name)
	}
	m.mu.Unlock()
	for _, name := range names {
		m.destroy(name, "shutdown")
	}
}

func newLinkID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return "ln_" + hex.EncodeToString(b[:])
}
