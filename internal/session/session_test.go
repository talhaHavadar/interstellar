package session

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"

	wormholev1 "github.com/talhaHavadar/interstellar/gen/wormhole/v1"
	"github.com/talhaHavadar/interstellar/internal/registry"
)

// fakeRegistry maps wormhole names to hand-built registry entries.
type fakeRegistry struct{ m map[string]*registry.Wormhole }

func (f fakeRegistry) Get(name string) (*registry.Wormhole, bool) {
	w, ok := f.m[name]
	return w, ok
}

// fakeClient records OpenLink/CloseLink calls and serves a controllable
// link stream. Only the methods the session manager uses are implemented.
type fakeClient struct {
	wormholev1.WormholeServiceClient

	manifest *wormholev1.Manifest

	mu        sync.Mutex
	opens     int32
	closes    int32
	openLinks map[string]*fakeStream // by link id
}

func newFakeClient(m *wormholev1.Manifest) *fakeClient {
	return &fakeClient{manifest: m, openLinks: map[string]*fakeStream{}}
}

func (c *fakeClient) OpenLink(ctx context.Context, in *wormholev1.OpenLinkRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[wormholev1.OpenLinkResponse], error) {
	atomic.AddInt32(&c.opens, 1)
	st := &fakeStream{events: make(chan *wormholev1.OpenLinkResponse, 4), ctx: ctx}
	c.mu.Lock()
	c.openLinks[in.LinkId] = st
	c.mu.Unlock()
	// Bring the link up immediately, echoing the descriptor for assertions.
	st.events <- &wormholev1.OpenLinkResponse{Event: &wormholev1.OpenLinkResponse_Up{
		Up: &wormholev1.LinkUp{Link: &wormholev1.Link{
			LinkId:         in.LinkId,
			PortName:       in.PortName,
			Type:           portType(c.manifest.Provides, in.PortName),
			DescriptorJson: `{"ok":true}`,
		}},
	}}
	return st, nil
}

func (c *fakeClient) CloseLink(ctx context.Context, in *wormholev1.CloseLinkRequest, _ ...grpc.CallOption) (*wormholev1.CloseLinkResponse, error) {
	atomic.AddInt32(&c.closes, 1)
	c.mu.Lock()
	if st := c.openLinks[in.LinkId]; st != nil {
		st.close()
	}
	c.mu.Unlock()
	return &wormholev1.CloseLinkResponse{}, nil
}

func portType(ports []*wormholev1.PortSpec, name string) string {
	for _, p := range ports {
		if p.Name == name {
			return p.Type
		}
	}
	return ""
}

// fakeStream embeds the interface so unused methods exist; only Recv is used.
type fakeStream struct {
	grpc.ServerStreamingClient[wormholev1.OpenLinkResponse]
	events chan *wormholev1.OpenLinkResponse
	ctx    context.Context

	once sync.Once
}

func (s *fakeStream) Recv() (*wormholev1.OpenLinkResponse, error) {
	select {
	case ev, ok := <-s.events:
		if !ok {
			return nil, io.EOF
		}
		return ev, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

func (s *fakeStream) close() { s.once.Do(func() { close(s.events) }) }

func provider(name, port, typ string) *registry.Wormhole {
	m := &wormholev1.Manifest{
		Name:     name,
		Provides: []*wormholev1.PortSpec{{Name: port, Type: typ}},
	}
	return &registry.Wormhole{Manifest: m, Client: newFakeClient(m)}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestAcquireReusesLink(t *testing.T) {
	wh := provider("local-exec", "host", "exec-endpoint")
	reg := fakeRegistry{m: map[string]*registry.Wormhole{"local-exec": wh}}
	mgr := New(reg, discardLogger(), map[string]Target{
		"box": {Name: "box", Wormhole: "local-exec", Port: "host", IdleTimeout: time.Hour},
	})
	defer mgr.Close()

	a, err := mgr.Acquire(context.Background(), "box")
	if err != nil {
		t.Fatal(err)
	}
	b, err := mgr.Acquire(context.Background(), "box")
	if err != nil {
		t.Fatal(err)
	}
	if a.Link.LinkId != b.Link.LinkId {
		t.Errorf("concurrent leases should share a link: %s vs %s", a.Link.LinkId, b.Link.LinkId)
	}
	fc := wh.Client.(*fakeClient)
	if got := atomic.LoadInt32(&fc.opens); got != 1 {
		t.Errorf("OpenLink called %d times, want 1", got)
	}
	if a.Link.Type != "exec-endpoint" {
		t.Errorf("link type = %q", a.Link.Type)
	}
	a.Release()
	b.Release()
}

func TestIdleTeardownAndCloseLink(t *testing.T) {
	wh := provider("local-exec", "host", "exec-endpoint")
	reg := fakeRegistry{m: map[string]*registry.Wormhole{"local-exec": wh}}
	mgr := New(reg, discardLogger(), map[string]Target{
		"box": {Name: "box", Wormhole: "local-exec", Port: "host", IdleTimeout: 30 * time.Millisecond},
	})
	defer mgr.Close()

	lease, err := mgr.Acquire(context.Background(), "box")
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()

	fc := wh.Client.(*fakeClient)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&fc.closes) == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&fc.closes); got != 1 {
		t.Errorf("idle link should have been closed once, got %d closes", got)
	}

	// Re-acquiring after teardown opens a fresh link.
	lease2, err := mgr.Acquire(context.Background(), "box")
	if err != nil {
		t.Fatal(err)
	}
	defer lease2.Release()
	if got := atomic.LoadInt32(&fc.opens); got != 2 {
		t.Errorf("OpenLink should have been called again, got %d", got)
	}
}

func TestViaChainResolves(t *testing.T) {
	vpn := provider("vpn", "tunnel", "network-context")
	// ssh provides exec-endpoint and requires a network-context named "net".
	sshManifest := &wormholev1.Manifest{
		Name:     "ssh",
		Provides: []*wormholev1.PortSpec{{Name: "target", Type: "exec-endpoint"}},
		Requires: []*wormholev1.PortSpec{{Name: "net", Type: "network-context"}},
	}
	ssh := &registry.Wormhole{Manifest: sshManifest, Client: newFakeClient(sshManifest)}

	reg := fakeRegistry{m: map[string]*registry.Wormhole{"vpn": vpn, "ssh": ssh}}
	targets := map[string]Target{
		"corp-vpn": {Name: "corp-vpn", Wormhole: "vpn", Port: "tunnel", IdleTimeout: time.Hour},
		"build-box": {Name: "build-box", Wormhole: "ssh", Port: "target",
			Via: map[string]string{"net": "corp-vpn"}, IdleTimeout: time.Hour},
	}
	if err := Validate(reg, targets); err != nil {
		t.Fatalf("validation: %v", err)
	}
	mgr := New(reg, discardLogger(), targets)
	defer mgr.Close()

	lease, err := mgr.Acquire(context.Background(), "build-box")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer lease.Release()

	// Both the ssh link and its upstream vpn link must have been opened.
	if got := atomic.LoadInt32(&vpn.Client.(*fakeClient).opens); got != 1 {
		t.Errorf("upstream vpn OpenLink = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&ssh.Client.(*fakeClient).opens); got != 1 {
		t.Errorf("ssh OpenLink = %d, want 1", got)
	}
	if lease.Link.Type != "exec-endpoint" {
		t.Errorf("resolved link type = %q, want exec-endpoint", lease.Link.Type)
	}
}

func TestAcquireUnknownTarget(t *testing.T) {
	mgr := New(fakeRegistry{m: map[string]*registry.Wormhole{}}, discardLogger(), map[string]Target{})
	if _, err := mgr.Acquire(context.Background(), "ghost"); err == nil {
		t.Error("want error for unknown target")
	}
}

func TestValidateErrors(t *testing.T) {
	vpn := provider("vpn", "tunnel", "network-context")
	ssh := &registry.Wormhole{Manifest: &wormholev1.Manifest{
		Name:     "ssh",
		Provides: []*wormholev1.PortSpec{{Name: "target", Type: "exec-endpoint"}},
		Requires: []*wormholev1.PortSpec{{Name: "net", Type: "network-context"}},
	}}
	ssh.Client = newFakeClient(ssh.Manifest)
	reg := fakeRegistry{m: map[string]*registry.Wormhole{"vpn": vpn, "ssh": ssh}}

	tests := []struct {
		name    string
		targets map[string]Target
		want    string
	}{
		{
			"unknown wormhole",
			map[string]Target{"x": {Name: "x", Wormhole: "nope", Port: "p"}},
			"is not loaded",
		},
		{
			"missing provided port",
			map[string]Target{"x": {Name: "x", Wormhole: "vpn", Port: "nope"}},
			"does not provide port",
		},
		{
			"unrouted required port",
			map[string]Target{"x": {Name: "x", Wormhole: "ssh", Port: "target"}},
			"is not routed",
		},
		{
			"via names non-required port",
			map[string]Target{
				"x": {Name: "x", Wormhole: "ssh", Port: "target", Via: map[string]string{"ghost": "v"}},
				"v": {Name: "v", Wormhole: "vpn", Port: "tunnel"},
			},
			"no required port",
		},
		{
			"via type mismatch",
			map[string]Target{
				"x":   {Name: "x", Wormhole: "ssh", Port: "target", Via: map[string]string{"net": "bad"}},
				"bad": {Name: "bad", Wormhole: "ssh", Port: "target", Via: map[string]string{"net": "v"}},
				"v":   {Name: "v", Wormhole: "vpn", Port: "tunnel"},
			},
			"needs",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(reg, tt.targets)
			if err == nil {
				t.Fatal("want error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not contain %q", err, tt.want)
			}
		})
	}
}

func TestValidateDetectsCycle(t *testing.T) {
	// Two ssh-like wormholes routing through each other.
	mk := func(name string) *registry.Wormhole {
		m := &wormholev1.Manifest{
			Name:     name,
			Provides: []*wormholev1.PortSpec{{Name: "out", Type: "network-context"}},
			Requires: []*wormholev1.PortSpec{{Name: "in", Type: "network-context"}},
		}
		return &registry.Wormhole{Manifest: m, Client: newFakeClient(m)}
	}
	reg := fakeRegistry{m: map[string]*registry.Wormhole{"a": mk("a"), "b": mk("b")}}
	targets := map[string]Target{
		"ta": {Name: "ta", Wormhole: "a", Port: "out", Via: map[string]string{"in": "tb"}},
		"tb": {Name: "tb", Wormhole: "b", Port: "out", Via: map[string]string{"in": "ta"}},
	}
	err := Validate(reg, targets)
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Errorf("want cycle error, got %v", err)
	}
}
