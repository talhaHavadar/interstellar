package wormhole

import (
	"context"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	wormholev1 "github.com/talhaHavadar/interstellar/gen/wormhole/v1"
)

// fakeOpenLinkStream is a minimal grpc.ServerStreamingServer that records the
// events OpenLink sends. Only Context and Send are exercised by OpenLink; the
// rest of grpc.ServerStream is left nil and never called.
type fakeOpenLinkStream struct {
	grpc.ServerStream
	ctx    context.Context
	mu     sync.Mutex
	events []*wormholev1.OpenLinkResponse
}

func (f *fakeOpenLinkStream) Context() context.Context { return f.ctx }

func (f *fakeOpenLinkStream) Send(ev *wormholev1.OpenLinkResponse) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
	return nil
}

func (f *fakeOpenLinkStream) snapshot() []*wormholev1.OpenLinkResponse {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*wormholev1.OpenLinkResponse(nil), f.events...)
}

// TestOpenLinkStreamsBeforeUp asserts a LinkHandler can stream progress and log
// events during bring-up, and that they arrive before the terminal LinkUp.
func TestOpenLinkStreamsBeforeUp(t *testing.T) {
	w := New("streamer", "0.1.0", "")
	w.Provide(
		Port{Name: "target", Type: PortTypeExecEndpoint, Description: "x"},
		func(ctx context.Context, req *LinkRequest) (*ActiveLink, error) {
			req.Progress(0.5, "reserving hardware")
			req.Logf("info", "polling the queue")
			return &ActiveLink{Descriptor: ExecEndpointDescriptor{Address: "unix:///tmp/x.sock"}}, nil
		},
	)

	s := newServer(w)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &fakeOpenLinkStream{ctx: ctx}

	done := make(chan error, 1)
	go func() {
		done <- s.OpenLink(&wormholev1.OpenLinkRequest{LinkId: "L1", PortName: "target"}, stream)
	}()

	// OpenLink blocks for the life of the link; wait until LinkUp is sent.
	upIdx := -1
	deadline := time.Now().Add(2 * time.Second)
	for upIdx < 0 {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for LinkUp; got %d events", len(stream.snapshot()))
		}
		for i, ev := range stream.snapshot() {
			if _, ok := ev.Event.(*wormholev1.OpenLinkResponse_Up); ok {
				upIdx = i
			}
		}
		if upIdx < 0 {
			time.Sleep(5 * time.Millisecond)
		}
	}

	var sawProgress, sawLog bool
	for _, ev := range stream.snapshot()[:upIdx] {
		switch ev.Event.(type) {
		case *wormholev1.OpenLinkResponse_Progress:
			sawProgress = true
		case *wormholev1.OpenLinkResponse_Log:
			sawLog = true
		}
	}
	if !sawProgress || !sawLog {
		t.Fatalf("want progress and log before LinkUp (progress=%v log=%v)", sawProgress, sawLog)
	}

	// teardown unblocks OpenLink.
	if err := s.teardown("L1"); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("OpenLink returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OpenLink did not return after teardown")
	}
}

// TestLinkRequestEmitNilSafe ensures the streaming helpers are no-ops when the
// server has not wired an emit (e.g. a handler invoked outside a live stream).
func TestLinkRequestEmitNilSafe(t *testing.T) {
	var req LinkRequest
	req.Logf("info", "no panic")
	req.Progress(0.1, "no panic")
}
