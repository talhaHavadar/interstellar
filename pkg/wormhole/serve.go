package wormhole

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	wormholev1 "github.com/talhaHavadar/interstellar/gen/wormhole/v1"
)

// server implements WormholeServiceServer on top of a Wormhole definition.
type server struct {
	wormholev1.UnimplementedWormholeServiceServer

	w *Wormhole

	mu    sync.Mutex
	links map[string]*servedLink
}

type servedLink struct {
	active *ActiveLink
	done   chan struct{} // closed exactly once, by CloseLink or stream teardown
	once   sync.Once
}

func newServer(w *Wormhole) *server {
	return &server{w: w, links: map[string]*servedLink{}}
}

func (s *server) Describe(_ context.Context, _ *wormholev1.DescribeRequest) (*wormholev1.DescribeResponse, error) {
	return &wormholev1.DescribeResponse{Manifest: s.w.manifest()}, nil
}

func (s *server) CallTool(req *wormholev1.CallToolRequest, stream grpc.ServerStreamingServer[wormholev1.CallToolResponse]) error {
	t, ok := s.w.tools[req.Tool]
	if !ok {
		return status.Errorf(codes.NotFound, "unknown tool %q", req.Tool)
	}

	links := make(map[string]Link, len(req.Links))
	for _, l := range req.Links {
		links[l.PortName] = Link{
			ID:         l.LinkId,
			PortName:   l.PortName,
			Type:       l.Type,
			Descriptor: json.RawMessage(l.DescriptorJson),
		}
	}

	// Handlers may emit logs/progress from multiple goroutines; stream.Send
	// is not safe for concurrent use.
	var sendMu sync.Mutex
	send := func(ev *wormholev1.CallToolResponse) {
		sendMu.Lock()
		defer sendMu.Unlock()
		_ = stream.Send(ev) // a dead stream also cancels the handler's ctx
	}

	call := &Call{ID: req.CallId, links: links, emit: send}

	out, err := func() (out any, err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("tool %q panicked: %v", req.Tool, r)
			}
		}()
		return t.handler(stream.Context(), call, []byte(req.ArgumentsJson))
	}()

	result := &wormholev1.ToolResult{}
	if err != nil {
		result.IsError = true
		result.ContentJson = mustJSON(map[string]string{"error": err.Error()})
	} else {
		content, merr := json.Marshal(out)
		if merr != nil {
			result.IsError = true
			result.ContentJson = mustJSON(map[string]string{"error": fmt.Sprintf("marshaling result: %v", merr)})
		} else {
			result.ContentJson = string(content)
		}
	}
	send(&wormholev1.CallToolResponse{Event: &wormholev1.CallToolResponse_Result{Result: result}})
	return nil
}

func (s *server) OpenLink(req *wormholev1.OpenLinkRequest, stream grpc.ServerStreamingServer[wormholev1.OpenLinkResponse]) error {
	h, ok := s.w.linkHandler[req.PortName]
	if !ok {
		return status.Errorf(codes.NotFound, "no provided port %q", req.PortName)
	}

	upstream := make([]Link, 0, len(req.Links))
	for _, l := range req.Links {
		upstream = append(upstream, Link{
			ID:         l.LinkId,
			PortName:   l.PortName,
			Type:       l.Type,
			Descriptor: json.RawMessage(l.DescriptorJson),
		})
	}

	// Serialize all sends on this stream: a LinkHandler may stream log/progress
	// (via LinkRequest.emit) from its own goroutines while we send Up/State.
	var sendMu sync.Mutex
	send := func(ev *wormholev1.OpenLinkResponse) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(ev)
	}

	active, err := h(stream.Context(), &LinkRequest{
		LinkID: req.LinkId,
		Config: json.RawMessage(req.ConfigJson),
		Links:  upstream,
		emit:   func(ev *wormholev1.OpenLinkResponse) { _ = send(ev) },
	})
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "opening link: %v", err)
	}

	descriptor, err := json.Marshal(active.Descriptor)
	if err != nil {
		s.closeActive(active)
		return status.Errorf(codes.Internal, "marshaling link descriptor: %v", err)
	}

	var portType string
	for _, p := range s.w.provides {
		if p.Name == req.PortName {
			portType = p.Type
		}
	}

	sl := &servedLink{active: active, done: make(chan struct{})}
	s.mu.Lock()
	s.links[req.LinkId] = sl
	s.mu.Unlock()

	if err := send(&wormholev1.OpenLinkResponse{
		Event: &wormholev1.OpenLinkResponse_Up{
			Up: &wormholev1.LinkUp{Link: &wormholev1.Link{
				LinkId:         req.LinkId,
				PortName:       req.PortName,
				Type:           portType,
				DescriptorJson: string(descriptor),
			}},
		},
	}); err != nil {
		s.teardown(req.LinkId)
		return err
	}

	// The stream stays open for the life of the link: it ends when the core
	// calls CloseLink, or when the core disappears (stream context done).
	select {
	case <-sl.done:
	case <-stream.Context().Done():
		s.teardown(req.LinkId)
	}
	_ = send(&wormholev1.OpenLinkResponse{
		Event: &wormholev1.OpenLinkResponse_State{
			State: &wormholev1.LinkState{State: "closed"},
		},
	})
	return nil
}

func (s *server) CloseLink(_ context.Context, req *wormholev1.CloseLinkRequest) (*wormholev1.CloseLinkResponse, error) {
	if err := s.teardown(req.LinkId); err != nil {
		return nil, status.Errorf(codes.Internal, "closing link: %v", err)
	}
	return &wormholev1.CloseLinkResponse{}, nil
}

func (s *server) Health(_ context.Context, _ *wormholev1.HealthRequest) (*wormholev1.HealthResponse, error) {
	return &wormholev1.HealthResponse{Ok: true}, nil
}

// teardown closes and forgets a link; idempotent.
func (s *server) teardown(linkID string) error {
	s.mu.Lock()
	sl, ok := s.links[linkID]
	delete(s.links, linkID)
	s.mu.Unlock()
	if !ok {
		return nil
	}
	var err error
	sl.once.Do(func() {
		err = s.closeActive(sl.active)
		close(sl.done)
	})
	return err
}

func (s *server) closeActive(a *ActiveLink) error {
	if a.Close == nil {
		return nil
	}
	return a.Close()
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		// Only reachable for unmarshalable values of our own construction.
		panic(err)
	}
	return string(b)
}
