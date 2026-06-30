package wormhole

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	execv1 "github.com/talhaHavadar/interstellar/gen/exec/v1"
)

// Command is one command to run through an exec endpoint.
type Command struct {
	// Argv is the program and its arguments. It is never passed through a
	// shell; build it explicitly.
	Argv []string
	// Env adds environment variables.
	Env map[string]string
	// Dir is the working directory; empty uses the provider's default.
	Dir string
	// Stdin is fed to the process then closed.
	Stdin []byte
	// Timeout kills the command after this duration (provider-side); zero
	// relies on the call context for cancellation. Expressed in
	// milliseconds on the wire.
	TimeoutMs int64
}

// ExecRunner runs commands against an exec endpoint provided by another
// wormhole. Obtain one with DialExecEndpoint, typically from the link a tool
// receives on a required exec-endpoint port.
type ExecRunner struct {
	conn   *grpc.ClientConn
	client execv1.ExecServiceClient
}

// DialExecEndpoint connects to an exec endpoint described by an
// ExecEndpointDescriptor (decoded from a link). Close it when done.
func DialExecEndpoint(d ExecEndpointDescriptor) (*ExecRunner, error) {
	if d.Address == "" {
		return nil, fmt.Errorf("exec endpoint descriptor has no address")
	}
	conn, err := grpc.NewClient(d.Address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dialing exec endpoint: %w", err)
	}
	return &ExecRunner{conn: conn, client: execv1.NewExecServiceClient(conn)}, nil
}

// ExecResult is the outcome of a Command.
type ExecResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Run executes cmd and collects its output. A non-zero exit code is returned
// in the result, not as an error; err is non-nil only when the command could
// not be run to completion.
//
// Run buffers the full stdout/stderr in memory before returning. For long
// commands or large outputs prefer RunStream — it forwards each chunk to a
// sink as it arrives, so a wormhole that re-emits to a downstream consumer
// does not accumulate the whole output and does not then flush it as a
// single oversized gRPC message at the end.
func (r *ExecRunner) Run(ctx context.Context, cmd Command) (*ExecResult, error) {
	stream, err := r.client.Run(ctx, &execv1.RunRequest{
		Argv:      cmd.Argv,
		Env:       cmd.Env,
		Dir:       cmd.Dir,
		Stdin:     cmd.Stdin,
		TimeoutMs: cmd.TimeoutMs,
	})
	if err != nil {
		return nil, err
	}
	res := &ExecResult{ExitCode: -1}
	for {
		ev, err := stream.Recv()
		if err == io.EOF {
			return res, nil
		}
		if err != nil {
			return nil, err
		}
		switch e := ev.Event.(type) {
		case *execv1.RunResponse_Stdout:
			res.Stdout = append(res.Stdout, e.Stdout...)
		case *execv1.RunResponse_Stderr:
			res.Stderr = append(res.Stderr, e.Stderr...)
		case *execv1.RunResponse_Exit:
			res.ExitCode = int(e.Exit.Code)
			if e.Exit.Error != "" {
				return res, fmt.Errorf("command failed: %s", e.Exit.Error)
			}
		}
	}
}

// RunStream executes cmd and forwards each stdout/stderr chunk and the exit
// code to sink as they arrive, without buffering the whole output in memory.
// This is the right API for a wormhole that wraps an upstream exec endpoint
// and re-emits to its own consumers (e.g. contained-debdev, testflinger).
// Run's all-at-end flush would produce a single sink.Stdout call carrying
// the entire output, which crosses gRPC's default 4 MiB MaxRecvMsgSize and
// fails the downstream Recv with ResourceExhausted as soon as the command's
// total output exceeds that ceiling.
//
// RunStream returns nil after the stream's EOF. A stream-level transport
// error returns it directly. An Exit event carrying a non-empty Error field
// is reported as a wrapped error AFTER its exit code has been pushed to the
// sink — callers can rely on sink.SetExit having been called when this path
// returns an error.
func (r *ExecRunner) RunStream(ctx context.Context, cmd Command, sink ExecSink) error {
	stream, err := r.client.Run(ctx, &execv1.RunRequest{
		Argv:      cmd.Argv,
		Env:       cmd.Env,
		Dir:       cmd.Dir,
		Stdin:     cmd.Stdin,
		TimeoutMs: cmd.TimeoutMs,
	})
	if err != nil {
		return err
	}
	for {
		ev, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch e := ev.Event.(type) {
		case *execv1.RunResponse_Stdout:
			sink.Stdout(e.Stdout)
		case *execv1.RunResponse_Stderr:
			sink.Stderr(e.Stderr)
		case *execv1.RunResponse_Exit:
			sink.SetExit(int(e.Exit.Code))
			if e.Exit.Error != "" {
				return fmt.Errorf("command failed: %s", e.Exit.Error)
			}
		}
	}
}

// Close releases the connection.
func (r *ExecRunner) Close() error { return r.conn.Close() }

// CommandFunc executes one command on behalf of an exec endpoint and streams
// its output through sink. Provider wormholes implement this; the shape of
// "where" the command runs (locally, over SSH, ...) is entirely the
// provider's concern.
type CommandFunc func(ctx context.Context, cmd Command, sink ExecSink) error

// ExecSink receives a running command's output. Stdout/Stderr may be called
// any number of times; exactly one of Exit (success path) is implied by
// returning nil from the CommandFunc with the code set via SetExit.
type ExecSink interface {
	Stdout(p []byte)
	Stderr(p []byte)
	// SetExit records the process exit code to report to the consumer.
	SetExit(code int)
}

// LinkSocketDir returns a per-link directory under the OS temp dir for a
// provider to place its sockets in. Provider and consumer wormholes run as
// children of the same gateway on one host, so this path is reachable from
// both.
func LinkSocketDir(linkID string) string {
	return filepath.Join(os.TempDir(), "interstellar-links", linkID)
}

// ServeExecEndpoint starts an ExecService backed by run on a freshly created
// unix socket under dir, and returns its descriptor plus a stop function.
// Provider wormholes call this from a LinkHandler:
//
//	desc, stop, err := wormhole.ServeExecEndpoint(linkDir, runOnHost)
//	return &wormhole.ActiveLink{Descriptor: desc, Close: stop}, err
func ServeExecEndpoint(dir string, run CommandFunc) (ExecEndpointDescriptor, func() error, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ExecEndpointDescriptor{}, nil, fmt.Errorf("creating link dir: %w", err)
	}
	sock := filepath.Join(dir, "exec.sock")
	_ = os.Remove(sock)
	lis, err := net.Listen("unix", sock)
	if err != nil {
		return ExecEndpointDescriptor{}, nil, fmt.Errorf("listening on link socket: %w", err)
	}

	srv := grpc.NewServer()
	execv1.RegisterExecServiceServer(srv, &execServer{run: run})

	go srv.Serve(lis)

	var once sync.Once
	stop := func() error {
		once.Do(func() {
			srv.GracefulStop()
			_ = os.Remove(sock)
		})
		return nil
	}
	return ExecEndpointDescriptor{Address: "unix://" + sock}, stop, nil
}

type execServer struct {
	execv1.UnimplementedExecServiceServer
	run CommandFunc
}

func (s *execServer) Run(req *execv1.RunRequest, stream grpc.ServerStreamingServer[execv1.RunResponse]) error {
	sink := &streamSink{stream: stream, exit: -1}
	cmd := Command{
		Argv:      req.Argv,
		Env:       req.Env,
		Dir:       req.Dir,
		Stdin:     req.Stdin,
		TimeoutMs: req.TimeoutMs,
	}
	err := s.run(stream.Context(), cmd, sink)
	exit := &execv1.Exit{Code: int32(sink.exitCode())}
	if err != nil {
		exit.Error = err.Error()
	}
	return stream.Send(&execv1.RunResponse{Event: &execv1.RunResponse_Exit{Exit: exit}})
}

// streamSink serializes sends; a CommandFunc may write output from multiple
// goroutines (e.g. separate stdout/stderr pumps).
type streamSink struct {
	stream grpc.ServerStreamingServer[execv1.RunResponse]

	mu   sync.Mutex
	exit int
	set  bool
}

func (s *streamSink) Stdout(p []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.stream.Send(&execv1.RunResponse{Event: &execv1.RunResponse_Stdout{Stdout: append([]byte(nil), p...)}})
}

func (s *streamSink) Stderr(p []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.stream.Send(&execv1.RunResponse{Event: &execv1.RunResponse_Stderr{Stderr: append([]byte(nil), p...)}})
}

func (s *streamSink) SetExit(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exit = code
	s.set = true
}

func (s *streamSink) exitCode() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.set {
		return -1
	}
	return s.exit
}
