package wormhole

import (
	"context"
	"strings"
	"testing"
)

func TestExecEndpointRoundTrip(t *testing.T) {
	// Provider: an exec endpoint that echoes argv and reports an exit code.
	run := func(ctx context.Context, cmd Command, sink ExecSink) error {
		sink.Stdout([]byte(strings.Join(cmd.Argv, " ")))
		sink.Stderr([]byte("on stderr"))
		if cmd.Env["FAIL"] == "1" {
			sink.SetExit(3)
			return nil
		}
		sink.SetExit(0)
		return nil
	}

	desc, stop, err := ServeExecEndpoint(t.TempDir(), run)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	runner, err := DialExecEndpoint(desc)
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()

	res, err := runner.Run(context.Background(), Command{Argv: []string{"hello", "world"}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if string(res.Stdout) != "hello world" {
		t.Errorf("stdout = %q", res.Stdout)
	}
	if string(res.Stderr) != "on stderr" {
		t.Errorf("stderr = %q", res.Stderr)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit = %d, want 0", res.ExitCode)
	}

	res, err = runner.Run(context.Background(), Command{Argv: []string{"x"}, Env: map[string]string{"FAIL": "1"}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.ExitCode != 3 {
		t.Errorf("exit = %d, want 3", res.ExitCode)
	}
}

func TestDialExecEndpointRejectsEmpty(t *testing.T) {
	if _, err := DialExecEndpoint(ExecEndpointDescriptor{}); err == nil {
		t.Error("want error for empty address")
	}
}

// chunkRecorder is a sink that records each Stdout/Stderr/Exit call as a
// distinct entry — so a test can prove RunStream forwards chunks AS they
// arrive instead of coalescing them into one buffer.
type chunkRecorder struct {
	stdout [][]byte
	stderr [][]byte
	exit   int
	exitOK bool
}

func (r *chunkRecorder) Stdout(p []byte)  { r.stdout = append(r.stdout, append([]byte(nil), p...)) }
func (r *chunkRecorder) Stderr(p []byte)  { r.stderr = append(r.stderr, append([]byte(nil), p...)) }
func (r *chunkRecorder) SetExit(code int) { r.exit = code; r.exitOK = true }

func TestRunStreamForwardsChunksSeparately(t *testing.T) {
	// The provider emits three distinct stdout chunks and one stderr chunk.
	// RunStream must hand each to the sink in order, not as one big concat —
	// that's the whole point of the streaming variant (the bug it fixes is
	// downstream wormholes flushing one giant final chunk that overflows
	// gRPC's default 4 MiB MaxRecvMsgSize on the next hop).
	run := func(ctx context.Context, cmd Command, sink ExecSink) error {
		sink.Stdout([]byte("alpha"))
		sink.Stdout([]byte("beta"))
		sink.Stderr([]byte("warn"))
		sink.Stdout([]byte("gamma"))
		sink.SetExit(0)
		return nil
	}

	desc, stop, err := ServeExecEndpoint(t.TempDir(), run)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	runner, err := DialExecEndpoint(desc)
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()

	rec := &chunkRecorder{}
	if err := runner.RunStream(context.Background(), Command{Argv: []string{"x"}}, rec); err != nil {
		t.Fatalf("RunStream: %v", err)
	}

	wantStdout := [][]byte{[]byte("alpha"), []byte("beta"), []byte("gamma")}
	if len(rec.stdout) != len(wantStdout) {
		t.Fatalf("stdout chunks = %d (%q), want 3 separate chunks", len(rec.stdout), rec.stdout)
	}
	for i, want := range wantStdout {
		if string(rec.stdout[i]) != string(want) {
			t.Errorf("stdout[%d] = %q, want %q", i, rec.stdout[i], want)
		}
	}
	if len(rec.stderr) != 1 || string(rec.stderr[0]) != "warn" {
		t.Errorf("stderr = %q, want one chunk %q", rec.stderr, "warn")
	}
	if !rec.exitOK || rec.exit != 0 {
		t.Errorf("exit = %d (set=%v), want 0/true", rec.exit, rec.exitOK)
	}
}

func TestRunStreamPropagatesExitCode(t *testing.T) {
	run := func(ctx context.Context, cmd Command, sink ExecSink) error {
		sink.Stdout([]byte("partial"))
		sink.SetExit(2)
		return nil
	}

	desc, stop, err := ServeExecEndpoint(t.TempDir(), run)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	runner, err := DialExecEndpoint(desc)
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()

	rec := &chunkRecorder{}
	if err := runner.RunStream(context.Background(), Command{Argv: []string{"x"}}, rec); err != nil {
		t.Fatalf("RunStream: %v", err)
	}
	if rec.exit != 2 {
		t.Errorf("exit = %d, want 2", rec.exit)
	}
	if len(rec.stdout) != 1 || string(rec.stdout[0]) != "partial" {
		t.Errorf("stdout = %q, want %q", rec.stdout, "partial")
	}
}
