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
