package wormhole

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"
)

// RunLocalCommand is a CommandFunc that runs a command on the host with
// os/exec, streaming stdout and stderr as they are produced. It never goes
// through a shell. Provider wormholes that execute on the gateway host
// (local-exec) and those that execute elsewhere but want the same streaming
// behavior can reuse it.
func RunLocalCommand(ctx context.Context, cmd Command, sink ExecSink) error {
	if len(cmd.Argv) == 0 {
		return fmt.Errorf("empty argv")
	}

	if cmd.TimeoutMs > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(cmd.TimeoutMs)*time.Millisecond)
		defer cancel()
	}

	c := exec.CommandContext(ctx, cmd.Argv[0], cmd.Argv[1:]...)
	c.Dir = cmd.Dir
	if len(cmd.Env) > 0 {
		env := make([]string, 0, len(cmd.Env))
		for k, v := range cmd.Env {
			env = append(env, k+"="+v)
		}
		c.Env = append(c.Environ(), env...)
	}
	if len(cmd.Stdin) > 0 {
		c.Stdin = bytes.NewReader(cmd.Stdin)
	}

	stdout, err := c.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := c.StderrPipe()
	if err != nil {
		return err
	}
	if err := c.Start(); err != nil {
		return fmt.Errorf("starting command: %w", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go pump(&wg, stdout, sink.Stdout)
	go pump(&wg, stderr, sink.Stderr)
	wg.Wait()

	err = c.Wait()
	if c.ProcessState != nil {
		sink.SetExit(c.ProcessState.ExitCode())
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		_ = exitErr
		// A non-zero exit is reported via the exit code, not as an error.
		return nil
	}
	return err
}

func pump(wg *sync.WaitGroup, r io.Reader, write func([]byte)) {
	defer wg.Done()
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			write(buf[:n])
		}
		if err != nil {
			return
		}
	}
}
