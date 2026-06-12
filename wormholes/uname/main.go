// Command uname is a minimal consumer wormhole: it runs `uname -a` on a
// target machine and returns the output. It owns no execution ability of its
// own — it requires an exec-endpoint port, which the gateway routes to
// whichever target the agent names. That is why it works with the existing
// "localhost" and "remote" targets without any wormhole-specific config:
// targets are shared infrastructure, and a tool requiring a port is offered
// every target whose type matches.
package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/talhaHavadar/interstellar/pkg/wormhole"
)

type unameInput struct{}

type unameOutput struct {
	Output string `json:"output"`
}

func main() {
	w := wormhole.New("uname", "0.1.0",
		"Reports `uname -a` from a target machine.")

	// Declare what we need from another wormhole: a place to run a command.
	w.Require(wormhole.Port{
		Name:        "shell",
		Type:        wormhole.PortTypeExecEndpoint,
		Description: "the machine to query",
	})

	wormhole.AddTool(w, wormhole.Tool[unameInput]{
		Name:          "uname",
		Description:   "Return `uname -a` (kernel and system information) from a target machine.",
		Capabilities:  []wormhole.Capability{wormhole.CapExecScoped},
		RequiresPorts: []string{"shell"},
		Handler:       runUname,
	})

	w.Serve()
}

func runUname(ctx context.Context, call *wormhole.Call, _ unameInput) (any, error) {
	link, ok := call.Link("shell")
	if !ok {
		return nil, fmt.Errorf("no exec endpoint linked")
	}
	var ep wormhole.ExecEndpointDescriptor
	if err := link.DecodeDescriptor(&ep); err != nil {
		return nil, fmt.Errorf("decoding exec endpoint: %w", err)
	}
	runner, err := wormhole.DialExecEndpoint(ep)
	if err != nil {
		return nil, err
	}
	defer runner.Close()

	// A fixed, purpose-built command — never caller-supplied.
	res, err := runner.Run(ctx, wormhole.Command{Argv: []string{"uname", "-a"}, TimeoutMs: 10_000})
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("uname exited %d: %s", res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return unameOutput{Output: strings.TrimSpace(string(res.Stdout))}, nil
}
