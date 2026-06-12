// Command echo is the smallest possible wormhole. It exists to prove the
// full agent → MCP → core → gRPC → wormhole path end to end, and as a
// template for the shape of a real wormhole: typed input, declared
// capabilities, structured output.
//
// Real wormholes are purpose-built: they expose specific operations
// ("build_source_package", "connect_vpn"), never a generic command runner.
package main

import (
	"context"
	"strings"

	"github.com/talhaHavadar/interstellar/pkg/wormhole"
)

type sayInput struct {
	Message string `json:"message" jsonschema:"the message to echo back"`
	Repeat  int    `json:"repeat,omitempty" jsonschema:"how many times to repeat the message (default 1)"`
}

type sayOutput struct {
	Echo  string `json:"echo"`
	Times int    `json:"times"`
}

func main() {
	w := wormhole.New("echo", "0.1.0",
		"Round-trip proof wormhole: echoes structured input back to the agent.")

	wormhole.AddTool(w, wormhole.Tool[sayInput]{
		Name:         "say",
		Description:  "Echo a message back, optionally repeated.",
		Capabilities: []wormhole.Capability{wormhole.CapRead},
		Handler: func(ctx context.Context, call *wormhole.Call, in sayInput) (any, error) {
			times := in.Repeat
			if times < 1 {
				times = 1
			}
			call.Logf("info", "echoing %d time(s)", times)
			parts := make([]string, times)
			for i := range parts {
				parts[i] = in.Message
			}
			return sayOutput{Echo: strings.Join(parts, " "), Times: times}, nil
		},
	})

	w.Serve()
}
