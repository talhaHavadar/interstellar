# Creating a wormhole

A wormhole is a single Go binary built on the
[`pkg/wormhole`](../pkg/wormhole) SDK. The core launches it, asks it what it
can do, and routes agent calls to it. You never deal with MCP, JSON-RPC, or
gRPC directly.

## Design rule first

Build **purpose-built protocols, not command runners**. A good wormhole
exposes a handful of typed operations that encode a workflow —
`build_source_package(distro, arch)` — and chooses the commands itself. If
your tool's input is "a command to run", you are building an
`exec.arbitrary` tool: it will be invisible to agents until a server admin
explicitly opts your wormhole in, and most won't. If you need to *reach*
somewhere to do your job, don't take credentials or addresses as input —
declare a required port and let the admin's configuration decide what's on
the other side.

## Minimal wormhole

```go
package main

import (
    "context"

    "github.com/talhaHavadar/interstellar/pkg/wormhole"
)

type greetInput struct {
    Name string `json:"name" jsonschema:"who to greet"`
}

func main() {
    w := wormhole.New("greeter", "0.1.0", "Greets people, properly.")

    wormhole.AddTool(w, wormhole.Tool[greetInput]{
        Name:         "greet",
        Description:  "Produce a greeting.",
        Capabilities: []wormhole.Capability{wormhole.CapRead},
        Handler: func(ctx context.Context, call *wormhole.Call, in greetInput) (any, error) {
            return map[string]string{"greeting": "Hello, " + in.Name}, nil
        },
    })

    w.Serve()
}
```

That's a complete wormhole. Build it and drop the binary into the gateway's
`--wormhole-dir`; on the next start the agent sees `greeter__greet`.

The input struct **is** the contract: its JSON Schema is generated from the
fields (`json` tags name them, `jsonschema` tags describe them) and shown to
the agent. The handler's return value is JSON-marshaled back. Returning an
error produces a tool error; panics are caught and reported the same way.

## Capabilities

Every tool declares what class of thing it does. Use the constants — they're
checked at compile time, validated again by the core, and a typo cannot pass:

| Constant | Meaning |
|----------|---------|
| `CapRead` | reads state, no side effects |
| `CapWrite` | mutates state via a fixed procedure |
| `CapNetwork` | establishes/alters connectivity |
| `CapExecScoped` | runs commands *the wormhole chooses* |
| `CapExecArbitrary` | runs commands *the caller supplies* — denied by default |

Declare honestly: the audit log records every call, and misdeclared
capabilities are the fastest way to lose users' trust.

## Long-running tools

`call.Logf` and `call.Progress` stream to the core while the handler runs:

```go
call.Logf("info", "fetching sources for %s", in.Package)
call.Progress(0.4, "compiling")
```

## Ports (composition)

Ports connect wormholes to each other; agents never see them. There are two
sides — consuming a port and providing one.

**Consuming.** Declare what you need, mark which tools need it, and read the
link inside the handler. The agent picks *which* target the link routes to
(the core injects a `<port>_target` argument); your handler just uses the
link:

```go
w.Require(wormhole.Port{
    Name: "shell", Type: wormhole.PortTypeExecEndpoint,
    Description: "machine to build on",
})

wormhole.AddTool(w, wormhole.Tool[buildInput]{
    Name:          "build_source_package",
    Capabilities:  []wormhole.Capability{wormhole.CapExecScoped},
    RequiresPorts: []string{"shell"},
    Handler: func(ctx context.Context, call *wormhole.Call, in buildInput) (any, error) {
        link, _ := call.Link("shell")
        var ep wormhole.ExecEndpointDescriptor
        if err := link.DecodeDescriptor(&ep); err != nil {
            return nil, err
        }
        runner, err := wormhole.DialExecEndpoint(ep)
        if err != nil {
            return nil, err
        }
        defer runner.Close()
        // Run a fixed, purpose-built sequence — never a caller-supplied command.
        res, err := runner.Run(ctx, wormhole.Command{Argv: []string{"dpkg-buildpackage", "-S"}})
        ...
    },
})
```

[`wormholes/sysinfo`](../wormholes/sysinfo/main.go) is a complete consumer.

**Providing.** `w.Provide(port, handler)` registers a handler that brings the
link up (connect the VPN, open the SSH session) and returns its descriptor
plus a close function the core calls on teardown. For exec endpoints the SDK
does the heavy lifting — `ServeExecEndpoint` stands up the service on a
socket; you supply a `CommandFunc` that runs one command wherever this
wormhole reaches:

```go
w.Provide(
    wormhole.Port{Name: "host", Type: wormhole.PortTypeExecEndpoint},
    func(ctx context.Context, req *wormhole.LinkRequest) (*wormhole.ActiveLink, error) {
        desc, stop, err := wormhole.ServeExecEndpoint(
            wormhole.LinkSocketDir(req.LinkID), wormhole.RunLocalCommand)
        if err != nil {
            return nil, err
        }
        return &wormhole.ActiveLink{Descriptor: desc, Close: stop}, nil
    },
)
```

[`wormholes/local-exec`](../wormholes/local-exec/main.go) is the minimal
provider; [`wormholes/ssh`](../wormholes/ssh/main.go) is one that *also*
consumes an optional `network-context` port, so its connection can be routed
through a VPN it knows nothing about. Descriptor types live in
[`pkg/wormhole/port.go`](../pkg/wormhole/port.go).

Targets — which configuration a port binds to — are defined by the server
admin in config, not by wormholes or agents. See
[architecture.md](architecture.md#composition-ports-and-links).

## Checklist before shipping

- Tool names are lowercase snake_case; the wormhole name is kebab-case
  (it prefixes your tools: `greeter__greet`).
- Every tool declares its real capabilities.
- Inputs are typed structs with `jsonschema` descriptions on every field.
- Nothing is written to stdout (the plugin handshake owns it) — log with
  `call.Logf` or stderr.
- `go build` the binary, drop it in the wormhole dir, and check
  `interstellar__status` reports it the way you intend.
