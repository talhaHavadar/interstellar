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

Ports connect wormholes to each other; agents never see them. Declare what
you need, and read the link inside the handler:

```go
w.Require(wormhole.Port{
    Name: "target", Type: wormhole.PortTypeExecEndpoint,
    Description: "machine to build on",
})

wormhole.AddTool(w, wormhole.Tool[buildInput]{
    Name:          "build_source_package",
    Capabilities:  []wormhole.Capability{wormhole.CapExecScoped},
    RequiresPorts: []string{"target"},
    Handler: func(ctx context.Context, call *wormhole.Call, in buildInput) (any, error) {
        link, _ := call.Link("target")
        var ep wormhole.ExecEndpointDescriptor
        if err := link.DecodeDescriptor(&ep); err != nil {
            return nil, err
        }
        // dial ep.Address and run the build steps there
        ...
    },
})
```

Providing a port is the mirror image: `w.Provide(port, handler)`, where the
handler brings the link up (connect the VPN, open the SSH session) and
returns its descriptor plus a close function. See the descriptor types in
[`pkg/wormhole/port.go`](../pkg/wormhole/port.go).

> Link resolution in the core is still in development; tools with
> `RequiresPorts` are currently refused at call time. The SDK surface is in
> place so wormholes can be written against it now.

## Checklist before shipping

- Tool names are lowercase snake_case; the wormhole name is kebab-case
  (it prefixes your tools: `greeter__greet`).
- Every tool declares its real capabilities.
- Inputs are typed structs with `jsonschema` descriptions on every field.
- Nothing is written to stdout (the plugin handshake owns it) — log with
  `call.Logf` or stderr.
- `go build` the binary, drop it in the wormhole dir, and check
  `interstellar__status` reports it the way you intend.
