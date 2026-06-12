# Architecture

Interstellar is a gateway with two very different boundaries, deliberately
speaking a different protocol on each.

```
            north side                          south side
AI agent ◀──MCP / JSON-RPC──▶ interstellard ◀──gRPC (go-plugin)──▶ wormholes
   (stdio or streamable HTTP)      │
                              policy · audit · registry · links
```

## North side: MCP

Agents connect over the standard MCP transports (stdio for local use,
streamable HTTP for remote). Every tool a wormhole exposes appears to the
agent as `<wormhole>__<tool>` with its JSON Schema forwarded verbatim, plus
MCP annotations derived from the tool's declared capabilities (a read-only
tool carries `readOnlyHint`). One built-in tool, `interstellar__status`,
describes the gateway itself — including tools *hidden* by policy and the
reason, so the agent's view is never silently incomplete.

## South side: wormhole plugins

A wormhole is a separate executable, launched and supervised by the core
(hashicorp/go-plugin handshake, gRPC over a local socket). The contract is
[proto/interstellar/wormhole/v1](../proto/interstellar/wormhole/v1/wormhole.proto):

- `Describe` returns the manifest: identity, tools, ports.
- `CallTool` executes a tool, streaming logs and progress before the result.
- `OpenLink`/`CloseLink` manage links on the wormhole's provided ports.

Process isolation is the point: a crashed or compromised wormhole doesn't
take the gateway with it, and each plugin can be sandboxed independently.
Manifests are validated at load; an invalid wormhole is refused with the
full list of problems, never partially loaded.

## Composition: ports and links

Tools are the agent-facing surface. **Ports** are the wormhole-facing one:
typed connection points declared in the manifest (`provides` / `requires`)
that let wormholes chain without knowing each other.

Port types define the schema of the **link descriptor** that travels over
them:

| Port type         | Descriptor                  | Example provider |
|-------------------|-----------------------------|------------------|
| `network-context` | SOCKS5 dialer socket path   | VPN wormhole     |
| `exec-endpoint`   | gRPC exec service address   | SSH wormhole     |

The target picture: `deb-builder` requires an `exec-endpoint`; `ssh`
provides one and optionally requires a `network-context`; `vpn` provides
that. When an agent asks to build a package on a machine behind a VPN, the
core resolves the chain, opens links outside-in, and hands the builder its
endpoint. The builder never knows there's a VPN; the VPN never knows what
runs through it; the core sees — and audits — everything.

Links are owned by the core: leased, reference-counted, reusable across
calls. *(The resolver and session manager are the next milestone; today,
tools that require ports are refused with a clear error.)*

## Policy and audit

Every tool declares **capability classes** in its manifest — `read`,
`write`, `network`, `exec.scoped`, `exec.arbitrary`. These are an
interstellar concept, not an MCP one, and they are enforced, not advisory:

- They're a protobuf enum end to end — an invalid class can't be expressed
  in the SDK, can't be serialized, and is refused at manifest validation.
- Policy denies `exec.arbitrary` (caller-supplied commands) by default.
  Admins opt individual wormholes in via config; capability names in config
  are validated at startup, so typos fail loudly.
- Denied tools are not registered at all — agents can't even see them —
  but `interstellar__status` reports the omission and why.
- The check runs again on every call, and every call (allowed or denied)
  is appended to a JSONL audit log with its arguments, outcome, and timing.

The deliberate consequence: the easiest way to give an agent remote
execution is a *purpose-built* wormhole with `exec.scoped` tools, not a
generic shell.

## Code map

| Path | What | Stability |
|------|------|-----------|
| `proto/interstellar/wormhole/v1` | wire contract | pre-1.0, may still change |
| `pkg/wormhole` | Go SDK for wormhole authors | public API |
| `internal/registry` | plugin launch + manifest validation | internal |
| `internal/policy`, `internal/audit` | enforcement + log | internal |
| `internal/mcpserver` | north-side MCP bridge | internal |
| `cmd/interstellard` | the daemon | — |
| `wormholes/` | first-party wormholes | examples of the intended style |

## Deployment

Docker today (see the [Dockerfile](../Dockerfile)): the image carries the
daemon plus first-party wormholes; extra wormholes are mounted into the
wormhole directory. Snap is planned: the core as `interstellar` with
first-party wormholes as snap components
(`snap install interstellar+vpn-gateway`); since components must be built
and published with the snap itself, the wormhole directory remains the
extension point for third-party wormholes on every platform.
