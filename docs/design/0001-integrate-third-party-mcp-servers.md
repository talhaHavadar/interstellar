# 1. Integrate third-party MCP servers as backends behind purpose-built wormholes

- Status: Accepted
- Date: 2026-06-14
- Deciders: Talha Can Havadar
- Tags: composition, mcp, security, sdk

Technical Story: Allow interstellar to make the tools of an existing third-party
MCP server available to agents, while preserving interstellar's control,
capability-classification, and audit guarantees over every downstream tool call.

## Context and Problem Statement

Interstellar is, on its north side, an MCP server: it presents the loaded
wormholes' tools to an agent (`internal/mcpserver/server.go:42`). There is a
large and growing ecosystem of third-party MCP servers (GitHub, Jira, Linear,
filesystem, browser, etc.). Users want to reuse those servers' functionality
through interstellar rather than re-implementing it.

The naive approach — connect to a third-party MCP server and forward all of its
tools to the agent — directly contradicts interstellar's founding principle
(`pkg/wormhole/wormhole.go:19-22`):

> Resist the temptation to expose a generic "run any command" tool [...] agents
> only ever see purpose-built, parameterized operations.

A forwarded third-party tool surface is the tool-layer equivalent of a generic
shell: schemas interstellar did not write, capability classes nobody verified,
and a manifest that can change underneath us. Interstellar's capability model
(`proto/.../wormhole.proto:38-53`) assumes the tool author declares capabilities
honestly and the audit log sees everything; a third-party MCP author never heard
of interstellar and provides, at most, non-binding MCP annotation *hints*.

The problem: **how do we integrate existing MCP servers without importing an
unaudited, un-classified, externally-defined tool surface to the agent?**

## Decision Drivers

- Preserve "composition without coupling": agents only ever see purpose-built,
  honestly-classified, parameterized tools.
- Preserve the single-boundary capability + audit guarantee: every downstream
  tool call is policy-gated and logged with a truthful capability class.
- Reuse the existing composition machinery (typed ports, the session manager's
  warm reference-counted links, network-context routing) rather than inventing a
  parallel mechanism.
- Keep secret handling consistent with the existing model (ambient credentials in
  the gateway environment, never in agent-visible arguments).
- Keep manifests static and load-time validation intact where possible.
- Keep per-integration authoring cost reasonable; share the transport plumbing.

## Considered Options

- **Option A — Generic curated MCP proxy.** A single `mcp-proxy` wormhole reads
  an admin allowlist of upstream tools (with admin-assigned capability classes
  and optional schema overrides), introspects the upstream at `Describe` time,
  and forwards the allowlisted tools as its own manifest.
- **Option B — Purpose-built adapter wormholes over a generic transport.** Treat
  the MCP server as a *backend* (like a VPN or an exec host). A generic provider
  wormhole holds the upstream MCP session and offers it as a new typed port
  (`mcp-endpoint`); purpose-built consumer wormholes — authored per integration —
  require that port and expose hand-written, honestly-classified tools that
  fulfill themselves by calling specific upstream tools internally.
- **Option C — Do nothing.** Users connect their agent to third-party MCP
  servers directly, outside interstellar.

## Decision Outcome

Chosen option: **Option B**, because it is the only option that preserves
interstellar's distinguishing guarantees (purpose-built surface, honest
capabilities, single-boundary audit) while still reusing — not duplicating — the
existing composition model. It is the direct structural analogue of the
exec-endpoint pattern (`local-exec`/`ssh` provide it; `sysinfo`/`uname` consume
it) and the network-context pattern (`tailscale`/`wireguard` are interchangeable
backends behind one typed contract).

Option A is retained as a deliberately-gated escape hatch (see "Generic proxy as
an opt-in escape hatch"), not as the primary path. Option C is rejected because
it forgoes the policy/audit control that is interstellar's value proposition.

### Architecture

Split the concern into a generic transport provider and a purpose-built semantic
consumer, connected by a new typed port.

```
  Provider (generic, reusable)            Consumer (purpose-built, authored per integration)
  ┌───────────────────────────┐          ┌──────────────────────────────────┐
  │ mcp-stdio / mcp-http       │ mcp-     │ github-issues (example)          │
  │  - spawns or connects the  │ endpoint │  - Require mcp-endpoint           │
  │    upstream MCP server     │ ───────▶ │  - Tools YOU define + classify    │
  │  - performs `initialize`   │  (port   │  - Each handler calls one or more │
  │  - holds the session       │   type)  │    upstream tools/call internally │
  │  - Provide mcp-endpoint     │         │  - Upstream is invisible to agent │
  │  - (optionally Require       │         └──────────────────────────────────┘
  │     network-context)         │
  └───────────────────────────┘
```

Components:

1. **New port type `mcp-endpoint`** in the SDK (`pkg/wormhole/port.go`), with a
   descriptor carrying the address of a local proxy the consumer dials (mirrors
   `ExecEndpointDescriptor`). The proxy speaks a normalized, minimal tool API
   (`list_tools`, `call_tool`) over gRPC/unix socket — interstellar's own narrow
   contract, not raw MCP, so consumers never depend on MCP wire details.

2. **Generic transport provider wormholes**, one per MCP transport:
   - `mcp-stdio` — spawns an upstream MCP server subprocess and speaks MCP over
     stdio. Admin config supplies the command, args, and (via ambient env) any
     upstream credentials.
   - `mcp-http` — connects to a remote streamable-HTTP / SSE MCP server. May
     `Require` a `network-context` (optional) so a remote MCP server behind a VPN
     is reached through `tailscale`/`wireguard` with no new mechanism.
   Each provider performs the MCP `initialize` handshake, owns the session for
   the link's lifetime, and exposes the normalized proxy on the descriptor.

3. **A shared SDK client helper** (`wormhole.DialMCPEndpoint`, analogue of
   `DialExecEndpoint`) so a consumer fulfills a tool with a few lines:
   `tools, _ := client.ListTools(ctx)` / `res, _ := client.CallTool(ctx, name, args)`.

4. **Purpose-built consumer wormholes**, authored per integration. They `Require`
   `mcp-endpoint`, declare their *own* tools with honest capability classes and
   their own input schemas, and in each handler call one or more specific
   upstream tools to fulfill the operation. The agent sees only these tools.

### How the drivers are satisfied

- **Purpose-built surface / honest capabilities:** the consumer author writes and
  classifies every agent-facing tool; nothing is forwarded blindly.
- **Single-boundary audit:** unchanged — the agent calls a normal consumer tool,
  which is policy-checked and audited exactly as today
  (`internal/mcpserver/server.go:216-244`). The upstream MCP calls happen inside
  the wormhole, below the agent boundary.
- **Reuse of composition machinery:** the upstream session is a normal link, so
  it is brought up, reference-counted, kept warm, and idle-torn-down by the
  session manager (`internal/session/session.go`) — important because MCP servers
  can be expensive to start (subprocess + `initialize`).
- **Composition:** `mcp-http` requiring `network-context` reuses the exact VPN
  routing `ssh` already uses (`wormholes/ssh/main.go`).
- **Secrets:** the upstream server's credentials are provided as ambient
  environment to the provider wormhole process (inherited from interstellard via
  `internal/registry/registry.go:74`), never as agent arguments — consistent with
  the existing secret-handling model.
- **Static manifest preserved:** consumer manifests are hand-written and static;
  no network I/O at `Describe`.

## Consequences

### Positive

- The agent-facing tool surface stays purpose-built, curated, and honestly
  classified — interstellar's identity is preserved.
- Interstellar effectively becomes a policy-enforcing, auditing **MCP-to-MCP
  gateway**: every downstream call is capability-classed, gated, and logged.
- Backends are interchangeable: a `github-issues` consumer can later be backed by
  the GitHub REST API instead of the GitHub MCP server with no agent-visible
  change.
- One transport provider per protocol is reused across all integrations; only the
  thin semantic consumer is authored per integration.

### Negative

- Authoring cost per integration: each new integration needs a hand-written
  consumer wormhole. (Mitigated by the shared transport providers + SDK helper.)
- New port type and a normalized tool-proxy contract to design, version, and
  maintain in the SDK.
- The transport providers introduce load-time/connection failure modes (spawning
  or reaching an upstream server) that pure consumers do not have today.

### Neutral / deferred

- Richer MCP semantics — server→client `sampling` and `elicitation` requests,
  resources, prompts, notifications — are **out of scope for v1**. The normalized
  proxy supports `list_tools` + `call_tool` only; sampling/elicitation are refused
  to avoid confused-deputy hazards.

## Pros and Cons of the Options

### Option A — Generic curated MCP proxy

- Good: drop-in; integrate any MCP server with config alone.
- Good: still gains the policy engine + audit log over the allowlisted subset.
- Bad: capability classes are admin-assigned over tools nobody wrote; MCP
  `readOnlyHint`/`destructiveHint` are non-binding hints — the honesty guarantee
  is weakened.
- Bad: dynamic manifest — `Describe` must do network I/O / spawn a subprocess;
  the upstream tool list can drift; load-time validation is reduced.
- Bad: malicious upstream tool descriptions can attempt to steer the agent
  (prompt-injection / confused deputy) with no curation in the way.

### Option B — Purpose-built adapter over a generic transport (chosen)

- Good: faithful to the philosophy; honest capabilities; static consumer
  manifests; interchangeable backends; reuses the composition machinery.
- Good: full composition (upstream MCP server behind a VPN) for free.
- Bad: per-integration authoring effort.
- Bad: more SDK surface (new port type + normalized proxy contract).

### Option C — Do nothing (agent connects directly)

- Good: zero work.
- Bad: forgoes policy, capability classification, and audit — interstellar's
  entire value proposition for this use case.

## Generic proxy as an opt-in escape hatch

For *trusted, internal* MCP servers where onboarding speed outweighs purity,
Option A may still be offered — but gated like `exec.arbitrary` is today
(`internal/policy/policy.go:39-40`): introduce a deny-by-default capability class
(e.g. `proxy.mcp`) that an admin must explicitly allow per wormhole. This makes
importing an externally-defined surface a conscious decision and keeps every
proxied call audited. It is explicitly *not* the headline path.

## Security Considerations

- **Capability honesty** is the core risk and the reason Option B is chosen:
  capabilities must be *authored*, not inferred from upstream.
- **Sampling / elicitation** (server→client requests) are refused in v1.
- **Prompt injection** via upstream tool metadata is bounded by curation in
  Option B; unbounded in Option A (hence the gate).
- **Secrets** for the upstream server follow the ambient-environment pattern and
  never traverse the agent/argument/audit channel.

## Implementation Notes (next steps, not yet decided in detail)

1. SDK: define `PortTypeMCPEndpoint` + descriptor in `pkg/wormhole/port.go`;
   design the normalized tool-proxy gRPC contract (`list_tools`, `call_tool`);
   add `ServeMCPEndpoint` (provider side) and `DialMCPEndpoint` (consumer side)
   helpers, mirroring the exec-endpoint helpers.
2. Provider: implement `mcp-stdio` first (simplest; subprocess + stdio). Decide on
   an MCP client library vs. a minimal hand-rolled client.
3. Consumer: build one reference integration (candidate: a small, well-known MCP
   server) end-to-end to validate the contract before generalizing.
4. `mcp-http` provider with optional `network-context` as a follow-up.
5. Revisit whether the normalized proxy should pass through structured content
   types beyond text.

## Open Questions

- Which MCP client library (if any) to depend on, given each wormhole is an
  isolated Go module.
- Exact shape of the normalized tool-proxy contract and how it represents MCP
  content blocks and errors.
- Whether `mcp-endpoint` should be one link per upstream server, or one link per
  (server, tool-subset) for finer policy scoping.

## Links

- Relates to: `docs/design/wormhole-tool-composition.md` (wormhole-to-wormhole
  tool calls — a different, rejected-for-now mechanism; this ADR keeps all
  cross-server calls *inside* a wormhole, below the agent boundary).
- ADR format: https://adr.github.io/
