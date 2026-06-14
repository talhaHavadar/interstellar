# Wormhole-to-wormhole tool composition

Status: exploratory — not planned. This note captures the design space and a
recommendation so the decision is on record.

## Question

Today a wormhole composes with another only through **typed ports**: a provider
`Provide`s a port (an exec-endpoint, a network-context), a consumer `Require`s
it, and the session manager brokers the link. Composition is of *infrastructure*
— wormholes share a capability (an exec socket, a SOCKS dialer), never an
*operation*.

Can a wormhole instead call another wormhole's **tool**? Concretely: can
`sysinfo` reuse the `uname` wormhole to get `uname -a`, rather than running the
command itself?

The answer today is no. `sysinfo` and `uname` are both *consumers* — each
`Require`s a `shell` exec-endpoint and `Provide`s nothing
(`wormholes/sysinfo/main.go:42`, `wormholes/uname/main.go:29`). Neither exposes
anything the other can link against. They are siblings over shared
infrastructure, not a provider/consumer pair. "Make sysinfo use uname" is a
category error in the current model.

This note evaluates adding the missing primitive.

## The three shapes

"Let a wormhole call another wormhole's tool" is not one design. It forks into
three points on the cost/philosophy curve. All three need the same missing
primitive — a **reverse channel** — because a wormhole is currently a pure gRPC
*server* and the core is the *client* (`proto/.../wormhole.proto:12-33`); a
wormhole has no way to call back into the core. hashicorp/go-plugin supports
this via its `GRPCBroker` (the plugin dials a host-served service), so it is
buildable, but it inverts the plugin's role from "server" to "server **and**
client," and the core's from "client" to "client **and** server." That
inversion is the root of most of the cost below.

- **A1 — Typed operation port (contract-based).** The consumer requires an
  *operation of a typed contract* (e.g. `kernel-info@v1` → `{output: string}`),
  not the `uname` wormhole by name. The admin wires which provider satisfies it,
  exactly as targets satisfy a port type today. The consumer never learns it is
  talking to `uname`.
- **A2 — Named tool dependency.** The consumer declares
  `requires_tools: [{wormhole: "uname", tool: "uname"}]` — a direct, named edge.
  Simple and explicit, but the consumer now *knows about* `uname`.
- **B — Free-form host callback.** Every wormhole gets a generic
  `call(wormhole, tool, args)` against the core at runtime. Maximum power, no
  static structure.

## Benefits

1. **Logic reuse across trust/process boundaries.** The real prize is not
   `uname -a` (one argv). It is reusing a callee that encapsulates something a
   shared library *cannot* give you: a live stateful connection, a credential
   the caller must never see, a license-bound tool, or code in a different
   language/host. Today that can't be reused without duplication.
2. **Higher-order / orchestrator wormholes.** A `deploy` wormhole could compose
   `build` + `ssh-copy` + `restart` as first-class, tested, auditable steps with
   structured intermediate results, instead of the agent stitching three tool
   calls together in a prompt.
3. **Smaller leaf wormholes, single source of truth.** A probe lives in exactly
   one wormhole; others consume it. DRY at the operation level.
4. **A new axis of expressiveness.** Ports share *plumbing*; tool calls would
   share *outcomes*.

## Disadvantages / costs

1. **The exec-endpoint problem makes this more than "call a function."** `uname`
   itself `Require`s a `shell` exec-endpoint. So when `sysinfo` calls `uname`,
   the core must decide *which target `uname` runs against* — almost always "the
   same one `sysinfo` was given." That means **link forwarding**: the consumer
   passes its resolved links down into the dependency call. This re-implements
   the `Via` mechanism (`internal/session/session.go:213-225`) at per-call
   granularity, dynamically, instead of at config-resolution time. It roughly
   doubles the design surface — the dependency carries links, not just args.
2. **A runtime call graph you can't fully validate up front.** Link composition
   today is a config-declared DAG (`Target.Via`), acyclic by construction and
   resolved before any tool runs. Tool-call composition creates a call graph.
   With A1/A2 (declared deps) you can do load-time cycle detection; with B you
   cannot — `A→B→A` becomes a runtime recursion/exhaustion risk. You now need a
   **depth limit, a per-call-tree cycle guard, and reentrancy reasoning** that
   the strictly unidirectional core (gateway→wormhole, never back) avoids today.
3. **The capability/audit story — currently a clean strength — gets muddy.**
   Today every privileged action crosses exactly one boundary: `callHandler` →
   `pol.CheckTool` → audit record (`internal/mcpserver/server.go:216-244`). One
   call, one decision, one record. With nesting:
   - A tool's *effective* capability set becomes the union of its transitive
     callees. `sysinfo` (`exec.scoped`) calling something that calls an
     `exec.arbitrary` tool can **launder** capability unless policy evaluates the
     *initiator*, not just the callee. `policy.CheckTool` only knows
     `(wormhole, tool)` today (`internal/policy/policy.go:96`).
   - Audit needs **call lineage / trees** (`parent_call_id`), and the nested
     `CallTool` streams (logs/progress) must be multiplexed into the parent
     record. The flat audit log becomes a forest.
4. **New failure & performance modes.** Latency stacks; partial failure mid-tree;
   fan-out amplification; lease lifecycle entangles with call trees (the session
   refcount/mutex now sees re-entrant `Acquire` from within an in-flight call).
   All tractable, all new invariants.
5. **Trust-boundary erosion.** A wormhole's blast radius is currently its own
   code plus the links it was granted. Tool calls let a buggy/compromised
   wormhole reach into others' operations; you'll want a per-wormhole "may-call"
   allowlist — more policy surface.

## Effect on the philosophy

The SDK's doc comment is a manifesto (`pkg/wormhole/wormhole.go:19-22`):

> Resist the temptation to expose a generic "run any command" tool. The
> interstellar composition model exists precisely so you don't need one: raw
> execution travels through ports between wormholes, and agents only ever see
> purpose-built, parameterized operations.

And the design principle: **composition without coupling — wormholes don't know
about each other, only about well-known port types.** The current stance is
sharp: **infrastructure composes; logic stays purpose-built and local.**

- **B (free-form callback) is a quiet betrayal** — the operation-level cousin of
  the "run any command" tool the SDK forbids. Rule it out.
- **A2 (named deps) keeps the no-generic-shell principle** (calls are still to
  purpose-built tools) **but breaks "composition without coupling"** — the
  consumer names `uname`.
- **A1 (typed operation ports) is the only variant true to the philosophy.** The
  consumer requires a typed contract; the admin wires the provider; nobody knows
  about anyone. It generalizes ports from "infrastructure capabilities" to
  "typed operations."

Even A1 dilutes the *clean single-boundary capability/audit model* — arguably
interstellar's strongest security property. That cost is paid regardless of
variant.

## Design sketch (A1 — the philosophy-preserving variant)

Reverse channel — core serves a host service the wormhole dials (go-plugin
broker):

```proto
service HostService {                       // NEW — core implements, wormhole calls
  rpc CallDependency(CallDependencyRequest) returns (stream CallToolResponse);
}
message CallDependencyRequest {
  string parent_call_id      = 1;   // audit lineage + cycle/depth tracking
  string dep_name            = 2;   // consumer's local handle, e.g. "kernel"
  string arguments_json      = 3;
  repeated Link forward_links = 4;  // consumer forwards its links to satisfy callee's ports
}
```

Manifest — a tool declares typed operation deps alongside `requires_ports`:

```proto
message ToolSpec {
  // ...
  repeated ToolDependency requires_tools = 6;   // NEW
}
message ToolDependency { string name = 1; string contract = 2; } // e.g. "kernel-info@v1"
```

SDK — inject a callable, mirror of `Call.Link`:

```go
out, err := call.CallDep(ctx, "kernel", kernelArgs)   // round-trips through the core
```

Core changes:

- **session/dispatch**: on `CallDependency`, resolve `contract → provider target`
  (admin config, same shape as `targetsByType` in
  `internal/mcpserver/server.go:93-113`); forward links to satisfy the callee's
  `requires_ports`; reuse the existing dispatch in `callHandler`.
- **cycle/depth guard**: a call-stack keyed on `parent_call_id` lineage; reject
  re-entry of an in-flight callee; cap depth.
- **policy**: add `CheckCall(initiator, callee)` and decide the laundering
  question (does the initiator's denied set apply transitively?).
- **audit**: child records with `parent_call_id`; multiplex nested log/progress.
- **validation**: with declared deps, do load-time cycle detection across the
  manifest graph.
- **config**: a contract→provider wiring section.

## Complexity delta

Touched: `proto` (+1 service, +3 messages, regen) · go-plugin **bidirectional
broker** wiring (the genuinely fiddly part) · `session` (call-stack, cycle
guard, link forwarding) · `policy` (caller→callee dimension) · `audit` (call
trees) · SDK (`CallDep` + dep declaration + injected client) · config schema +
load-time validation · docs/philosophy.

Roughly several hundred to ~1k LOC plus generated code — but the LOC understates
it. The real cost is a permanent increase in the invariants you carry:
acyclicity, depth bounds, reentrancy safety, transitive capability accounting,
link-forwarding correctness, lease lifecycle under re-entrant `Acquire`. It is
comparable in conceptual weight to the *entire existing session/link subsystem*
— call it a doubling of the composition core's surface. This is a "we're
evolving interstellar into a typed service mesh" decision, not a feature.

## Recommendation

**For the specific `sysinfo`-uses-`uname` case: do not build this. It is
over-engineering.** The "logic" being reused is one argv (`{"uname","-a"}`). The
cheaper answers fully cover it:

1. **Shared Go library** (e.g. `pkg/probes`) both wormholes import — DRY with
   zero architectural change. This is the idiomatic fix and what the current
   philosophy implies.
2. **Status quo** — both are sibling consumers of the same exec-endpoint;
   `sysinfo` already runs `uname -n`/`-sr` itself
   (`wormholes/sysinfo/main.go:75-76`).
3. **Compose at the agent layer** — the agent calls both tools and merges.
   Keeps the gateway unidirectional.

**Option 2 earns its complexity only when the callee encapsulates something a
library can't share:** live stateful sessions, a credential the caller must not
see, a license/host/trust boundary, or a different runtime. None of those hold
for `uname`. The day a wormhole becomes a *stateful privileged service* that
others must reuse **without** absorbing its internals or its secrets is when A1
(typed operation ports) becomes worth the spend — and A1 is the only variant to
allow through the door, because it is the only one that does not quietly sell
off the project's "composition without coupling" identity.
