# interstellar

A controlled gateway between AI agents and your infrastructure.

Interstellar is an [MCP](https://modelcontextprotocol.io) server that an AI
agent connects to like any other — but instead of one fixed toolbox, its
functionality comes from **wormholes**: purpose-built plugins that each do one
job well (build a Debian package, reach a machine over SSH, bring up a VPN)
and compose with each other. The gateway sits in the middle and enforces
policy, records an audit log, and keeps the agent away from raw access.

```
AI agent ──MCP (JSON-RPC)──▶ interstellard ──gRPC──▶ wormhole plugins
                              │ policy │ audit │      (separate processes)
```

**Design stance:** wormholes expose _specific, typed operations_
(`deb-builder__build_source_package(distro, arch)`), not generic command
runners. Raw execution travels between wormholes over typed ports that agents
never see, and tools that accept caller-supplied commands are denied by
default policy until a server admin explicitly opts in.
See [docs/architecture.md](docs/architecture.md).

## Status

Early development, but the core is end-to-end. Working today: the MCP gateway
(stdio + streamable HTTP), the wormhole plugin system and Go SDK,
capability-based policy, the audit log, and **composition** — the session
manager resolves the links a tool needs, chaining wormholes through
admin-defined targets (including routing one wormhole's connection through
another via `via`). First-party wormholes: `local-exec` and `ssh` (provide
command execution), `sysinfo` (a purpose-built consumer), and `echo`. Not yet
shipped: a VPN wormhole providing `network-context`, and snap packaging with
wormholes as snap components.

## Quick start

```sh
make            # builds bin/interstellard and bin/wormholes/*
bin/interstellard --wormhole-dir bin/wormholes
```

The MCP endpoint is now at `http://127.0.0.1:8420`. Add it to an agent — for
Claude Code:

```sh
claude mcp add --transport http interstellar http://127.0.0.1:8420
```

Or run it locally over stdio, no HTTP involved:

```sh
claude mcp add interstellar -- /path/to/interstellard --stdio --wormhole-dir /path/to/wormholes
```

Ask the agent to call `interstellar__status` to see what's loaded — wormholes,
tools (including ones hidden by policy or for lack of a target, and why), and
the configured targets.

### Composition

Wormholes that need to reach a machine declare a typed port; an admin binds
that port to a **target** in config. For example, point the `sysinfo`
wormhole at the gateway host:

```yaml
# config.yaml
targets:
  localhost:
    wormhole: local-exec
    port: host
```

```sh
bin/interstellard --config config.yaml --wormhole-dir bin/wormholes
```

Now `sysinfo__get_system_info` takes a `shell_target` argument (`localhost`),
and the gateway routes the call through the `local-exec` wormhole. Swap in the
`ssh` wormhole — optionally with `via` pointing at a VPN target — and the same
tool runs on a remote machine behind a tunnel, without the tool or the agent
knowing anything about the path. See
[config.example.yaml](config.example.yaml) and
[docs/architecture.md](docs/architecture.md).

### Docker

```sh
docker build -t interstellar .
docker run -p 8420:8420 -v interstellar-data:/var/lib/interstellar interstellar
```

Add wormholes by mounting their binaries into
`/var/lib/interstellar/wormholes`.

## Configuration

Copy [config.example.yaml](config.example.yaml) and pass it with
`--config`. Flags (`--listen`, `--wormhole-dir`, `--audit-log`) override the
file. Policy lives in the config; capability names are validated at startup,
so a typo fails loudly instead of silently allowing or hiding tools.

## Writing a wormhole

A wormhole is a single Go binary built on `pkg/wormhole` — about 30 lines for
a working one. See [docs/creating-a-wormhole.md](docs/creating-a-wormhole.md),
or read [wormholes/echo](wormholes/echo/main.go), the minimal example.

## Development

```sh
make test       # unit + end-to-end (spawns real plugin processes)
make gen        # regenerate gRPC code after editing proto/
```

The wire contract lives in
[proto/interstellar/wormhole/v1](proto/interstellar/wormhole/v1/wormhole.proto);
`pkg/wormhole` is the public SDK. Everything under `internal/` is free to
change.
