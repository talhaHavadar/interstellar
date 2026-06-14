---
title: "Introducing Interstellar — A Gateway to Tame Your AI Agents"
description: "Giving your agents access into your infrastructure, without handing them a raw shell — and without them skipping the steps that matter."
author: "Talha Can Havadar"
date: "2026-06-14"
tags: [ai, agents, mcp, infrastructure, security]
published_on:
  - <URL>
---

# Introducing Interstellar — A Gateway to Tame Your AI Agents

_Giving your agents access into your infrastructure, without handing them a raw shell._

## The feeling of unsafe

There's a moment, the first time you wire an AI agent up to something real, where you pause and think. The agent is genuinely helpful — it writes the command, reasons about the output, fixes its own mistakes. Then it asks to run something on your build server, and you realize the tool you gave it is basically `ssh` with an LLM attached.

MCP made connecting agents to tools easy. Maybe a little _too_ easy. The path of the least resistance is a generic `run_command` tool: hand the agent a shell and let it figure the things out. It works. But it's also terrifying. That tool, runs with your privileges, on your network, with your credentials, and the only thing between a confused tool-call and a wiped directory is the model's good judgment.

I wanted my agents to have a real reach, build a package on a machine behind a VPN, check a server's health without handing them a raw shell. So I built the **Interstellar**.

## A different approach

There are other MCP gateways out there, and they're good at what they do: aggregating MCP servers, running them in containers, managing secrets, proxying to clients. Interstellar makes a different bet about what a gateway _for agents_ should be:

**Agents should get purpose-built, typed operations, not generic power.**

Instead of one server with a fixed toolbox, Interstellar's functionality comes from **wormholes**: small, single-purpose plugins. A wormhole doesn't expose "run any command." It exposes `build_source_package(url)` or `get_system_info()`. The operations are narrow on purpose — and the system actively resists genericness. A tool that takes a caller-supplied command has to declare itself `exec.arbitrary`, and that capability is **denied by default**. You can have it; you just have to walk up to the gate and unlock it deliberately.

But that sounds restrictive (I hear you!). Two things turn it from bearable into better: the execution you get becomes trustworthy, and the reach you get becomes composable. Let's start with trust.

## Reasoning is non-deterministic. Execution shouldn't be.

Here's a different kind of trust problem — the one that actually wears you down.

I run a fairly involved agentic workflow: skills, a knowledge base I built up over time. I lean on it for real tasks. One of them is a code review with a solid checklist, where some steps are marked **MANDATORY**. Most of the time it works beautifully. But every so often the agent just… skips the mandatory step. Not because it failed — because, on that run, it decided it didn't need to. I ask about it, it apologizes, runs it again. And now I'm reviewing the reviewer.

That's the nature of agents: they're non-deterministic by design. For _reasoning_ — deciding what to do, chaining thoughts, making sense of messy output — that's exactly what you want. For _execution_, it's a liability. "MANDATORY" in a prompt is a strong suggestion, not a guarantee; the model is always free to reinterpret it.

Wormholes draw the line in the right place. The _procedure_ lives inside the wormhole, as code — every step, every time, in the same order. The agent still decides _when_ to run it and _what_ to run it against, and it interprets the result. But it can't skip step three of your review, because step three isn't an instruction it's choosing to execute, it's a line of code in a tool it called.

So you keep the part agents are genuinely good at — the judgment, the orchestration — and you make the part you need to trust _deterministic_. The non-determinism moves up to where it belongs, and the execution stops drifting. And since every call is audited, you don't just hope the procedure ran the way it should — you can see that it did.

## Composition, or: how the agent reaches the unreachable

Now, about that reach/access. Here's the scenario that shaped the whole design: I want an agent to build a Debian package on a machine that sits behind a VPN.

The naive version, hands the agent, SSH credentials, a VPN config, and a shell, and hopes. The Interstellar version: the agent asks to build on a _target_ called `build-box`, and that's all it ever sees.

Behind the scenes, wormholes connect to **each other** through typed ports the agent never touches:

- a `deb-builder` wormhole needs somewhere to run commands (an `exec-endpoint`)
- an `ssh` wormhole _provides_ an exec-endpoint, and optionally needs a network path (a `network-context`)
- a `wireguard` or `tailscale` wormhole _provides_ that network path

The gateway resolves the chain — bring up the VPN, open SSH _through_ it, hand the builder a place to run — and the agent just picks a target from a menu. It never sees the SSH key. It never sees the VPN. The builder doesn't know a VPN exists; the VPN doesn't know what runs through it.

And this isn't hand-waving — it's a few lines of config. Here's an actual target from my own gateway: an SSH box reached _through_ a Tailscale network, with the credentials and routing entirely on my side:

```yaml
targets:
  tailnet:
    wormhole: tailscale
    port: tailnet
    config:
      hostname: interstellar-gw
      authkey_env: TS_AUTHKEY
  gfx1201:
    wormhole: ssh
    port: target
    idle_timeout: 5m
    # via is a TARGET-level field (same indent as wormhole/port/config) — route
    # the SSH connection through the tailnet network-context.
    via:
      net: tailnet
    config:
      host: gfx1201
      user: talha
      # Password is read from $INTERSTELLAR_REMOTE_PASSWORD, not stored here.
      password_env: GFX1201_SSH_PASSWORD
      insecure_skip_host_key_check: true # deliberate opt-out
policy:
  deny_capabilities: [exec.arbitrary]
  wormholes: {}
```

The agent picks `gfx1201`. The gateway brings up the tailnet, dials SSH through it, and runs the operation. **Targets are configuration I own; the agent chooses from a menu I wrote** — it never holds a secret or names an arbitrary host.

This is the part I think is genuinely different. Most gateways _aggregate_ tools. Interstellar _composes_ them. Add a new way to reach a machine — a bastion, a different tunnel — and it lights up for every wormhole that needs to reach machines, at once, with no code changes.

## The control

Because the whole point is _taming_, the gateway is opinionated about control:

- **Policy.** Every tool declares what class of thing it does — `read`, `write`, `network`, `exec.scoped`, `exec.arbitrary` — and the gateway enforces it. A typo in your policy fails at startup, not silently.
- **Audit.** Every call, allowed or denied, is logged with the resolved chain it ran through. You can answer "what did the agent actually do?"
- **Isolation.** Wormholes are separate processes (gRPC plugins), so a misbehaving one can't take the gateway down and can be sandboxed on its own.

## Ease of use

Philosophy is cheap. Here's the thing working. Interstellar ships as a container image, and the whole deployment is a `docker compose up`:

```shell
cd deploy/interstellar-mcp
cp .env.example .env     # secrets, if you need any
$EDITOR config.yaml      # define your targets
docker compose up -d
```

```shell
$ docker compose up -d
[+] up 3/3
 ✔ Network interstellar-mcp_default               Created                                                                                                                    0.0s
 ✔ Container interstellar-mcp-install-tailscale-1 Exited                                                                                                                     0.7s
 ✔ Container interstellar-mcp-interstellar-1      Started                                                                                                                    0.7s

What's next:
    Filter, search, and stream logs from all your Compose services
    in one place with Docker Desktop's Logs view. docker-desktop://dashboard/logs?appId=interstellar-mcp
```

Point your agent at it and ask what's there:

```shell
claude mcp add --transport http interstellar http://127.0.0.1:8420
```

```
❯ hey get the status of interstellar

⏺ I'll load the interstellar status tool and check it.

  Called interstellar (ctrl+o to expand)

⏺ Here's the status of the interstellar gateway (version main):

  Wormholes (6 loaded)

  ┌────────────┬─────────┬──────────────────────────┬──────────────────────────────────────────────────────────┐
  │  Wormhole  │ Version │      Exposed Tools       │                           Role                           │
  ├────────────┼─────────┼──────────────────────────┼──────────────────────────────────────────────────────────┤
  │ echo       │ 0.1.0   │ echo__say                │ Round-trip proof — echoes input back                     │
  ├────────────┼─────────┼──────────────────────────┼──────────────────────────────────────────────────────────┤
  │ sysinfo    │ 0.1.0   │ sysinfo__get_system_info │ Reports system info (needs a shell)                      │
  ├────────────┼─────────┼──────────────────────────┼──────────────────────────────────────────────────────────┤
  │ uname      │ 0.1.0   │ uname__uname             │ Reports uname -a (needs a shell)                         │
  ├────────────┼─────────┼──────────────────────────┼──────────────────────────────────────────────────────────┤
  │ local-exec │ 0.1.0   │ —                        │ Provides host exec-endpoint (runs on gateway host)       │
  ├────────────┼─────────┼──────────────────────────┼──────────────────────────────────────────────────────────┤
  │ ssh        │ 0.1.0   │ —                        │ Provides target exec-endpoint over SSH (optional tunnel) │
  ├────────────┼─────────┼──────────────────────────┼──────────────────────────────────────────────────────────┤
  │ tailscale  │ 0.1.0   │ —                        │ Provides tailnet network-context (userspace tsnet)       │
  └────────────┴─────────┴──────────────────────────┴──────────────────────────────────────────────────────────┘

  Targets (2 configured)

  ┌─────────┬───────────┬─────────────────┬─────────┬─────────────┐
  │ Target  │ Wormhole  │      Type       │   Via   │    Live     │
  ├─────────┼───────────┼─────────────────┼─────────┼─────────────┤
  │ tailnet │ tailscale │ network-context │ —       │ ❌ not live │
  ├─────────┼───────────┼─────────────────┼─────────┼─────────────┤
  │ gfx1201 │ ssh       │ exec-endpoint   │ tailnet │ ❌ not live │
  └─────────┴───────────┴─────────────────┴─────────┴─────────────┘

  Summary

  - 3 tools currently exposed: echo__say, sysinfo__get_system_info, uname__uname.
  - sysinfo and uname both require an exec-endpoint (shell) to actually reach a machine — they're routable to host (local-exec) or gfx1201 (ssh).
  - The gfx1201 SSH target routes through the tailnet network-context, but both are currently not live (live: false) — so the Tailscale connection and the SSH hop aren't
  established yet.

  Everything is loaded and healthy, but the remote path (tailnet → gfx1201) hasn't been activated. Want me to bring it up or run one of the exposed tools against a target?
```

Now say you want your agents to reach machines on your Tailscale network (the `tailnet` target from the config above). You don't cross-compile anything or copy binaries around — wormholes ship as their own images. You add one installer service and tell the gateway to wait for it[^compose]:

```yaml
services:
  install-tailscale: # one-shot: drops the binary in, then exits
    image: ghcr.io/talhahavadar/wormhole-tailscale:latest
    volumes: ["extra-wormholes:/out"]
    restart: "no"

  interstellar:
    image: ghcr.io/talhahavadar/interstellar:latest
    depends_on:
      install-tailscale: { condition: service_completed_successfully }
    command:
      - --wormhole-dir=/var/lib/interstellar/wormholes # built-ins
      - --wormhole-dir=/opt/interstellar/wormholes # installed extras
      # ...
    volumes:
      - ./config.yaml:/etc/interstellar/config.yaml:ro
      - extra-wormholes:/opt/interstellar/wormholes:ro
```

`docker compose up -d` again. The installer container drops the tailscale wormhole into a shared volume, the gateway picks it up, and now `gfx1201` is reachable. Ask the agent for the health of a box that only exists on your private network:

```
❯ get sysinfo of gfx1201

  Called interstellar (ctrl+o to expand)

⏺ System info for gfx1201 (routed via the tailnet → ssh path, which brought the target live):

  ┌──────────┬─────────────────────────────────────────────────────┐
  │  Field   │                        Value                        │
  ├──────────┼─────────────────────────────────────────────────────┤
  │ Hostname │ gfx1201                                             │
  ├──────────┼─────────────────────────────────────────────────────┤
  │ Kernel   │ Linux 7.0.0-14-generic                              │
  ├──────────┼─────────────────────────────────────────────────────┤
  │ Uptime   │ 8 days, 17:30 (2 users, load avg 1.00, 1.00, 1.00)  │
  ├──────────┼─────────────────────────────────────────────────────┤
  │ Disk     │ / — 186G total, 120G used, 59G available (68% used) │
  └──────────┴─────────────────────────────────────────────────────┘

  Everything's reachable and healthy. A couple of notes worth flagging:
  - Load average is a steady 1.00 across all windows — something is keeping exactly one core busy continuously (likely a long-running job). Want me to check what's running?
  - Root filesystem at 68% — plenty of headroom (59G free) for now.
```

The agent just ran `uname`, `uptime`, and `df` on a machine it has no credentials for, reachable only through a tunnel it knows nothing about — and all it did was name a target. That's the feeling I was chasing.

## Writing your own wormhole

When the built-ins aren't enough, a wormhole is a small Go program: define a typed input, declare your capabilities, write the handler. Roughly thirty lines for something real. It builds to a single binary, and there's a one-file Dockerfile template plus a CI workflow that auto-discovers it and publishes a multi-arch (amd64 and arm64 for now) image.

The design _wants_ you to build narrow, purpose-built tools. A wormhole that wraps your exact deploy, your exact health check, your exact review checklist — and nothing else — is the whole idea. That's where the determinism comes from.

## Where it is, and where it's going

Interstellar is early, but it's end-to-end today: the MCP gateway (stdio and HTTP), the wormhole plugin system and SDK, capability policy, the audit log, and the composition engine that chains wormholes through targets. The built-ins cover local and SSH execution; `tailscale` and `wireguard` give you userspace tunnels with no root and no nested containers.

If giving your agents real reach, but on a leash you designed, resonates with you, I'd love for you to try it.

- **Interstellar:** [github.com/talhaHavadar/interstellar](https://github.com/talhaHavadar/interstellar)
- **Wormholes:** [github.com/talhaHavadar/wormholes](https://github.com/talhaHavadar/wormholes)

Agents are only going to get more capable. I'd rather meet that with a gateway than a prayer.

[^compose]: Trimmed for the post. The complete compose file, loopback binding, audit-log persistence, secrets, and every installer, is in [`deploy/interstellar-mcp/docker-compose.yml`](https://github.com/talhaHavadar/interstellar/blob/main/deploy/interstellar-mcp/docker-compose.yml).
