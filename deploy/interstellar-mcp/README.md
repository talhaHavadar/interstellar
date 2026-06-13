# Deploy interstellar with Docker Compose

A self-hosted gateway in three steps.

```sh
cp .env.example .env     # fill in secrets you need (optional to start)
$EDITOR config.yaml      # define your targets
docker compose up -d
```

The MCP endpoint is then at `http://127.0.0.1:8420`. Point an agent at it:

```sh
claude mcp add --transport http interstellar http://127.0.0.1:8420
```

Ask it to call `interstellar__status` to see what's loaded, or `echo__say` for a
no-config liveness check.

## What's in here

| File                 | Purpose                                                |
| -------------------- | ------------------------------------------------------ |
| `docker-compose.yml` | the service definition                                 |
| `config.yaml`        | your targets + policy (no secrets) — mounted read-only |
| `.env.example`       | template for secrets; copy to `.env` (gitignored)      |

## Security

- **The HTTP endpoint has no authentication.** The compose file binds it to
  `127.0.0.1` so only this host can reach it. To use it from another machine,
  put it behind an SSH tunnel, a Tailscale ACL, or a reverse proxy that adds
  auth — do **not** change the bind to `0.0.0.0` on an untrusted network.
- **Secrets go in `.env`, never in `config.yaml`.** Reference them from targets
  with `password_env:` / `authkey_env:`. `config.yaml` is mounted read-only.
- The container runs as a non-root user with `no-new-privileges`.

## Image

`docker-compose.yml` pulls `ghcr.io/talhahavadar/interstellar:latest` (published
by CI). To run from a local checkout instead, comment out `image:` and uncomment
the `build:` block.

## Updating

```sh
docker compose pull && docker compose up -d
```

One caveat: the `interstellar-data` volume is seeded with the **built-in
wormholes** on first run, and an existing volume is not re-seeded on upgrade. If
a new image ships updated built-in wormholes, recreate the volume to pick them
up — note this also clears the persisted audit log, so back it up first if you
need the history:

```sh
docker run --rm -v compose_interstellar-data:/d -v "$PWD":/out busybox \
  cp /d/audit.jsonl /out/audit-backup.jsonl     # optional backup
docker compose down -v && docker compose up -d
```

## Adding more wormholes

The built-in wormholes (`echo`, `local-exec`, `ssh`, `sysinfo`, `uname`) ship in
the image. To add more — for example `tailscale` or `wireguard` from the
[wormholes repo](https://github.com/talhaHavadar/wormholes) — **uncomment its
installer service and the matching `depends_on` entry** in
`docker-compose.yml`. Each installer is a published image that copies its
wormhole binary into a shared volume and exits; the gateway loads it from a
second `--wormhole-dir`, alongside the built-ins. No building, no copying, no
architecture matching (the images are multi-arch):

```yaml
services:
  install-tailscale:
    image: ghcr.io/talhahavadar/wormhole-tailscale:latest
    volumes: [ "extra-wormholes:/out" ]
    restart: "no"

  interstellar:
    depends_on:
      install-tailscale:
        condition: service_completed_successfully
```

Then `docker compose up -d`. Confirm with `interstellar__status`. To update an
installed wormhole later: `docker compose pull && docker compose up -d`.

> Prefer a hand-built binary? You can still bind-mount a local folder of Linux
> wormhole binaries as an extra `--wormhole-dir` — but the installer images are
> the easy path.

## A note on local-exec inside the container

The `local-exec` / `sysinfo` / `uname` wormholes run commands _inside this
container_, which is a minimal distroless image with no shell or coreutils — so
a `localhost` exec target won't find `uname`/`sh`. interstellar is built to reach
**other** machines (over SSH, optionally tunnelled); point your targets there.
