# syntax=docker/dockerfile:1
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=${VERSION}" -o /out/interstellard ./cmd/interstellard
RUN for w in echo local-exec ssh sysinfo uname vpn-wireguard tailscale; do \
      CGO_ENABLED=0 go build -o /out/wormholes/$w ./wormholes/$w; \
    done

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/interstellard /usr/bin/interstellard
# First-party wormholes ship in the image; mount extra ones over this
# directory (or alongside) to extend the gateway.
COPY --from=build /out/wormholes /var/lib/interstellar/wormholes
VOLUME /var/lib/interstellar
EXPOSE 8420
ENTRYPOINT ["/usr/bin/interstellard"]
CMD ["--listen", "0.0.0.0:8420", \
     "--wormhole-dir", "/var/lib/interstellar/wormholes", \
     "--audit-log", "/var/lib/interstellar/audit.jsonl"]
