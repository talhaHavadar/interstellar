# syntax=docker/dockerfile:1
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=${VERSION}" -o /out/interstellard ./cmd/interstellard
# Stage the runtime state directory (wormholes live here; the audit log and any
# mounted config land here too) so it can be copied with the right owner.
RUN mkdir -p /out/state/wormholes && \
    for w in echo local-exec ssh sysinfo uname; do \
      CGO_ENABLED=0 go build -o /out/state/wormholes/$w ./wormholes/$w; \
    done

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/interstellard /usr/bin/interstellard
COPY --from=build --chown=nonroot:nonroot /out/state /var/lib/interstellar
VOLUME /var/lib/interstellar
EXPOSE 8420
ENTRYPOINT ["/usr/bin/interstellard"]
CMD ["--listen", "0.0.0.0:8420", \
     "--wormhole-dir", "/var/lib/interstellar/wormholes", \
     "--audit-log", "/var/lib/interstellar/audit.jsonl"]
