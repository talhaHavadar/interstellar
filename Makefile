GOBIN := $(shell go env GOPATH)/bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: all build wormholes run test gen lint clean

all: build wormholes

build:
	go build -ldflags "$(LDFLAGS)" -o bin/interstellard ./cmd/interstellard

# Each first-party wormhole builds to its own binary in bin/wormholes/.
WORMHOLES := echo local-exec ssh sysinfo uname vpn-wireguard tailscale

# Run the gateway over HTTP. Override CONFIG/LISTEN as needed, e.g.
#   make run CONFIG=local.yaml LISTEN=127.0.0.1:8420
CONFIG ?= local.yaml
LISTEN ?= 127.0.0.1:8420
run: build wormholes
	./bin/interstellard --listen $(LISTEN) --config $(CONFIG) --wormhole-dir bin/wormholes
wormholes:
	@for w in $(WORMHOLES); do \
		echo "building wormhole $$w"; \
		go build -o bin/wormholes/$$w ./wormholes/$$w || exit 1; \
	done

test:
	go test ./...

# Regenerate gRPC code from proto/. Requires buf, protoc-gen-go and
# protoc-gen-go-grpc (go install github.com/bufbuild/buf/cmd/buf@latest ...).
gen:
	PATH="$(PATH):$(GOBIN)" buf lint
	PATH="$(PATH):$(GOBIN)" buf generate

lint:
	go vet ./...
	PATH="$(PATH):$(GOBIN)" buf lint

clean:
	rm -rf bin
