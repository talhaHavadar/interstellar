// Package registry discovers, launches, and supervises wormhole plugin
// processes, and validates their manifests before admitting them.
package registry

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"

	wormholev1 "github.com/talhaHavadar/interstellar/gen/wormhole/v1"
	"github.com/talhaHavadar/interstellar/pkg/wormhole"
)

const describeTimeout = 15 * time.Second

// Wormhole is a loaded, validated, running wormhole plugin.
type Wormhole struct {
	Manifest *wormholev1.Manifest
	Client   wormholev1.WormholeServiceClient
	// Path of the plugin binary, for diagnostics.
	Path string

	kill func()
}

// Registry holds the loaded wormholes.
type Registry struct {
	logger *slog.Logger

	mu        sync.Mutex
	wormholes map[string]*Wormhole
}

func New(logger *slog.Logger) *Registry {
	return &Registry{logger: logger, wormholes: map[string]*Wormhole{}}
}

// LoadDir loads every executable in dir as a wormhole. A plugin that fails
// to load or validate is skipped with a logged error; one bad wormhole must
// not keep the gateway down.
func (r *Registry) LoadDir(ctx context.Context, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("reading wormhole directory: %w", err)
	}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		info, err := e.Info()
		if err != nil || e.IsDir() || info.Mode()&0o111 == 0 {
			continue
		}
		if _, err := r.Load(ctx, path); err != nil {
			r.logger.Error("skipping wormhole", "path", path, "error", err)
		}
	}
	return nil
}

// Load launches the plugin binary at path, fetches and validates its
// manifest, and admits it to the registry.
func (r *Registry) Load(ctx context.Context, path string) (*Wormhole, error) {
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig:  wormhole.Handshake,
		Plugins:          map[string]plugin.Plugin{wormhole.PluginName: &wormhole.GRPCPlugin{}},
		Cmd:              exec.Command(path),
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		Logger: hclog.New(&hclog.LoggerOptions{
			Name:   "wormhole",
			Output: os.Stderr,
			Level:  hclog.Warn,
		}),
	})

	rpcClient, err := client.Client()
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf("starting plugin: %w", err)
	}
	raw, err := rpcClient.Dispense(wormhole.PluginName)
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf("dispensing plugin: %w", err)
	}
	svc, ok := raw.(wormholev1.WormholeServiceClient)
	if !ok {
		client.Kill()
		return nil, fmt.Errorf("plugin is not a wormhole (got %T)", raw)
	}

	dctx, cancel := context.WithTimeout(ctx, describeTimeout)
	defer cancel()
	resp, err := svc.Describe(dctx, &wormholev1.DescribeRequest{})
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf("describe: %w", err)
	}
	manifest := resp.GetManifest()
	if err := ValidateManifest(manifest); err != nil {
		client.Kill()
		return nil, fmt.Errorf("invalid manifest: %w", err)
	}

	w := &Wormhole{Manifest: manifest, Client: svc, Path: path, kill: client.Kill}

	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, dup := r.wormholes[manifest.Name]; dup {
		client.Kill()
		return nil, fmt.Errorf("name %q already loaded from %s", manifest.Name, existing.Path)
	}
	r.wormholes[manifest.Name] = w
	r.logger.Info("wormhole loaded",
		"name", manifest.Name, "version", manifest.Version,
		"tools", len(manifest.Tools), "path", path)
	return w, nil
}

// All returns the loaded wormholes, sorted by name.
func (r *Registry) All() []*Wormhole {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*Wormhole, 0, len(r.wormholes))
	for _, w := range r.wormholes {
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Manifest.Name < out[j].Manifest.Name })
	return out
}

// Get returns the named wormhole.
func (r *Registry) Get(name string) (*Wormhole, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	w, ok := r.wormholes[name]
	return w, ok
}

// Close terminates all plugin processes.
func (r *Registry) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, w := range r.wormholes {
		w.kill()
		delete(r.wormholes, name)
	}
}
