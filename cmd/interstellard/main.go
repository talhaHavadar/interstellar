// Command interstellard is the interstellar gateway daemon: it loads
// wormhole plugins and serves their tools to AI agents over MCP.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/talhaHavadar/interstellar/internal/audit"
	"github.com/talhaHavadar/interstellar/internal/config"
	"github.com/talhaHavadar/interstellar/internal/mcpserver"
	"github.com/talhaHavadar/interstellar/internal/policy"
	"github.com/talhaHavadar/interstellar/internal/registry"
)

// version is stamped by the build (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "interstellard:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath  = flag.String("config", "", "path to YAML config file")
		listen      = flag.String("listen", "", "HTTP listen address for the MCP endpoint (overrides config)")
		stdio       = flag.Bool("stdio", false, "serve MCP over stdio instead of HTTP (for local agents)")
		wormholeDir = flag.String("wormhole-dir", "", "directory of wormhole plugin executables (overrides config)")
		auditPath   = flag.String("audit-log", "", "path of the JSONL audit log (overrides config)")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return nil
	}

	// In stdio mode stdout carries the MCP stream, so all logging goes to
	// stderr (slog's default) in both modes.
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if *wormholeDir != "" {
		cfg.WormholeDir = *wormholeDir
	}
	if *auditPath != "" {
		cfg.AuditLog = *auditPath
	}

	pol, err := policy.New(cfg.Policy)
	if err != nil {
		return err
	}

	aud, err := audit.Open(cfg.AuditLog)
	if err != nil {
		return err
	}
	defer aud.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	reg := registry.New(logger)
	defer reg.Close()
	if cfg.WormholeDir != "" {
		if err := reg.LoadDir(ctx, cfg.WormholeDir); err != nil {
			return err
		}
	} else {
		logger.Warn("no wormhole directory configured; only built-in tools are available")
	}

	server := mcpserver.New(version, reg, pol, aud, logger)

	if *stdio {
		logger.Info("serving MCP over stdio", "version", version)
		return server.Run(ctx, &mcp.StdioTransport{})
	}

	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	httpServer := &http.Server{Addr: cfg.Listen, Handler: handler}

	errc := make(chan error, 1)
	go func() {
		logger.Info("serving MCP over HTTP", "addr", cfg.Listen, "version", version)
		errc <- httpServer.ListenAndServe()
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return nil
	}
}
