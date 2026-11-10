// Command rotor is a forward proxy (HTTP, HTTPS via CONNECT, SOCKS5) that
// rotates outbound traffic across a pool of exit IP addresses.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kirillfreidman/rotor/internal/admin"
	"github.com/kirillfreidman/rotor/internal/config"
	"github.com/kirillfreidman/rotor/internal/pool"
	"github.com/kirillfreidman/rotor/internal/proxy"
	"github.com/kirillfreidman/rotor/internal/tenant"
)

func main() {
	cfgPath := flag.String("config", "config.json", "path to the JSON config file")
	logLevel := flag.String("log-level", "info", "debug, info, warn or error")
	flag.Parse()

	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(*logLevel)); err != nil {
		slog.Error("bad -log-level", "err", err)
		os.Exit(2)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}

	tenants := tenant.NewRegistry(cfg.Users)
	p := pool.New(cfg.Exits, pool.Options{
		DialTimeout:         cfg.Timeouts.Dial.Duration,
		SessionTTL:          cfg.SessionTTL.Duration,
		IdleTimeout:         cfg.Timeouts.Idle.Duration,
		AllowPrivateTargets: cfg.AllowPrivateTargets,
	})
	srv := &proxy.Server{Tenants: tenants, Pool: p, Timeouts: cfg.Timeouts, Log: log}

	// ctx is cancelled on SIGINT/SIGTERM, which starts graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go p.RunHealthChecks(ctx, cfg.Health.Target, cfg.Health.Interval.Duration, cfg.Health.Timeout.Duration, log)
	go p.RunJanitor(ctx, time.Minute)

	var adminSrv *http.Server
	if cfg.AdminListen != "" {
		adminSrv = &http.Server{
			Addr:              cfg.AdminListen,
			Handler:           admin.Handler(srv, tenants, p),
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			log.Info("admin listening", "addr", cfg.AdminListen)
			if err := adminSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("admin server", "err", err)
			}
		}()
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
	log.Info("proxy listening", "addr", ln.Addr().String(), "exits", len(cfg.Exits), "users", len(cfg.Users))

	drained := make(chan struct{})
	go func() {
		defer close(drained)
		<-ctx.Done()
		log.Info("shutting down: draining connections (up to 30s)")
		sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if adminSrv != nil {
			adminSrv.Shutdown(sctx)
		}
		if err := srv.Shutdown(sctx); err != nil {
			log.Warn("forced close of remaining connections", "err", err)
		}
	}()

	if err := srv.Serve(ln); err != nil {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
	<-drained // Serve returns as soon as the listener closes; wait for the drain
	log.Info("bye")
}
