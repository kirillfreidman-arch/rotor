// Package admin serves operational endpoints: Prometheus metrics and a
// liveness check. It is separate from the proxy port so customers never
// reach it.
package admin

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/kirillfreidman/rotor/internal/pool"
	"github.com/kirillfreidman/rotor/internal/proxy"
	"github.com/kirillfreidman/rotor/internal/tenant"
)

// Handler returns the admin HTTP handler.
func Handler(srv *proxy.Server, tenants *tenant.Registry, p *pool.Pool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.Write([]byte(render(srv, tenants, p)))
	})
	return mux
}

// render writes the Prometheus text exposition format by hand. It is a
// simple line format, and writing it directly keeps the project free of
// dependencies:
//
//	# TYPE name counter
//	name{label="value"} 123
func render(srv *proxy.Server, tenants *tenant.Registry, p *pool.Pool) string {
	var b strings.Builder
	metric := func(name, typ, help string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}

	metric("rotor_client_connections", "gauge", "Client connections open now.")
	fmt.Fprintf(&b, "rotor_client_connections %d\n", srv.Active.Load())
	metric("rotor_client_connections_total", "counter", "Client connections accepted.")
	fmt.Fprintf(&b, "rotor_client_connections_total %d\n", srv.Total.Load())
	metric("rotor_sticky_sessions", "gauge", "Sticky sessions held.")
	fmt.Fprintf(&b, "rotor_sticky_sessions %d\n", p.Sessions())

	all := tenants.All()
	metric("rotor_user_bytes_total", "counter", "Metered bytes per user and direction.")
	for _, t := range all {
		fmt.Fprintf(&b, "rotor_user_bytes_total{user=%q,direction=\"up\"} %d\n", t.Name, t.BytesUp.Load())
		fmt.Fprintf(&b, "rotor_user_bytes_total{user=%q,direction=\"down\"} %d\n", t.Name, t.BytesDown.Load())
	}
	metric("rotor_user_connections", "gauge", "Open connections per user.")
	for _, t := range all {
		fmt.Fprintf(&b, "rotor_user_connections{user=%q} %d\n", t.Name, t.Active())
	}
	metric("rotor_user_requests_total", "counter", "Accepted connections/requests per user.")
	for _, t := range all {
		fmt.Fprintf(&b, "rotor_user_requests_total{user=%q} %d\n", t.Name, t.Conns.Load())
	}
	metric("rotor_user_rejected_total", "counter", "Connections refused by the per-user limit.")
	for _, t := range all {
		fmt.Fprintf(&b, "rotor_user_rejected_total{user=%q} %d\n", t.Name, t.Rejected.Load())
	}

	exits := p.Exits()
	label := func(e *pool.Exit) string {
		return fmt.Sprintf("ip=%q,country=%q", e.IP.String(), e.Country)
	}
	metric("rotor_exit_healthy", "gauge", "1 if the exit passes health checks.")
	for _, e := range exits {
		v := 0
		if e.Healthy() {
			v = 1
		}
		fmt.Fprintf(&b, "rotor_exit_healthy{%s} %d\n", label(e), v)
	}
	metric("rotor_exit_score", "gauge", "Exit quality score (EWMA of dial success, 0-1).")
	for _, e := range exits {
		fmt.Fprintf(&b, "rotor_exit_score{%s} %.3f\n", label(e), e.Score())
	}
	metric("rotor_exit_connections", "gauge", "Upstream connections open per exit.")
	for _, e := range exits {
		fmt.Fprintf(&b, "rotor_exit_connections{%s} %d\n", label(e), e.Active.Load())
	}
	metric("rotor_exit_connections_total", "counter", "Upstream connections opened per exit.")
	for _, e := range exits {
		fmt.Fprintf(&b, "rotor_exit_connections_total{%s} %d\n", label(e), e.Total.Load())
	}
	return b.String()
}
