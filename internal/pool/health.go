package pool

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// RunHealthChecks probes every exit by opening a TCP connection from it to
// target, once per interval, until ctx is cancelled.
//
// A TCP handshake is a cheap, protocol-neutral check: it proves the source
// IP is routable and not null-routed or firewalled. It does not prove the IP
// has a clean reputation with any particular website; see docs/DESIGN.md.
func (p *Pool) RunHealthChecks(ctx context.Context, target string, interval, timeout time.Duration, log *slog.Logger) {
	if target == "" {
		log.Info("active health checks disabled (no health.target)")
		return
	}
	check := func() {
		var wg sync.WaitGroup
		for _, e := range p.exits {
			wg.Add(1)
			go func(e *Exit) { // check all exits in parallel
				defer wg.Done()
				cctx, cancel := context.WithTimeout(ctx, timeout)
				defer cancel()
				// Use the raw dialer, not e.Dial: health probes should
				// not count as customer traffic or move the score.
				c, err := e.dialer.DialContext(cctx, e.network, target)
				if err == nil {
					c.Close()
				}
				if e.checkResult(err == nil) {
					if err == nil {
						log.Info("exit recovered", "ip", e.IP.String())
					} else {
						log.Warn("exit marked unhealthy", "ip", e.IP.String(), "err", err)
					}
				}
			}(e)
		}
		wg.Wait()
	}

	check() // run once immediately so a bad IP is caught at startup
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			check()
		}
	}
}
