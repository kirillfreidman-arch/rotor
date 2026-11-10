// Package proxy is the data plane: it accepts client connections, speaks
// HTTP or SOCKS5 to them, and moves bytes to and from the target.
package proxy

import (
	"bufio"
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kirillfreidman/rotor/internal/config"
	"github.com/kirillfreidman/rotor/internal/pool"
	"github.com/kirillfreidman/rotor/internal/tenant"
)

// Server is the proxy listener. Fill the exported fields, then call Serve.
type Server struct {
	Tenants  *tenant.Registry
	Pool     *pool.Pool
	Timeouts config.Timeouts
	Log      *slog.Logger

	Active atomic.Int64  // client connections open now
	Total  atomic.Uint64 // client connections ever accepted

	mu      sync.Mutex
	ln      net.Listener
	conns   map[net.Conn]struct{}
	closing atomic.Bool
	wg      sync.WaitGroup
}

// Serve accepts connections until the listener is closed by Shutdown.
// Each connection gets its own goroutine. Go's runtime multiplexes them over
// epoll, so a blocked read costs a few KB of stack, not an OS thread.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	s.ln = ln
	if s.conns == nil {
		s.conns = make(map[net.Conn]struct{})
	}
	s.mu.Unlock()

	var backoff time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if s.closing.Load() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			// Typically EMFILE (out of file descriptors). Retrying in a
			// tight loop would burn 100% CPU, so back off briefly.
			backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
			s.Log.Error("accept failed, backing off", "err", err, "backoff", backoff)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		s.track(c, true)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.track(c, false)
			defer c.Close()
			s.handle(c)
		}()
	}
}

// Shutdown stops accepting, waits for open connections to finish, and
// force-closes whatever is still open when ctx expires.
func (s *Server) Shutdown(ctx context.Context) error {
	s.closing.Store(true)
	s.mu.Lock()
	if s.ln != nil {
		s.ln.Close()
	}
	s.mu.Unlock()

	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		s.mu.Lock()
		for c := range s.conns {
			c.Close()
		}
		s.mu.Unlock()
		<-done
		return ctx.Err()
	}
}

func (s *Server) track(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.conns[c] = struct{}{}
		s.Active.Add(1)
		s.Total.Add(1)
	} else {
		delete(s.conns, c)
		s.Active.Add(-1)
	}
}

// handle detects the protocol from the first byte and dispatches.
//
// A SOCKS5 client always opens with the version byte 0x05. An HTTP client
// opens with a method name in ASCII ("GET", "CONNECT", ...), and no method
// starts with byte 0x05. So one peeked byte is enough to tell them apart,
// and both protocols can share one port.
func (s *Server) handle(c net.Conn) {
	// The whole handshake (protocol detection, auth, request) must finish
	// within this deadline. Without it, a client that connects and sends
	// nothing would hold a goroutine and a file descriptor forever
	// (slowloris).
	c.SetDeadline(time.Now().Add(s.Timeouts.Handshake.Duration))

	br := bufio.NewReaderSize(c, 4096)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	if first[0] == socks5Version {
		s.serveSOCKS5(c, br)
	} else {
		s.serveHTTP(c, br)
	}
}

// dialTarget picks an exit for this tenant and connects to target from it.
func (s *Server) dialTarget(t *tenant.Tenant, o tenant.Options, target string) (net.Conn, *pool.Exit, error) {
	e, err := s.Pool.Pick(t.Name, o.Session, o.Country)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeouts.Dial.Duration)
	defer cancel()
	up, err := e.Dial(ctx, target)
	return up, e, err
}

func (s *Server) logTunnel(proto string, t *tenant.Tenant, o tenant.Options, e *pool.Exit, target string, up, down int64, start time.Time) {
	s.Log.Info("tunnel closed",
		"proto", proto, "user", t.Name, "session", o.Session, "country", o.Country,
		"exit", e.IP.String(), "target", target,
		"bytes_up", up, "bytes_down", down,
		"duration", time.Since(start).Round(time.Millisecond))
}

// isTimeout reports whether err is any kind of timeout.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}
