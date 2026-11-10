// Package pool manages the exit IPs: which one a connection leaves from
// (rotation, sticky sessions, geo filter) and whether each one is healthy.
package pool

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kirillfreidman/rotor/internal/config"
)

// ErrNoExit means no healthy exit matches the request (e.g. a country with
// no IPs, or every IP failing health checks).
var ErrNoExit = errors.New("no healthy exit available")

// ErrForbiddenTarget means the target resolved to a private, loopback or
// link-local address and AllowPrivateTargets is off.
var ErrForbiddenTarget = errors.New("target address not allowed")

// Options configures a Pool.
type Options struct {
	DialTimeout time.Duration
	SessionTTL  time.Duration
	// IdleTimeout bounds how long plain-HTTP forwarding waits for response
	// headers from the origin.
	IdleTimeout time.Duration
	// AllowPrivateTargets lets customers reach loopback/private addresses.
	// Off in production (see guardTarget); on for local demos and tests.
	AllowPrivateTargets bool
}

// Exit is one outbound IP address.
type Exit struct {
	IP      net.IP
	Country string

	network   string // "tcp4" or "tcp6", matching the IP family
	dialer    *net.Dialer
	transport *http.Transport

	// Health state. Written by the health checker and by dial results,
	// read on every Pick, so it is guarded by a mutex (writes are rare
	// compared to the traffic itself).
	mu        sync.Mutex
	healthy   bool
	fails     int     // consecutive failed active checks
	successes int     // consecutive successful active checks
	score     float64 // EWMA of dial success, 0..1

	Active atomic.Int64  // connections open right now
	Total  atomic.Uint64 // connections ever opened
}

func newExit(c config.Exit, o Options) *Exit {
	ip := net.ParseIP(c.IP)
	e := &Exit{
		IP:      ip,
		Country: strings.ToLower(c.Country),
		network: "tcp6",
		healthy: true,
		score:   1,
	}
	if ip.To4() != nil {
		// An IPv4 source address cannot reach an IPv6 destination (and the
		// reverse). Dialing "tcp4" makes the resolver return only A records
		// for this exit, so the family always matches.
		e.network = "tcp4"
	}
	e.dialer = &net.Dialer{
		// LocalAddr is the whole trick behind IP rotation: the kernel uses
		// this as the source address in the SYN, so the target sees it.
		// Port 0 lets the kernel pick an ephemeral port.
		LocalAddr: &net.TCPAddr{IP: ip},
		Timeout:   o.DialTimeout,
		KeepAlive: 30 * time.Second, // detect dead peers on long tunnels
	}
	if !o.AllowPrivateTargets {
		e.dialer.Control = guardTarget
	}
	// One http.Transport per exit gives each exit its own pool of
	// keep-alive connections for plain-HTTP forwarding. Sharing one
	// transport would mix connections from different source IPs.
	e.transport = &http.Transport{
		Proxy: nil, // never chain to an environment-configured proxy
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return e.Dial(ctx, addr)
		},
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: o.IdleTimeout,
		// A proxy must not change the payload. With compression enabled
		// Go would add Accept-Encoding: gzip and transparently decompress,
		// so the client would get different bytes than it asked for.
		DisableCompression: true,
		// Upstream HTTP/2 is only negotiated over TLS, and plain-HTTP
		// forwarding is cleartext, so stay on HTTP/1.1.
		ForceAttemptHTTP2: false,
	}
	return e
}

// Dial opens a TCP connection to addr from this exit's IP.
func (e *Exit) Dial(ctx context.Context, addr string) (net.Conn, error) {
	c, err := e.dialer.DialContext(ctx, e.network, addr)
	e.observe(err == nil)
	if err != nil {
		return nil, err
	}
	e.Active.Add(1)
	e.Total.Add(1)
	return &trackedConn{Conn: c, exit: e}, nil
}

// Transport is the keep-alive pool for plain-HTTP requests from this exit.
func (e *Exit) Transport() *http.Transport { return e.transport }

// Healthy reports the current health state.
func (e *Exit) Healthy() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.healthy
}

// Score is the exit's quality score (exponentially weighted dial success).
func (e *Exit) Score() float64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.score
}

// observe updates the quality score from a real customer dial.
//
// Customer dials only move the score; they never flip the healthy flag. A
// customer pointing at a dead website would otherwise eject a perfectly good
// IP. Only active checks against a known-good target decide health.
func (e *Exit) observe(ok bool) {
	const alpha = 0.1 // weight of the newest sample
	v := 0.0
	if ok {
		v = 1
	}
	e.mu.Lock()
	e.score = (1-alpha)*e.score + alpha*v
	e.mu.Unlock()
}

// checkResult applies an active health-check result with hysteresis:
// 3 failures in a row to mark unhealthy, 2 successes in a row to recover.
// Without hysteresis a flaky IP would flap in and out of rotation.
func (e *Exit) checkResult(ok bool) (changed bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	was := e.healthy
	if ok {
		e.fails = 0
		e.successes++
		if !e.healthy && e.successes >= 2 {
			e.healthy = true
		}
	} else {
		e.successes = 0
		e.fails++
		if e.healthy && e.fails >= 3 {
			e.healthy = false
		}
	}
	return was != e.healthy
}

func (e *Exit) matches(country string) bool {
	return country == "" || e.Country == country
}

// trackedConn decrements the exit's active counter exactly once on Close.
// Wrapping hides the *net.TCPConn type (and its CloseWrite), so it exposes
// Unwrap for the relay to reach the real socket.
type trackedConn struct {
	net.Conn
	exit   *Exit
	closed atomic.Bool
}

func (c *trackedConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.exit.Active.Add(-1)
	}
	return c.Conn.Close()
}

// Unwrap exposes the underlying *net.TCPConn.
func (c *trackedConn) Unwrap() net.Conn { return c.Conn }

type session struct {
	exit    *Exit
	expires time.Time
}

// Pool chooses exits.
type Pool struct {
	exits []*Exit
	next  atomic.Uint64 // round-robin cursor

	ttl      time.Duration
	mu       sync.Mutex
	sessions map[string]*session

	now func() time.Time // replaceable in tests
}

// New builds a pool from config.
func New(exits []config.Exit, o Options) *Pool {
	p := &Pool{ttl: o.SessionTTL, sessions: map[string]*session{}, now: time.Now}
	for _, c := range exits {
		p.exits = append(p.exits, newExit(c, o))
	}
	return p
}

// guardTarget blocks connections to internal addresses (SSRF protection).
// Without it, any customer could ask the proxy for 127.0.0.1:9090 (our admin
// port), 10.x.x.x (our internal network) or 169.254.169.254 (the cloud
// metadata service, which hands out credentials).
//
// It runs as net.Dialer.Control, which the kernel-facing dial code calls
// with the already-resolved IP, right before connect(2). Checking here
// instead of resolving the name ourselves first closes the DNS-rebinding
// gap: a hostile DNS server cannot answer "public IP" to our check and
// "127.0.0.1" to the real connect, because there is only one resolution.
func guardTarget(network, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return ErrForbiddenTarget
	}
	ip := ap.Addr().Unmap() // treat ::ffff:127.0.0.1 as 127.0.0.1
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() ||
		cgnat.Contains(ip) {
		return ErrForbiddenTarget
	}
	return nil
}

// cgnat is the carrier-grade NAT range (RFC 6598), private in practice.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Exits returns every exit (for health checks and metrics).
func (p *Pool) Exits() []*Exit { return p.exits }

// Pick returns the exit for one connection.
//
//   - sessionID == "": rotate, a different exit on every call.
//   - sessionID != "": sticky, the same exit for as long as the session is
//     used at least once per TTL and the exit stays healthy. If the exit dies
//     the session moves to a new one (the client sees a new IP, which is
//     better than an error).
//
// Sessions are keyed by user too, so two customers who both pick session
// "1" do not share an IP.
func (p *Pool) Pick(user, sessionID, country string) (*Exit, error) {
	if sessionID == "" {
		return p.rotate(country)
	}
	key := user + "\x00" + country + "\x00" + sessionID
	now := p.now()

	p.mu.Lock()
	defer p.mu.Unlock()
	if s, ok := p.sessions[key]; ok && now.Before(s.expires) && s.exit.Healthy() {
		s.expires = now.Add(p.ttl) // sliding expiry
		return s.exit, nil
	}
	e, err := p.rotate(country)
	if err != nil {
		return nil, err
	}
	p.sessions[key] = &session{exit: e, expires: now.Add(p.ttl)}
	return e, nil
}

// rotate is lock-free round robin over the healthy exits that match.
// One atomic increment picks a start point; we then walk forward until we
// find a usable exit. No allocation per call.
func (p *Pool) rotate(country string) (*Exit, error) {
	n := uint64(len(p.exits))
	start := p.next.Add(1) - 1
	for i := uint64(0); i < n; i++ {
		e := p.exits[(start+i)%n]
		if e.matches(country) && e.Healthy() {
			return e, nil
		}
	}
	return nil, ErrNoExit
}

// Sessions returns the number of sticky sessions held.
func (p *Pool) Sessions() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.sessions)
}

// expire drops sessions past their TTL. Without this the map would grow
// forever with one-off session IDs.
func (p *Pool) expire() {
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, s := range p.sessions {
		if now.After(s.expires) {
			delete(p.sessions, k)
		}
	}
}

// RunJanitor expires sessions every interval until ctx is cancelled.
func (p *Pool) RunJanitor(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.expire()
		}
	}
}
