package proxy

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kirillfreidman/rotor/internal/pool"
	"github.com/kirillfreidman/rotor/internal/tenant"
)

// serveHTTP handles an HTTP proxy connection. Two kinds of request arrive:
//
//	CONNECT example.com:443 HTTP/1.1      -> open a raw TCP tunnel (used for HTTPS;
//	                                         the proxy never sees the TLS plaintext)
//	GET http://example.com/path HTTP/1.1  -> forward a plain-HTTP request
//	                                         (absolute URL, the "absolute-form")
//
// A plain-HTTP connection can carry many requests (keep-alive), so this is a
// loop. A CONNECT turns the connection into a tunnel and ends the loop.
func (s *Server) serveHTTP(c net.Conn, br *bufio.Reader) {
	var t *tenant.Tenant // set on first authenticated request
	defer func() {
		if t != nil {
			t.Release()
		}
	}()

	for first := true; ; first = false {
		if !first {
			c.SetReadDeadline(time.Now().Add(s.Timeouts.Idle.Duration))
		}
		req, err := http.ReadRequest(br)
		if err != nil {
			if first && !errors.Is(err, io.EOF) {
				writeStatus(c, http.StatusBadRequest, "malformed request")
			}
			return
		}

		rt, opts, err := s.authHTTP(req)
		if err != nil {
			writeStatus(c, http.StatusProxyAuthRequired, "proxy authentication required")
			return
		}
		if t == nil {
			if !rt.Acquire() {
				writeStatus(c, http.StatusTooManyRequests, "connection limit reached")
				return
			}
			t = rt
		} else if rt != t {
			// One connection belongs to one tenant, so a connection's
			// slot and its metering are never split between customers.
			writeStatus(c, http.StatusProxyAuthRequired, "credentials changed on connection")
			return
		}

		if req.Method == http.MethodConnect {
			s.serveConnect(c, br, req, t, opts)
			return
		}
		if !s.forward(c, req, t, opts) {
			return
		}
	}
}

// authHTTP checks the Proxy-Authorization header:
//
//	Proxy-Authorization: Basic base64("user:password")
func (s *Server) authHTTP(req *http.Request) (*tenant.Tenant, tenant.Options, error) {
	user, pass, ok := parseBasic(req.Header.Get("Proxy-Authorization"))
	if !ok {
		return nil, tenant.Options{}, tenant.ErrAuth
	}
	return s.Tenants.Authenticate(user, pass)
}

func parseBasic(h string) (user, pass string, ok bool) {
	const prefix = "basic "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	user, pass, ok = strings.Cut(string(raw), ":")
	return user, pass, ok
}

// serveConnect opens a tunnel. After "200 Connection Established" the proxy
// only moves bytes; for HTTPS those bytes are TLS records it cannot read.
func (s *Server) serveConnect(c net.Conn, br *bufio.Reader, req *http.Request, t *tenant.Tenant, opts tenant.Options) {
	target := req.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		writeStatus(c, http.StatusBadRequest, "CONNECT target must be host:port")
		return
	}
	up, e, err := s.dialTarget(t, opts, target)
	if err != nil {
		writeStatus(c, statusForErr(err), "cannot reach target")
		return
	}
	defer up.Close()

	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	start := time.Now()
	upN, downN := relay(c, br, up, t, s.Timeouts.Idle.Duration)
	s.logTunnel("http-connect", t, opts, e, target, upN, downN, start)
}

// forward sends one plain-HTTP request upstream and writes the response
// back. It returns false when the client connection must be closed.
func (s *Server) forward(c net.Conn, req *http.Request, t *tenant.Tenant, opts tenant.Options) (keepAlive bool) {
	if req.URL.Scheme != "http" || req.URL.Host == "" {
		writeStatus(c, http.StatusBadRequest, "proxy requests need an absolute http:// URL (use CONNECT for https)")
		return false
	}
	e, err := s.Pool.Pick(t.Name, opts.Session, opts.Country)
	if err != nil {
		writeStatus(c, statusForErr(err), "no exit available")
		return false
	}
	idle := s.Timeouts.Idle.Duration
	start := time.Now()

	// Connection-level ("hop-by-hop") semantics apply only between two
	// adjacent hops. The client's Connection: close is about the
	// client<->proxy connection, not proxy<->origin, which has its own
	// keep-alive pool. So remember it, and strip it from what goes out.
	clientClose := req.Close
	req.Close = false
	req.RequestURI = "" // must be empty on outgoing client requests
	removeHopByHop(req.Header)

	// The transport writes the request body from its own goroutine, so
	// this counter is shared between goroutines and must be atomic.
	var up atomic.Int64
	if req.Body != nil && req.Body != http.NoBody {
		req.Body = &meteredBody{ReadCloser: req.Body, conn: c, idle: idle, meter: func(n int64) { up.Add(n); t.AddUp(n) }}
	}

	resp, err := e.Transport().RoundTrip(req)
	if err != nil {
		writeStatus(c, statusForErr(err), "upstream request failed")
		return false
	}
	defer resp.Body.Close()
	removeHopByHop(resp.Header)

	// We must close after this response if the client asked to, if the
	// origin is HTTP/1.0, or if the body has no length and is not chunked
	// (then end-of-body is signalled by closing the connection).
	closeAfter := clientClose || resp.Close || !resp.ProtoAtLeast(1, 1) ||
		(resp.ContentLength < 0 && !isChunked(resp.TransferEncoding))
	resp.Close = closeAfter // makes resp.Write emit "Connection: close"

	mw := &meteredWriter{conn: c, idle: idle, meter: t.AddDown}
	bw := bufio.NewWriterSize(mw, 32<<10)
	if err := resp.Write(bw); err != nil {
		return false
	}
	if err := bw.Flush(); err != nil {
		return false
	}
	s.Log.Info("http request",
		"user", t.Name, "session", opts.Session, "country", opts.Country,
		"exit", e.IP.String(), "method", req.Method, "host", req.URL.Host,
		"status", resp.StatusCode, "bytes_up", up.Load(), "bytes_down", mw.n,
		"duration", time.Since(start).Round(time.Millisecond))
	return !closeAfter
}

// hopByHop headers describe one TCP hop and must not be forwarded
// (RFC 9110 section 7.6.1). Proxy-Authorization is also removed so the
// customer's credentials never reach the target site.
var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func removeHopByHop(h http.Header) {
	// Headers named in Connection are hop-by-hop too ("Connection: foo"
	// means "header foo is only for you").
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopByHop {
		h.Del(name)
	}
}

func isChunked(te []string) bool {
	return len(te) > 0 && te[0] == "chunked"
}

// statusForErr maps an internal error to the HTTP status the client sees.
func statusForErr(err error) int {
	switch {
	case errors.Is(err, pool.ErrNoExit):
		return http.StatusServiceUnavailable // 503: retry later or with other options
	case errors.Is(err, pool.ErrForbiddenTarget):
		return http.StatusForbidden
	case isTimeout(err):
		return http.StatusGatewayTimeout // 504
	default:
		return http.StatusBadGateway // 502: refused, DNS failure, reset...
	}
}

// writeStatus writes a minimal error response and signals close.
func writeStatus(c net.Conn, code int, msg string) {
	extra := ""
	if code == http.StatusProxyAuthRequired {
		// Tells the client which scheme to retry with.
		extra = "Proxy-Authenticate: Basic realm=\"rotor\"\r\n"
	}
	body := msg + "\n"
	fmt.Fprintf(c, "HTTP/1.1 %d %s\r\n%sContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), extra, len(body), body)
}

// meteredBody counts request-body bytes read from the client and refreshes
// the read deadline before each read, so a slow but active upload is fine
// and a stalled one times out.
type meteredBody struct {
	io.ReadCloser
	conn  net.Conn
	idle  time.Duration
	meter func(int64)
}

func (b *meteredBody) Read(p []byte) (int, error) {
	b.conn.SetReadDeadline(time.Now().Add(b.idle))
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.meter(int64(n))
	}
	return n, err
}

// meteredWriter counts response bytes written to the client, with the same
// per-write deadline idea.
type meteredWriter struct {
	conn  net.Conn
	idle  time.Duration
	meter func(int64)
	n     int64
}

func (w *meteredWriter) Write(p []byte) (int, error) {
	w.conn.SetWriteDeadline(time.Now().Add(w.idle))
	n, err := w.conn.Write(p)
	if n > 0 {
		w.n += int64(n)
		w.meter(int64(n))
	}
	return n, err
}
