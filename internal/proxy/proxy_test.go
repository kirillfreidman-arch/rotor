package proxy

// End-to-end tests: a real proxy on a real socket, real clients, and local
// "target" servers. Exits are 127.0.0.2 and 127.0.0.3. On Linux the whole
// 127.0.0.0/8 block is bound to the loopback interface, so these work with
// no setup and the target sees them as distinct source IPs.

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kirillfreidman/rotor/internal/config"
	"github.com/kirillfreidman/rotor/internal/pool"
	"github.com/kirillfreidman/rotor/internal/tenant"
)

type env struct {
	addr    string
	tenants *tenant.Registry
	srv     *Server
}

type opts struct {
	exits        []config.Exit
	users        []config.User
	idle         time.Duration
	allowPrivate bool
}

func start(t testing.TB, o opts) *env {
	t.Helper()
	if o.exits == nil {
		o.exits = []config.Exit{{IP: "127.0.0.2", Country: "de"}, {IP: "127.0.0.3", Country: "us"}}
	}
	if o.users == nil {
		o.users = []config.User{{Name: "alice", Password: "secret"}}
	}
	if o.idle == 0 {
		o.idle = 5 * time.Second
	}
	timeouts := config.Timeouts{
		Handshake: config.Duration{Duration: 2 * time.Second},
		Dial:      config.Duration{Duration: 2 * time.Second},
		Idle:      config.Duration{Duration: o.idle},
	}
	reg := tenant.NewRegistry(o.users)
	p := pool.New(o.exits, pool.Options{
		DialTimeout: time.Second, SessionTTL: time.Minute, IdleTimeout: o.idle,
		AllowPrivateTargets: o.allowPrivate,
	})
	srv := &Server{Tenants: reg, Pool: p, Timeouts: timeouts,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	})
	return &env{addr: ln.Addr().String(), tenants: reg, srv: srv}
}

// whoami replies with the caller's IP, i.e. the exit the proxy used.
var whoami = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	fmt.Fprint(w, ip)
})

func httpClient(proxyAddr, user string) *http.Client {
	u := &url.URL{Scheme: "http", Host: proxyAddr, User: url.UserPassword(user, "secret")}
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}, Timeout: 5 * time.Second}
}

func get(t *testing.T, c *http.Client, u string) string {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	return string(b)
}

func TestHTTPRotates(t *testing.T) {
	target := httptest.NewServer(whoami)
	defer target.Close()
	e := start(t, opts{allowPrivate: true})
	c := httpClient(e.addr, "alice")

	var ips []string
	for i := 0; i < 4; i++ {
		ips = append(ips, get(t, c, target.URL))
	}
	if ips[0] == ips[1] || ips[0] != ips[2] || ips[1] != ips[3] {
		t.Fatalf("expected alternating exits, got %v", ips)
	}
}

func TestHTTPStickySession(t *testing.T) {
	target := httptest.NewServer(whoami)
	defer target.Close()
	e := start(t, opts{allowPrivate: true})
	c := httpClient(e.addr, "alice-session-abc")

	first := get(t, c, target.URL)
	for i := 0; i < 5; i++ {
		if ip := get(t, c, target.URL); ip != first {
			t.Fatalf("sticky session changed IP: %s -> %s", first, ip)
		}
	}
}

func TestHTTPCountryTargeting(t *testing.T) {
	target := httptest.NewServer(whoami)
	defer target.Close()
	e := start(t, opts{allowPrivate: true})
	c := httpClient(e.addr, "alice-country-us")
	for i := 0; i < 4; i++ {
		if ip := get(t, c, target.URL); ip != "127.0.0.3" {
			t.Fatalf("country us left from %s", ip)
		}
	}
}

func TestHTTPRequiresAuth(t *testing.T) {
	target := httptest.NewServer(whoami)
	defer target.Close()
	e := start(t, opts{allowPrivate: true})
	u, _ := url.Parse("http://" + e.addr)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
	resp, err := c.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired || resp.Header.Get("Proxy-Authenticate") == "" {
		t.Fatalf("want 407 with Proxy-Authenticate, got %d %v", resp.StatusCode, resp.Header)
	}
}

func TestHTTPSViaCONNECT(t *testing.T) {
	target := httptest.NewTLSServer(whoami)
	defer target.Close()
	e := start(t, opts{allowPrivate: true})

	c := httpClient(e.addr, "alice-country-de")
	tr := c.Transport.(*http.Transport)
	tr.TLSClientConfig = &tls.Config{RootCAs: target.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}

	if ip := get(t, c, target.URL); ip != "127.0.0.2" { // Go sends CONNECT for https:// URLs
		t.Fatalf("CONNECT left from %s", ip)
	}
	tn, _, _ := e.tenants.Authenticate("alice", "secret")
	if tn.BytesUp.Load() == 0 || tn.BytesDown.Load() == 0 {
		t.Fatalf("tunnel not metered: up=%d down=%d", tn.BytesUp.Load(), tn.BytesDown.Load())
	}
}

func TestSSRFGuardBlocksLoopback(t *testing.T) {
	target := httptest.NewServer(whoami)
	defer target.Close()
	e := start(t, opts{allowPrivate: false})
	resp, err := httpClient(e.addr, "alice").Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 for a loopback target, got %d", resp.StatusCode)
	}
}

// ---- SOCKS5, spoken byte by byte so the test documents the wire format ----

// socksDial runs the SOCKS5 handshake and returns the reply code, the bound
// address from the reply, and the connection.
func socksDial(t *testing.T, proxyAddr, user, pass string, atyp byte, addr []byte, port uint16) (byte, string, net.Conn) {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	must := func(want []byte) {
		got := make([]byte, len(want))
		if _, err := io.ReadFull(c, got); err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("got % x, want % x", got, want)
		}
	}
	c.Write([]byte{0x05, 0x01, 0x02}) // VER, NMETHODS=1, METHOD=user/pass
	must([]byte{0x05, 0x02})

	auth := []byte{0x01, byte(len(user))}
	auth = append(auth, user...)
	auth = append(auth, byte(len(pass)))
	auth = append(auth, pass...)
	c.Write(auth)
	status := make([]byte, 2)
	io.ReadFull(c, status)
	if status[1] != 0x00 {
		return 0xFF, "", c // auth failed
	}

	req := []byte{0x05, 0x01, 0x00, atyp} // VER, CMD=CONNECT, RSV, ATYP
	req = append(req, addr...)
	req = binary.BigEndian.AppendUint16(req, port)
	c.Write(req)

	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		t.Fatal(err)
	}
	var bound string
	if head[3] == 0x01 {
		b := make([]byte, 6)
		io.ReadFull(c, b)
		bound = net.IP(b[:4]).String()
	}
	return head[1], bound, c
}

func hostPort(t *testing.T, rawURL string) (net.IP, uint16) {
	u, _ := url.Parse(rawURL)
	h, p, _ := net.SplitHostPort(u.Host)
	var port int
	fmt.Sscan(p, &port)
	return net.ParseIP(h).To4(), uint16(port)
}

func TestSOCKS5IPv4AndDomain(t *testing.T) {
	target := httptest.NewServer(whoami)
	defer target.Close()
	e := start(t, opts{allowPrivate: true})
	ip, port := hostPort(t, target.URL)

	cases := []struct {
		name string
		atyp byte
		addr []byte
	}{
		{"ipv4", 0x01, ip},
		{"domain", 0x03, append([]byte{byte(len("localhost"))}, "localhost"...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep, bound, c := socksDial(t, e.addr, "alice-country-us", "secret", tc.atyp, tc.addr, port)
			defer c.Close()
			if rep != 0x00 {
				t.Fatalf("reply code %#x", rep)
			}
			if bound != "127.0.0.3" {
				t.Fatalf("BND.ADDR = %s, want the exit IP", bound)
			}
			fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
			resp, err := http.ReadResponse(bufio.NewReader(c), nil)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			if string(body) != "127.0.0.3" {
				t.Fatalf("target saw %s", body)
			}
		})
	}
}

func TestSOCKS5RejectsBadPasswordAndNoAuth(t *testing.T) {
	e := start(t, opts{allowPrivate: true})
	rep, _, c := socksDial(t, e.addr, "alice", "wrong", 0x01, []byte{127, 0, 0, 1}, 80)
	c.Close()
	if rep != 0xFF {
		t.Fatal("bad password accepted")
	}

	c2, _ := net.Dial("tcp", e.addr)
	defer c2.Close()
	c2.Write([]byte{0x05, 0x01, 0x00}) // offers only "no auth"
	b := make([]byte, 2)
	io.ReadFull(c2, b)
	if b[1] != 0xFF {
		t.Fatalf("no-auth client got method %#x, want 0xFF", b[1])
	}
}

func TestSOCKS5ConnectionRefused(t *testing.T) {
	e := start(t, opts{allowPrivate: true})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	ln.Close() // nothing listens there now
	rep, _, c := socksDial(t, e.addr, "alice", "secret", 0x01, []byte{127, 0, 0, 1}, port)
	c.Close()
	if rep != repConnRefused {
		t.Fatalf("reply %#x, want connection refused (0x05)", rep)
	}
}

func TestPerUserConnectionLimit(t *testing.T) {
	echo := startEcho(t)
	e := start(t, opts{allowPrivate: true, users: []config.User{{Name: "alice", Password: "secret", MaxConns: 1}}})
	ip, port := splitTCP(echo)

	rep, _, c1 := socksDial(t, e.addr, "alice", "secret", 0x01, ip, port)
	defer c1.Close()
	if rep != 0 {
		t.Fatalf("first connection refused: %#x", rep)
	}
	rep, _, c2 := socksDial(t, e.addr, "alice", "secret", 0x01, ip, port)
	c2.Close()
	if rep != repNotAllowed {
		t.Fatalf("second connection: reply %#x, want not allowed (0x02)", rep)
	}
}

// ---- relay edge cases ----

func startEcho(t testing.TB) net.Addr {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return ln.Addr()
}

func splitTCP(a net.Addr) ([]byte, uint16) {
	ta := a.(*net.TCPAddr)
	return ta.IP.To4(), uint16(ta.Port)
}

func connectAuth() string {
	return "Proxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n" // base64("alice:secret")
}

// The client sends CONNECT and its first payload in a single write, the way
// a TLS client using "TCP fast open"-style eagerness does. The payload ends
// up in the proxy's bufio buffer and must be forwarded.
func TestCONNECTPipelinedPayload(t *testing.T) {
	echo := startEcho(t)
	e := start(t, opts{allowPrivate: true})
	c, _ := net.Dial("tcp", e.addr)
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))

	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: x\r\n%s\r\nHELLO-PIPELINED", echo, connectAuth())
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT failed: %v %v", resp, err)
	}
	got := make([]byte, len("HELLO-PIPELINED"))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("pipelined bytes lost: %v", err)
	}
}

// The client half-closes after sending; the target must still be able to
// answer, and the answer must reach the client.
func TestCONNECTHalfClose(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		n, _ := io.Copy(io.Discard, c) // read until the client's FIN
		fmt.Fprintf(c, "got %d bytes", n)
	}()

	e := start(t, opts{allowPrivate: true})
	c, _ := net.Dial("tcp", e.addr)
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: x\r\n%s\r\n", ln.Addr(), connectAuth())
	br := bufio.NewReader(c)
	if resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect}); err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT failed: %v", err)
	}
	c.Write(make([]byte, 1000))
	c.(*net.TCPConn).CloseWrite()
	answer, _ := io.ReadAll(br)
	if string(answer) != "got 1000 bytes" {
		t.Fatalf("answer after half-close = %q", answer)
	}
}

// An idle tunnel is closed; a tunnel with traffic in only one direction is
// not (that is the bug per-direction read deadlines would cause).
func TestIdleTimeout(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { // drip one byte every 50ms for 600ms, never read
				defer c.Close()
				r := bufio.NewReader(c)
				mode, _ := r.ReadByte()
				if mode == 's' {
					time.Sleep(time.Second)
					return
				}
				for i := 0; i < 12; i++ {
					time.Sleep(50 * time.Millisecond)
					c.Write([]byte{'x'})
				}
			}(c)
		}
	}()
	e := start(t, opts{allowPrivate: true, idle: 200 * time.Millisecond})

	tunnel := func(mode byte) (*bufio.Reader, net.Conn) {
		c, _ := net.Dial("tcp", e.addr)
		c.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: x\r\n%s\r\n", ln.Addr(), connectAuth())
		br := bufio.NewReader(c)
		http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		c.Write([]byte{mode})
		return br, c
	}

	// Download-only for 600ms, longer than the 200ms idle timeout.
	br, c := tunnel('d')
	got, _ := io.ReadAll(br)
	c.Close()
	if len(got) != 12 {
		t.Fatalf("one-way transfer cut short: got %d of 12 bytes", len(got))
	}

	// Silent: should be closed after ~200ms, well before the target's 1s.
	br, c = tunnel('s')
	defer c.Close()
	startT := time.Now()
	io.ReadAll(br)
	if d := time.Since(startT); d > 800*time.Millisecond {
		t.Fatalf("idle tunnel closed after %v, want ~200ms", d)
	}
}

func TestMalformedRequest(t *testing.T) {
	e := start(t, opts{allowPrivate: true})
	c, _ := net.Dial("tcp", e.addr)
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte("NOT A VALID REQUEST\r\n\r\n"))
	line, _ := bufio.NewReader(c).ReadString('\n')
	if !strings.Contains(line, "400") {
		t.Fatalf("got %q, want 400", line)
	}
}

// ---- benchmarks ----

// BenchmarkCONNECTThroughput pushes data through a CONNECT tunnel to a sink.
// `go test -bench . -benchtime 2000x ./internal/proxy` reports MB/s.
func BenchmarkCONNECTThroughput(b *testing.B) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	done := make(chan int64, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		n, _ := io.Copy(io.Discard, c)
		c.Close()
		done <- n
	}()
	e := start(b, opts{allowPrivate: true, idle: time.Minute})
	c, _ := net.Dial("tcp", e.addr)
	defer c.Close()
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: x\r\n%s\r\n", ln.Addr(), connectAuth())
	br := bufio.NewReader(c)
	if resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect}); err != nil || resp.StatusCode != 200 {
		b.Fatal("CONNECT failed")
	}

	buf := make([]byte, 1<<20)
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.Write(buf); err != nil {
			b.Fatal(err)
		}
	}
	c.(*net.TCPConn).CloseWrite()
	if n := <-done; n != int64(b.N)*int64(len(buf)) {
		b.Fatalf("sink got %d bytes, want %d", n, int64(b.N)*int64(len(buf)))
	}
}

// BenchmarkHTTPRequest measures one small plain-HTTP request through the
// proxy over a kept-alive client connection (latency the proxy adds).
func BenchmarkHTTPRequest(b *testing.B) {
	target := httptest.NewServer(whoami)
	defer target.Close()
	e := start(b, opts{allowPrivate: true})
	c := httpClient(e.addr, "alice")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := c.Get(target.URL)
		if err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}
