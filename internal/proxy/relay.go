package proxy

import (
	"bufio"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kirillfreidman/rotor/internal/tenant"
)

// bufPool recycles copy buffers. Two buffers per tunnel would otherwise be
// allocated and garbage-collected for every connection.
var bufPool = sync.Pool{New: func() any { b := make([]byte, 32<<10); return &b }}

// relay copies bytes in both directions between an established client
// connection and the upstream connection, until both directions are done.
// It returns the bytes metered in each direction.
//
// Three details matter here:
//
//  1. Pipelined bytes. The handshake was read through a bufio.Reader, which
//     may already hold bytes the client sent right after its request (an
//     eager TLS ClientHello after CONNECT, for example). Those bytes are in
//     our buffer, not in the socket, so they must be forwarded first or the
//     TLS handshake would hang.
//
//  2. Metering and idle detection on every read. See pipe for why this is
//     a plain read/write loop and not splice(2).
//
//  3. Half-close. When one side finishes sending (EOF), we pass that on with
//     CloseWrite (a TCP FIN) but keep the other direction open. Plenty of
//     protocols send a request, half-close, then read the full response.
func relay(client net.Conn, br *bufio.Reader, upstream net.Conn, t *tenant.Tenant, idle time.Duration) (up, down int64) {
	client.SetDeadline(time.Time{}) // handshake is over; idle watchdog takes over

	if n := br.Buffered(); n > 0 { // (1)
		b, _ := br.Peek(n)
		w, err := upstream.Write(b)
		up += int64(w)
		t.AddUp(int64(w))
		if err != nil {
			return up, down
		}
	}

	// Idle watchdog. Per-direction read deadlines are wrong for a proxy: in
	// a large download the client sends nothing for minutes, so a read
	// deadline on the client side would kill a busy tunnel. What we want is
	// "no bytes in either direction for `idle`". One timer per tunnel checks
	// a shared last-activity timestamp and closes both sockets when it is
	// stale. Closing unblocks both copy goroutines.
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	touch := func() { last.Store(time.Now().UnixNano()) }
	done := make(chan struct{})
	defer close(done)
	go func() {
		timer := time.NewTimer(idle)
		defer timer.Stop()
		for {
			select {
			case <-done:
				return
			case <-timer.C:
				quiet := time.Since(time.Unix(0, last.Load()))
				if quiet < idle {
					timer.Reset(idle - quiet) // traffic seen: check again later
					continue
				}
				client.Close()
				upstream.Close()
				return
			}
		}
	}()

	// Unwrap to the *net.TCPConn so closeWrite can send a FIN; wrapper
	// types (pool.trackedConn) do not have CloseWrite.
	rawClient, rawUp := unwrap(client), unwrap(upstream)

	var wg sync.WaitGroup
	wg.Add(2)
	var upN, downN int64
	go func() {
		defer wg.Done()
		upN = pipe(rawUp, rawClient, t.AddUp, touch, client, upstream)
	}()
	go func() {
		defer wg.Done()
		downN = pipe(rawClient, rawUp, t.AddDown, touch, client, upstream)
	}()
	wg.Wait()
	return up + upN, down + downN
}

// pipe copies src -> dst until EOF or error. On a clean EOF it half-closes
// dst (3). On an error (reset, closed by the watchdog) it closes both
// connections so the opposite pipe stops too.
//
// Why not io.Copy and its zero-copy splice(2) path? Splice moves data inside
// the kernel and only returns to us when the whole requested amount has
// moved. A slow stream (a long-poll, a websocket sending a few bytes a
// minute) would then never be metered and never count as activity, so the
// idle watchdog would kill a live tunnel. An early version of this code used
// io.CopyN with splice and the tests caught exactly that. The user-space
// loop costs one copy per read; it buys exact, live metering.
func pipe(dst, src net.Conn, meter func(int64), touch func(), a, b net.Conn) int64 {
	bp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bp)
	buf := *bp

	var total int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			touch()
			w, werr := dst.Write(buf[:n])
			total += int64(w)
			meter(int64(w))
			if werr != nil {
				a.Close()
				b.Close()
				return total
			}
		}
		if rerr == io.EOF {
			closeWrite(dst)
			return total
		}
		if rerr != nil {
			a.Close()
			b.Close()
			return total
		}
	}
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}

// unwrap strips wrapper types to reach the *net.TCPConn underneath.
func unwrap(c net.Conn) net.Conn {
	for {
		u, ok := c.(interface{ Unwrap() net.Conn })
		if !ok {
			return c
		}
		c = u.Unwrap()
	}
}
