# rotor — design notes

This document explains why the code is shaped the way it is: the decisions, the alternatives I considered, and the known limits.

## 1. Connection lifecycle

```
accept ─▶ handshake deadline set ─▶ peek 1 byte ─┬─ 0x05 ─▶ SOCKS5 greeting → auth → request
                                                 └─ else ─▶ HTTP request → Proxy-Authorization
        ─▶ tenant.Acquire (limit) ─▶ pool.Pick (exit) ─▶ dial from exit IP (SSRF guard)
        ─▶ reply to client ─▶ relay (two copy goroutines + idle watchdog) ─▶ close, log
```

Each client connection gets one goroutine for the handshake. A tunnel adds two copy goroutines (one per direction) and one idle watchdog. Go parks blocked goroutines on epoll, so an idle tunnel costs memory (a few KB of stack plus two 32 KB pooled buffers) but no threads or CPU.

## 2. One port for HTTP and SOCKS5

A SOCKS5 client's first byte is always `0x05`. An HTTP client starts with an ASCII method name, and none starts with `0x05`. Peeking one byte through a `bufio.Reader` is enough to dispatch. Customers then have one endpoint to configure, and operators have one port to firewall and load-balance.

**Consequence:** the peek can pull more than one byte into the buffer. Everything after it reads through the same `bufio.Reader`, and the relay forwards any bytes still in the buffer before it starts copying from the socket (see §5).

## 3. Routing options live in the username

`alice-country-de-session-42` carries the user, the geo filter and the sticky-session ID. This is the convention commercial proxy networks use, and the reason is practical: every client can send a username, including curl, browsers, Selenium, Python `requests` and SOCKS libraries. HTTPS tunnels and SOCKS5 have no way to carry custom headers end to end. `-` is reserved as the separator, so config validation rejects user names that contain it.

## 4. Exit selection

- **Rotation:** an atomic counter picks a starting index, then a forward scan finds the first exit that is healthy and matches the country filter. There's no lock and no allocation per pick. With N exits and K unhealthy, the scan is at most N steps.
- **Sticky sessions:** a map from `user + country + sessionID` to an exit with an expiry time, guarded by a mutex. The TTL slides: each use extends it, so an active scraping job keeps its IP. The key includes the user so two customers who both choose `session-1` don't share an IP. It includes the country so `de` and `us` requests with the same ID don't collide. A janitor goroutine drops expired entries so one-off IDs can't grow the map without bound.
- **Failover:** if a session's exit becomes unhealthy, the next `Pick` gives the session a new exit. The customer sees a new IP instead of an error. Whether to fail over or fail hard is a product decision; some customers prefer an error to a silent IP change. That could be a per-request option.

## 5. The relay

`relay` handles three things that are easy to get wrong:

1. **Pipelined bytes.** Clients may send data right after `CONNECT` or the SOCKS request without waiting for the reply, for example an eager TLS ClientHello. Those bytes are already in the handshake `bufio.Reader`, not in the socket, so they're written upstream first. Without this, a TLS handshake through the proxy can hang. Covered by `TestCONNECTPipelinedPayload`.
2. **Half-close.** When one side sends FIN, the relay forwards it with `CloseWrite` and keeps the opposite direction open. Request-then-half-close protocols depend on this. Covered by `TestCONNECTHalfClose`.
3. **Idle timeout across both directions.** A per-socket read deadline is the obvious tool and it's wrong for a proxy: during a long download the client sends nothing, so a client-side read deadline would kill a busy tunnel. Instead, both copy loops update a shared last-activity timestamp, and a watchdog closes both sockets when nothing has moved in either direction for `idle`. Covered by `TestIdleTimeout`, which runs a download-only stream that lasts longer than the timeout.

**Why not splice(2)?** On Linux, `io.Copy` between two `*net.TCPConn`s uses splice: zero-copy, with bytes never entering user space. The first version used `io.CopyN` in chunks to keep splice and still meter. The tests showed that splice returns only after the whole chunk has moved. A slow stream (a long-poll, a websocket with occasional messages) then never showed activity, so the watchdog killed live tunnels and the bytes were never metered. The relay now uses a plain read/write loop with pooled 32 KB buffers: one memory copy per read, in exchange for exact, live metering and correct idle detection. The benchmark still shows ~2.3 GB/s through a tunnel on 2 vCPUs. If profiling showed copying was the bottleneck, one option is splice for bulk transfers, with metering from kernel counters (`TCP_INFO` bytes_acked/bytes_received) instead of counting in user space.

## 6. Plain-HTTP forwarding

- Each exit has its own `http.Transport`, so every exit keeps its own pool of keep-alive connections to origins. A shared transport would reuse a connection opened from IP A for a request that's supposed to leave from IP B.
- `DisableCompression: true`. Otherwise Go adds `Accept-Encoding: gzip` and transparently decompresses, and the client receives bytes it never asked for.
- Hop-by-hop headers (RFC 9110 §7.6.1) are removed in both directions: `Connection`, any header it names, `Keep-Alive`, `Proxy-*`, `TE`, `Trailer`, `Transfer-Encoding` and `Upgrade`. `Proxy-Authorization` is among them, so customer credentials never reach the target site.
- The client's `Connection: close` applies to the client↔proxy hop only. It's remembered locally and not forwarded, so the upstream pool keeps its connection.
- No `Via` or `X-Forwarded-For` header is added. The point of the product is that the target sees the exit IP, not the customer.

## 7. Health and quality are separate signals

- **Health (binary)** comes only from active checks: a TCP handshake from each exit to a known-good target. 3 consecutive failures mark the exit unhealthy and 2 consecutive successes recover it. The asymmetry is deliberate hysteresis, so a flaky IP doesn't flap in and out of rotation.
- **Score (0–1)** is an exponentially weighted average (α = 0.1) of real customer dial results. It does **not** affect health. If customer failures could eject exits, one customer pointing a crawler at a dead site would take good IPs out of rotation for everyone.

A TCP handshake proves an IP is routable. It doesn't prove the IP has a good reputation with a particular site. Real reputation management needs per-target signals: HTTP 403/429 rates, CAPTCHA pages, blocklist lookups (Spamhaus and similar) and ASN-level patterns. The score field is where those signals would feed in, for example to weight selection or to rest an IP that's being blocked.

## 8. Security

- **SSRF guard.** Without it, any customer could request `127.0.0.1:9090` (the admin port), internal `10.x` services or `169.254.169.254` (cloud metadata, which hands out credentials). The check runs in `net.Dialer.Control`, which receives the already-resolved IP just before `connect(2)`. Because there's only one DNS resolution, a hostile DNS server can't pass the check with one answer and connect with another (DNS rebinding). Covered by `TestGuardTarget` and `TestSSRFGuardBlocksLoopback`.
- **No anonymous access.** An open proxy is found and abused within hours, and the abuse burns the reputation of every exit IP.
- **Timeouts at every phase:** a handshake deadline (slowloris), a dial timeout, a response-header timeout and the idle watchdog.
- **Constant-time password comparison**, and the same error whether the user or the password was wrong.
- **Per-user connection limits**, so one tenant can't exhaust file descriptors for the others.

## 9. Metering

Bytes are counted on every successful write in both directions, using per-tenant atomics. A mutex here would serialise every core on every read. Metering starts once the tenant is authenticated, so handshake bytes aren't billed. For plain HTTP, upload counts request bodies and download counts the full response, headers included.

## 10. What a production version needs

| Area | Gap | Direction |
|---|---|---|
| Protocols | HTTP/2 and HTTP/3 to the client, SOCKS5 UDP ASSOCIATE | HTTP/2 `CONNECT` streams multiplex many tunnels over one connection. HTTP/3 means QUIC over UDP, and proxying it needs UDP relay or MASQUE (`CONNECT-UDP`, RFC 9298) |
| Scale-out | Sessions and counters live in one process | Shared session store (Redis) or consistent hashing of session IDs to nodes; meters flushed to a time-series store or billing pipeline |
| Exits | Static list in config | Dynamic registry: residential and mobile exits are peers that connect *in* over a reverse tunnel, so they come and go, sit behind NAT and need very different health expectations from datacenter IPs |
| Geo | Labels set by hand | Geo-IP database (country/city/ASN) with periodic refresh; geo-IP accuracy is weak below country level, especially for mobile carriers |
| Reputation | TCP-level health only | Per-target block detection, blocklist feeds, cool-down and rotation policies |
| Ops | Logs and a metrics endpoint | Tracing, per-tenant rate limits (bytes/s, not just connections), config hot reload |
| Kernel | Defaults | `SO_REUSEPORT` across processes, raised `ulimit -n`, a wider ephemeral port range, `tcp_tw_reuse`, and `IP_BIND_ADDRESS_NO_PORT` so binding to an exit IP doesn't reserve the port before `connect` |
