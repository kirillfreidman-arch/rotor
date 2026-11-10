# rotor

A forward proxy written in Go that rotates outbound traffic across a pool of exit IP addresses. It speaks HTTP, HTTPS (via `CONNECT`) and SOCKS5 on a single port, and it has no third-party dependencies.

```
client ──HTTP / CONNECT / SOCKS5──▶ rotor ──from exit IP A, B, C…──▶ target site
                                     │
                                     ├─ auth + per-user limits
                                     ├─ rotation / sticky sessions / geo filter
                                     ├─ exit health checks + quality score
                                     └─ per-user bandwidth metering → /metrics
```

## Features

- **Three protocols on one port.** Plain HTTP forwarding, HTTPS tunnels with `CONNECT`, and SOCKS5 (RFC 1928, `CONNECT` command, IPv4/IPv6/domain targets). The protocol is detected from the first byte.
- **Authentication.** HTTP `Proxy-Authorization: Basic` and SOCKS5 username/password (RFC 1929). Passwords are compared in constant time. Anonymous access is not offered.
- **IP rotation.** Each connection leaves from the next healthy exit IP, using lock-free round robin.
- **Sticky sessions.** `alice-session-<id>` keeps the same exit IP while the session is in use, with a sliding TTL. If that exit fails, the session moves to a healthy one.
- **Geo-targeting.** `alice-country-de` only uses exits labelled `de`. The two options combine: `alice-country-de-session-42`.
- **Health checks.** Exits are probed actively. 3 failures in a row remove an exit from rotation and 2 successes bring it back (hysteresis). Each exit also has a quality score: an exponentially weighted average of its real dial success rate.
- **Multi-tenancy.** Per-user concurrent connection limits, with sessions isolated per user.
- **Bandwidth metering.** Exact byte counts per user and direction, updated live on every read and exposed as Prometheus metrics.
- **Hardening.** SSRF guard, so customers can't reach loopback, private ranges or cloud metadata (DNS-rebinding safe). Handshake and idle timeouts (slowloris). Hop-by-hop header stripping. Graceful shutdown.
- **IPv4 and IPv6 exits.** Each exit dials only in its own address family.

## Quick start

Requires Go 1.22 or newer.

```bash
make test     # unit + end-to-end tests, with the race detector
make demo     # starts rotor and a local "whoami" target, shows everything working
```

On macOS, first add the demo exit IPs to the loopback interface: `sudo ifconfig lo0 alias 127.0.0.2` (and the same for `.3` and `.4`).

Demo output:

```
== rotating (new exit IP per request)
127.0.0.2
127.0.0.3
127.0.0.4
127.0.0.2
== sticky session (same IP while the session lives)
127.0.0.3
127.0.0.3
127.0.0.3
== geo-targeting: country us
127.0.0.4
127.0.0.4
== SOCKS5 (proxy resolves the name: socks5h)
127.0.0.3
== wrong password
HTTP 407
```

## Usage

```bash
cp config.example.json config.json   # edit users and exit IPs
go build -o bin/ ./cmd/... && ./bin/rotor -config config.json
```

```bash
curl -x http://127.0.0.1:8080 -U alice:change-me https://example.com                          # rotate
curl -x http://127.0.0.1:8080 -U alice-session-job42:change-me https://example.com            # sticky
curl -x http://127.0.0.1:8080 -U alice-country-us:change-me https://example.com               # geo
curl --socks5-hostname 127.0.0.1:8080 -U alice:change-me https://example.com                  # SOCKS5
curl http://127.0.0.1:9090/metrics                                                            # metrics
```

On a real server, the exit IPs are the addresses assigned to the machine, for example extra IPv4 addresses or addresses from a routed IPv6 /64. Set `allow_private_targets` to `false` and set a `health.target` such as `1.1.1.1:443`.

## Configuration

See [`config.example.json`](config.example.json). Every field is documented in [`internal/config/config.go`](internal/config/config.go). Durations are strings such as `"30s"`.

## Layout

```
cmd/rotor/          entry point: config, wiring, signals, graceful shutdown
cmd/whoami/         tiny target server for the demo (replies with the caller's IP)
internal/proxy/     data plane: listener, protocol detection, HTTP, CONNECT, SOCKS5, relay
internal/pool/      exit IPs: rotation, sticky sessions, geo filter, health, SSRF guard
internal/tenant/    users: auth, username options, connection limits, metering
internal/admin/     /metrics (Prometheus text format) and /healthz
internal/config/    JSON config loading and validation
docs/DESIGN.md      design decisions, trade-offs and what a production version needs
```

## Performance

Measured with `make bench` on a 2-vCPU cloud container. Client, proxy and target all run on loopback in one process, so treat these numbers as an upper bound on proxy overhead, not as real-network figures.

| Benchmark | Result |
|---|---|
| `CONNECT` tunnel throughput (1 MiB writes) | ~2.3 GB/s |
| Small plain-HTTP request through the proxy (keep-alive) | ~88 µs/request |

## Design

[`docs/DESIGN.md`](docs/DESIGN.md) explains the decisions behind the code: why one port, why options live in the username, why the relay doesn't use splice(2), how health and scoring differ, the SSRF guard, and what's missing for production (HTTP/2 and HTTP/3, UDP, distributed session state, IP reputation feeds).
