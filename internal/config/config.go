// Package config loads and validates rotor's JSON configuration.
//
// JSON (not YAML) is used on purpose: it is in the standard library, so the
// whole project has zero third-party dependencies.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// Config is the top-level configuration file.
type Config struct {
	// Listen is the address of the proxy port. HTTP and SOCKS5 share it:
	// the protocol is detected from the first byte the client sends.
	Listen string `json:"listen"`

	// AdminListen serves /metrics and /healthz. Keep it on localhost or a
	// private network: it exposes per-user traffic numbers.
	AdminListen string `json:"admin_listen"`

	Users []User `json:"users"`
	Exits []Exit `json:"exits"`

	Timeouts Timeouts `json:"timeouts"`
	Health   Health   `json:"health"`

	// AllowPrivateTargets lets customers connect to loopback/private/
	// link-local addresses. Leave false in production (SSRF protection);
	// the local demo turns it on so it can reach a server on 127.0.0.1.
	AllowPrivateTargets bool `json:"allow_private_targets"`

	// SessionTTL is how long a sticky session keeps its exit IP after the
	// last time it was used (sliding expiry).
	SessionTTL Duration `json:"session_ttl"`
}

// User is one customer (tenant) of the proxy.
type User struct {
	Name     string `json:"name"`
	Password string `json:"password"`
	// MaxConns caps concurrent connections for this user (0 = unlimited).
	// This is the simplest form of tenant isolation: one noisy customer
	// cannot eat every file descriptor on the box.
	MaxConns int64 `json:"max_conns"`
}

// Exit is one outbound IP address. The proxy binds outgoing connections to
// this address, so the target site sees it as the client's IP.
type Exit struct {
	IP string `json:"ip"`
	// Country is a label used for geo-targeting (e.g. "de"). In a real
	// network it would come from a geo-IP database or the upstream provider.
	Country string `json:"country"`
}

// Timeouts bound every phase of a connection's life.
type Timeouts struct {
	Handshake Duration `json:"handshake"` // client must finish auth + request within this
	Dial      Duration `json:"dial"`      // connecting to the target
	Idle      Duration `json:"idle"`      // no bytes in either direction for this long -> close
}

// Health configures active health checks of exit IPs.
type Health struct {
	// Target is a host:port that should always be reachable (e.g.
	// "1.1.1.1:443"). Empty disables active checks and every exit is healthy.
	Target   string   `json:"target"`
	Interval Duration `json:"interval"`
	Timeout  Duration `json:"timeout"`
}

// Duration lets JSON use "30s" / "5m" instead of nanosecond integers.
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"30s\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

// Load reads, defaults and validates a config file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields() // catch typos like "max_con"
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	c.ApplyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// ApplyDefaults fills in anything left empty.
func (c *Config) ApplyDefaults() {
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	def := func(d *Duration, v time.Duration) {
		if d.Duration == 0 {
			d.Duration = v
		}
	}
	def(&c.Timeouts.Handshake, 10*time.Second)
	def(&c.Timeouts.Dial, 10*time.Second)
	def(&c.Timeouts.Idle, 5*time.Minute)
	def(&c.Health.Interval, 15*time.Second)
	def(&c.Health.Timeout, 3*time.Second)
	def(&c.SessionTTL, 10*time.Minute)
}

// Validate rejects configs that would fail at runtime.
func (c *Config) Validate() error {
	if len(c.Users) == 0 {
		return errors.New("config: at least one user is required")
	}
	seen := map[string]bool{}
	for _, u := range c.Users {
		if u.Name == "" || u.Password == "" {
			return errors.New("config: every user needs a name and a password")
		}
		// '-' separates options in the proxy username (alice-session-x),
		// so it cannot appear in the account name itself.
		if strings.Contains(u.Name, "-") {
			return fmt.Errorf("config: user %q: names cannot contain '-'", u.Name)
		}
		if seen[u.Name] {
			return fmt.Errorf("config: duplicate user %q", u.Name)
		}
		seen[u.Name] = true
	}
	if len(c.Exits) == 0 {
		return errors.New("config: at least one exit IP is required")
	}
	for _, e := range c.Exits {
		if net.ParseIP(e.IP) == nil {
			return fmt.Errorf("config: exit %q is not an IP address", e.IP)
		}
	}
	return nil
}
