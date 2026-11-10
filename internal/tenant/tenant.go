// Package tenant handles customers: authentication, the options they pass in
// their proxy username, per-user connection limits and bandwidth metering.
package tenant

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/kirillfreidman/rotor/internal/config"
)

// Options are the routing options a client encodes in its proxy username.
//
// This is the convention most commercial proxy networks use, because every
// client (curl, browsers, scrapers, SOCKS libraries) can already send a
// username, while custom headers are impossible for SOCKS5 and for HTTPS
// tunnels. Format:
//
//	alice                              rotate on every connection
//	alice-session-abc123               sticky: same exit IP while the session lives
//	alice-country-de                   only use exits labelled "de"
//	alice-country-de-session-abc123    both
type Options struct {
	User    string
	Session string
	Country string
}

// ParseUsername splits "alice-country-de-session-x" into Options.
func ParseUsername(s string) (Options, error) {
	parts := strings.Split(s, "-")
	o := Options{User: parts[0]}
	if o.User == "" {
		return o, errors.New("empty username")
	}
	rest := parts[1:]
	if len(rest)%2 != 0 {
		return o, fmt.Errorf("options must be key-value pairs, got %q", s)
	}
	for i := 0; i < len(rest); i += 2 {
		k, v := rest[i], rest[i+1]
		if v == "" {
			return o, fmt.Errorf("empty value for %q", k)
		}
		switch k {
		case "session":
			o.Session = v
		case "country":
			o.Country = strings.ToLower(v)
		default:
			return o, fmt.Errorf("unknown option %q", k)
		}
	}
	return o, nil
}

// Tenant is one customer plus its live counters. All counters are atomics:
// they are touched on every chunk of every connection, so a mutex here would
// become a point of contention between cores.
type Tenant struct {
	Name     string
	password []byte
	maxConns int64

	active    atomic.Int64
	BytesUp   atomic.Uint64 // client -> target
	BytesDown atomic.Uint64 // target -> client
	Conns     atomic.Uint64 // accepted connections/requests
	Rejected  atomic.Uint64 // refused because of MaxConns
}

// Acquire reserves a connection slot. It returns false when the tenant is at
// its limit. The compare-and-swap loop makes check-and-increment atomic
// without a lock.
func (t *Tenant) Acquire() bool {
	if t.maxConns <= 0 {
		t.active.Add(1)
		t.Conns.Add(1)
		return true
	}
	for {
		cur := t.active.Load()
		if cur >= t.maxConns {
			t.Rejected.Add(1)
			return false
		}
		if t.active.CompareAndSwap(cur, cur+1) {
			t.Conns.Add(1)
			return true
		}
	}
}

// Release frees a slot taken by Acquire.
func (t *Tenant) Release() { t.active.Add(-1) }

// Active is the number of connections currently open.
func (t *Tenant) Active() int64 { return t.active.Load() }

// AddUp / AddDown record metered bytes. Their signature matches the callback
// the relay code takes, so they can be passed directly.
func (t *Tenant) AddUp(n int64)   { t.BytesUp.Add(uint64(n)) }
func (t *Tenant) AddDown(n int64) { t.BytesDown.Add(uint64(n)) }

// Registry holds every tenant. It is built once at startup and never
// modified, so it is safe to read from many goroutines without locking.
type Registry struct {
	byName map[string]*Tenant
}

// ErrAuth is returned for any authentication failure. It deliberately does
// not say whether the user or the password was wrong.
var ErrAuth = errors.New("authentication failed")

func NewRegistry(users []config.User) *Registry {
	r := &Registry{byName: make(map[string]*Tenant, len(users))}
	for _, u := range users {
		r.byName[u.Name] = &Tenant{Name: u.Name, password: []byte(u.Password), maxConns: u.MaxConns}
	}
	return r
}

// Authenticate checks a proxy username (with options) and password.
func (r *Registry) Authenticate(username, password string) (*Tenant, Options, error) {
	opts, err := ParseUsername(username)
	if err != nil {
		return nil, opts, fmt.Errorf("%w: %v", ErrAuth, err)
	}
	t, ok := r.byName[opts.User]
	if !ok {
		return nil, opts, ErrAuth
	}
	// Constant-time compare so response timing does not leak how many
	// leading bytes of a guessed password were correct.
	if subtle.ConstantTimeCompare(t.password, []byte(password)) != 1 {
		return nil, opts, ErrAuth
	}
	return t, opts, nil
}

// All returns tenants sorted by name (for stable metrics output).
func (r *Registry) All() []*Tenant {
	out := make([]*Tenant, 0, len(r.byName))
	for _, t := range r.byName {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
