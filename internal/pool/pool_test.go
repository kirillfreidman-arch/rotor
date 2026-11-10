package pool

import (
	"errors"
	"testing"
	"time"

	"github.com/kirillfreidman/rotor/internal/config"
)

func testPool() *Pool {
	return New([]config.Exit{
		{IP: "127.0.0.2", Country: "de"},
		{IP: "127.0.0.3", Country: "de"},
		{IP: "127.0.0.4", Country: "us"},
	}, Options{DialTimeout: time.Second, SessionTTL: time.Minute})
}

func TestRotationCyclesAllExits(t *testing.T) {
	p := testPool()
	seen := map[string]int{}
	for i := 0; i < 9; i++ {
		e, err := p.Pick("alice", "", "")
		if err != nil {
			t.Fatal(err)
		}
		seen[e.IP.String()]++
	}
	for ip, n := range seen {
		if n != 3 {
			t.Errorf("%s picked %d times, want 3 (even round robin)", ip, n)
		}
	}
}

func TestCountryFilter(t *testing.T) {
	p := testPool()
	for i := 0; i < 5; i++ {
		e, _ := p.Pick("alice", "", "us")
		if e.IP.String() != "127.0.0.4" {
			t.Fatalf("country us gave %s", e.IP)
		}
	}
	if _, err := p.Pick("alice", "", "fr"); !errors.Is(err, ErrNoExit) {
		t.Fatalf("unknown country: want ErrNoExit, got %v", err)
	}
}

func TestStickySession(t *testing.T) {
	p := testPool()
	first, _ := p.Pick("alice", "s1", "")
	for i := 0; i < 10; i++ {
		if e, _ := p.Pick("alice", "s1", ""); e != first {
			t.Fatalf("sticky session moved from %s to %s", first.IP, e.IP)
		}
	}
	// Same session name, different user: must be independent.
	p.Pick("bob", "s1", "") // advance the cursor
	if p.Sessions() != 2 {
		t.Fatalf("sessions = %d, want 2", p.Sessions())
	}
}

func TestStickySessionExpires(t *testing.T) {
	p := testPool()
	now := time.Unix(0, 0)
	p.now = func() time.Time { return now }

	first, _ := p.Pick("alice", "s1", "")
	now = now.Add(2 * time.Minute) // past the 1m TTL
	p.expire()
	if p.Sessions() != 0 {
		t.Fatal("expired session not removed")
	}
	second, _ := p.Pick("alice", "s1", "")
	if first == second {
		t.Fatal("expected a fresh exit after expiry (round robin moved on)")
	}
}

func TestUnhealthyExitIsSkippedAndSessionMoves(t *testing.T) {
	p := testPool()
	sticky, _ := p.Pick("alice", "s1", "de")

	for i := 0; i < 3; i++ { // 3 failed checks -> unhealthy
		sticky.checkResult(false)
	}
	if sticky.Healthy() {
		t.Fatal("exit should be unhealthy after 3 failures")
	}
	for i := 0; i < 6; i++ {
		if e, _ := p.Pick("alice", "", ""); e == sticky {
			t.Fatal("unhealthy exit was picked")
		}
	}
	if e, _ := p.Pick("alice", "s1", "de"); e == sticky {
		t.Fatal("sticky session should move off a dead exit")
	}

	sticky.checkResult(true)
	if sticky.Healthy() {
		t.Fatal("one success should not be enough to recover (hysteresis)")
	}
	sticky.checkResult(true)
	if !sticky.Healthy() {
		t.Fatal("two successes should recover the exit")
	}
}

func TestAllUnhealthy(t *testing.T) {
	p := testPool()
	for _, e := range p.Exits() {
		for i := 0; i < 3; i++ {
			e.checkResult(false)
		}
	}
	if _, err := p.Pick("alice", "", ""); !errors.Is(err, ErrNoExit) {
		t.Fatalf("want ErrNoExit, got %v", err)
	}
}

func TestGuardTarget(t *testing.T) {
	blocked := []string{"127.0.0.1:80", "10.1.2.3:80", "192.168.1.1:443", "169.254.169.254:80",
		"[::1]:80", "[::ffff:127.0.0.1]:80", "100.64.0.1:80", "[fe80::1]:80", "0.0.0.0:80"}
	for _, a := range blocked {
		if err := guardTarget("tcp", a, nil); !errors.Is(err, ErrForbiddenTarget) {
			t.Errorf("%s should be blocked", a)
		}
	}
	for _, a := range []string{"1.1.1.1:443", "[2606:4700:4700::1111]:443"} {
		if err := guardTarget("tcp", a, nil); err != nil {
			t.Errorf("%s should be allowed, got %v", a, err)
		}
	}
}
