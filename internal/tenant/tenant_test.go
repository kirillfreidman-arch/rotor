package tenant

import (
	"errors"
	"testing"

	"github.com/kirillfreidman/rotor/internal/config"
)

func TestParseUsername(t *testing.T) {
	cases := []struct {
		in      string
		want    Options
		wantErr bool
	}{
		{"alice", Options{User: "alice"}, false},
		{"alice-session-abc", Options{User: "alice", Session: "abc"}, false},
		{"alice-country-DE", Options{User: "alice", Country: "de"}, false},
		{"alice-country-de-session-7", Options{User: "alice", Country: "de", Session: "7"}, false},
		{"alice-session", Options{}, true},   // odd number of parts
		{"alice-color-red", Options{}, true}, // unknown key
		{"-session-x", Options{}, true},      // empty user
		{"alice-session-", Options{}, true},  // empty value
	}
	for _, c := range cases {
		got, err := ParseUsername(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("%q: err = %v, wantErr %v", c.in, err, c.wantErr)
			continue
		}
		if !c.wantErr && got != c.want {
			t.Errorf("%q: got %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestAuthenticate(t *testing.T) {
	r := NewRegistry([]config.User{{Name: "alice", Password: "pw"}})
	if _, o, err := r.Authenticate("alice-session-1", "pw"); err != nil || o.Session != "1" {
		t.Fatalf("valid login failed: %v %+v", err, o)
	}
	for _, c := range [][2]string{{"alice", "nope"}, {"bob", "pw"}, {"alice-bad", "pw"}} {
		if _, _, err := r.Authenticate(c[0], c[1]); !errors.Is(err, ErrAuth) {
			t.Errorf("%v: want ErrAuth, got %v", c, err)
		}
	}
}

func TestAcquireLimit(t *testing.T) {
	r := NewRegistry([]config.User{{Name: "a", Password: "p", MaxConns: 2}})
	tn, _, _ := r.Authenticate("a", "p")
	if !tn.Acquire() || !tn.Acquire() {
		t.Fatal("first two acquires should succeed")
	}
	if tn.Acquire() {
		t.Fatal("third acquire should fail at MaxConns=2")
	}
	tn.Release()
	if !tn.Acquire() {
		t.Fatal("acquire after release should succeed")
	}
	if tn.Rejected.Load() != 1 {
		t.Fatalf("rejected = %d, want 1", tn.Rejected.Load())
	}
}
