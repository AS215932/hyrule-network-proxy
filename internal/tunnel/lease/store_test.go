package lease

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T, min, max int) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "leases.db"), min, max)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestCreateAllocatesDistinctPortsAndTokens(t *testing.T) {
	s := newTestStore(t, 20000, 20002)
	a, err := s.Create(CreateParams{LeaseID: "a", Duration: time.Hour})
	if err != nil {
		t.Fatalf("create a: %v", err)
	}
	b, err := s.Create(CreateParams{LeaseID: "b", Duration: time.Hour})
	if err != nil {
		t.Fatalf("create b: %v", err)
	}
	if a.AllocatedPort == b.AllocatedPort {
		t.Fatalf("ports collided: %d", a.AllocatedPort)
	}
	if a.Token == b.Token || a.Token == "" {
		t.Fatalf("tokens not distinct/non-empty: %q %q", a.Token, b.Token)
	}
	if len(a.Token) != 32 {
		t.Fatalf("expected 32-char base32 token, got %d", len(a.Token))
	}
}

func TestCreateIsIdempotentOnLeaseID(t *testing.T) {
	s := newTestStore(t, 20000, 20010)
	first, _ := s.Create(CreateParams{LeaseID: "dup", Duration: time.Hour})
	second, err := s.Create(CreateParams{LeaseID: "dup", Duration: 5 * time.Hour})
	if err != nil {
		t.Fatalf("second create: %v", err)
	}
	if first.AllocatedPort != second.AllocatedPort || first.Token != second.Token {
		t.Fatalf("idempotent create changed port/token")
	}
	active, _ := s.Stats()
	if active != 1 {
		t.Fatalf("expected 1 lease, got %d", active)
	}
}

func TestPortsExhausted(t *testing.T) {
	s := newTestStore(t, 20050, 20050) // single port
	if _, err := s.Create(CreateParams{LeaseID: "a", Duration: time.Hour}); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := s.Create(CreateParams{LeaseID: "b", Duration: time.Hour}); err != ErrPortsExhausted {
		t.Fatalf("expected ErrPortsExhausted, got %v", err)
	}
}

func TestByTokenAndExpiry(t *testing.T) {
	s := newTestStore(t, 20060, 20070)
	l, _ := s.Create(CreateParams{LeaseID: "x", Duration: time.Hour})
	got, ok := s.ByToken(l.Token)
	if !ok || got.LeaseID != "x" {
		t.Fatalf("ByToken failed")
	}
	if _, ok := s.ByToken("nope"); ok {
		t.Fatalf("ByToken matched bogus token")
	}
	if l.Expired(time.Now()) {
		t.Fatalf("fresh lease should not be expired")
	}
	if !l.Expired(l.ExpiresAt.Add(time.Second)) {
		t.Fatalf("lease should be expired past ExpiresAt")
	}
}

func TestRevokeFreesPort(t *testing.T) {
	s := newTestStore(t, 20080, 20080)
	l, _ := s.Create(CreateParams{LeaseID: "a", Duration: time.Hour})
	if err := s.Revoke("a"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, ok := s.ByToken(l.Token); ok {
		t.Fatalf("token still valid after revoke")
	}
	// port should be reusable now
	if _, err := s.Create(CreateParams{LeaseID: "b", Duration: time.Hour}); err != nil {
		t.Fatalf("create after revoke: %v", err)
	}
	if err := s.Revoke("missing"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestReloadRehydratesLiveAndPrunesExpired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leases.db")
	s, err := Open(path, 20090, 20100)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	live, _ := s.Create(CreateParams{LeaseID: "live", Duration: time.Hour})
	// Push expiry into the past so the reload path must prune it.
	if _, err := s.Extend("live", -2*time.Hour); err != nil {
		t.Fatalf("extend: %v", err)
	}
	_ = s.Close()

	s2, err := Open(path, 20090, 20100)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	// live lease was pushed into the past, so it should be pruned on reload.
	if _, ok := s2.ByToken(live.Token); ok {
		t.Fatalf("expired lease should have been pruned on reload")
	}
}

func TestExpiredBeforeAndMarkExpired(t *testing.T) {
	s := newTestStore(t, 20110, 20120)
	_, _ = s.Create(CreateParams{LeaseID: "soon", Duration: time.Millisecond})
	time.Sleep(5 * time.Millisecond)
	ids := s.ExpiredBefore(time.Now())
	if len(ids) != 1 || ids[0] != "soon" {
		t.Fatalf("expected [soon], got %v", ids)
	}
	if err := s.MarkExpired("soon"); err != nil {
		t.Fatalf("mark expired: %v", err)
	}
	active, _ := s.Stats()
	if active != 0 {
		t.Fatalf("expected 0 active, got %d", active)
	}
}

func TestAllowsIP(t *testing.T) {
	open := Lease{}
	if !open.AllowsIP(net.ParseIP("203.0.113.5")) {
		t.Fatalf("empty allowlist should allow all")
	}
	restricted := Lease{AllowlistCIDRs: []string{"203.0.113.0/24"}}
	if !restricted.AllowsIP(net.ParseIP("203.0.113.5")) {
		t.Fatalf("in-range IP should be allowed")
	}
	if restricted.AllowsIP(net.ParseIP("198.51.100.1")) {
		t.Fatalf("out-of-range IP should be denied")
	}
}
