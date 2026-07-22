package sshd

import (
	"sync"
	"time"
)

// Bounds for the auth limiter's tracking map. cleanupInterval caps how often the
// O(n) eviction scan runs (so a multi-IP flood can't turn every admission into a
// full scan), and hardCap bounds memory: once the map is full of live entries,
// unknown source IPs are refused rather than allowed to grow it without bound.
const (
	authCleanupInterval = 5 * time.Second
	authHardCap         = 65536
)

// authLimiter is a per-source-IP fixed-window rate limiter guarding the SSH
// handshake against lease-token brute force. It is intentionally simple; the
// token's 160-bit entropy is the real defense, this only blunts volume. Cleanup
// is amortized (at most once per authCleanupInterval) and the map is hard-capped
// so a distributed / IPv6-source flood cannot exhaust CPU or memory.
type authLimiter struct {
	mu          sync.Mutex
	max         int
	window      time.Duration
	seen        map[string]*windowCounter
	lastCleanup time.Time
}

type windowCounter struct {
	count int
	start time.Time
}

func newAuthLimiter(max int, window time.Duration) *authLimiter {
	return &authLimiter{max: max, window: window, seen: make(map[string]*windowCounter)}
}

// allow reports whether another attempt from ip is permitted right now.
func (a *authLimiter) allow(ip string) bool {
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()

	a.maybeCleanup(now)

	w, ok := a.seen[ip]
	if ok && now.Sub(w.start) <= a.window {
		if w.count >= a.max {
			return false
		}
		w.count++
		return true
	}
	// New or expired window for this IP. Guard map growth: if we are at the hard
	// cap and this is an unknown IP, refuse rather than grow unbounded. (A single
	// cleanup already ran above; anything still present is within its window.)
	if !ok && len(a.seen) >= authHardCap {
		return false
	}
	a.seen[ip] = &windowCounter{count: 1, start: now}
	return true
}

// maybeCleanup evicts expired entries at most once per authCleanupInterval, so
// the O(n) scan cost is amortized instead of paid on every connection.
func (a *authLimiter) maybeCleanup(now time.Time) {
	if now.Sub(a.lastCleanup) < authCleanupInterval {
		return
	}
	a.lastCleanup = now
	for k, w := range a.seen {
		if now.Sub(w.start) > a.window {
			delete(a.seen, k)
		}
	}
}
