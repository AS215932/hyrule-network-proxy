package sshd

import (
	"sync"
	"time"
)

// authLimiter is a per-source-IP fixed-window rate limiter guarding the SSH
// handshake against lease-token brute force. It is intentionally simple; the
// token's 160-bit entropy is the real defense, this only blunts volume.
type authLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	seen   map[string]*windowCounter
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

	// Opportunistically evict stale entries so the map does not grow unbounded.
	if len(a.seen) > 4096 {
		for k, w := range a.seen {
			if now.Sub(w.start) > a.window {
				delete(a.seen, k)
			}
		}
	}

	w, ok := a.seen[ip]
	if !ok || now.Sub(w.start) > a.window {
		a.seen[ip] = &windowCounter{count: 1, start: now}
		return true
	}
	if w.count >= a.max {
		return false
	}
	w.count++
	return true
}
