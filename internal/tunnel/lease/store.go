// Package lease owns tunnel lease state: the lease model, crash-safe bbolt
// persistence, and the public data-port allocator. Hyrule Cloud is the billing
// authority; this store is the daemon's local, low-latency source of truth for
// SSH auth and port assignment, reconciled against the cloud on startup.
package lease

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

const (
	StatusActive  = "active"
	StatusExpired = "expired"
	StatusRevoked = "revoked"
)

var bucketName = []byte("leases")

// tokenEncoding is lowercase base32 without padding: SSH-username-safe and
// case-insensitive-clean for humans copying it into an ssh command.
var tokenEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// Lease is a single reverse-tunnel reservation.
type Lease struct {
	LeaseID        string    `json:"lease_id"`
	Token          string    `json:"token"`
	AllocatedPort  int       `json:"allocated_port"`
	AllowlistCIDRs []string  `json:"allowlist_cidrs,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	Status         string    `json:"status"`
}

// Expired reports whether the lease is past its expiry at now.
func (l Lease) Expired(now time.Time) bool { return !now.Before(l.ExpiresAt) }

// AllowsIP reports whether a visitor source IP may connect. An empty allowlist
// means open to all (the firewall is open-by-default for the data range).
func (l Lease) AllowsIP(ip net.IP) bool {
	if len(l.AllowlistCIDRs) == 0 {
		return true
	}
	for _, c := range l.AllowlistCIDRs {
		_, n, err := net.ParseCIDR(c)
		if err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// CreateParams is the input to Create.
type CreateParams struct {
	LeaseID        string
	Duration       time.Duration
	AllowlistCIDRs []string
}

// Store holds leases in memory (indexed by id and token) backed by bbolt.
type Store struct {
	mu      sync.RWMutex
	db      *bolt.DB
	byID    map[string]*Lease
	byToken map[string]*Lease
	alloc   *portAllocator
}

// Open loads the lease store from dbPath, reserving ports for every live lease
// and pruning any lease that is already expired or revoked. minPort/maxPort
// bound the data-port range.
func Open(dbPath string, minPort, maxPort int) (*Store, error) {
	db, err := bolt.Open(dbPath, 0o600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open lease db: %w", err)
	}
	s := &Store{
		db:      db,
		byID:    make(map[string]*Lease),
		byToken: make(map[string]*Lease),
		alloc:   newPortAllocator(minPort, maxPort),
	}
	now := time.Now()
	if err := db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketName)
		if err != nil {
			return err
		}
		var stale [][]byte
		if err := b.ForEach(func(k, v []byte) error {
			var l Lease
			if err := json.Unmarshal(v, &l); err != nil {
				stale = append(stale, append([]byte(nil), k...))
				return nil
			}
			if l.Status != StatusActive || l.Expired(now) {
				stale = append(stale, append([]byte(nil), k...))
				return nil
			}
			// Prune a lease whose port is now outside the configured range (the
			// range was narrowed/moved since it was minted): binding it would
			// listen outside the public firewall range or advertise an
			// unreachable port. Drop it rather than retain it as active.
			if l.AllocatedPort < minPort || l.AllocatedPort > maxPort {
				stale = append(stale, append([]byte(nil), k...))
				return nil
			}
			cp := l
			s.byID[l.LeaseID] = &cp
			s.byToken[l.Token] = &cp
			s.alloc.reserve(l.AllocatedPort)
			return nil
		}); err != nil {
			return err
		}
		for _, k := range stale {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Create allocates a port and mints a token for a new lease. It is idempotent
// on LeaseID: a repeated create for an existing lease returns it unchanged, so a
// cloud retry after a settle hiccup never double-allocates a port.
func (s *Store) Create(p CreateParams) (Lease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.byID[p.LeaseID]; ok {
		return *existing, nil
	}
	// Fail closed: reject a malformed allowlist rather than allocate a lease
	// whose restriction silently parses to nothing.
	for _, c := range p.AllowlistCIDRs {
		if _, _, err := net.ParseCIDR(c); err != nil {
			return Lease{}, fmt.Errorf("%w: %q", ErrInvalidCIDR, c)
		}
	}
	port, err := s.alloc.allocate()
	if err != nil {
		return Lease{}, err
	}
	token, err := mintToken()
	if err != nil {
		s.alloc.release(port)
		return Lease{}, err
	}
	now := time.Now()
	l := &Lease{
		LeaseID:        p.LeaseID,
		Token:          token,
		AllocatedPort:  port,
		AllowlistCIDRs: p.AllowlistCIDRs,
		CreatedAt:      now,
		ExpiresAt:      now.Add(p.Duration),
		Status:         StatusActive,
	}
	if err := s.persist(l); err != nil {
		s.alloc.release(port)
		return Lease{}, err
	}
	s.byID[l.LeaseID] = l
	s.byToken[l.Token] = l
	return *l, nil
}

// Extend pushes a lease's expiry out by d and returns the new expiry. The new
// expiry is persisted BEFORE the in-memory copy is mutated, so a persistence
// failure leaves SSH auth and the sweeper honoring the old (paid-for) expiry
// rather than granting unbilled extra time until restart.
func (s *Store) Extend(id string, d time.Duration) (Lease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.byID[id]
	if !ok {
		return Lease{}, ErrNotFound
	}
	updated := *l
	updated.ExpiresAt = l.ExpiresAt.Add(d)
	if err := s.persist(&updated); err != nil {
		return Lease{}, err
	}
	l.ExpiresAt = updated.ExpiresAt
	return *l, nil
}

// Revoke removes a lease and frees its port. Returns ErrNotFound if absent.
func (s *Store) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.remove(id, StatusRevoked)
}

// MarkExpired removes a lease that has passed its expiry, freeing its port.
func (s *Store) MarkExpired(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.remove(id, StatusExpired)
}

// MarkExpiredIfBefore rechecks a lease's expiry under the lock and, if it still
// expires at or before cutoff, deletes it. It reports (wasExpired, removed):
// wasExpired distinguishes "still expired" from "renewed since the snapshot" so
// the caller tears the forward down even when the row delete failed (a bbolt
// error must not leave an expired public listener serving); removed reports
// whether the persisted row was actually deleted.
func (s *Store) MarkExpiredIfBefore(id string, cutoff time.Time) (wasExpired, removed bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.byID[id]
	if !ok {
		return false, false, nil
	}
	if l.ExpiresAt.After(cutoff) {
		return false, false, nil // renewed since the snapshot
	}
	if err := s.remove(id, StatusExpired); err != nil {
		return true, false, err // still expired, but the row delete failed
	}
	return true, true, nil
}

// remove deletes a lease from bbolt FIRST, then from the in-memory indexes and
// the port allocator. Deleting the persisted row before releasing the port
// prevents a later create from reusing the port while the old row is still on
// disk (which would rehydrate two leases on one port after a restart). On a
// bbolt failure the in-memory state is left intact so nothing is lost.
// The status arg is advisory; the row is deleted either way since the daemon
// keeps only live leases.
func (s *Store) remove(id, _ string) error {
	l, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b == nil {
			return nil
		}
		return b.Delete([]byte(id))
	}); err != nil {
		return err
	}
	delete(s.byID, id)
	delete(s.byToken, l.Token)
	s.alloc.release(l.AllocatedPort)
	return nil
}

// Get returns a lease by id.
func (s *Store) Get(id string) (Lease, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	l, ok := s.byID[id]
	if !ok {
		return Lease{}, false
	}
	return *l, true
}

// ByToken returns the live lease whose token matches, using a constant-time
// compare on the candidate to avoid leaking token bytes via timing.
func (s *Store) ByToken(token string) (Lease, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	l, ok := s.byToken[token]
	if !ok {
		return Lease{}, false
	}
	if subtle.ConstantTimeCompare([]byte(l.Token), []byte(token)) != 1 {
		return Lease{}, false
	}
	return *l, true
}

// List returns all live leases sorted by id for stable output.
func (s *Store) List() []Lease {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Lease, 0, len(s.byID))
	for _, l := range s.byID {
		out = append(out, *l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LeaseID < out[j].LeaseID })
	return out
}

// ExpiredBefore returns the ids of leases that have expired at or before now.
func (s *Store) ExpiredBefore(now time.Time) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var ids []string
	for id, l := range s.byID {
		if l.Expired(now) {
			ids = append(ids, id)
		}
	}
	return ids
}

// Stats returns the count of live leases and the count of free data ports.
func (s *Store) Stats() (active, freePorts int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID), s.alloc.free()
}

func (s *Store) persist(l *Lease) error {
	data, err := json.Marshal(l)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b == nil {
			return fmt.Errorf("leases bucket missing")
		}
		return b.Put([]byte(l.LeaseID), data)
	})
}

// mintToken returns a 160-bit lowercase-base32 token (32 chars).
func mintToken() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return tokenEncoding.EncodeToString(buf), nil
}

// ErrNotFound is returned when a lease id is unknown.
var ErrNotFound = fmt.Errorf("lease not found")

// ErrPortsExhausted is returned when the data-port range has no free port.
var ErrPortsExhausted = fmt.Errorf("no free data ports")

// ErrInvalidCIDR is returned when a lease allowlist entry is not a valid CIDR.
var ErrInvalidCIDR = fmt.Errorf("invalid allowlist CIDR")
