// Package tunnel wires the lease store to the SSH forward manager and backs the
// control API. It is the daemon's application core: create/extend/revoke a
// lease, project a lease into its wire response (folding in live connection
// stats), and sweep expired leases.
package tunnel

import (
	"log/slog"
	"time"

	"github.com/AS215932/hyrule-network-proxy/internal/tunnel/config"
	"github.com/AS215932/hyrule-network-proxy/internal/tunnel/contract"
	"github.com/AS215932/hyrule-network-proxy/internal/tunnel/lease"
	"github.com/AS215932/hyrule-network-proxy/internal/tunnel/metrics"
	"github.com/AS215932/hyrule-network-proxy/internal/tunnel/sshd"
	"github.com/AS215932/hyrule-network-proxy/internal/version"
)

// Coordinator is the application core shared by the control API and the sweeper.
type Coordinator struct {
	cfg     config.Config
	store   *lease.Store
	manager *sshd.Manager
	metrics *metrics.Metrics
	log     *slog.Logger
}

func NewCoordinator(cfg config.Config, store *lease.Store, mgr *sshd.Manager, m *metrics.Metrics, log *slog.Logger) *Coordinator {
	c := &Coordinator{cfg: cfg, store: store, manager: mgr, metrics: m, log: log}
	c.RefreshMetrics()
	return c
}

// CreateLease provisions a new lease, clamping duration to the configured
// bounds. It is idempotent on lease_id via the store.
func (c *Coordinator) CreateLease(req contract.CreateLeaseRequest) (contract.LeaseResponse, error) {
	dur := c.clampDuration(req.DurationSeconds)
	l, err := c.store.Create(lease.CreateParams{
		LeaseID:        req.LeaseID,
		Duration:       dur,
		AllowlistCIDRs: req.AllowlistCIDRs,
	})
	if err != nil {
		c.metrics.Reconcile.WithLabelValues("create_failed").Inc()
		return contract.LeaseResponse{}, err
	}
	c.metrics.Reconcile.WithLabelValues("created").Inc()
	c.RefreshMetrics()
	return c.toResponse(l, true), nil
}

// ExtendLease pushes a lease's expiry out by the (clamped) duration.
func (c *Coordinator) ExtendLease(id string, req contract.ExtendLeaseRequest) (contract.LeaseResponse, error) {
	dur := c.clampDuration(req.DurationSeconds)
	l, err := c.store.Extend(id, dur)
	if err != nil {
		return contract.LeaseResponse{}, err
	}
	c.metrics.Reconcile.WithLabelValues("extended").Inc()
	return c.toResponse(l, false), nil
}

// RevokeLease deletes the lease from the store FIRST, then tears down the
// forward. Removing it from the store before teardown means a concurrent
// tcpip-forward (which re-checks the store under the manager lock in
// StartForward) can no longer install a listener for the revoked lease.
func (c *Coordinator) RevokeLease(id string) error {
	if err := c.store.Revoke(id); err != nil {
		return err
	}
	c.manager.Teardown(id)
	c.metrics.Reconcile.WithLabelValues("revoked").Inc()
	c.RefreshMetrics()
	return nil
}

// GetLease returns a lease projection, or false if unknown.
func (c *Coordinator) GetLease(id string) (contract.LeaseResponse, bool) {
	l, ok := c.store.Get(id)
	if !ok {
		return contract.LeaseResponse{}, false
	}
	return c.toResponse(l, false), true
}

// ListLeases returns projections of all live leases (no tokens).
func (c *Coordinator) ListLeases() []contract.LeaseResponse {
	leases := c.store.List()
	out := make([]contract.LeaseResponse, 0, len(leases))
	for _, l := range leases {
		out = append(out, c.toResponse(l, false))
	}
	return out
}

// Health returns the daemon health projection.
func (c *Coordinator) Health() contract.HealthResponse {
	active, free := c.store.Stats()
	return contract.HealthResponse{
		Status:       "ok",
		Service:      "hyrule-tunnel-proxy",
		Version:      version.Version,
		ActiveLeases: active,
		FreePorts:    free,
	}
}

// SweepExpired tears down and deletes every lease past its expiry, returning the
// number reaped. Belt-and-braces with the cloud worker, which also revokes.
//
// The store is updated BEFORE the forward is torn down so activation (which
// re-checks the store under the manager lock) cannot race a listener back in
// after teardown. Deletion is conditional on the lease still being expired at
// the sweep cutoff, so an extension that lands between the snapshot and the
// delete is not clobbered.
func (c *Coordinator) SweepExpired() int {
	cutoff := time.Now()
	ids := c.store.ExpiredBefore(cutoff)
	reaped := 0
	for _, id := range ids {
		removed, err := c.store.MarkExpiredIfBefore(id, cutoff)
		if err != nil || !removed {
			continue // a renewal landed, or already gone — leave it be
		}
		c.manager.Teardown(id)
		c.metrics.Reconcile.WithLabelValues("expired").Inc()
		reaped++
	}
	if reaped > 0 {
		c.RefreshMetrics()
	}
	return reaped
}

// RefreshMetrics updates the lease/port gauges from store state.
func (c *Coordinator) RefreshMetrics() {
	active, free := c.store.Stats()
	c.metrics.LeasesActive.Set(float64(active))
	c.metrics.PortsFree.Set(float64(free))
}

func (c *Coordinator) clampDuration(seconds int64) time.Duration {
	if seconds < c.cfg.MinLeaseSeconds {
		seconds = c.cfg.MinLeaseSeconds
	}
	if seconds > c.cfg.MaxLeaseSeconds {
		seconds = c.cfg.MaxLeaseSeconds
	}
	return time.Duration(seconds) * time.Second
}

func (c *Coordinator) toResponse(l lease.Lease, includeToken bool) contract.LeaseResponse {
	connected, visitors, bytesIn, bytesOut := c.manager.Stats(l.LeaseID)
	resp := contract.LeaseResponse{
		LeaseID:      l.LeaseID,
		Port:         l.AllocatedPort,
		EndpointHost: c.cfg.EndpointHost,
		SSHPort:      c.cfg.SSHPort,
		Status:       l.Status,
		ExpiresAt:    l.ExpiresAt,
		Connected:    connected,
		VisitorConns: visitors,
		BytesIn:      bytesIn,
		BytesOut:     bytesOut,
	}
	if includeToken {
		resp.Token = l.Token
	}
	return resp
}
