// Package contract defines the JSON wire types for the hyrule-tunnel-proxy
// control API. Hyrule Cloud is the sole authorized caller; these types are the
// shared contract between the Go daemon and the Python provider client.
package contract

import "time"

// CreateLeaseRequest is the body of POST /v1/leases. The lease_id is supplied
// by Hyrule Cloud and is the idempotency key: a repeated create for an existing
// id returns the same token and port rather than allocating a second one.
type CreateLeaseRequest struct {
	LeaseID         string   `json:"lease_id"`
	DurationSeconds int64    `json:"duration_seconds"`
	AllowlistCIDRs  []string `json:"allowlist_cidrs,omitempty"`
}

// ExtendLeaseRequest is the body of POST /v1/leases/{id}/extend.
type ExtendLeaseRequest struct {
	DurationSeconds int64 `json:"duration_seconds"`
}

// LeaseResponse is returned by create/get and is an element of ListLeasesResponse.
// Token is only ever populated on the create response; get/list omit it so a
// reconcile pull never re-exposes secrets.
type LeaseResponse struct {
	LeaseID      string    `json:"lease_id"`
	Token        string    `json:"token,omitempty"`
	Port         int       `json:"port"`
	EndpointHost string    `json:"endpoint_host"`
	SSHPort      int       `json:"ssh_port"`
	Status       string    `json:"status"`
	ExpiresAt    time.Time `json:"expires_at"`
	Connected    bool      `json:"connected"`
	VisitorConns int       `json:"visitor_conns"`
	BytesIn      int64     `json:"bytes_in"`
	BytesOut     int64     `json:"bytes_out"`
}

// ListLeasesResponse is returned by GET /v1/leases and drives cloud reconcile.
type ListLeasesResponse struct {
	Leases []LeaseResponse `json:"leases"`
}

// HealthResponse is returned by GET /v1/health.
type HealthResponse struct {
	Status       string `json:"status"`
	Service      string `json:"service"`
	Version      string `json:"version"`
	ActiveLeases int    `json:"active_leases"`
	FreePorts    int    `json:"free_ports"`
}

// ErrorResponse is the body for any non-2xx control response.
type ErrorResponse struct {
	Error string `json:"error"`
}
