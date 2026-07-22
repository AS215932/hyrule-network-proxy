// Package control serves the internal, Bearer-authed control API that Hyrule
// Cloud calls to create, extend, revoke, and inspect tunnel leases. It must bind
// only to an internal address; it is never exposed publicly.
package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/AS215932/hyrule-network-proxy/internal/tunnel/contract"
	"github.com/AS215932/hyrule-network-proxy/internal/tunnel/lease"
	"github.com/AS215932/hyrule-network-proxy/internal/tunnel/metrics"
)

const maxControlBodyBytes = 16 << 10

// Service is the lease-management surface the control API needs, implemented by
// tunnel.Coordinator.
type Service interface {
	CreateLease(contract.CreateLeaseRequest) (contract.LeaseResponse, error)
	ExtendLease(id string, req contract.ExtendLeaseRequest) (contract.LeaseResponse, error)
	RevokeLease(id string) error
	GetLease(id string) (contract.LeaseResponse, bool)
	ListLeases() []contract.LeaseResponse
	Health() contract.HealthResponse
}

type API struct {
	svc     Service
	token   string
	metrics *metrics.Metrics
	log     *slog.Logger
}

func New(svc Service, token string, m *metrics.Metrics, log *slog.Logger) *API {
	return &API{svc: svc, token: token, metrics: m, log: log}
}

func (a *API) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/leases", a.withAuth("create", a.handleCreate))
	mux.HandleFunc("GET /v1/leases", a.withAuth("list", a.handleList))
	mux.HandleFunc("GET /v1/leases/{id}", a.withAuth("get", a.handleGet))
	mux.HandleFunc("POST /v1/leases/{id}/extend", a.withAuth("extend", a.handleExtend))
	mux.HandleFunc("DELETE /v1/leases/{id}", a.withAuth("revoke", a.handleRevoke))
	mux.HandleFunc("GET /v1/health", a.withAuth("health", a.handleHealth))
	return mux
}

func (a *API) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req contract.CreateLeaseRequest
	if err := decodeJSON(r.Body, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.LeaseID == "" {
		writeError(w, http.StatusBadRequest, "lease_id is required")
		return
	}
	if req.DurationSeconds <= 0 {
		writeError(w, http.StatusBadRequest, "duration_seconds must be positive")
		return
	}
	resp, err := a.svc.CreateLease(req)
	if err != nil {
		if errors.Is(err, lease.ErrPortsExhausted) {
			writeError(w, http.StatusServiceUnavailable, "no free tunnel ports")
			return
		}
		a.log.Error("create_lease_failed", "lease_id", req.LeaseID, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "create failed")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *API) handleExtend(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req contract.ExtendLeaseRequest
	if err := decodeJSON(r.Body, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.DurationSeconds <= 0 {
		writeError(w, http.StatusBadRequest, "duration_seconds must be positive")
		return
	}
	resp, err := a.svc.ExtendLease(id, req)
	if err != nil {
		if errors.Is(err, lease.ErrNotFound) {
			writeError(w, http.StatusNotFound, "lease not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "extend failed")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *API) handleRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := a.svc.RevokeLease(id); err != nil {
		if errors.Is(err, lease.ErrNotFound) {
			writeError(w, http.StatusNotFound, "lease not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "revoke failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) handleGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	resp, ok := a.svc.GetLease(id)
	if !ok {
		writeError(w, http.StatusNotFound, "lease not found")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *API) handleList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, contract.ListLeasesResponse{Leases: a.svc.ListLeases()})
}

func (a *API) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.svc.Health())
}

func (a *API) record(op string, code int) {
	a.metrics.ControlRequests.WithLabelValues(op, strconv.Itoa(code)).Inc()
}

func decodeJSON(r io.Reader, out any) error {
	data, err := io.ReadAll(io.LimitReader(r, maxControlBodyBytes+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > maxControlBodyBytes {
		return fmt.Errorf("request body too large")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, contract.ErrorResponse{Error: msg})
}
