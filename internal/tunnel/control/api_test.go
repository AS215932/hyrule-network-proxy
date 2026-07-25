package control

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AS215932/hyrule-network-proxy/internal/tunnel/contract"
	"github.com/AS215932/hyrule-network-proxy/internal/tunnel/lease"
	"github.com/AS215932/hyrule-network-proxy/internal/tunnel/metrics"
)

// fakeService is a minimal in-memory Service for control-API tests.
type fakeService struct {
	leases map[string]contract.LeaseResponse
}

func newFake() *fakeService { return &fakeService{leases: map[string]contract.LeaseResponse{}} }

func (f *fakeService) CreateLease(req contract.CreateLeaseRequest) (contract.LeaseResponse, error) {
	if len(f.leases) >= 1 && req.LeaseID == "exhaust" {
		return contract.LeaseResponse{}, lease.ErrPortsExhausted
	}
	r := contract.LeaseResponse{LeaseID: req.LeaseID, Token: "tok-" + req.LeaseID, Port: 10000, EndpointHost: "tun.hyrule.host", SSHPort: 2222, Status: lease.StatusActive, ExpiresAt: time.Now().Add(time.Hour)}
	f.leases[req.LeaseID] = r
	return r, nil
}
func (f *fakeService) ExtendLease(id string, _ contract.ExtendLeaseRequest) (contract.LeaseResponse, error) {
	r, ok := f.leases[id]
	if !ok {
		return contract.LeaseResponse{}, lease.ErrNotFound
	}
	return r, nil
}
func (f *fakeService) RevokeLease(id string) error {
	if _, ok := f.leases[id]; !ok {
		return lease.ErrNotFound
	}
	delete(f.leases, id)
	return nil
}
func (f *fakeService) GetLease(id string) (contract.LeaseResponse, bool) {
	r, ok := f.leases[id]
	return r, ok
}
func (f *fakeService) ListLeases() []contract.LeaseResponse {
	out := []contract.LeaseResponse{}
	for _, r := range f.leases {
		out = append(out, r)
	}
	return out
}
func (f *fakeService) Health() contract.HealthResponse {
	return contract.HealthResponse{Status: "ok", Service: "hyrule-tunnel-proxy", ActiveLeases: len(f.leases)}
}

func testAPI(t *testing.T) http.Handler {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(newFake(), "secret", metrics.New(), log).Router()
}

func do(t *testing.T, h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		buf = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, buf)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestControlRequiresAuth(t *testing.T) {
	h := testAPI(t)
	if rec := do(t, h, "GET", "/v1/health", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: want 401, got %d", rec.Code)
	}
	if rec := do(t, h, "GET", "/v1/health", "wrong", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: want 401, got %d", rec.Code)
	}
	if rec := do(t, h, "GET", "/v1/health", "secret", nil); rec.Code != http.StatusOK {
		t.Fatalf("good token: want 200, got %d", rec.Code)
	}
}

func TestControlCreateValidation(t *testing.T) {
	h := testAPI(t)
	if rec := do(t, h, "POST", "/v1/leases", "secret", map[string]any{"duration_seconds": 3600}); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing lease_id: want 400, got %d", rec.Code)
	}
	if rec := do(t, h, "POST", "/v1/leases", "secret", map[string]any{"lease_id": "a", "duration_seconds": 0}); rec.Code != http.StatusBadRequest {
		t.Fatalf("zero duration: want 400, got %d", rec.Code)
	}
	rec := do(t, h, "POST", "/v1/leases", "secret", contract.CreateLeaseRequest{LeaseID: "a", DurationSeconds: 3600})
	if rec.Code != http.StatusOK {
		t.Fatalf("valid create: want 200, got %d", rec.Code)
	}
	var resp contract.LeaseResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Token == "" || resp.Port == 0 {
		t.Fatalf("create response missing token/port: %+v", resp)
	}
}

func TestControlPortsExhausted(t *testing.T) {
	h := testAPI(t)
	do(t, h, "POST", "/v1/leases", "secret", contract.CreateLeaseRequest{LeaseID: "first", DurationSeconds: 3600})
	rec := do(t, h, "POST", "/v1/leases", "secret", contract.CreateLeaseRequest{LeaseID: "exhaust", DurationSeconds: 3600})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("exhausted: want 503, got %d", rec.Code)
	}
}

func TestControlNotFoundPaths(t *testing.T) {
	h := testAPI(t)
	if rec := do(t, h, "GET", "/v1/leases/missing", "secret", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("get missing: want 404, got %d", rec.Code)
	}
	if rec := do(t, h, "DELETE", "/v1/leases/missing", "secret", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("delete missing: want 404, got %d", rec.Code)
	}
	if rec := do(t, h, "POST", "/v1/leases/missing/extend", "secret", contract.ExtendLeaseRequest{DurationSeconds: 3600}); rec.Code != http.StatusNotFound {
		t.Fatalf("extend missing: want 404, got %d", rec.Code)
	}
}

func TestControlRejectsTrailingJSON(t *testing.T) {
	h := testAPI(t)
	// Valid object followed by trailing data must be rejected, not executed.
	for _, body := range []string{
		`{"lease_id":"x","duration_seconds":3600}]`,
		`{"lease_id":"x","duration_seconds":3600}{"lease_id":"y","duration_seconds":3600}`,
		`{"lease_id":"x","duration_seconds":3600} garbage`,
	} {
		req := httptest.NewRequest("POST", "/v1/leases", bytes.NewReader([]byte(body)))
		req.Header.Set("Authorization", "Bearer secret")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("trailing data %q: want 400, got %d", body, rec.Code)
		}
	}
}

func TestControlLifecycle(t *testing.T) {
	h := testAPI(t)
	do(t, h, "POST", "/v1/leases", "secret", contract.CreateLeaseRequest{LeaseID: "x", DurationSeconds: 3600})
	if rec := do(t, h, "GET", "/v1/leases/x", "secret", nil); rec.Code != http.StatusOK {
		t.Fatalf("get: want 200, got %d", rec.Code)
	}
	if rec := do(t, h, "DELETE", "/v1/leases/x", "secret", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d", rec.Code)
	}
	if rec := do(t, h, "GET", "/v1/leases/x", "secret", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("get after delete: want 404, got %d", rec.Code)
	}
}
