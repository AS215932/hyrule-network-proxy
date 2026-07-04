package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AS215932/hyrule-network-proxy/internal/config"
	"github.com/AS215932/hyrule-network-proxy/internal/metrics"
	"github.com/AS215932/hyrule-network-proxy/internal/transport"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	cfg := config.Config{
		APIListenAddr:        "127.0.0.1:0",
		MetricsListenAddr:    "127.0.0.1:0",
		AuthToken:            "secret",
		TorSOCKSAddr:         "127.0.0.1:1",
		I2PHTTPProxy:         "http://127.0.0.1:1",
		Yggdrasil:            false,
		MaxRequestBodyBytes:  65536,
		MaxResponseBodyBytes: 65536,
		DefaultTimeout:       15 * time.Second,
		MaxTimeout:           60 * time.Second,
		MaxRedirects:         3,
		LogLevel:             "info",
	}
	client, err := transport.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return New(cfg, client, metrics.New())
}

func TestAPIRequiresAuth(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	rr := httptest.NewRecorder()
	s.APIRouter().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestHealthWithAuth(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rr := httptest.NewRecorder()
	s.APIRouter().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestRequestEmitsMetrics(t *testing.T) {
	s := testServer(t)
	// Direct request to a loopback target is denied by the SSRF guard (403),
	// which drives both the request counter and the policy-denial counter.
	body := strings.NewReader(`{"url":"http://127.0.0.1:8080","method":"GET","proxy_mode":"direct"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/request", body)
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.APIRouter().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("handler should return 200 envelope, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := testutil.CollectAndCount(s.metrics.RequestsTotal); got != 1 {
		t.Fatalf("expected 1 request metric series, got %d", got)
	}
	if got := testutil.CollectAndCount(s.metrics.PolicyDenialsTotal); got != 1 {
		t.Fatalf("expected 1 policy-denial metric series, got %d", got)
	}
	if v := testutil.ToFloat64(s.metrics.RequestsTotal.WithLabelValues("direct", "4xx")); v != 1 {
		t.Fatalf("expected requests_total{direct,4xx}=1, got %v", v)
	}
}

func TestMetricsRouteMethodScoped(t *testing.T) {
	s := testServer(t)

	get := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	getRR := httptest.NewRecorder()
	s.MetricsRouter().ServeHTTP(getRR, get)
	if getRR.Code != http.StatusOK {
		t.Fatalf("GET /metrics expected 200, got %d", getRR.Code)
	}

	post := httptest.NewRequest(http.MethodPost, "/metrics", nil)
	postRR := httptest.NewRecorder()
	s.MetricsRouter().ServeHTTP(postRR, post)
	if postRR.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /metrics expected 405, got %d", postRR.Code)
	}
}
