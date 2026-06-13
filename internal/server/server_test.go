package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AS215932/hyrule-network-proxy/internal/config"
	"github.com/AS215932/hyrule-network-proxy/internal/metrics"
	"github.com/AS215932/hyrule-network-proxy/internal/transport"
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
