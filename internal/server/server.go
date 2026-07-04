package server

import (
	"net/http"

	"github.com/AS215932/hyrule-network-proxy/internal/config"
	"github.com/AS215932/hyrule-network-proxy/internal/metrics"
	"github.com/AS215932/hyrule-network-proxy/internal/transport"
)

type Server struct {
	cfg     config.Config
	client  *transport.Client
	metrics *metrics.Metrics
}

func New(cfg config.Config, client *transport.Client, m *metrics.Metrics) *Server {
	return &Server{cfg: cfg, client: client, metrics: m}
}

func (s *Server) APIRouter() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.withAuth(s.handleHealth))
	mux.HandleFunc("GET /v1/modes", s.withAuth(s.handleModes))
	mux.HandleFunc("POST /v1/request", s.withAuth(s.handleRequest))
	return mux
}

func (s *Server) MetricsRouter() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.Handle("GET /metrics", metrics.Handler(s.metrics.Registry))
	return mux
}
