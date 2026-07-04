package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AS215932/hyrule-network-proxy/internal/config"
	"github.com/AS215932/hyrule-network-proxy/internal/metrics"
	"github.com/AS215932/hyrule-network-proxy/internal/server"
	"github.com/AS215932/hyrule-network-proxy/internal/transport"
	"github.com/AS215932/hyrule-network-proxy/internal/version"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.Load()
	if err != nil {
		slog.Error("config_load_failed", "error", err.Error())
		os.Exit(1)
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: config.ParseLogLevel(cfg.LogLevel)})))

	client, err := transport.NewClient(cfg)
	if err != nil {
		slog.Error("client_init_failed", "error", err.Error())
		os.Exit(1)
	}
	m := metrics.New()
	srv := server.New(cfg, client, m)

	apiServer := &http.Server{
		Addr:              cfg.APIListenAddr,
		Handler:           srv.APIRouter(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	metricsServer := &http.Server{
		Addr:              cfg.MetricsListenAddr,
		Handler:           srv.MetricsRouter(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go serve("api", apiServer)
	go serve("metrics", metricsServer)

	slog.Info("hyrule_network_proxy_started",
		"service", "hyrule-network-proxy",
		"version", version.Version,
		"api_listen_addr", cfg.APIListenAddr,
		"metrics_listen_addr", cfg.MetricsListenAddr,
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	<-ctx.Done()
	stop()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = apiServer.Shutdown(shutdownCtx)
	_ = metricsServer.Shutdown(shutdownCtx)
	slog.Info("hyrule_network_proxy_stopped", "service", "hyrule-network-proxy")
}

func serve(name string, srv *http.Server) {
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("http_server_failed", "server", name, "error", err.Error())
		os.Exit(1)
	}
}
