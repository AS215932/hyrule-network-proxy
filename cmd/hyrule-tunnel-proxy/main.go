// Command hyrule-tunnel-proxy is the public reverse-SSH tunnel daemon. Hosts
// behind NAT run `ssh -R 0:localhost:22 <lease-token>@tun.hyrule.host -p 2222`
// and become reachable on a public TCP port. Hyrule Cloud verifies and settles
// the x402 payment and calls this daemon's internal control API to mint leases;
// this daemon owns the public SSH intake, per-lease data ports, and a free STUN
// responder. It is a sibling binary to hyrule-network-proxy but a separate
// process with its own user and token.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	nconfig "github.com/AS215932/hyrule-network-proxy/internal/config"
	"github.com/AS215932/hyrule-network-proxy/internal/tunnel"
	"github.com/AS215932/hyrule-network-proxy/internal/tunnel/config"
	"github.com/AS215932/hyrule-network-proxy/internal/tunnel/control"
	"github.com/AS215932/hyrule-network-proxy/internal/tunnel/lease"
	"github.com/AS215932/hyrule-network-proxy/internal/tunnel/metrics"
	"github.com/AS215932/hyrule-network-proxy/internal/tunnel/sshd"
	"github.com/AS215932/hyrule-network-proxy/internal/tunnel/stun"
	"github.com/AS215932/hyrule-network-proxy/internal/version"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.Load()
	if err != nil {
		slog.Error("config_load_failed", "error", err.Error())
		os.Exit(1)
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: nconfig.ParseLogLevel(cfg.LogLevel)}))
	slog.SetDefault(log)

	store, err := lease.Open(filepath.Join(cfg.StateDir, "leases.db"), cfg.DataPortMin, cfg.DataPortMax)
	if err != nil {
		slog.Error("lease_store_open_failed", "error", err.Error())
		os.Exit(1)
	}
	defer store.Close()

	m := metrics.New()

	sshServer, err := sshd.New(sshd.Config{
		ListenAddr:              cfg.SSHListenAddr,
		HostKeyPath:             cfg.HostKeyPath,
		EndpointHost:            cfg.EndpointHost,
		SSHPort:                 cfg.SSHPort,
		MaxVisitorConnsPerLease: cfg.MaxVisitorConnsPerLease,
		KeepaliveInterval:       cfg.KeepaliveInterval,
		AuthAttemptsPerWindow:   cfg.AuthAttemptsPerWindow,
		AuthWindow:              cfg.AuthWindow,
	}, store, m, log)
	if err != nil {
		slog.Error("ssh_server_init_failed", "error", err.Error())
		os.Exit(1)
	}

	coord := tunnel.NewCoordinator(cfg, store, sshServer.Manager(), m, log)
	api := control.New(coord, cfg.AuthToken, m, log)
	stunResponder := stun.New(cfg.STUNListenAddr, m, log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	controlServer := &http.Server{Addr: cfg.ControlListenAddr, Handler: api.Router(), ReadHeaderTimeout: 5 * time.Second}
	metricsServer := &http.Server{Addr: cfg.MetricsListenAddr, Handler: metricsRouter(m, coord), ReadHeaderTimeout: 5 * time.Second}

	go serveHTTP("control", controlServer)
	go serveHTTP("metrics", metricsServer)
	go func() {
		if err := sshServer.ListenAndServe(ctx); err != nil {
			slog.Error("ssh_server_failed", "error", err.Error())
			stop()
		}
	}()
	go func() {
		if err := stunResponder.ListenAndServe(ctx); err != nil {
			slog.Warn("stun_responder_failed", "error", err.Error())
		}
	}()
	go runSweeper(ctx, coord)

	slog.Info("hyrule_tunnel_proxy_started",
		"service", "hyrule-tunnel-proxy",
		"version", version.Version,
		"ssh_listen_addr", cfg.SSHListenAddr,
		"control_listen_addr", cfg.ControlListenAddr,
		"metrics_listen_addr", cfg.MetricsListenAddr,
		"stun_listen_addr", cfg.STUNListenAddr,
		"endpoint_host", cfg.EndpointHost,
		"data_port_range", cfg.DataPortMin,
		"host_key_fingerprint", sshServer.HostKeyFingerprint(),
	)

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = controlServer.Shutdown(shutdownCtx)
	_ = metricsServer.Shutdown(shutdownCtx)
	slog.Info("hyrule_tunnel_proxy_stopped", "service", "hyrule-tunnel-proxy")
}

// runSweeper reaps expired leases every second (time-based expiry, no idle logic).
func runSweeper(ctx context.Context, coord *tunnel.Coordinator) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			coord.SweepExpired()
		}
	}
}

func metricsRouter(m *metrics.Metrics, coord *tunnel.Coordinator) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		coord.RefreshMetrics()
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.Handle("GET /metrics", m.Handler())
	return mux
}

func serveHTTP(name string, srv *http.Server) {
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("http_server_failed", "server", name, "error", err.Error())
		os.Exit(1)
	}
}
