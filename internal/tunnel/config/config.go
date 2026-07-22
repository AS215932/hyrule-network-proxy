// Package config loads the hyrule-tunnel-proxy daemon configuration from HTP_*
// environment variables. It mirrors the network-proxy config loader; log-level
// parsing is reused from the shared internal/config package.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type Config struct {
	// SSHListenAddr is the public SSH intake. ":2222" binds both families via a
	// dual-stack socket, which covers the IPv6 GUA and the DNAT'd IPv4.
	SSHListenAddr string
	// ControlListenAddr is the internal control API (Hyrule Cloud only). Must not
	// be a wildcard bind in production — it is the money path.
	ControlListenAddr string
	MetricsListenAddr string
	STUNListenAddr    string

	// AuthToken gates the control API (Bearer). Distinct from lease tokens.
	AuthToken string

	EndpointHost string // advertised public hostname, e.g. tun.hyrule.host
	SSHPort      int    // advertised public SSH port (post-DNAT), e.g. 2222

	StateDir    string
	HostKeyPath string

	DataPortMin int
	DataPortMax int

	MinLeaseSeconds int64
	MaxLeaseSeconds int64

	MaxVisitorConnsPerLease int

	AuthAttemptsPerWindow int
	AuthWindow            time.Duration
	KeepaliveInterval     time.Duration

	LogLevel string
}

func Load() (Config, error) {
	stateDir := getenv("HTP_STATE_DIR", "/var/lib/hyrule-tunnel-proxy")
	cfg := Config{
		SSHListenAddr:           getenv("HTP_SSH_LISTEN_ADDR", ":2222"),
		ControlListenAddr:       getenv("HTP_CONTROL_LISTEN_ADDR", "127.0.0.1:8452"),
		MetricsListenAddr:       getenv("HTP_METRICS_LISTEN_ADDR", "127.0.0.1:8453"),
		STUNListenAddr:          getenv("HTP_STUN_LISTEN_ADDR", ":3478"),
		AuthToken:               os.Getenv("HTP_AUTH_TOKEN"),
		EndpointHost:            getenv("HTP_ENDPOINT_HOST", "tun.hyrule.host"),
		SSHPort:                 getenvInt("HTP_SSH_PORT", 2222),
		StateDir:                stateDir,
		HostKeyPath:             getenv("HTP_HOST_KEY_PATH", filepath.Join(stateDir, "ssh_host_ed25519_key")),
		MinLeaseSeconds:         getenvInt64("HTP_MIN_LEASE_SECONDS", 3600),
		MaxLeaseSeconds:         getenvInt64("HTP_MAX_LEASE_SECONDS", 2592000),
		MaxVisitorConnsPerLease: getenvInt("HTP_MAX_VISITOR_CONNS_PER_LEASE", 64),
		AuthAttemptsPerWindow:   getenvInt("HTP_AUTH_ATTEMPTS_PER_WINDOW", 5),
		AuthWindow:              time.Duration(getenvInt("HTP_AUTH_WINDOW_SECONDS", 30)) * time.Second,
		KeepaliveInterval:       time.Duration(getenvInt("HTP_KEEPALIVE_SECONDS", 30)) * time.Second,
		LogLevel:                getenv("HTP_LOG_LEVEL", "info"),
	}

	min, max, err := parsePortRange(getenv("HTP_DATA_PORT_RANGE", "10000-10499"))
	if err != nil {
		return cfg, fmt.Errorf("invalid HTP_DATA_PORT_RANGE: %w", err)
	}
	cfg.DataPortMin, cfg.DataPortMax = min, max

	if cfg.AuthToken == "" {
		return cfg, fmt.Errorf("HTP_AUTH_TOKEN is required")
	}
	if cfg.EndpointHost == "" {
		return cfg, fmt.Errorf("HTP_ENDPOINT_HOST is required")
	}
	if cfg.MinLeaseSeconds <= 0 || cfg.MaxLeaseSeconds < cfg.MinLeaseSeconds {
		return cfg, fmt.Errorf("invalid lease duration bounds")
	}
	if cfg.MaxVisitorConnsPerLease <= 0 {
		return cfg, fmt.Errorf("HTP_MAX_VISITOR_CONNS_PER_LEASE must be positive")
	}
	if cfg.AuthAttemptsPerWindow <= 0 || cfg.AuthWindow <= 0 {
		return cfg, fmt.Errorf("invalid auth rate-limit settings")
	}
	return cfg, nil
}

// parsePortRange parses "10000-10499" into inclusive [min, max] bounds.
func parsePortRange(s string) (int, int, error) {
	var lo, hi int
	n, err := fmt.Sscanf(s, "%d-%d", &lo, &hi)
	if err != nil || n != 2 {
		return 0, 0, fmt.Errorf("expected MIN-MAX, got %q", s)
	}
	if lo < 1 || hi > 65535 || lo > hi {
		return 0, 0, fmt.Errorf("range %d-%d out of bounds", lo, hi)
	}
	return lo, hi, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	v, err := strconv.Atoi(os.Getenv(key))
	if err != nil {
		return fallback
	}
	return v
}

func getenvInt64(key string, fallback int64) int64 {
	v, err := strconv.ParseInt(os.Getenv(key), 10, 64)
	if err != nil {
		return fallback
	}
	return v
}
