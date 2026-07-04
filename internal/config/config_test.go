package config

import (
	"log/slog"
	"testing"
)

func TestLoadRequiresAuthToken(t *testing.T) {
	t.Setenv("HNP_AUTH_TOKEN", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected Load to fail without HNP_AUTH_TOKEN")
	}
}

func TestLoadDefaults(t *testing.T) {
	t.Setenv("HNP_AUTH_TOKEN", "test-token")
	// Force the optional vars empty so we assert the documented defaults.
	for _, key := range []string{
		"HNP_API_LISTEN_ADDR", "HNP_METRICS_LISTEN_ADDR", "HNP_MAX_REDIRECTS",
		"HNP_DEFAULT_TIMEOUT_SECONDS", "HNP_MAX_TIMEOUT_SECONDS",
	} {
		t.Setenv(key, "")
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.APIListenAddr != "127.0.0.1:8450" {
		t.Fatalf("unexpected APIListenAddr default: %q", cfg.APIListenAddr)
	}
	if cfg.MetricsListenAddr != "127.0.0.1:8451" {
		t.Fatalf("unexpected MetricsListenAddr default: %q", cfg.MetricsListenAddr)
	}
	if cfg.MaxRedirects != 3 {
		t.Fatalf("unexpected MaxRedirects default: %d", cfg.MaxRedirects)
	}
	if cfg.DefaultTimeout > cfg.MaxTimeout {
		t.Fatal("DefaultTimeout must not exceed MaxTimeout")
	}
}

func TestParseLogLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug":    slog.LevelDebug,
		"DEBUG":    slog.LevelDebug,
		"info":     slog.LevelInfo,
		"warn":     slog.LevelWarn,
		"warning":  slog.LevelWarn,
		"error":    slog.LevelError,
		"":         slog.LevelInfo,
		"nonsense": slog.LevelInfo,
	}
	for in, want := range cases {
		if got := ParseLogLevel(in); got != want {
			t.Errorf("ParseLogLevel(%q) = %v, want %v", in, got, want)
		}
	}
}
