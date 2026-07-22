package config

import (
	"testing"
)

func TestParsePortRange(t *testing.T) {
	lo, hi, err := parsePortRange("10000-10499")
	if err != nil || lo != 10000 || hi != 10499 {
		t.Fatalf("got %d-%d err %v", lo, hi, err)
	}
	for _, bad := range []string{"", "abc", "500", "10499-10000", "0-10", "1-70000"} {
		if _, _, err := parsePortRange(bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

func TestLoadRequiresAuthToken(t *testing.T) {
	t.Setenv("HTP_AUTH_TOKEN", "")
	if _, err := Load(); err == nil {
		t.Fatalf("expected error when HTP_AUTH_TOKEN unset")
	}
}

func TestLoadDefaults(t *testing.T) {
	t.Setenv("HTP_AUTH_TOKEN", "x")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.SSHListenAddr != ":2222" || cfg.DataPortMin != 10000 || cfg.DataPortMax != 10499 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if cfg.EndpointHost != "tun.hyrule.host" {
		t.Fatalf("unexpected endpoint host: %s", cfg.EndpointHost)
	}
}

func TestLoadRejectsBadPortRange(t *testing.T) {
	t.Setenv("HTP_AUTH_TOKEN", "x")
	t.Setenv("HTP_DATA_PORT_RANGE", "nonsense")
	if _, err := Load(); err == nil {
		t.Fatalf("expected error for bad port range")
	}
}

func TestIsWildcardAddr(t *testing.T) {
	for _, w := range []string{":8452", "0.0.0.0:8452", "[::]:8452", "garbage"} {
		if !isWildcardAddr(w) {
			t.Fatalf("expected %q to be wildcard/unsafe", w)
		}
	}
	for _, ok := range []string{"127.0.0.1:8452", "[2a0c:b641:b50:2::e0]:8452"} {
		if isWildcardAddr(ok) {
			t.Fatalf("expected %q to be a valid internal bind", ok)
		}
	}
}

func TestLoadRejectsWildcardControlAndMetrics(t *testing.T) {
	t.Setenv("HTP_AUTH_TOKEN", "x")
	t.Setenv("HTP_CONTROL_LISTEN_ADDR", "[::]:8452")
	if _, err := Load(); err == nil {
		t.Fatalf("expected error for wildcard control listener")
	}
	t.Setenv("HTP_CONTROL_LISTEN_ADDR", "127.0.0.1:8452")
	t.Setenv("HTP_METRICS_LISTEN_ADDR", "0.0.0.0:8453")
	if _, err := Load(); err == nil {
		t.Fatalf("expected error for wildcard metrics listener")
	}
}
