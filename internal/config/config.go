package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"
)

type Config struct {
	APIListenAddr     string
	MetricsListenAddr string
	AuthToken         string

	TorSOCKSAddr string
	I2PHTTPProxy string
	Yggdrasil    bool

	MaxRequestBodyBytes  int64
	MaxResponseBodyBytes int64
	DefaultTimeout       time.Duration
	MaxTimeout           time.Duration
	MaxRedirects         int
	LogLevel             string
}

func Load() (Config, error) {
	cfg := Config{
		APIListenAddr:        getenv("HNP_API_LISTEN_ADDR", "127.0.0.1:8450"),
		MetricsListenAddr:    getenv("HNP_METRICS_LISTEN_ADDR", "127.0.0.1:8451"),
		AuthToken:            os.Getenv("HNP_AUTH_TOKEN"),
		TorSOCKSAddr:         getenv("HNP_TOR_SOCKS_ADDR", "127.0.0.1:9050"),
		I2PHTTPProxy:         getenv("HNP_I2P_HTTP_PROXY", "http://127.0.0.1:4444"),
		Yggdrasil:            getenvBool("HNP_YGGDRASIL_ENABLED", true),
		MaxRequestBodyBytes:  getenvInt64("HNP_MAX_REQUEST_BODY_BYTES", 65536),
		MaxResponseBodyBytes: getenvInt64("HNP_MAX_RESPONSE_BODY_BYTES", 65536),
		DefaultTimeout:       time.Duration(getenvInt("HNP_DEFAULT_TIMEOUT_SECONDS", 15)) * time.Second,
		MaxTimeout:           time.Duration(getenvInt("HNP_MAX_TIMEOUT_SECONDS", 60)) * time.Second,
		MaxRedirects:         getenvInt("HNP_MAX_REDIRECTS", 3),
		LogLevel:             getenv("HNP_LOG_LEVEL", "info"),
	}
	if cfg.AuthToken == "" {
		return cfg, fmt.Errorf("HNP_AUTH_TOKEN is required")
	}
	if _, err := url.Parse(cfg.I2PHTTPProxy); err != nil {
		return cfg, fmt.Errorf("invalid HNP_I2P_HTTP_PROXY: %w", err)
	}
	if cfg.MaxRequestBodyBytes <= 0 || cfg.MaxResponseBodyBytes <= 0 {
		return cfg, fmt.Errorf("body size limits must be positive")
	}
	if cfg.MaxTimeout <= 0 || cfg.DefaultTimeout <= 0 || cfg.DefaultTimeout > cfg.MaxTimeout {
		return cfg, fmt.Errorf("invalid timeout settings")
	}
	return cfg, nil
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(key))
	if err != nil {
		return fallback
	}
	return value
}

func getenvInt64(key string, fallback int64) int64 {
	value, err := strconv.ParseInt(os.Getenv(key), 10, 64)
	if err != nil {
		return fallback
	}
	return value
}

func getenvBool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}
