package transport

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/AS215932/hyrule-network-proxy/internal/config"
	"github.com/AS215932/hyrule-network-proxy/internal/contract"
)

func testClient(t *testing.T) *Client {
	t.Helper()
	cfg := config.Config{
		AuthToken:            "secret",
		TorSOCKSAddr:         "127.0.0.1:1",
		I2PHTTPProxy:         "http://127.0.0.1:1",
		Yggdrasil:            false,
		MaxRequestBodyBytes:  65536,
		MaxResponseBodyBytes: 16,
		DefaultTimeout:       5 * time.Second,
		MaxTimeout:           10 * time.Second,
		MaxRedirects:         3,
	}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestBodyTooLarge(t *testing.T) {
	body := strings.Repeat("x", 65537)
	resp := testClient(t).Do(context.Background(), contract.NetworkRequest{
		URL:       "https://example.com",
		Method:    "POST",
		ProxyMode: contract.ProxyModeDirect,
		Body:      &body,
	})
	if resp.StatusCode != 400 || resp.Error == nil {
		t.Fatalf("expected 400 body error, got %#v", resp)
	}
}

func TestDirectLoopbackDeniedBeforeDial(t *testing.T) {
	resp := testClient(t).Do(context.Background(), contract.NetworkRequest{
		URL:       "http://127.0.0.1:8080",
		Method:    "GET",
		ProxyMode: contract.ProxyModeDirect,
	})
	if resp.StatusCode != 403 || resp.Error == nil {
		t.Fatalf("expected 403 policy denial, got %#v", resp)
	}
}

func TestI2PRejectsClearnetBeforeDial(t *testing.T) {
	resp := testClient(t).Do(context.Background(), contract.NetworkRequest{
		URL:       "https://example.com",
		Method:    "GET",
		ProxyMode: contract.ProxyModeI2P,
	})
	if resp.StatusCode != 403 || resp.Error == nil {
		t.Fatalf("expected 403 policy denial, got %#v", resp)
	}
}

func TestModesReportUnavailableLocalDaemons(t *testing.T) {
	modes := testClient(t).Modes()
	if !modes[contract.ProxyModeDirect].Available {
		t.Fatal("direct should always be available")
	}
	if modes[contract.ProxyModeTor].Available {
		t.Fatal("tor should be unavailable with test dead port")
	}
	if modes[contract.ProxyModeI2P].Available {
		t.Fatal("i2p should be unavailable with test dead port")
	}
	if modes[contract.ProxyModeYggdrasil].Available {
		t.Fatal("yggdrasil should be unavailable when disabled")
	}
}
