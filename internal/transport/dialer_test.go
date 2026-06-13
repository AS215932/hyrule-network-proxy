package transport

import (
	"context"
	"errors"
	"testing"

	"github.com/AS215932/hyrule-network-proxy/internal/contract"
	"github.com/AS215932/hyrule-network-proxy/internal/policy"
)

func TestResolveDialAddressRejectsLoopback(t *testing.T) {
	_, err := resolveDialAddress(context.Background(), "127.0.0.1", "80", contract.ProxyModeDirect)
	if !errors.Is(err, policy.ErrPolicyDenied) {
		t.Fatalf("expected policy denial, got %v", err)
	}
}

func TestResolveDialAddressAllowsPublicLiteral(t *testing.T) {
	addr, err := resolveDialAddress(context.Background(), "8.8.8.8", "443", contract.ProxyModeDirect)
	if err != nil {
		t.Fatalf("expected public literal to pass, got %v", err)
	}
	if addr != "8.8.8.8:443" {
		t.Fatalf("unexpected dial addr %q", addr)
	}
}

func TestResolveDialAddressYggdrasilMode(t *testing.T) {
	addr, err := resolveDialAddress(context.Background(), "200::1", "80", contract.ProxyModeYggdrasil)
	if err != nil {
		t.Fatalf("expected yggdrasil literal to pass, got %v", err)
	}
	if addr != "[200::1]:80" {
		t.Fatalf("unexpected dial addr %q", addr)
	}
	_, err = resolveDialAddress(context.Background(), "200::1", "80", contract.ProxyModeDirect)
	if !errors.Is(err, policy.ErrPolicyDenied) {
		t.Fatalf("expected direct-mode denial, got %v", err)
	}
}
