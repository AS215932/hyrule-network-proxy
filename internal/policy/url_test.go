package policy

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/AS215932/hyrule-network-proxy/internal/contract"
)

func fakeResolver(addrs ...string) func(string) ([]netip.Addr, error) {
	return func(string) ([]netip.Addr, error) {
		out := make([]netip.Addr, 0, len(addrs))
		for _, raw := range addrs {
			out = append(out, netip.MustParseAddr(raw))
		}
		return out, nil
	}
}

func TestNormalizeMethod(t *testing.T) {
	if got, err := NormalizeMethod("get"); err != nil || got != "GET" {
		t.Fatalf("NormalizeMethod(get) = %q, %v", got, err)
	}
	if _, err := NormalizeMethod("CONNECT"); err == nil {
		t.Fatal("CONNECT should be rejected")
	}
}

func TestParseAndValidateURLModeNames(t *testing.T) {
	cases := []struct {
		name string
		url  string
		mode string
		deny bool
	}{
		{"direct clearnet", "https://example.com", contract.ProxyModeDirect, false},
		{"direct onion", "http://exampleonion.onion", contract.ProxyModeDirect, true},
		{"tor onion", "http://exampleonion.onion", contract.ProxyModeTor, false},
		{"i2p only i2p", "http://site.i2p", contract.ProxyModeI2P, false},
		{"i2p rejects clearnet", "https://example.com", contract.ProxyModeI2P, true},
		{"ygg rejects onion", "http://exampleonion.onion", contract.ProxyModeYggdrasil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseAndValidateURL(tc.url, tc.mode)
			if tc.deny && err == nil {
				t.Fatal("expected rejection")
			}
			if !tc.deny && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateResolvedHostBlocksPrivate(t *testing.T) {
	err := ValidateResolvedHost("example.com", contract.ProxyModeDirect, fakeResolver("10.0.0.1"))
	if !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("expected policy denial, got %v", err)
	}
}

func TestValidateResolvedHostAllowsPublic(t *testing.T) {
	err := ValidateResolvedHost("example.com", contract.ProxyModeDirect, fakeResolver("8.8.8.8", "2606:4700:4700::1111"))
	if err != nil {
		t.Fatalf("expected public addresses to pass, got %v", err)
	}
}

func TestValidateResolvedHostYggdrasil(t *testing.T) {
	if err := ValidateResolvedHost("200::1", contract.ProxyModeYggdrasil, fakeResolver()); err != nil {
		t.Fatalf("expected yggdrasil literal to pass: %v", err)
	}
	if err := ValidateResolvedHost("200::1", contract.ProxyModeDirect, fakeResolver()); !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("expected yggdrasil literal to be denied in direct mode, got %v", err)
	}
}
