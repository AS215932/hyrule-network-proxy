package policy

import (
	"net/http"
	"testing"

	"github.com/AS215932/hyrule-network-proxy/internal/contract"
)

func redirectReq(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	return req
}

func TestRedirectPolicyStopsAfterMax(t *testing.T) {
	check := RedirectPolicy(contract.ProxyModeDirect, 3, fakeResolver("93.184.216.34"))

	via := make([]*http.Request, 4) // already followed 4 hops > max 3
	if err := check(redirectReq(t, "https://public.example/"), via); err == nil {
		t.Fatal("expected error after exceeding max redirects")
	}
}

func TestRedirectPolicyBlocksPrivateTarget(t *testing.T) {
	check := RedirectPolicy(contract.ProxyModeDirect, 3, fakeResolver("10.0.0.5"))

	if err := check(redirectReq(t, "https://private.example/"), nil); err == nil {
		t.Fatal("expected redirect to private IP to be denied")
	}
}

func TestRedirectPolicyAllowsPublicTarget(t *testing.T) {
	check := RedirectPolicy(contract.ProxyModeDirect, 3, fakeResolver("93.184.216.34"))

	if err := check(redirectReq(t, "https://public.example/next"), nil); err != nil {
		t.Fatalf("expected public redirect to be allowed, got %v", err)
	}
}

func TestRedirectPolicyBlocksAlternateNetworkName(t *testing.T) {
	check := RedirectPolicy(contract.ProxyModeDirect, 3, DefaultResolver)
	// direct mode must never be redirected onto a .onion/.i2p name
	if err := check(redirectReq(t, "http://example.onion/"), nil); err == nil {
		t.Fatal("expected direct-mode redirect to .onion to be denied")
	}
}
