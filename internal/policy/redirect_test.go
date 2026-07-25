package policy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
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

// The tests above call RedirectPolicy's returned func directly, which proves
// the policy logic is correct in isolation but not that installing it as
// http.Client.CheckRedirect actually stops a real redirect chain — a client
// built with the wrong mode, the wrong resolver, or a CheckRedirect that
// silently never got assigned would still pass every test above. These two
// exercise the exact wiring transport.NewClient uses (a real *http.Client
// with CheckRedirect = RedirectPolicy(...)) against a real multi-hop HTTP
// redirect from an httptest.Server.

func TestRedirectPolicyOnRealClientBlocksRedirectToPrivateTarget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://private.example/blocked", http.StatusFound)
	}))
	defer server.Close()

	client := &http.Client{
		CheckRedirect: RedirectPolicy(contract.ProxyModeDirect, 3, fakeResolver("10.0.0.5")),
	}

	resp, err := client.Get(server.URL)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected the real http.Client to refuse a redirect resolving to a private address")
	}
}

func TestRedirectPolicyOnRealClientAllowsRedirectToPublicTarget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/final" {
			fmt.Fprint(w, "ok")
			return
		}
		http.Redirect(w, r, "http://public.example/final", http.StatusFound)
	}))
	defer server.Close()

	client := &http.Client{
		// Route every real dial to the httptest server regardless of the
		// requested host — a literal loopback IP is always policy-denied
		// (see ValidateResolvedHost), so the redirect target has to be a
		// hostname for the resolver-driven "is this public" check under
		// test to run at all. fakeResolver ignores the hostname it's given,
		// simulating "public.example resolves publicly".
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, server.Listener.Addr().String())
			},
		},
		CheckRedirect: RedirectPolicy(contract.ProxyModeDirect, 3, fakeResolver("93.184.216.34")),
	}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("expected the real http.Client to follow a redirect resolving to a public address, got %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected the redirect chain to reach /final, got status %d", resp.StatusCode)
	}
}
