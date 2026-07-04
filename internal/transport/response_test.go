package transport

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AS215932/hyrule-network-proxy/internal/contract"
)

// fetch performs a real (unguarded) round trip to a loopback test server so we
// can exercise the production response-processing path (buildResponse) against
// genuine http.Response headers and bodies. The SSRF dial guard deliberately
// blocks loopback for real proxy requests, so buildResponse is tested directly.
func fetch(t *testing.T, url string) *http.Response {
	t.Helper()
	resp, err := http.Get(url) //nolint:noctx // test helper
	if err != nil {
		t.Fatalf("fetch %s: %v", url, err)
	}
	return resp
}

func TestBuildResponseTruncatesAndStripsHeaders(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Denied headers must never reach the caller.
		w.Header().Set("Set-Cookie", "session=secret")
		w.Header().Set("X-Payment", "0xdeadbeef")
		w.Header().Set("X-Api-Key", "leaked")
		w.Header().Set("Payment-Signature", "sig")
		// An allowed header must be preserved.
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("A", 100)))
	}))
	defer ts.Close()

	c := testClient(t) // MaxResponseBodyBytes == 16
	resp := fetch(t, ts.URL)
	out := c.buildResponse(resp, contract.ProxyModeDirect, time.Now())

	if out.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", out.StatusCode)
	}
	if len(out.Body) != 16 {
		t.Fatalf("expected body truncated to 16 bytes, got %d", len(out.Body))
	}
	if out.Headers["x-hyrule-truncated"] != "true" {
		t.Fatalf("expected x-hyrule-truncated=true, got %q", out.Headers["x-hyrule-truncated"])
	}
	if out.Headers["Content-Type"] == "" {
		t.Fatal("expected allowed Content-Type header to be preserved")
	}
	for _, denied := range []string{"Set-Cookie", "X-Payment", "X-Api-Key", "Payment-Signature"} {
		if _, ok := out.Headers[denied]; ok {
			t.Fatalf("denied header %s must be stripped from the response", denied)
		}
	}
}

func TestBuildResponseSmallBodyNotTruncated(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	defer ts.Close()

	c := testClient(t)
	resp := fetch(t, ts.URL)
	out := c.buildResponse(resp, contract.ProxyModeDirect, time.Now())

	if out.Body != "hello" {
		t.Fatalf("expected body %q, got %q", "hello", out.Body)
	}
	if _, ok := out.Headers["x-hyrule-truncated"]; ok {
		t.Fatal("small response must not be marked truncated")
	}
}
