package policy

import "testing"

func TestSanitizeRequestHeaders(t *testing.T) {
	got := SanitizeRequestHeaders(map[string]string{
		"Accept":        "text/html",
		"Authorization": "Bearer secret",
		"Cookie":        "a=b",
		"User-Agent":    "test",
		"X-Payment":     "secret",
	})
	if got["Accept"] != "text/html" {
		t.Fatal("Accept should be forwarded")
	}
	if got["User-Agent"] != "test" {
		t.Fatal("User-Agent should be forwarded")
	}
	if _, ok := got["Authorization"]; ok {
		t.Fatal("Authorization should be dropped")
	}
	if _, ok := got["Cookie"]; ok {
		t.Fatal("Cookie should be dropped")
	}
	if _, ok := got["X-Payment"]; ok {
		t.Fatal("X-Payment should be dropped")
	}
}

func TestAllowResponseHeader(t *testing.T) {
	if !AllowResponseHeader("content-type") {
		t.Fatal("content-type should be returned")
	}
	if AllowResponseHeader("set-cookie") {
		t.Fatal("set-cookie should be redacted")
	}
}
