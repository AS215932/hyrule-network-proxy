package policy

import (
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
)

func RedirectPolicy(mode string, maxRedirects int, resolver func(string) ([]netip.Addr, error)) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) > maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		if _, err := ParseAndValidateURL(req.URL.String(), mode); err != nil {
			return err
		}
		if err := ValidateResolvedHost(req.URL.Hostname(), mode, resolver); err != nil {
			return err
		}
		return nil
	}
}

func SameModeRedirectOK(target *url.URL, mode string, resolver func(string) ([]netip.Addr, error)) error {
	if _, err := ParseAndValidateURL(target.String(), mode); err != nil {
		return err
	}
	return ValidateResolvedHost(target.Hostname(), mode, resolver)
}
