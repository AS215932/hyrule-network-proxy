package policy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/AS215932/hyrule-network-proxy/internal/contract"
)

var ErrPolicyDenied = errors.New("policy denied")

var AllowedMethods = map[string]struct{}{
	"GET":  {},
	"HEAD": {},
	"POST": {},
}

func NormalizeMethod(method string) (string, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}
	if _, ok := AllowedMethods[method]; !ok {
		return "", fmt.Errorf("unsupported HTTP method: %s", method)
	}
	return method, nil
}

func ParseAndValidateURL(raw string, mode string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("unsupported URL scheme")
	}
	if parsed.Hostname() == "" {
		return nil, fmt.Errorf("invalid URL: host is required")
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("URL userinfo is not allowed")
	}

	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	switch mode {
	case contract.ProxyModeDirect:
		if strings.HasSuffix(host, ".onion") || strings.HasSuffix(host, ".i2p") {
			return nil, fmt.Errorf("%w: direct mode cannot access alternate-network names", ErrPolicyDenied)
		}
	case contract.ProxyModeTor:
		if strings.HasSuffix(host, ".i2p") {
			return nil, fmt.Errorf("%w: tor mode cannot access .i2p names", ErrPolicyDenied)
		}
	case contract.ProxyModeI2P:
		if !strings.HasSuffix(host, ".i2p") {
			return nil, fmt.Errorf("%w: i2p mode requires .i2p hostnames", ErrPolicyDenied)
		}
	case contract.ProxyModeYggdrasil:
		if strings.HasSuffix(host, ".onion") || strings.HasSuffix(host, ".i2p") {
			return nil, fmt.Errorf("%w: yggdrasil mode cannot access .onion or .i2p names", ErrPolicyDenied)
		}
	default:
		return nil, fmt.Errorf("unsupported proxy mode: %s", mode)
	}
	return parsed, nil
}

func ValidateResolvedHost(host string, mode string, resolver func(string) ([]netip.Addr, error)) error {
	host = strings.Trim(host, "[]")
	if ip, err := netip.ParseAddr(host); err == nil {
		if !IPAllowedForMode(ip, mode) {
			return fmt.Errorf("%w: destination IP %s is disallowed for %s", ErrPolicyDenied, ip, mode)
		}
		return nil
	}
	if strings.EqualFold(host, "localhost") || strings.EqualFold(host, "localhost.localdomain") {
		return fmt.Errorf("%w: localhost is disallowed", ErrPolicyDenied)
	}
	if strings.HasSuffix(strings.ToLower(host), ".onion") || strings.HasSuffix(strings.ToLower(host), ".i2p") {
		return nil
	}

	addrs, err := resolver(host)
	if err != nil {
		return err
	}
	if len(addrs) == 0 {
		return fmt.Errorf("host resolved to no addresses")
	}
	for _, addr := range addrs {
		if !IPAllowedForMode(addr, mode) {
			return fmt.Errorf("%w: host resolves to disallowed IP %s", ErrPolicyDenied, addr)
		}
	}
	return nil
}

func DefaultResolver(host string) ([]netip.Addr, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if ok {
			out = append(out, addr.Unmap())
		}
	}
	return out, nil
}
