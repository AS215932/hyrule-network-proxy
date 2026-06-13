package transport

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/AS215932/hyrule-network-proxy/internal/contract"
	"github.com/AS215932/hyrule-network-proxy/internal/policy"
	xproxy "golang.org/x/net/proxy"
)

type guardedDialer struct {
	mode string
	net  net.Dialer
}

func newGuardedDialer(mode string) *guardedDialer {
	return &guardedDialer{mode: mode, net: net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}}
}

func (d *guardedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	dialAddr, err := resolveDialAddress(ctx, host, port, d.mode)
	if err != nil {
		return nil, err
	}
	return d.net.DialContext(ctx, network, dialAddr)
}

type guardedSOCKSDialer struct {
	mode  string
	socks xproxy.ContextDialer
}

func (d *guardedSOCKSDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if d.mode == contract.ProxyModeTor && strings.HasSuffix(strings.ToLower(strings.TrimSuffix(host, ".")), ".onion") {
		return d.socks.DialContext(ctx, network, address)
	}
	dialAddr, err := resolveDialAddress(ctx, host, port, d.mode)
	if err != nil {
		return nil, err
	}
	return d.socks.DialContext(ctx, network, dialAddr)
}

func resolveDialAddress(ctx context.Context, host, port, mode string) (string, error) {
	host = strings.Trim(host, "[]")
	if ip, err := netip.ParseAddr(host); err == nil {
		if !policy.IPAllowedForMode(ip, mode) {
			return "", fmt.Errorf("%w: destination IP %s is disallowed for %s", policy.ErrPolicyDenied, ip, mode)
		}
		return net.JoinHostPort(ip.String(), port), nil
	}
	if strings.EqualFold(host, "localhost") || strings.EqualFold(host, "localhost.localdomain") {
		return "", fmt.Errorf("%w: localhost is disallowed", policy.ErrPolicyDenied)
	}

	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("host resolved to no addresses")
	}
	var selected netip.Addr
	for _, addr := range addrs {
		addr = addr.Unmap()
		if !policy.IPAllowedForMode(addr, mode) {
			return "", fmt.Errorf("%w: host resolves to disallowed IP %s", policy.ErrPolicyDenied, addr)
		}
		if !selected.IsValid() {
			selected = addr
		}
	}
	if !selected.IsValid() {
		return "", fmt.Errorf("host resolved to no usable addresses")
	}
	return net.JoinHostPort(selected.String(), port), nil
}
