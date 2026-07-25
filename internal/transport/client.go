package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AS215932/hyrule-network-proxy/internal/config"
	"github.com/AS215932/hyrule-network-proxy/internal/contract"
	"github.com/AS215932/hyrule-network-proxy/internal/policy"
	xproxy "golang.org/x/net/proxy"
)

type Client struct {
	cfg        config.Config
	directHTTP *http.Client
	torHTTP    *http.Client
	i2pHTTP    *http.Client
	yggHTTP    *http.Client
}

func NewClient(cfg config.Config) (*Client, error) {
	direct := &http.Client{
		Transport: &http.Transport{DialContext: newGuardedDialer(contract.ProxyModeDirect).DialContext},
		Timeout:   cfg.MaxTimeout,
	}
	direct.CheckRedirect = policy.RedirectPolicy(contract.ProxyModeDirect, cfg.MaxRedirects, policy.DefaultResolver)

	torTransport, err := torRoundTripper(cfg.TorSOCKSAddr)
	if err != nil {
		return nil, err
	}
	tor := &http.Client{Transport: torTransport, Timeout: cfg.MaxTimeout}
	tor.CheckRedirect = policy.RedirectPolicy(contract.ProxyModeTor, cfg.MaxRedirects, policy.DefaultResolver)

	i2pURL, err := url.Parse(cfg.I2PHTTPProxy)
	if err != nil {
		return nil, err
	}
	i2p := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(i2pURL)},
		Timeout:   cfg.MaxTimeout,
	}
	i2p.CheckRedirect = policy.RedirectPolicy(contract.ProxyModeI2P, cfg.MaxRedirects, policy.DefaultResolver)

	ygg := &http.Client{
		Transport: &http.Transport{DialContext: newGuardedDialer(contract.ProxyModeYggdrasil).DialContext},
		Timeout:   cfg.MaxTimeout,
	}
	ygg.CheckRedirect = policy.RedirectPolicy(contract.ProxyModeYggdrasil, cfg.MaxRedirects, policy.DefaultResolver)

	return &Client{cfg: cfg, directHTTP: direct, torHTTP: tor, i2pHTTP: i2p, yggHTTP: ygg}, nil
}

func torRoundTripper(addr string) (http.RoundTripper, error) {
	dialer, err := xproxy.SOCKS5("tcp", addr, nil, xproxy.Direct)
	if err != nil {
		return nil, err
	}
	ctxDialer, ok := dialer.(xproxy.ContextDialer)
	if !ok {
		return nil, errors.New("SOCKS5 dialer does not implement ContextDialer")
	}
	guarded := &guardedSOCKSDialer{mode: contract.ProxyModeTor, socks: ctxDialer}
	return &http.Transport{DialContext: guarded.DialContext}, nil
}

func (c *Client) Do(ctx context.Context, in contract.NetworkRequest) contract.NetworkResponse {
	start := time.Now()
	mode := in.ProxyMode
	if mode == "" {
		mode = contract.ProxyModeDirect
	}
	method, err := policy.NormalizeMethod(in.Method)
	if err != nil {
		return errorResponse(400, mode, start, err)
	}
	parsed, err := policy.ParseAndValidateURL(in.URL, mode)
	if err != nil {
		status := 400
		if errors.Is(err, policy.ErrPolicyDenied) {
			status = 403
		}
		return errorResponse(status, mode, start, err)
	}
	if err := c.validateHost(parsed.Hostname(), mode); err != nil {
		return errorResponse(403, mode, start, err)
	}

	bodyBytes := []byte(nil)
	if in.Body != nil {
		bodyBytes = []byte(*in.Body)
		if int64(len(bodyBytes)) > c.cfg.MaxRequestBodyBytes {
			return errorResponse(400, mode, start, fmt.Errorf("request body exceeds limit"))
		}
	}

	timeout := c.cfg.DefaultTimeout
	if in.TimeoutSeconds > 0 {
		timeout = time.Duration(in.TimeoutSeconds) * time.Second
	}
	if timeout > c.cfg.MaxTimeout {
		timeout = c.cfg.MaxTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, parsed.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return errorResponse(400, mode, start, err)
	}
	for key, value := range policy.SanitizeRequestHeaders(in.Headers) {
		req.Header.Set(key, value)
	}

	client, err := c.clientForMode(mode)
	if err != nil {
		return errorResponse(400, mode, start, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return errorResponse(502, mode, start, fmt.Errorf("network error: %w", err))
	}
	defer resp.Body.Close()

	return c.buildResponse(resp, mode, start)
}

// buildResponse reads a bounded amount of the upstream response body, applies
// the response header denylist, and marks truncation. It never returns the
// denied headers (auth/cookie/payment) to the caller.
func (c *Client) buildResponse(resp *http.Response, mode string, start time.Time) contract.NetworkResponse {
	limited := io.LimitReader(resp.Body, c.cfg.MaxResponseBodyBytes+1)
	respBytes, err := io.ReadAll(limited)
	if err != nil {
		return errorResponse(502, mode, start, fmt.Errorf("response read error: %w", err))
	}
	truncated := int64(len(respBytes)) > c.cfg.MaxResponseBodyBytes
	if truncated {
		respBytes = respBytes[:c.cfg.MaxResponseBodyBytes]
	}

	headers := map[string]string{}
	for key, values := range resp.Header {
		if policy.AllowResponseHeader(key) && len(values) > 0 {
			headers[key] = strings.Join(values, ", ")
		}
	}
	if truncated {
		headers["x-hyrule-truncated"] = "true"
	}

	return contract.NetworkResponse{
		StatusCode:     resp.StatusCode,
		Headers:        headers,
		Body:           string(respBytes),
		ElapsedSeconds: time.Since(start).Seconds(),
		ProxyMode:      mode,
		Error:          nil,
	}
}

func (c *Client) validateHost(host string, mode string) error {
	if mode == contract.ProxyModeTor && strings.HasSuffix(strings.ToLower(host), ".onion") {
		return nil
	}
	if mode == contract.ProxyModeI2P && strings.HasSuffix(strings.ToLower(host), ".i2p") {
		return nil
	}
	return policy.ValidateResolvedHost(host, mode, policy.DefaultResolver)
}

func (c *Client) clientForMode(mode string) (*http.Client, error) {
	switch mode {
	case contract.ProxyModeDirect:
		return c.directHTTP, nil
	case contract.ProxyModeTor:
		return c.torHTTP, nil
	case contract.ProxyModeI2P:
		return c.i2pHTTP, nil
	case contract.ProxyModeYggdrasil:
		return c.yggHTTP, nil
	default:
		return nil, fmt.Errorf("unsupported proxy mode: %s", mode)
	}
}

func errorResponse(status int, mode string, start time.Time, err error) contract.NetworkResponse {
	msg := err.Error()
	return contract.NetworkResponse{
		StatusCode:     status,
		Headers:        map[string]string{},
		Body:           "",
		ElapsedSeconds: time.Since(start).Seconds(),
		ProxyMode:      mode,
		Error:          &msg,
	}
}
