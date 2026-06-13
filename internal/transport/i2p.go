package transport

import (
	"net/url"
	"time"
)

func (c *Client) i2pAvailable() (bool, string) {
	parsed, err := url.Parse(c.cfg.I2PHTTPProxy)
	if err != nil || parsed.Host == "" {
		return false, "invalid i2p proxy URL"
	}
	if tcpAvailable(parsed.Host, 750*time.Millisecond) {
		return true, ""
	}
	return false, "i2p HTTP proxy unavailable"
}
