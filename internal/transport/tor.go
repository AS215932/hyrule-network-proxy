package transport

import "time"

func (c *Client) torAvailable() (bool, string) {
	if tcpAvailable(c.cfg.TorSOCKSAddr, 750*time.Millisecond) {
		return true, ""
	}
	return false, "tor SOCKS listener unavailable"
}
