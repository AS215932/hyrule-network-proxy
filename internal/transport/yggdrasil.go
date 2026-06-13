package transport

import (
	"net"
	"net/netip"

	"github.com/AS215932/hyrule-network-proxy/internal/policy"
)

func (c *Client) yggdrasilAvailable() (bool, string) {
	if !c.cfg.Yggdrasil {
		return false, "yggdrasil disabled"
	}
	if hasYggdrasilAddress() {
		return true, ""
	}
	return false, "no yggdrasil address detected"
}

func hasYggdrasilAddress() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, raw := range addrs {
			prefix, err := netip.ParsePrefix(raw.String())
			if err != nil {
				continue
			}
			if policy.IsYggdrasilIP(prefix.Addr()) {
				return true
			}
		}
	}
	return false
}
