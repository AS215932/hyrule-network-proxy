package transport

import "github.com/AS215932/hyrule-network-proxy/internal/contract"

func (c *Client) Modes() map[string]contract.ModeInfo {
	modes := map[string]contract.ModeInfo{}
	modes[contract.ProxyModeDirect] = contract.ModeInfo{Available: true}

	available, reason := c.torAvailable()
	modes[contract.ProxyModeTor] = modeInfo(available, reason)

	available, reason = c.i2pAvailable()
	modes[contract.ProxyModeI2P] = modeInfo(available, reason)

	available, reason = c.yggdrasilAvailable()
	modes[contract.ProxyModeYggdrasil] = modeInfo(available, reason)

	return modes
}

func modeInfo(available bool, reason string) contract.ModeInfo {
	if reason == "" {
		return contract.ModeInfo{Available: available}
	}
	return contract.ModeInfo{Available: available, Reason: &reason}
}
