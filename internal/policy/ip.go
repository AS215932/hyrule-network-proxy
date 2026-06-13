package policy

import "net/netip"

var yggdrasilPrefix = netip.MustParsePrefix("200::/7")

func IsPublicIP(addr netip.Addr) bool {
	return addr.IsValid() && addr.IsGlobalUnicast() && !addr.IsPrivate() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() && !addr.IsMulticast() && !addr.IsUnspecified()
}

func IsYggdrasilIP(addr netip.Addr) bool {
	return addr.IsValid() && yggdrasilPrefix.Contains(addr)
}

func IPAllowedForMode(addr netip.Addr, mode string) bool {
	switch mode {
	case "direct", "tor":
		return IsPublicIP(addr) && !IsYggdrasilIP(addr)
	case "yggdrasil":
		return IsYggdrasilIP(addr)
	default:
		return false
	}
}
