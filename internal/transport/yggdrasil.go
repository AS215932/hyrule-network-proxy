package transport

func (c *Client) yggdrasilAvailable() (bool, string) {
	if c.cfg.Yggdrasil {
		return true, ""
	}
	return false, "yggdrasil disabled"
}
