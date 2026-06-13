package contract

const (
	ProxyModeDirect    = "direct"
	ProxyModeTor       = "tor"
	ProxyModeI2P       = "i2p"
	ProxyModeYggdrasil = "yggdrasil"
)

var AllModes = []string{ProxyModeDirect, ProxyModeTor, ProxyModeI2P, ProxyModeYggdrasil}

type NetworkRequest struct {
	RequestID      string            `json:"request_id,omitempty"`
	URL            string            `json:"url"`
	Method         string            `json:"method"`
	Headers        map[string]string `json:"headers,omitempty"`
	Body           *string           `json:"body,omitempty"`
	ProxyMode      string            `json:"proxy_mode"`
	TimeoutSeconds int               `json:"timeout_seconds"`
}

type NetworkResponse struct {
	StatusCode     int               `json:"status_code"`
	Headers        map[string]string `json:"headers"`
	Body           string            `json:"body"`
	ElapsedSeconds float64           `json:"elapsed_seconds"`
	ProxyMode      string            `json:"proxy_mode"`
	Error          *string           `json:"error"`
}

type HealthResponse struct {
	Status  string `json:"status"`
	Service string `json:"service"`
	Version string `json:"version"`
}

type ModeInfo struct {
	Available bool    `json:"available"`
	Reason    *string `json:"reason"`
}

type ModesResponse struct {
	Modes map[string]ModeInfo `json:"modes"`
}
