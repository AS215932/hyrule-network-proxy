package policy

import "strings"

var requestHeaderAllowlist = map[string]struct{}{
	"accept":            {},
	"accept-language":   {},
	"cache-control":     {},
	"content-type":      {},
	"if-modified-since": {},
	"if-none-match":     {},
	"user-agent":        {},
}

var responseHeaderDenylist = map[string]struct{}{
	"authorization":       {},
	"cookie":              {},
	"proxy-authorization": {},
	"set-cookie":          {},
	"x-api-key":           {},
	"x-payment":           {},
	"payment-signature":   {},
}

func SanitizeRequestHeaders(input map[string]string) map[string]string {
	out := make(map[string]string)
	for key, value := range input {
		name := strings.ToLower(strings.TrimSpace(key))
		if _, ok := requestHeaderAllowlist[name]; ok {
			out[key] = value
		}
	}
	return out
}

func AllowResponseHeader(key string) bool {
	_, denied := responseHeaderDenylist[strings.ToLower(strings.TrimSpace(key))]
	return !denied
}
