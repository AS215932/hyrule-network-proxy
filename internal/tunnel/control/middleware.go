package control

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// withAuth enforces a constant-time Bearer token check on the control API and
// records the outcome under the given op label. Copied from the network-proxy
// sidecar's auth middleware — the control API is the money path and must never
// be reachable without the shared token.
func (a *API) withAuth(op string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			http.Error(rec, "unauthorized", http.StatusUnauthorized)
			a.record(op, rec.status)
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(auth, prefix))
		if subtle.ConstantTimeCompare([]byte(token), []byte(a.token)) != 1 {
			http.Error(rec, "unauthorized", http.StatusUnauthorized)
			a.record(op, rec.status)
			return
		}
		next(rec, r)
		a.record(op, rec.status)
	}
}

// statusRecorder captures the response status code for metrics.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.wroteHeader = true
	}
	return s.ResponseWriter.Write(b)
}
