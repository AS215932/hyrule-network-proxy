package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/AS215932/hyrule-network-proxy/internal/contract"
	"github.com/AS215932/hyrule-network-proxy/internal/version"
)

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, contract.HealthResponse{Status: "ok", Service: "hyrule-network-proxy", Version: version.Version})
}

func (s *Server) handleModes(w http.ResponseWriter, _ *http.Request) {
	modes := s.client.Modes()
	for mode, info := range modes {
		s.metrics.SetModeAvailable(mode, info.Available)
	}
	writeJSON(w, http.StatusOK, contract.ModesResponse{Modes: modes})
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	requestStarted := time.Now()
	var in contract.NetworkRequest
	if err := decodeLimitedJSON(r.Body, s.cfg.MaxRequestBodyBytes+4096, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if in.ProxyMode == "" {
		in.ProxyMode = contract.ProxyModeDirect
	}
	resp := s.client.Do(r.Context(), in)
	if resp.Error != nil && (resp.StatusCode == 400 || resp.StatusCode == 403) {
		s.metrics.ObservePolicyDenial(in.ProxyMode, *resp.Error)
	}
	requestBytes := 0
	if in.Body != nil {
		requestBytes = len(*in.Body)
	}
	s.metrics.ObserveRequest(in.ProxyMode, resp.StatusCode, time.Since(requestStarted), requestBytes, len(resp.Body))
	logRequest(in, resp)
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	modes := s.client.Modes()
	for _, info := range modes {
		if info.Available {
			_, _ = w.Write([]byte("ok\n"))
			return
		}
	}
	http.Error(w, "no proxy modes available", http.StatusServiceUnavailable)
}

func decodeLimitedJSON(r io.Reader, maxBytes int64, out any) error {
	limited := io.LimitReader(r, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if int64(len(data)) > maxBytes {
		return fmt.Errorf("request exceeds limit")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func logRequest(in contract.NetworkRequest, resp contract.NetworkResponse) {
	host := ""
	scheme := ""
	if parsed, err := url.Parse(in.URL); err == nil {
		host = parsed.Hostname()
		scheme = parsed.Scheme
	}
	truncated := false
	if value, ok := resp.Headers["x-hyrule-truncated"]; ok && value == "true" {
		truncated = true
	}
	var errText string
	if resp.Error != nil {
		errText = *resp.Error
	}
	slog.Info("proxy_request",
		"service", "hyrule-network-proxy",
		"request_id", in.RequestID,
		"proxy_mode", in.ProxyMode,
		"method", in.Method,
		"target_scheme", scheme,
		"target_host", host,
		"status_code", resp.StatusCode,
		"elapsed_seconds", resp.ElapsedSeconds,
		"truncated", truncated,
		"error", errText,
	)
}
