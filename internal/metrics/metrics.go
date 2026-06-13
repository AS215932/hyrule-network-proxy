package metrics

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type Metrics struct {
	Registry           *prometheus.Registry
	RequestsTotal      *prometheus.CounterVec
	RequestDuration    *prometheus.HistogramVec
	RequestBytesTotal  *prometheus.CounterVec
	ResponseBytesTotal *prometheus.CounterVec
	PolicyDenialsTotal *prometheus.CounterVec
	ModeAvailable      *prometheus.GaugeVec
}

func New() *Metrics {
	m := &Metrics{Registry: prometheus.NewRegistry()}
	m.RequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "hyrule_network_proxy_requests_total", Help: "Total handled proxy requests."},
		[]string{"mode", "status_class"},
	)
	m.RequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{Name: "hyrule_network_proxy_request_duration_seconds", Help: "Proxy request duration.", Buckets: prometheus.DefBuckets},
		[]string{"mode"},
	)
	m.RequestBytesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "hyrule_network_proxy_request_bytes_total", Help: "Total request bytes accepted."},
		[]string{"mode"},
	)
	m.ResponseBytesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "hyrule_network_proxy_response_bytes_total", Help: "Total response bytes returned."},
		[]string{"mode"},
	)
	m.PolicyDenialsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "hyrule_network_proxy_policy_denials_total", Help: "Total policy denials."},
		[]string{"mode", "reason"},
	)
	m.ModeAvailable = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "hyrule_network_proxy_mode_available", Help: "Whether a mode is currently available."},
		[]string{"mode"},
	)
	m.Registry.MustRegister(m.RequestsTotal, m.RequestDuration, m.RequestBytesTotal, m.ResponseBytesTotal, m.PolicyDenialsTotal, m.ModeAvailable)
	return m
}

func (m *Metrics) ObserveRequest(mode string, status int, dur time.Duration, reqBytes int, respBytes int) {
	class := strconv.Itoa(status/100) + "xx"
	m.RequestsTotal.WithLabelValues(mode, class).Inc()
	m.RequestDuration.WithLabelValues(mode).Observe(dur.Seconds())
	m.RequestBytesTotal.WithLabelValues(mode).Add(float64(reqBytes))
	m.ResponseBytesTotal.WithLabelValues(mode).Add(float64(respBytes))
}

func (m *Metrics) ObservePolicyDenial(mode, reason string) {
	m.PolicyDenialsTotal.WithLabelValues(mode, reason).Inc()
}

func (m *Metrics) SetModeAvailable(mode string, available bool) {
	value := 0.0
	if available {
		value = 1.0
	}
	m.ModeAvailable.WithLabelValues(mode).Set(value)
}
