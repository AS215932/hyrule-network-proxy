// Package metrics holds the Prometheus registry and instruments for the
// hyrule-tunnel-proxy daemon. Series are aggregate (no per-lease labels) to keep
// cardinality bounded across the full data-port range.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	Registry *prometheus.Registry

	LeasesActive       prometheus.Gauge
	PortsFree          prometheus.Gauge
	SSHConnections     *prometheus.GaugeVec
	SSHAuthFailures    prometheus.Counter
	VisitorConnections prometheus.Gauge
	BytesForwarded     *prometheus.CounterVec
	STUNRequests       prometheus.Counter
	ControlRequests    *prometheus.CounterVec
	Reconcile          *prometheus.CounterVec
}

func New() *Metrics {
	m := &Metrics{Registry: prometheus.NewRegistry()}
	m.LeasesActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "tunnel_leases_active", Help: "Currently live tunnel leases.",
	})
	m.PortsFree = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "tunnel_ports_free", Help: "Free data ports in the allocation range.",
	})
	m.SSHConnections = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tunnel_ssh_connections", Help: "Active SSH intake connections by state.",
	}, []string{"state"})
	m.SSHAuthFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "tunnel_ssh_auth_failures_total", Help: "Rejected SSH auth attempts.",
	})
	m.VisitorConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "tunnel_visitor_connections_active", Help: "Active visitor connections across all leases.",
	})
	m.BytesForwarded = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tunnel_bytes_forwarded_total", Help: "Bytes forwarded through tunnels.",
	}, []string{"direction"})
	m.STUNRequests = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "tunnel_stun_requests_total", Help: "STUN binding requests answered.",
	})
	m.ControlRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tunnel_control_requests_total", Help: "Control API requests by op and status code.",
	}, []string{"op", "code"})
	m.Reconcile = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tunnel_lease_reconcile_total", Help: "Lease lifecycle events.",
	}, []string{"result"})

	m.Registry.MustRegister(
		m.LeasesActive, m.PortsFree, m.SSHConnections, m.SSHAuthFailures,
		m.VisitorConnections, m.BytesForwarded, m.STUNRequests,
		m.ControlRequests, m.Reconcile,
	)
	return m
}

// Handler returns the Prometheus scrape handler for this registry.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}
