package sshd

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/AS215932/hyrule-network-proxy/internal/tunnel/lease"
	"github.com/AS215932/hyrule-network-proxy/internal/tunnel/metrics"
	gossh "golang.org/x/crypto/ssh"
)

// forwardedTCPPayload is the RFC 4254 "forwarded-tcpip" channel-open payload.
type forwardedTCPPayload struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

// forward is one lease's active public data listener plus the SSH connection it
// delivers visitor traffic to.
type forward struct {
	leaseID       string
	conn          *gossh.ServerConn
	listener      net.Listener
	connectedAddr string
	connectedPort uint32
	allowNets     []*net.IPNet // empty => open to all
	visitors      atomic.Int64
	bytesIn       atomic.Int64
	bytesOut      atomic.Int64
	closeOnce     sync.Once
}

// allows reports whether a visitor source IP may connect.
func (f *forward) allows(ip net.IP) bool {
	if len(f.allowNets) == 0 {
		return true
	}
	for _, n := range f.allowNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (f *forward) close() {
	f.closeOnce.Do(func() {
		_ = f.listener.Close()
	})
}

// Manager owns the set of active forwards, one per lease. It enforces
// last-writer-wins: a new client connection for a lease replaces the old one.
type Manager struct {
	mu          sync.Mutex
	forwards    map[string]*forward
	store       LeaseLookup
	metrics     *metrics.Metrics
	log         *slog.Logger
	maxVisitors int
}

// parseCIDRs parses lease allowlist entries, silently dropping malformed ones
// (the cloud validates them before create, so this is defensive only).
func parseCIDRs(cidrs []string) []*net.IPNet {
	var out []*net.IPNet
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func NewManager(store LeaseLookup, m *metrics.Metrics, log *slog.Logger, maxVisitors int) *Manager {
	return &Manager{
		forwards:    make(map[string]*forward),
		store:       store,
		metrics:     m,
		log:         log,
		maxVisitors: maxVisitors,
	}
}

// StartForward binds the lease's allocated public port and begins delivering
// visitor connections to conn. Any pre-existing forward for the lease (an older
// connection) is torn down first.
func (m *Manager) StartForward(conn *gossh.ServerConn, l lease.Lease, bindAddr string, connectedPort uint32) error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", l.AllocatedPort))
	if err != nil {
		return fmt.Errorf("bind data port %d: %w", l.AllocatedPort, err)
	}

	m.mu.Lock()
	if old := m.forwards[l.LeaseID]; old != nil {
		old.close()
		if old.conn != conn {
			_ = old.conn.Close()
		}
	}
	f := &forward{
		leaseID:       l.LeaseID,
		conn:          conn,
		listener:      ln,
		connectedAddr: bindAddr,
		connectedPort: connectedPort,
		allowNets:     parseCIDRs(l.AllowlistCIDRs),
	}
	m.forwards[l.LeaseID] = f
	m.mu.Unlock()

	m.log.Info("forward_started", "lease_id", l.LeaseID, "port", l.AllocatedPort)
	go m.acceptVisitors(f)
	return nil
}

// Teardown closes and forgets a lease's forward, if any.
func (m *Manager) Teardown(leaseID string) {
	m.mu.Lock()
	f := m.forwards[leaseID]
	delete(m.forwards, leaseID)
	m.mu.Unlock()
	if f != nil {
		f.close()
		m.log.Info("forward_torn_down", "lease_id", leaseID)
	}
}

// OnConnClosed tears down a lease's forward only if it still belongs to conn,
// so a reconnect that already replaced the forward is left untouched.
func (m *Manager) OnConnClosed(leaseID string, conn *gossh.ServerConn) {
	m.mu.Lock()
	f := m.forwards[leaseID]
	if f != nil && f.conn == conn {
		delete(m.forwards, leaseID)
		m.mu.Unlock()
		f.close()
		return
	}
	m.mu.Unlock()
}

// Active reports whether a lease currently has a connected client.
func (m *Manager) Active(leaseID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.forwards[leaseID]
	return ok
}

// Stats returns live connection stats for a lease, used by the status endpoint.
// connected is false (and counts zero) when no client is currently attached.
func (m *Manager) Stats(leaseID string) (connected bool, visitors int, bytesIn, bytesOut int64) {
	m.mu.Lock()
	f := m.forwards[leaseID]
	m.mu.Unlock()
	if f == nil {
		return false, 0, 0, 0
	}
	return true, int(f.visitors.Load()), f.bytesIn.Load(), f.bytesOut.Load()
}

// acceptVisitors accepts public connections on the lease's data port and pipes
// each one over a forwarded-tcpip channel to the client.
func (m *Manager) acceptVisitors(f *forward) {
	for {
		vc, err := f.listener.Accept()
		if err != nil {
			return // listener closed
		}
		go m.handleVisitor(f, vc)
	}
}

func (m *Manager) handleVisitor(f *forward, vc net.Conn) {
	defer vc.Close()

	ip := net.ParseIP(remoteIP(vc.RemoteAddr()))
	if ip != nil && !f.allows(ip) {
		return
	}
	if f.visitors.Load() >= int64(m.maxVisitors) {
		return
	}
	f.visitors.Add(1)
	m.metrics.VisitorConnections.Inc()
	defer func() {
		f.visitors.Add(-1)
		m.metrics.VisitorConnections.Dec()
	}()

	originAddr, originPortStr, _ := net.SplitHostPort(vc.RemoteAddr().String())
	originPort, _ := strconv.Atoi(originPortStr)
	payload := gossh.Marshal(forwardedTCPPayload{
		Addr:       f.connectedAddr,
		Port:       f.connectedPort,
		OriginAddr: originAddr,
		OriginPort: uint32(originPort),
	})
	ch, reqs, err := f.conn.OpenChannel("forwarded-tcpip", payload)
	if err != nil {
		return
	}
	defer ch.Close()
	go gossh.DiscardRequests(reqs)

	// Bidirectional copy. "in" = visitor→client, "out" = client→visitor.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(ch, vc)
		f.bytesIn.Add(n)
		m.metrics.BytesForwarded.WithLabelValues("in").Add(float64(n))
		ch.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(vc, ch)
		f.bytesOut.Add(n)
		m.metrics.BytesForwarded.WithLabelValues("out").Add(float64(n))
		if tc, ok := vc.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
}
