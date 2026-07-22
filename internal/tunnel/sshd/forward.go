package sshd

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

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

// forward is a lease's active public data listener plus its addressing. Visitor
// accounting lives on the owning leaseState (not here), so it survives forward
// generations — a cancel + re-forward can't reset the counter and bypass the cap.
type forward struct {
	listener      net.Listener
	connectedAddr string
	connectedPort uint32
	allowNets     []*net.IPNet // empty + !allowlistSet => open to all
	allowlistSet  bool         // a restriction was requested for this lease
	closeOnce     sync.Once

	// Active visitor sockets, closed on teardown so a blocked visitor→channel
	// copy unblocks (otherwise wg.Wait and the visitor-count decrement never run
	// and descriptors leak).
	vmu      sync.Mutex
	visitors map[net.Conn]struct{}
	closed   bool
}

// allows reports whether a visitor source IP may connect. It fails CLOSED: if a
// lease requested an allowlist but it parsed to zero usable networks, no visitor
// is allowed, so a typo'd restriction never silently opens the port to everyone.
func (f *forward) allows(ip net.IP) bool {
	if len(f.allowNets) == 0 {
		return !f.allowlistSet
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
		f.vmu.Lock()
		f.closed = true
		for vc := range f.visitors {
			_ = vc.Close()
		}
		f.visitors = nil
		f.vmu.Unlock()
	})
}

// trackVisitor registers a visitor socket for teardown-time closure, returning
// false if the forward is already closed (the caller should drop the socket).
func (f *forward) trackVisitor(vc net.Conn) bool {
	f.vmu.Lock()
	defer f.vmu.Unlock()
	if f.closed {
		return false
	}
	if f.visitors == nil {
		f.visitors = make(map[net.Conn]struct{})
	}
	f.visitors[vc] = struct{}{}
	return true
}

func (f *forward) untrackVisitor(vc net.Conn) {
	f.vmu.Lock()
	if f.visitors != nil {
		delete(f.visitors, vc)
	}
	f.vmu.Unlock()
}

// leaseState is the single authenticated connection for a lease plus its current
// forward (if any) and per-lease traffic accounting. Exactly one connection per
// lease is tracked (last-writer-wins), so a token holder cannot accumulate
// unbounded sockets and every session is closable by teardown.
type leaseState struct {
	conn     *gossh.ServerConn
	forward  *forward
	visitors atomic.Int64
	bytesIn  atomic.Int64
	bytesOut atomic.Int64
}

// reserveVisitorSlot atomically reserves a visitor slot if the current count is
// below max. The caller must Add(-1) on release.
func (s *leaseState) reserveVisitorSlot(max int64) bool {
	for {
		cur := s.visitors.Load()
		if cur >= max {
			return false
		}
		if s.visitors.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

// Manager owns per-lease connection + forward state. It enforces last-writer-
// wins: a new authenticated connection for a lease replaces the old one.
type Manager struct {
	mu          sync.Mutex
	leases      map[string]*leaseState
	store       LeaseLookup
	metrics     *metrics.Metrics
	log         *slog.Logger
	maxVisitors int
}

// visitorIP extracts a visitor's source IP, preferring the structured
// *net.TCPAddr (so an IPv6 zone like %eth0 doesn't defeat parsing). Returns nil
// if no IP can be determined — a restricted lease then rejects the visitor.
func visitorIP(addr net.Addr) net.IP {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.IP
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
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
		leases:      make(map[string]*leaseState),
		store:       store,
		metrics:     m,
		log:         log,
		maxVisitors: maxVisitors,
	}
}

// ErrLeaseGone means the lease was revoked/expired between authentication and
// this forward request. ErrDuplicateForward means the connection already has an
// active forward for the lease.
var (
	ErrLeaseGone        = fmt.Errorf("lease no longer active")
	ErrDuplicateForward = fmt.Errorf("connection already has an active forward")
)

// RegisterConn records the authenticated connection for a lease, last-writer-
// wins: any prior connection (and its forward) for the lease is closed. It
// re-validates the lease against the store under the same lock Teardown uses, so
// a connection can't be registered for a lease that revocation/expiry already
// tore down (which would leave an idle socket alive). Returns false if the lease
// is gone/expired; the caller must then close the connection.
func (m *Manager) RegisterConn(conn *gossh.ServerConn, leaseID string) bool {
	m.mu.Lock()
	l, ok := m.store.Get(leaseID)
	if !ok || l.Expired(time.Now()) {
		m.mu.Unlock()
		return false
	}
	old := m.leases[leaseID]
	m.leases[leaseID] = &leaseState{conn: conn}
	m.mu.Unlock()
	if old != nil {
		if old.forward != nil {
			old.forward.close()
		}
		if old.conn != conn {
			_ = old.conn.Close()
		}
	}
	return true
}

// StartForward validates the lease and binds its allocated public port for the
// (already-registered) connection. Runs under a single lock hold and Teardown
// holds the same lock, so activation is serialized with revocation: once the
// coordinator removes the lease from the store (BEFORE Teardown), no forward can
// be installed. Returns the assigned public port and the connected-port to echo.
func (m *Manager) StartForward(conn *gossh.ServerConn, leaseID, bindAddr string, requestedPort uint32) (assignedPort int, connectedPort uint32, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	l, ok := m.store.Get(leaseID)
	if !ok || l.Expired(time.Now()) {
		return 0, 0, ErrLeaseGone
	}
	st := m.leases[leaseID]
	if st == nil || st.conn != conn {
		// The connection isn't the registered one (raced a takeover) — refuse.
		return 0, 0, ErrLeaseGone
	}
	if st.forward != nil {
		// Already forwarding on this connection: refuse rather than reset the
		// (per-lease) visitor counter or leak the prior listener.
		return 0, 0, ErrDuplicateForward
	}

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", l.AllocatedPort))
	if err != nil {
		return 0, 0, fmt.Errorf("bind data port %d: %w", l.AllocatedPort, err)
	}
	connectedPort = requestedPort
	if requestedPort == 0 {
		connectedPort = uint32(l.AllocatedPort)
	}
	f := &forward{
		listener:      ln,
		connectedAddr: bindAddr,
		connectedPort: connectedPort,
		allowNets:     parseCIDRs(l.AllowlistCIDRs),
		allowlistSet:  len(l.AllowlistCIDRs) > 0,
	}
	st.forward = f
	m.log.Info("forward_started", "lease_id", leaseID, "port", l.AllocatedPort)
	go m.acceptVisitors(st, f)
	return l.AllocatedPort, connectedPort, nil
}

// Teardown closes a lease's forward AND its connection, and forgets the lease,
// so a revoked/expired lease cannot resend tcpip-forward or linger as a socket.
func (m *Manager) Teardown(leaseID string) {
	m.mu.Lock()
	st := m.leases[leaseID]
	delete(m.leases, leaseID)
	m.mu.Unlock()
	if st != nil {
		if st.forward != nil {
			st.forward.close()
		}
		_ = st.conn.Close()
		m.log.Info("forward_torn_down", "lease_id", leaseID)
	}
}

// CancelForward closes a lease's forward (only if it belongs to conn) but keeps
// the connection and its per-lease visitor accounting, so a stale cancel from an
// older connection can't drop a newer one, and a cancel+re-forward can't reset
// the visitor cap.
func (m *Manager) CancelForward(leaseID string, conn *gossh.ServerConn) {
	m.mu.Lock()
	st := m.leases[leaseID]
	var f *forward
	if st != nil && st.conn == conn && st.forward != nil {
		f = st.forward
		st.forward = nil
	}
	m.mu.Unlock()
	if f != nil {
		f.close()
	}
}

// OnConnClosed forgets a lease's state only if it still belongs to conn, so a
// reconnect that already replaced it is left untouched.
func (m *Manager) OnConnClosed(leaseID string, conn *gossh.ServerConn) {
	m.mu.Lock()
	st := m.leases[leaseID]
	if st != nil && st.conn == conn {
		delete(m.leases, leaseID)
		m.mu.Unlock()
		if st.forward != nil {
			st.forward.close()
		}
		return
	}
	m.mu.Unlock()
}

// Stats returns live connection stats for a lease, used by the status endpoint.
func (m *Manager) Stats(leaseID string) (connected bool, visitors int, bytesIn, bytesOut int64) {
	m.mu.Lock()
	st := m.leases[leaseID]
	if st == nil {
		m.mu.Unlock()
		return false, 0, 0, 0
	}
	// Read the forward pointer under the lock (StartForward/CancelForward write
	// it under the same lock — reading it after unlocking would be a data race).
	connected = st.forward != nil
	m.mu.Unlock()
	return connected, int(st.visitors.Load()), st.bytesIn.Load(), st.bytesOut.Load()
}

// acceptVisitors accepts public connections on the lease's data port and pipes
// each over a forwarded-tcpip channel to the client. A transient accept error
// (e.g. EMFILE) is retried with bounded backoff; the loop exits only when the
// listener is closed.
func (m *Manager) acceptVisitors(st *leaseState, f *forward) {
	const maxBackoff = time.Second
	var backoff time.Duration
	for {
		vc, err := f.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return // listener closed by teardown/cancel
			}
			if backoff == 0 {
				backoff = 5 * time.Millisecond
			} else {
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
			m.log.Warn("visitor_accept_error", "error", err.Error(), "backoff", backoff.String())
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		go m.handleVisitor(st, f, vc)
	}
}

func (m *Manager) handleVisitor(st *leaseState, f *forward, vc net.Conn) {
	defer vc.Close()

	// Fail closed on a restricted lease: use the address's IP directly and reject
	// anything we can't resolve to an allowed IP (e.g. an IPv6 link-local peer
	// with a zone like fe80::1%eth0 that net.ParseIP can't parse).
	ip := visitorIP(vc.RemoteAddr())
	if f.allowlistSet || len(f.allowNets) > 0 {
		if ip == nil || !f.allows(ip) {
			return
		}
	}
	// Track the socket so teardown can close it (unblocking both copy directions),
	// and reserve a per-lease visitor slot atomically (survives forward gens).
	if !f.trackVisitor(vc) {
		return // forward already torn down
	}
	defer f.untrackVisitor(vc)
	if !st.reserveVisitorSlot(int64(m.maxVisitors)) {
		return
	}
	m.metrics.VisitorConnections.Inc()
	defer func() {
		st.visitors.Add(-1)
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
	ch, reqs, err := st.conn.OpenChannel("forwarded-tcpip", payload)
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
		st.bytesIn.Add(n)
		m.metrics.BytesForwarded.WithLabelValues("in").Add(float64(n))
		ch.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(vc, ch)
		st.bytesOut.Add(n)
		m.metrics.BytesForwarded.WithLabelValues("out").Add(float64(n))
		if tc, ok := vc.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
}
