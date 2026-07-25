// Package sshd implements the public SSH intake for the reverse-tunnel service.
//
// Security model: this is the sanctioned public-facing counterpart to the
// internal-only network-proxy egress sidecar. It accepts ONLY remote port
// forwarding (ssh -R) and refuses everything an egress proxy would need —
// direct-tcpip (ssh -L / -D / SOCKS), exec, shell commands, and subsystems.
// The SSH username is the x402 lease token; there is no password or key auth.
package sshd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/AS215932/hyrule-network-proxy/internal/tunnel/lease"
	"github.com/AS215932/hyrule-network-proxy/internal/tunnel/metrics"
	gossh "golang.org/x/crypto/ssh"
)

// LeaseLookup is the subset of the lease store the SSH server needs.
type LeaseLookup interface {
	ByToken(token string) (lease.Lease, bool)
	Get(id string) (lease.Lease, bool)
}

// Config configures the SSH intake server.
type Config struct {
	ListenAddr              string
	HostKeyPath             string
	EndpointHost            string
	SSHPort                 int
	MaxVisitorConnsPerLease int
	KeepaliveInterval       time.Duration
	AuthAttemptsPerWindow   int
	AuthWindow              time.Duration
}

// Server is the SSH intake listener.
type Server struct {
	cfg     Config
	signer  gossh.Signer
	store   LeaseLookup
	manager *Manager
	metrics *metrics.Metrics
	log     *slog.Logger
	limiter *authLimiter
}

// New builds an SSH intake server, loading or generating the persistent host key.
func New(cfg Config, store LeaseLookup, m *metrics.Metrics, log *slog.Logger) (*Server, error) {
	signer, err := loadOrCreateHostKey(cfg.HostKeyPath)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:     cfg,
		signer:  signer,
		store:   store,
		manager: NewManager(store, m, log, cfg.MaxVisitorConnsPerLease),
		metrics: m,
		log:     log,
		limiter: newAuthLimiter(cfg.AuthAttemptsPerWindow, cfg.AuthWindow),
	}, nil
}

// Manager exposes the forward manager for lifecycle teardown by the coordinator.
func (s *Server) Manager() *Manager { return s.manager }

// HostKeyFingerprint returns the server host-key fingerprint for the banner/docs.
func (s *Server) HostKeyFingerprint() string { return gossh.FingerprintSHA256(s.signer.PublicKey()) }

// serverConfig builds a per-connection SSH server config. Auth succeeds iff the
// username is a live lease token; "none" and "password" both resolve the same
// way so rescue clients (which have no key) connect without a prompt.
func (s *Server) serverConfig() *gossh.ServerConfig {
	authByToken := func(conn gossh.ConnMetadata) (*gossh.Permissions, error) {
		l, ok := s.store.ByToken(conn.User())
		if !ok || l.Expired(time.Now()) {
			s.metrics.SSHAuthFailures.Inc()
			return nil, fmt.Errorf("invalid or expired lease token")
		}
		return &gossh.Permissions{Extensions: map[string]string{"lease_id": l.LeaseID}}, nil
	}
	cfg := &gossh.ServerConfig{
		// Token-only: the username is the lease token, authenticated via the
		// guarded "none" method so rescue clients (which have no key) connect
		// without a prompt. Password auth is deliberately NOT offered — it must
		// not be an enabled protocol method.
		NoClientAuth: true,
		NoClientAuthCallback: func(conn gossh.ConnMetadata) (*gossh.Permissions, error) {
			return authByToken(conn)
		},
		ServerVersion: "SSH-2.0-hyrule-tunnel",
	}
	cfg.AddHostKey(s.signer)
	return cfg
}

// ListenAndServe binds the intake address and serves until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("ssh listen %s: %w", s.cfg.ListenAddr, err)
	}
	return s.Serve(ctx, ln)
}

// Serve accepts SSH intake connections on ln until ctx is cancelled. Exposed so
// tests can bind their own listener and learn its port.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	s.log.Info("ssh_intake_listening", "addr", ln.Addr().String(), "fingerprint", s.HostKeyFingerprint())
	const maxAcceptBackoff = time.Second
	var acceptBackoff time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			// A persistent resource error (e.g. EMFILE at the fd limit) would
			// otherwise spin a tight CPU + journal-flooding loop. Back off with a
			// bounded exponential delay so the daemon recovers as descriptors free.
			if acceptBackoff == 0 {
				acceptBackoff = 5 * time.Millisecond
			} else {
				acceptBackoff *= 2
				if acceptBackoff > maxAcceptBackoff {
					acceptBackoff = maxAcceptBackoff
				}
			}
			s.log.Warn("ssh_accept_error", "error", err.Error(), "backoff", acceptBackoff.String())
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(acceptBackoff):
			}
			continue
		}
		acceptBackoff = 0
		host := remoteIP(conn.RemoteAddr())
		if !s.limiter.allow(host) {
			s.metrics.SSHAuthFailures.Inc()
			_ = conn.Close()
			continue
		}
		go s.handleConn(ctx, conn)
	}
}

// handleConn runs the SSH handshake and, on success, wires reverse forwarding.
func (s *Server) handleConn(ctx context.Context, raw net.Conn) {
	_ = raw.SetDeadline(time.Now().Add(30 * time.Second)) // handshake deadline
	sconn, chans, reqs, err := gossh.NewServerConn(raw, s.serverConfig())
	if err != nil {
		_ = raw.Close()
		return
	}
	_ = raw.SetDeadline(time.Time{}) // clear; keepalives govern liveness now

	leaseID := sconn.Permissions.Extensions["lease_id"]
	l, ok := s.store.Get(leaseID)
	if !ok || l.Expired(time.Now()) {
		_ = sconn.Close()
		return
	}
	s.metrics.SSHConnections.WithLabelValues("connected").Inc()
	defer s.metrics.SSHConnections.WithLabelValues("connected").Dec()
	s.log.Info("ssh_client_connected", "lease_id", leaseID, "port", l.AllocatedPort)

	// Register the connection (last-writer-wins). This bounds a lease to one live
	// connection even if it never forwards, and makes the session closable by
	// teardown — a token holder can't accumulate idle sockets. Registration
	// re-validates the lease under the teardown lock; if it lost a race with
	// revocation/expiry, refuse and close.
	if !s.manager.RegisterConn(sconn, leaseID) {
		_ = sconn.Close()
		return
	}

	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go s.keepalive(connCtx, sconn)
	go s.rejectChannels(chans)

	s.handleGlobalRequests(sconn, reqs, l)

	// Connection closed: tear down its forward only if it still owns it (a newer
	// reconnect may already have replaced it).
	s.manager.OnConnClosed(leaseID, sconn)
	_ = sconn.Close()
	s.log.Info("ssh_client_disconnected", "lease_id", leaseID)
}

// handleGlobalRequests services tcpip-forward / cancel-tcpip-forward and drops
// everything else. It returns when the request channel closes (conn shutdown).
func (s *Server) handleGlobalRequests(sconn *gossh.ServerConn, reqs <-chan *gossh.Request, l lease.Lease) {
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			var m struct {
				Addr string
				Port uint32
			}
			if err := gossh.Unmarshal(req.Payload, &m); err != nil {
				replyRequest(req, false, nil)
				continue
			}
			// StartForward re-validates the lease against the store under its lock
			// (a session authenticated before its lease expired/was revoked must
			// not be able to install a public listener) and binds the lease's
			// allocated port, ignoring the client's requested port. On a gone/
			// expired lease, refuse and close the connection.
			assignedPort, _, err := s.manager.StartForward(sconn, l.LeaseID, m.Addr, m.Port)
			if err != nil {
				replyRequest(req, false, nil)
				if errors.Is(err, ErrLeaseGone) {
					_ = sconn.Close()
					return
				}
				s.log.Warn("forward_start_failed", "lease_id", l.LeaseID, "error", err.Error())
				continue
			}
			if req.WantReply {
				if m.Port == 0 {
					_ = req.Reply(true, gossh.Marshal(struct{ Port uint32 }{uint32(assignedPort)}))
				} else {
					_ = req.Reply(true, nil)
				}
			}
		case "cancel-tcpip-forward":
			// Scoped to this connection so a stale cancel can't drop a newer
			// connection's forward.
			s.manager.CancelForward(l.LeaseID, sconn)
			replyRequest(req, true, nil)
		default:
			// keepalive@openssh.com and anything unexpected: decline.
			replyRequest(req, false, nil)
		}
	}
}

// rejectChannels refuses every channel type. Reverse forwarding needs no client
// channel; a "session" is refused (no shell) and "direct-tcpip" (ssh -L / SOCKS)
// is the abuse vector this service exists to deny.
func (s *Server) rejectChannels(chans <-chan gossh.NewChannel) {
	for newChan := range chans {
		_ = newChan.Reject(gossh.Prohibited, "hyrule-tunnel accepts only remote (-R) port forwarding")
	}
}

// keepalive sends periodic keepalives and closes the connection after three
// consecutive failures, so dead NAT bindings are reaped.
func (s *Server) keepalive(ctx context.Context, sconn *gossh.ServerConn) {
	if s.cfg.KeepaliveInterval <= 0 {
		return
	}
	t := time.NewTicker(s.cfg.KeepaliveInterval)
	defer t.Stop()
	misses := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// SendRequest waits for the reply with no deadline; a blackholed NAT
			// path (socket never closed) would block it forever and the three-
			// miss reap would never fire. Bound each request so a stale binding
			// is reaped predictably.
			if err := s.sendKeepalive(sconn); err != nil {
				misses++
				if misses >= 3 {
					_ = sconn.Close()
					return
				}
				continue
			}
			misses = 0
		}
	}
}

// sendKeepalive sends one keepalive and waits at most KeepaliveInterval for the
// reply, returning an error on failure or timeout.
func (s *Server) sendKeepalive(sconn *gossh.ServerConn) error {
	done := make(chan error, 1)
	go func() {
		_, _, err := sconn.SendRequest("keepalive@openssh.com", true, nil)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(s.cfg.KeepaliveInterval):
		return fmt.Errorf("keepalive timed out")
	}
}

func replyRequest(req *gossh.Request, ok bool, payload []byte) {
	if req.WantReply {
		_ = req.Reply(ok, payload)
	}
}

func remoteIP(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// loadOrCreateHostKey reads an ed25519 host key from path, generating and
// persisting one (0600) on first run so the fingerprint is stable across
// restarts.
func loadOrCreateHostKey(path string) (gossh.Signer, error) {
	if data, err := os.ReadFile(path); err == nil {
		signer, err := gossh.ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse host key %s: %w", path, err)
		}
		return signer, nil
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, fmt.Errorf("persist host key %s: %w", path, err)
	}
	return gossh.ParsePrivateKey(pemBytes)
}
