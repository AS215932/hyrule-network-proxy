package sshd

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/AS215932/hyrule-network-proxy/internal/tunnel/lease"
	"github.com/AS215932/hyrule-network-proxy/internal/tunnel/metrics"
	gossh "golang.org/x/crypto/ssh"
)

// testHarness starts an SSH intake server on a random loopback port and returns
// the store and dial address.
func testHarness(t *testing.T) (*lease.Store, string) {
	t.Helper()
	store, err := lease.Open(filepath.Join(t.TempDir(), "leases.db"), 21000, 21050)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	m := metrics.New()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := New(Config{
		HostKeyPath:             filepath.Join(t.TempDir(), "hostkey"),
		EndpointHost:            "tun.test",
		SSHPort:                 2222,
		MaxVisitorConnsPerLease: 8,
		KeepaliveInterval:       0, // disable in tests
		AuthAttemptsPerWindow:   100,
		AuthWindow:              time.Second,
	}, store, m, log)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx, ln)
	return store, ln.Addr().String()
}

func dialClient(t *testing.T, addr, token string) (*gossh.Client, error) {
	t.Helper()
	cfg := &gossh.ClientConfig{
		User:            token,
		Auth:            nil, // offer "none" auth, as a rescue client would
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	return gossh.Dial("tcp", addr, cfg)
}

func TestReverseForwardEndToEnd(t *testing.T) {
	store, addr := testHarness(t)
	l, _ := store.Create(lease.CreateParams{LeaseID: "e2e", Duration: time.Hour})

	client, err := dialClient(t, addr, l.Token)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	// Client requests a remote forward (ssh -R 0:...). The server must ignore the
	// requested port and bind the lease's allocated port.
	fwd, err := client.ListenTCP(&net.TCPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("remote forward: %v", err)
	}
	defer fwd.Close()
	if got := fwd.Addr().(*net.TCPAddr).Port; got != l.AllocatedPort {
		t.Fatalf("forward bound port %d, want lease port %d", got, l.AllocatedPort)
	}

	// The "NAT'd host" side: echo "pong" to any visitor.
	go func() {
		c, err := fwd.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		_, _ = r.ReadString('\n')
		_, _ = c.Write([]byte("pong\n"))
	}()

	// The visitor side: dial the public data port on the server.
	vc, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(l.AllocatedPort)), 3*time.Second)
	if err != nil {
		t.Fatalf("visitor dial: %v", err)
	}
	defer vc.Close()
	_, _ = vc.Write([]byte("ping\n"))
	_ = vc.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := bufio.NewReader(vc).ReadString('\n')
	if err != nil || resp != "pong\n" {
		t.Fatalf("visitor got %q err %v, want pong", resp, err)
	}
}

func TestDirectTCPIPRejected(t *testing.T) {
	// ssh -L / -D / SOCKS: opening a direct-tcpip channel must be refused. This is
	// the egress-abuse guard and the reason this is a separate binary.
	store, addr := testHarness(t)
	l, _ := store.Create(lease.CreateParams{LeaseID: "noegress", Duration: time.Hour})
	client, err := dialClient(t, addr, l.Token)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	if conn, err := client.Dial("tcp", "example.com:80"); err == nil {
		conn.Close()
		t.Fatalf("direct-tcpip (ssh -L) must be rejected, but Dial succeeded")
	}
}

func TestSessionChannelRejected(t *testing.T) {
	// No shell/exec: opening a session channel must be refused.
	store, addr := testHarness(t)
	l, _ := store.Create(lease.CreateParams{LeaseID: "noshell", Duration: time.Hour})
	client, err := dialClient(t, addr, l.Token)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	if sess, err := client.NewSession(); err == nil {
		sess.Close()
		t.Fatalf("session channel must be rejected, but NewSession succeeded")
	}
}

func TestForwardRefusedAfterLeaseExpires(t *testing.T) {
	// A session authenticated before its lease expired must not be able to open a
	// public listener afterwards (per-forward revalidation).
	store, addr := testHarness(t)
	l, _ := store.Create(lease.CreateParams{LeaseID: "expmid", Duration: time.Hour})
	client, err := dialClient(t, addr, l.Token)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	// Expire the lease after auth but before the forward request.
	if _, err := store.Extend("expmid", -2*time.Hour); err != nil {
		t.Fatalf("extend: %v", err)
	}
	if fwd, err := client.ListenTCP(&net.TCPAddr{IP: net.IPv4zero, Port: 0}); err == nil {
		fwd.Close()
		t.Fatalf("remote forward must be refused once the lease has expired")
	}
}

func TestDuplicateForwardFromSameConnRefused(t *testing.T) {
	// A second remote forward on the SAME connection must be refused (it would
	// otherwise reset the visitor counter and bypass the per-lease cap).
	store, addr := testHarness(t)
	l, _ := store.Create(lease.CreateParams{LeaseID: "dup2", Duration: time.Hour})
	client, err := dialClient(t, addr, l.Token)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	fwd, err := client.ListenTCP(&net.TCPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("first forward: %v", err)
	}
	defer fwd.Close()
	if fwd2, err := client.ListenTCP(&net.TCPAddr{IP: net.IPv4zero, Port: 0}); err == nil {
		fwd2.Close()
		t.Fatalf("a duplicate forward on the same connection must be refused")
	}
}

func TestForwardAllowsFailsClosed(t *testing.T) {
	// A lease that requested an allowlist which parsed to zero usable networks
	// must deny every visitor, never fall open.
	f := &forward{allowlistSet: true}
	if f.allows(net.ParseIP("203.0.113.9")) {
		t.Fatalf("empty-but-configured allowlist must fail closed")
	}
	open := &forward{allowlistSet: false}
	if !open.allows(net.ParseIP("203.0.113.9")) {
		t.Fatalf("no allowlist must allow all")
	}
}

func TestInvalidTokenRejected(t *testing.T) {
	_, addr := testHarness(t)
	if client, err := dialClient(t, addr, "definitely-not-a-valid-token"); err == nil {
		client.Close()
		t.Fatalf("auth with invalid token must fail")
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	store, addr := testHarness(t)
	l, _ := store.Create(lease.CreateParams{LeaseID: "exp", Duration: time.Hour})
	if _, err := store.Extend("exp", -2*time.Hour); err != nil {
		t.Fatalf("extend: %v", err)
	}
	if client, err := dialClient(t, addr, l.Token); err == nil {
		client.Close()
		t.Fatalf("auth with expired lease must fail")
	}
}
