// Package stun implements a minimal, unauthenticated STUN binding responder
// (RFC 5389). It answers a client's "what is my public IP:port" question — a
// free funnel primitive that Hyrule Cloud's /v1/voip/check STUN arm probes and
// that seeds the Phase-2 NAT-type classifier. It performs no billing.
package stun

import (
	"context"
	"log/slog"
	"net"

	"github.com/AS215932/hyrule-network-proxy/internal/tunnel/metrics"
	"github.com/pion/stun"
)

// Responder serves STUN binding requests over UDP.
type Responder struct {
	addr    string
	metrics *metrics.Metrics
	log     *slog.Logger
}

func New(addr string, m *metrics.Metrics, log *slog.Logger) *Responder {
	return &Responder{addr: addr, metrics: m, log: log}
}

// ListenAndServe binds the UDP address and answers binding requests until ctx
// is cancelled.
func (r *Responder) ListenAndServe(ctx context.Context) error {
	lc := net.ListenConfig{}
	pc, err := lc.ListenPacket(ctx, "udp", r.addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()
	r.log.Info("stun_listening", "addr", r.addr)

	buf := make([]byte, 1500)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				continue
			}
		}
		udpAddr, ok := src.(*net.UDPAddr)
		if !ok {
			continue
		}
		r.respond(pc, udpAddr, buf[:n])
	}
}

func (r *Responder) respond(pc net.PacketConn, src *net.UDPAddr, raw []byte) {
	req := &stun.Message{Raw: append([]byte(nil), raw...)}
	if err := req.Decode(); err != nil {
		return
	}
	if req.Type != stun.BindingRequest {
		return
	}
	resp, err := stun.Build(
		stun.NewTransactionIDSetter(req.TransactionID),
		stun.BindingSuccess,
		&stun.XORMappedAddress{IP: src.IP, Port: src.Port},
		stun.Fingerprint,
	)
	if err != nil {
		return
	}
	if _, err := pc.WriteTo(resp.Raw, src); err != nil {
		return
	}
	r.metrics.STUNRequests.Inc()
}
