package sidecar

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/sidecar/pqtunnel"
)

// serveEgress listens on the loopback address the xApp was pointed at and carries
// every connection to the peer sidecar over an authorized tunnel.
func (s *Sidecar) serveEgress(ctx context.Context, route EgressRoute) error {
	l, err := net.Listen("tcp", route.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", route.Listen, err)
	}
	s.log.Info("egress_listening", "route", route.Name, "listen", route.Listen, "peer", route.Peer, "peer_name", route.PeerName)
	return s.acceptLoop(ctx, l, func(local net.Conn) {
		defer local.Close()
		if err := s.forward(ctx, route, local); err != nil {
			s.count("egress_failed_" + route.Name)
			s.log.Warn("egress_failed", "route", route.Name, "peer", route.Peer, "error", err.Error())
		}
	})
}

func (s *Sidecar) forward(ctx context.Context, route EgressRoute, local net.Conn) error {
	start := time.Now()
	frame, tok, err := s.buildAuthFrame(ctx, route)
	if err != nil {
		return err
	}

	dialer := &net.Dialer{Timeout: s.cfg.DialTimeout}
	raw, err := dialer.DialContext(ctx, "tcp", route.Peer)
	if err != nil {
		return fmt.Errorf("dial peer sidecar %s: %w", route.Peer, err)
	}
	defer raw.Close()

	tun, err := pqtunnel.Client(ctx, raw, s.tunnelConfig(route.PeerName))
	if err != nil {
		return fmt.Errorf("tunnel handshake with %s: %w", route.Peer, err)
	}
	hs := tun.HandshakeStats()

	if err := tun.SetDeadline(time.Now().Add(s.cfg.AuthTimeout)); err != nil {
		return err
	}
	payload, err := encodeJSON(frame)
	if err != nil {
		return err
	}
	if err := tun.WriteMessage(payload); err != nil {
		return fmt.Errorf("send authorization frame: %w", err)
	}
	raw2, err := tun.ReadMessage()
	if err != nil {
		return fmt.Errorf("read authorization reply: %w", err)
	}
	var ack authAck
	if err := decodeJSON(raw2, &ack); err != nil {
		return fmt.Errorf("authorization reply is not JSON: %w", err)
	}
	if !ack.OK {
		s.count("egress_rejected_" + ack.Code)
		return fmt.Errorf("peer refused the token: %s (%s)", ack.Code, ack.Detail)
	}
	if err := tun.SetDeadline(time.Time{}); err != nil {
		return err
	}

	s.count("egress_ok_" + route.Name)
	s.log.Info("egress_authorized",
		"route", route.Name, "peer", route.Peer, "peer_cert", tun.Peer().CommonName(),
		"binding", tok.Binding, "cnf", tok.Thumbprint, "token_alg", tok.Alg, "post_quantum", tok.PostQuantum,
		"kex", "ML-KEM-768", "peer_sig_alg", tun.Peer().Alg,
		"handshake_ms", ms(hs.Total), "setup_ms", ms(time.Since(start)))

	relay(tun, local)
	return nil
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
