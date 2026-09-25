package sidecar

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/sidecar/pqtunnel"
	xappresource "github.com/oran-ricsec/xapp-token-binding/xapp-resource"
)

// serveIngress accepts tunnel connections from peer sidecars. A connection reaches
// the application only after the handshake authenticated the peer certificate and the
// validator accepted the access token bound to it.
func (s *Sidecar) serveIngress(ctx context.Context) error {
	l, err := net.Listen("tcp", s.cfg.IngressListen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.cfg.IngressListen, err)
	}
	s.log.Info("ingress_listening", "listen", s.cfg.IngressListen, "routes", len(s.cfg.IngressRoutes))
	return s.acceptLoop(ctx, l, func(raw net.Conn) {
		defer raw.Close()
		if err := s.accept(ctx, raw); err != nil {
			s.log.Warn("ingress_failed", "remote", raw.RemoteAddr().String(), "error", err.Error())
		}
	})
}

func (s *Sidecar) accept(ctx context.Context, raw net.Conn) error {
	start := time.Now()
	tun, err := pqtunnel.Server(ctx, raw, s.tunnelConfig(""))
	if err != nil {
		s.count("ingress_handshake_failed")
		return fmt.Errorf("tunnel handshake: %w", err)
	}
	peer := tun.Peer()
	hs := tun.HandshakeStats()

	if err := tun.SetDeadline(time.Now().Add(s.cfg.AuthTimeout)); err != nil {
		return err
	}
	payload, err := tun.ReadMessage()
	if err != nil {
		s.count("ingress_no_auth_frame")
		return fmt.Errorf("read authorization frame: %w", err)
	}
	var frame authFrame
	if err := decodeJSON(payload, &frame); err != nil {
		return s.refuse(tun, "authorization_frame_malformed", err.Error())
	}
	if frame.Version != authFrameVersion {
		return s.refuse(tun, "authorization_frame_version", fmt.Sprintf("frame version %d is not supported", frame.Version))
	}
	local, ok := s.cfg.IngressTarget(frame.Route)
	if !ok {
		return s.refuse(tun, "route_unknown", fmt.Sprintf("route %q is not served here", frame.Route))
	}

	// The target the proof was minted for must be this sidecar and this route, not
	// some other destination the peer also talks to.
	want := "https://" + s.cfg.IngressAuthority(frame.Route)
	if frame.Target != want {
		return s.refuse(tun, "channel_target_mismatch", fmt.Sprintf("authorization frame targets %q, this route is %q", frame.Target, want))
	}

	p, rej := s.validator.AuthorizeChannel(ctx, xappresource.ChannelRequest{
		Token:     frame.Token,
		Proof:     frame.Proof,
		PeerChain: peer.Chain,
		Target:    frame.Target,
		Operation: xappresource.ChannelOperation,
	})
	if rej != nil {
		s.count("ingress_rejected_" + rej.Code)
		s.log.Warn("ingress_rejected",
			"route", frame.Route, "peer_cert", peer.CommonName(), "client_id", frame.ClientID,
			"reason_code", rej.Code, "reason", rej.Detail, "validation_ms", ms(time.Since(start)))
		return s.refuse(tun, rej.Code, rej.Detail)
	}

	// The token was accepted; the caller it names must also be the peer that
	// completed the handshake, so a stolen token cannot be presented over a tunnel
	// authenticated with a different certificate.
	if p.ClientID != "" && peer.CommonName() != "" && p.ClientID != peer.CommonName() {
		s.count("ingress_rejected_peer_identity_mismatch")
		return s.refuse(tun, "peer_identity_mismatch",
			fmt.Sprintf("token names client %q but the tunnel peer certificate is CN=%q", p.ClientID, peer.CommonName()))
	}

	if err := s.reply(tun, authAck{OK: true, Binding: p.Binding, Peer: s.cfg.Name}); err != nil {
		return err
	}
	if err := tun.SetDeadline(time.Time{}); err != nil {
		return err
	}
	s.count("ingress_ok_" + frame.Route)
	s.log.Info("ingress_authorized",
		"route", frame.Route, "client_id", p.ClientID, "peer_cert", peer.CommonName(), "peer_sig_alg", peer.Alg,
		"binding", p.Binding, "cnf", p.Thumbprint, "kex", "ML-KEM-768",
		"handshake_ms", ms(hs.Total), "authz_ms", ms(time.Since(start)), "target", local)

	app, err := (&net.Dialer{Timeout: s.cfg.DialTimeout}).DialContext(ctx, "tcp", local)
	if err != nil {
		s.count("ingress_app_unreachable")
		return fmt.Errorf("connect to the application at %s: %w", local, err)
	}
	defer app.Close()
	relay(app, tun)
	return nil
}

// refuse sends the reason to the peer and closes the connection.
func (s *Sidecar) refuse(tun *pqtunnel.Conn, code, detail string) error {
	if err := s.reply(tun, authAck{OK: false, Code: code, Detail: detail}); err != nil {
		return err
	}
	return fmt.Errorf("refused: %s (%s)", code, detail)
}

func (s *Sidecar) reply(tun *pqtunnel.Conn, ack authAck) error {
	b, err := encodeJSON(ack)
	if err != nil {
		return err
	}
	return tun.WriteMessage(b)
}
