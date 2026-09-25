package xappresource

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// ChannelRequest is one authorization attempt on a channel that is not HTTP over
// TLS: the sidecar post-quantum tunnel, which carries RMR and HTTP alike.
//
// The checks are identical to the HTTP ones, because they are the same checks: the
// certificate the peer proved possession of during the tunnel handshake takes the
// place of the TLS peer certificate, and the authorization frame sent as the first
// record on the tunnel takes the place of the Authorization and DPoP headers.
type ChannelRequest struct {
	// Token is the access token the peer presented.
	Token string
	// Proof is the DPoP proof for a jkt-bound token (method C); empty for a
	// certificate-bound token (methods A and B).
	Proof string
	// PeerChain is the certificate chain the peer authenticated with, leaf first.
	PeerChain []*x509.Certificate
	// Target is the canonical URI of the destination, for example
	// https://xapp-b.ricxapp.svc.cluster.local:4570/rmr. It is what the proof
	// must carry in htu.
	Target string
	// Operation is what the proof must carry in htm; the sidecar uses TUNNEL.
	Operation string
}

// ChannelOperation is the htm value used for a tunnel authorization frame. It is not
// an HTTP method precisely because this is not an HTTP request, so a proof minted for
// a tunnel can never be replayed against an HTTP resource and the other way round.
const ChannelOperation = "TUNNEL"

// AuthorizeChannel runs every check Authorize runs, against a tunnel peer instead of
// a TLS peer. It returns the authorized caller or the first failure.
func (v *Validator) AuthorizeChannel(ctx context.Context, cr ChannelRequest) (*Principal, *Rejection) {
	if cr.Token == "" {
		return nil, reject(ReasonAuthorizationMissing, "authorization frame carries no access token")
	}
	u, err := url.Parse(cr.Target)
	if err != nil || u.Host == "" {
		return nil, reject(ReasonDPoPHtuMismatch, "channel target %q is not an absolute URI", cr.Target)
	}
	op := cr.Operation
	if op == "" {
		op = ChannelOperation
	}
	scheme := "Bearer"
	if cr.Proof != "" {
		scheme = "DPoP"
	}
	req := &http.Request{
		Method: op,
		URL:    u,
		Host:   u.Host,
		Header: http.Header{"Authorization": {scheme + " " + cr.Token}},
		// A non-nil TLS state is how the validator learns the peer certificate. The
		// tunnel established it with ML-KEM and ML-DSA rather than with TLS, but the
		// binding check is the same comparison against the same chain.
		TLS: &tls.ConnectionState{PeerCertificates: cr.PeerChain},
	}
	if cr.Proof != "" {
		req.Header.Set("DPoP", cr.Proof)
	}
	return v.Authorize(req.WithContext(ctx), v.channelMode())
}

// channelMode is the validation mode used for tunnel traffic.
func (v *Validator) channelMode() Mode {
	if v.introspect != nil && v.cfg.ChannelMode == ModeIntrospection {
		return ModeIntrospection
	}
	return ModeLocal
}

// ChannelTarget builds the canonical target URI for a tunnel route.
func ChannelTarget(host string, port int, route string) string {
	return fmt.Sprintf("https://%s:%d/%s", host, port, route)
}

// ChannelProofWindow is the accepted age of a tunnel authorization proof.
func (v *Validator) ChannelProofWindow() time.Duration { return v.cfg.DPoPProofWindow }
