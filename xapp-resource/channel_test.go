package xappresource

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"testing"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/jose"
	"github.com/oran-ricsec/xapp-token-binding/internal/pki"
)

const channelTarget = "https://xapp-d-sidecar.ricxapp.svc.cluster.local:4570/rmr"

func chain(c ...*x509.Certificate) []*x509.Certificate { return c }

// The tunnel carries RMR and HTTP alike, so these cases are what protects both.
func TestChannelCertificateBinding(t *testing.T) {
	f := newFixture(t)
	peer := f.leaf("xapp-sidecar-c", time.Hour)
	other := f.leaf("xapp-sidecar-e", time.Hour)
	bound := f.token(map[string]any{"x5t#S256": pki.ThumbprintS256(peer.Leaf)})

	cases := []struct {
		name     string
		req      ChannelRequest
		wantCode string
	}{
		{"token bound to the handshake certificate is accepted",
			ChannelRequest{Token: bound, PeerChain: chain(peer.Leaf), Target: channelTarget}, ""},
		{"token bound to another certificate is refused",
			ChannelRequest{Token: bound, PeerChain: chain(other.Leaf), Target: channelTarget}, ReasonX5tMismatch},
		{"no peer certificate at all is refused",
			ChannelRequest{Token: bound, Target: channelTarget}, ReasonClientCertMissing},
		{"an unbound bearer token is refused",
			ChannelRequest{Token: f.token(nil), PeerChain: chain(peer.Leaf), Target: channelTarget}, ReasonCnfMissing},
	}
	for _, tc := range cases {
		p, rej := f.v.AuthorizeChannel(context.Background(), tc.req)
		switch {
		case tc.wantCode == "" && rej != nil:
			t.Errorf("%s: rejected with %s (%s)", tc.name, rej.Code, rej.Detail)
		case tc.wantCode == "" && p.Binding != "x5t#S256":
			t.Errorf("%s: binding is %q", tc.name, p.Binding)
		case tc.wantCode != "" && (rej == nil || rej.Code != tc.wantCode):
			t.Errorf("%s: got %v, want %s", tc.name, rej, tc.wantCode)
		}
	}
}

func TestChannelProofBinding(t *testing.T) {
	f := newFixture(t)
	peer := f.leaf("xapp-sidecar-d", time.Hour)
	signer, err := jose.GenerateSigner("ES256")
	if err != nil {
		t.Fatal(err)
	}
	jkt, err := signer.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	tok := f.token(map[string]any{"jkt": jkt})

	proof := func(target string, at time.Time) string {
		sum := jose.B64(sha256Sum(tok))
		p, err := signer.SignCompact(
			map[string]any{"typ": "dpop+jwt", "jwk": signer.PublicKey()},
			map[string]any{"jti": jose.B64([]byte(target + at.String())), "htm": ChannelOperation,
				"htu": target, "iat": at.Unix(), "ath": sum})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	if _, rej := f.v.AuthorizeChannel(context.Background(), ChannelRequest{
		Token: tok, Proof: proof(channelTarget, time.Now()), PeerChain: chain(peer.Leaf), Target: channelTarget,
	}); rej != nil {
		t.Errorf("a valid channel proof was rejected: %s (%s)", rej.Code, rej.Detail)
	}

	// A proof minted for a different destination must not open this one.
	elsewhere := "https://xapp-x-sidecar.ricxapp.svc.cluster.local:4570/rmr"
	if _, rej := f.v.AuthorizeChannel(context.Background(), ChannelRequest{
		Token: tok, Proof: proof(elsewhere, time.Now()), PeerChain: chain(peer.Leaf), Target: channelTarget,
	}); rej == nil || rej.Code != ReasonDPoPHtuMismatch {
		t.Errorf("proof for another target: got %v, want %s", rej, ReasonDPoPHtuMismatch)
	}

	// The same proof twice is a replay.
	replayed := proof(channelTarget, time.Now())
	req := ChannelRequest{Token: tok, Proof: replayed, PeerChain: chain(peer.Leaf), Target: channelTarget}
	if _, rej := f.v.AuthorizeChannel(context.Background(), req); rej != nil {
		t.Fatalf("first use rejected: %s", rej.Code)
	}
	if _, rej := f.v.AuthorizeChannel(context.Background(), req); rej == nil || rej.Code != ReasonDPoPReplayed {
		t.Errorf("replayed proof: got %v, want %s", rej, ReasonDPoPReplayed)
	}

	// A jkt-bound token presented with no proof at all is refused.
	if _, rej := f.v.AuthorizeChannel(context.Background(), ChannelRequest{
		Token: tok, PeerChain: chain(peer.Leaf), Target: channelTarget,
	}); rej == nil || rej.Code != ReasonDPoPAsBearer {
		t.Errorf("proofless jkt token: got %v, want %s", rej, ReasonDPoPAsBearer)
	}
}

func sha256Sum(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}
