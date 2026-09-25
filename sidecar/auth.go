package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	xappclient "github.com/oran-ricsec/xapp-token-binding/xapp-client"
	xappresource "github.com/oran-ricsec/xapp-token-binding/xapp-resource"
)

// authFrame is the first control message on every tunnel connection. It carries the
// access token and, for a jkt-bound token, the proof of possession of the key the
// token is bound to. Nothing else flows until the peer has accepted it.
type authFrame struct {
	Version  int    `json:"v"`
	ClientID string `json:"client_id"`
	Route    string `json:"route"`
	Target   string `json:"target"`
	Token    string `json:"token"`
	Proof    string `json:"proof,omitempty"`
}

// authAck is the reply. A rejection carries the validator reason code, so the sending
// side logs exactly why it was refused instead of seeing a closed connection.
type authAck struct {
	OK      bool   `json:"ok"`
	Binding string `json:"binding,omitempty"`
	Peer    string `json:"peer,omitempty"`
	Code    string `json:"code,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

const authFrameVersion = 1

// target is the canonical URI of one egress route, used as the proof htu.
func (r EgressRoute) target() string {
	return "https://" + r.Peer + "/" + r.Name
}

// buildAuthFrame obtains a currently valid bound token and, when the token is bound
// to a key rather than to a certificate, a fresh proof of possession of that key.
func (s *Sidecar) buildAuthFrame(ctx context.Context, route EgressRoute) (*authFrame, *xappclient.Token, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.TokenTimeout)
	defer cancel()
	tok, err := s.client.Token(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("access token: %w", err)
	}
	f := &authFrame{
		Version:  authFrameVersion,
		ClientID: s.client.ClientID(),
		Route:    route.Name,
		Target:   route.target(),
		Token:    tok.Value,
	}
	if tok.Binding == "jkt" {
		d, ok := s.client.(xappclient.DPoP)
		if !ok {
			return nil, nil, fmt.Errorf("token is bound to cnf.jkt but this client holds no proof key")
		}
		signer := d.Signer()
		if tok.PostQuantum {
			if d.PQSigner() == nil {
				return nil, nil, fmt.Errorf("post-quantum token but no ML-DSA proof key")
			}
			signer = d.PQSigner()
		}
		proof, err := xappclient.BuildDPoPProof(signer, xappresource.ChannelOperation, f.Target, tok.Value, "", time.Now())
		if err != nil {
			return nil, nil, fmt.Errorf("channel proof: %w", err)
		}
		f.Proof = proof
	}
	return f, tok, nil
}

func encodeJSON(v any) ([]byte, error) { return json.Marshal(v) }

func decodeJSON(b []byte, v any) error { return json.Unmarshal(b, v) }
