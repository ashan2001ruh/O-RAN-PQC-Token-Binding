package xappclient

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/pki"
)

// certBound implements Methods A and B (RFC 8705). The only differences between the
// two are the certificate lifetime and base.rotateKeys; the Keycloak configuration
// and this code path are shared.
//
// In post-quantum mode the same flow runs twice over: Keycloak issues a token bound
// to the classical certificate, then the shim re-issues it, ML-DSA-signed and bound
// to the ML-DSA certificate, which is the one presented to resource servers.
type certBound struct {
	*base
}

// Token returns a token bound to the current certificate. Rotation is driven by the
// certificate lifetime, not the token lifetime: when a certificate enters its renewal
// window a new key/certificate is obtained first, which invalidates the cached token.
func (c *certBound) Token(ctx context.Context) (*Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.needsRenewal() {
		if _, err := c.rotateLocked(ctx); err != nil {
			return nil, err
		}
	}
	if t := c.cached; t != nil && t.usable(time.Now()) {
		return t, nil
	}
	if c.rotateKeys && c.cfg.Rotation == RotateEveryToken && c.tokensOnCert > 0 {
		if _, err := c.rotateLocked(ctx); err != nil {
			return nil, err
		}
	}
	return c.issueLocked(ctx)
}

func (c *certBound) IssueToken(ctx context.Context) (*Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.needsRenewal() {
		if _, err := c.rotateLocked(ctx); err != nil {
			return nil, err
		}
	}
	return c.issueLocked(ctx)
}

func (c *certBound) issueLocked(ctx context.Context) (*Token, error) {
	// The certificate the authorization server authenticates and binds to: the
	// classical one while the shim is in the path, the ML-DSA one once it is not.
	leaf := c.asIdentity().Leaf()
	if leaf == nil {
		return nil, fmt.Errorf("client not started: no identity certificate")
	}
	resp, err := c.getIssuer().Issue(ctx, TokenRequest{
		TokenURL: c.cfg.TokenURL, ClientID: c.cfg.ClientID, Scope: c.cfg.Scope, HTTPClient: c.asClient(),
	})
	if err != nil {
		return nil, c.asLegError(err)
	}
	tok, err := newToken(resp)
	if err != nil {
		return nil, err
	}
	// Keycloak issues a token even if the certificate never reached it, so the binding
	// is checked on receipt and its absence is an error.
	x5t, err := cnfMember(tok.Claims, "x5t#S256")
	if err != nil {
		c.log.Error("token_binding_missing", "error", err,
			"hint", "client certificate did not reach Keycloak or 'OAuth 2.0 Mutual TLS Certificate Bound Access Tokens' is off")
		return nil, err
	}
	if want := pki.ThumbprintS256(leaf); x5t != want {
		return nil, fmt.Errorf("%w: cnf.x5t#S256=%s, presented certificate=%s", ErrBindingMismatch, x5t, want)
	}
	tok.Binding, tok.Thumbprint, tok.CertNotAfter = "x5t#S256", x5t, leaf.NotAfter
	c.log.Debug("token_issued", "binding", tok.Binding, "cnf", x5t, "alg", tok.Alg,
		"expires_at", tok.ExpiresAt.UTC().Format(time.RFC3339), "bytes", len(tok.Value))

	switch {
	case c.pqDirect():
		// The authorization server already issued the post-quantum token, bound to
		// the ML-DSA certificate verified above. Nothing to upgrade.
		if err := c.requirePQToken(tok); err != nil {
			return nil, err
		}
	case c.cfg.PQEnabled:
		if tok, err = c.upgradeCertBound(ctx, tok); err != nil {
			return nil, err
		}
	}
	c.cached = tok
	c.tokensOnCert++
	return tok, nil
}

// upgradeCertBound transfers the binding from the classical certificate to the
// post-quantum one and returns the ML-DSA-signed token.
func (c *certBound) upgradeCertBound(ctx context.Context, classical *Token) (*Token, error) {
	pqLeaf := c.pqID.Leaf()
	if pqLeaf == nil {
		return nil, fmt.Errorf("post-quantum identity certificate is not available")
	}
	tok, err := c.upgradeToPQ(ctx, classical, bearerDecorator, c.pqCertProof)
	if err != nil {
		return nil, err
	}
	if err := c.verifyPQBinding(tok, "x5t#S256", pki.ThumbprintS256(pqLeaf)); err != nil {
		return nil, err
	}
	tok.CertNotAfter = pqLeaf.NotAfter
	c.log.Debug("pq_token_ready", "alg", tok.Alg, "cnf", tok.Thumbprint,
		"cert_key_alg", pki.KeyAlgName(pqLeaf.PublicKey), "bytes", len(tok.Value))
	return tok, nil
}

func bearerDecorator(req *http.Request, classical *Token) error {
	req.Header.Set("Authorization", "Bearer "+classical.Value)
	return nil
}

func (c *certBound) Authorize(req *http.Request, tok *Token) error {
	req.Header.Set("Authorization", "Bearer "+tok.Value)
	return nil
}

func (c *certBound) Do(req *http.Request) (*http.Response, error) {
	tok, err := c.Token(req.Context())
	if err != nil {
		return nil, err
	}
	if err := c.Authorize(req, tok); err != nil {
		return nil, err
	}
	return c.HTTPClient().Do(req)
}
