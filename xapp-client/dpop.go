package xappclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/jose"
	"github.com/oran-ricsec/xapp-token-binding/internal/netx"
)

// dpopClient implements Method C (RFC 9449). The transport uses the xApp RIC
// certificate (every connection is mTLS and Keycloak authenticates the client with
// it), while the access token is bound to the DPoP key via cnf.jkt.
//
// In post-quantum mode the client holds two DPoP keys: the classical one, which
// Keycloak can verify, and an ML-DSA one, which the shim binds into the upgraded
// token and which signs every proof sent to resource servers.
type dpopClient struct {
	*base
	signer jose.Signer
	jkt    string

	pqSigner jose.Signer // ML-DSA proof key (PQ mode)
	pqJKT    string

	nonceMu sync.Mutex
	nonces  map[string]string // DPoP-Nonce per origin
}

// DPoP exposes the proof keys to tests and benchmarks.
type DPoP interface {
	Signer() jose.Signer
	JKT() string
	Proof(method, rawURL, accessToken string) (string, error)
	// PQSigner is the ML-DSA proof key, nil outside PQ mode.
	PQSigner() jose.Signer
	PQJKT() string
}

func (c *dpopClient) Signer() jose.Signer   { return c.signer }
func (c *dpopClient) JKT() string           { return c.jkt }
func (c *dpopClient) PQSigner() jose.Signer { return c.pqSigner }
func (c *dpopClient) PQJKT() string         { return c.pqJKT }

// BuildDPoPProof creates a DPoP proof JWT (RFC 9449 section 4.2). When accessToken is
// not empty the proof carries ath = base64url(SHA-256(accessToken)). The signer
// decides the algorithm, so the same function produces ES256 and ML-DSA-44 proofs.
func BuildDPoPProof(s jose.Signer, method, rawURL, accessToken, nonce string, now time.Time) (string, error) {
	htu, err := netx.NormalizeHTU(rawURL)
	if err != nil {
		return "", err
	}
	jti := make([]byte, 18)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	claims := map[string]any{"jti": jose.B64(jti), "htm": method, "htu": htu, "iat": now.Unix()}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = jose.B64(sum[:])
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	return s.SignCompact(map[string]any{"typ": "dpop+jwt", "jwk": s.PublicKey()}, claims)
}

func origin(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

func (c *dpopClient) nonce(rawURL string) string {
	c.nonceMu.Lock()
	defer c.nonceMu.Unlock()
	return c.nonces[origin(rawURL)]
}

func (c *dpopClient) setNonce(rawURL, n string) {
	c.nonceMu.Lock()
	c.nonces[origin(rawURL)] = n
	c.nonceMu.Unlock()
}

// asSigner is the proof key the authorization server binds the token to, with its
// thumbprint. It is the ML-DSA key only when the server issues post-quantum tokens
// itself; otherwise the shim transfers the binding afterwards.
func (c *dpopClient) asSigner() (jose.Signer, string) {
	if c.pqDirect() && c.pqSigner != nil {
		return c.pqSigner, c.pqJKT
	}
	return c.signer, c.jkt
}

// Proof builds a proof with the classical key (used with Keycloak and the shim).
func (c *dpopClient) Proof(method, rawURL, accessToken string) (string, error) {
	return BuildDPoPProof(c.signer, method, rawURL, accessToken, c.nonce(rawURL), time.Now())
}

// proofFor picks the key that matches the token: ML-DSA for an upgraded token,
// classical otherwise.
func (c *dpopClient) proofFor(tok *Token, method, rawURL string) (string, error) {
	signer := c.signer
	if tok.PostQuantum {
		if c.pqSigner == nil {
			return "", errors.New("post-quantum token but no ML-DSA proof key")
		}
		signer = c.pqSigner
	}
	return BuildDPoPProof(signer, method, rawURL, tok.Value, c.nonce(rawURL), time.Now())
}

func (c *dpopClient) Token(ctx context.Context) (*Token, error) {
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
	return c.issueLocked(ctx)
}

func (c *dpopClient) IssueToken(ctx context.Context) (*Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.needsRenewal() {
		if _, err := c.rotateLocked(ctx); err != nil {
			return nil, err
		}
	}
	return c.issueLocked(ctx)
}

func (c *dpopClient) issueLocked(ctx context.Context) (*Token, error) {
	// The proof key the authorization server binds the token to: the classical one
	// while the shim is in the path, the ML-DSA one once the server can verify it.
	signer, wantJKT := c.asSigner()
	var resp *TokenResponse
	for attempt := 0; ; attempt++ {
		proof, err := BuildDPoPProof(signer, http.MethodPost, c.cfg.TokenURL, "", c.nonce(c.cfg.TokenURL), time.Now())
		if err != nil {
			return nil, err
		}
		resp, err = c.getIssuer().Issue(ctx, TokenRequest{
			TokenURL: c.cfg.TokenURL, ClientID: c.cfg.ClientID, Scope: c.cfg.Scope, DPoPProof: proof, HTTPClient: c.asClient(),
		})
		var ie *IssuerError
		if err != nil && attempt == 0 && errors.As(err, &ie) && ie.NeedsNonce() {
			c.setNonce(c.cfg.TokenURL, ie.DPoPNonce)
			continue
		}
		if err != nil {
			return nil, c.asLegError(err)
		}
		break
	}
	tok, err := newToken(resp)
	if err != nil {
		return nil, err
	}
	jkt, err := cnfMember(tok.Claims, "jkt")
	if err != nil {
		c.log.Error("token_binding_missing", "error", err, "hint", "'Require DPoP bound tokens' is off or the DPoP header was dropped")
		return nil, err
	}
	if jkt != wantJKT {
		return nil, fmt.Errorf("%w: cnf.jkt=%s, proof key=%s", ErrBindingMismatch, jkt, wantJKT)
	}
	if !strings.EqualFold(resp.TokenType, "DPoP") {
		return nil, fmt.Errorf("%w: token_type is %q, expected DPoP", ErrBindingMismatch, resp.TokenType)
	}
	tok.Binding, tok.Thumbprint = "jkt", jkt
	c.log.Debug("token_issued", "binding", tok.Binding, "cnf", jkt, "alg", tok.Alg,
		"expires_at", tok.ExpiresAt.UTC().Format(time.RFC3339), "bytes", len(tok.Value))

	switch {
	case c.pqDirect():
		// Already bound to the ML-DSA proof key verified above; no upgrade needed.
		if err := c.requirePQToken(tok); err != nil {
			return nil, err
		}
	case c.cfg.PQEnabled:
		if tok, err = c.upgradeDPoP(ctx, tok); err != nil {
			return nil, err
		}
	}
	c.cached = tok
	return tok, nil
}

// upgradeDPoP transfers the binding from the classical DPoP key to the ML-DSA one.
// The upgrade request proves possession of the classical key with an ordinary DPoP
// proof, and of the ML-DSA key with the post-quantum binding proof.
func (c *dpopClient) upgradeDPoP(ctx context.Context, classical *Token) (*Token, error) {
	decorate := func(req *http.Request, tok *Token) error {
		proof, err := c.Proof(req.Method, req.URL.String(), tok.Value)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "DPoP "+tok.Value)
		req.Header.Set("DPoP", proof)
		return nil
	}
	tok, err := c.upgradeToPQ(ctx, classical, decorate, c.pqJWKProof)
	if err != nil {
		return nil, err
	}
	if err := c.verifyPQBinding(tok, "jkt", c.pqJKT); err != nil {
		return nil, err
	}
	c.log.Debug("pq_token_ready", "alg", tok.Alg, "cnf", tok.Thumbprint,
		"proof_alg", c.pqSigner.Alg(), "bytes", len(tok.Value))
	return tok, nil
}

// Authorize sets the DPoP scheme and a fresh proof bound to this request and token.
func (c *dpopClient) Authorize(req *http.Request, tok *Token) error {
	proof, err := c.proofFor(tok, req.Method, req.URL.String())
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "DPoP "+tok.Value)
	req.Header.Set("DPoP", proof)
	return nil
}

func (c *dpopClient) Do(req *http.Request) (*http.Response, error) {
	tok, err := c.Token(req.Context())
	if err != nil {
		return nil, err
	}
	if err := c.Authorize(req, tok); err != nil {
		return nil, err
	}
	client := c.HTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	// Resource-server nonce challenge (RFC 9449 section 9): retry once if the body can be replayed.
	if n := resp.Header.Get("DPoP-Nonce"); resp.StatusCode == http.StatusUnauthorized && n != "" &&
		strings.Contains(resp.Header.Get("WWW-Authenticate"), "use_dpop_nonce") && (req.Body == nil || req.GetBody != nil) {
		resp.Body.Close()
		c.setNonce(req.URL.String(), n)
		retry := req.Clone(req.Context())
		if req.GetBody != nil {
			if retry.Body, err = req.GetBody(); err != nil {
				return nil, err
			}
		}
		if err := c.Authorize(retry, tok); err != nil {
			return nil, err
		}
		return client.Do(retry)
	}
	return resp, nil
}
