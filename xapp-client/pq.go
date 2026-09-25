package xappclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/cert"
	"github.com/oran-ricsec/xapp-token-binding/internal/jose"
	"github.com/oran-ricsec/xapp-token-binding/internal/netx"
	"github.com/oran-ricsec/xapp-token-binding/internal/pki"
	"github.com/oran-ricsec/xapp-token-binding/internal/pqbind"
)

// upgradeResponse mirrors pqshim.UpgradeResponse.
type upgradeResponse struct {
	AccessToken string         `json:"access_token"`
	TokenType   string         `json:"token_type"`
	ExpiresIn   int            `json:"expires_in"`
	Alg         string         `json:"alg"`
	Cnf         map[string]any `json:"cnf"`
}

// decorator sets the Authorization header (and, for method C, the classical DPoP
// proof) on the upgrade request.
type decorator func(req *http.Request, classical *Token) error

// pqProofFunc builds the ML-DSA proof that carries the new binding.
type pqProofFunc func(htu, classicalToken string) (string, error)

// upgradeToPQ exchanges a classical Keycloak token for an ML-DSA-signed token bound
// to this client's post-quantum credential. The request travels over the classical
// mTLS identity, because the shim first re-checks the classical binding exactly as a
// resource server would.
func (b *base) upgradeToPQ(ctx context.Context, classical *Token, decorate decorator, proof pqProofFunc) (*Token, error) {
	url := b.cfg.upgradeURL()
	ctx, cancel := context.WithTimeout(ctx, b.cfg.PQUpgradeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, err
	}
	if err := decorate(req, classical); err != nil {
		return nil, err
	}
	pqProof, err := proof(url, classical.Value)
	if err != nil {
		return nil, fmt.Errorf("build post-quantum binding proof: %w", err)
	}
	req.Header.Set(pqbind.ProofHeader, pqProof)

	start := time.Now()
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pq-shim upgrade: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pq-shim upgrade: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var up upgradeResponse
	if err := json.Unmarshal(body, &up); err != nil {
		return nil, fmt.Errorf("pq-shim response: %w", err)
	}
	tok, err := newToken(&TokenResponse{AccessToken: up.AccessToken, TokenType: up.TokenType,
		ExpiresIn: up.ExpiresIn, ReceivedAt: time.Now()})
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(tok.Alg, "ML-DSA-") {
		return nil, fmt.Errorf("%w: upgraded token is signed with %q, not ML-DSA", ErrBindingMismatch, tok.Alg)
	}
	tok.PostQuantum = true
	tok.Classical = classical
	b.log.Debug("token_upgraded", "alg", tok.Alg, "bytes", len(tok.Value),
		"classical_bytes", len(classical.Value), "elapsed_ms", ms(time.Since(start)))
	return tok, nil
}

// pqCertProof proves possession of the post-quantum identity certificate (Methods A
// and B). The certificate chain travels in the x5c protected header, so the shim can
// verify it against the post-quantum CA and bind the new token to its thumbprint.
func (b *base) pqCertProof(htu, classicalToken string) (string, error) {
	current := b.pqID.Current()
	if current == nil {
		return "", fmt.Errorf("no post-quantum identity certificate")
	}
	alg := pki.KeyAlgName(current.Leaf.PublicKey)
	signer, err := jose.SignerFromKey(alg, current.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("post-quantum signer (%s): %w", alg, err)
	}
	chain := &cert.Chain{}
	for _, der := range current.Certificate {
		if err := chain.AddString(base64.StdEncoding.EncodeToString(der)); err != nil {
			return "", err
		}
	}
	return signer.SignCompact(
		map[string]any{"typ": pqbind.ProofType, "x5c": chain},
		pqProofClaims(htu, classicalToken))
}

// pqJWKProof proves possession of the post-quantum DPoP key (Method C). The AKP
// public key travels in the jwk header and becomes the new cnf.jkt.
func (c *dpopClient) pqJWKProof(htu, classicalToken string) (string, error) {
	if c.pqSigner == nil {
		return "", fmt.Errorf("no post-quantum DPoP key")
	}
	return c.pqSigner.SignCompact(
		map[string]any{"typ": pqbind.ProofType, "jwk": c.pqSigner.PublicKey()},
		pqProofClaims(htu, classicalToken))
}

func pqProofClaims(htu, classicalToken string) map[string]any {
	jti := make([]byte, 18)
	_, _ = rand.Read(jti)
	sum := sha256.Sum256([]byte(classicalToken))
	normalised, err := netx.NormalizeHTU(htu)
	if err != nil {
		normalised = htu
	}
	return map[string]any{
		"jti": jose.B64(jti),
		"htm": http.MethodPost,
		"htu": normalised,
		"iat": time.Now().Unix(),
		"ath": jose.B64(sum[:]),
	}
}

// verifyPQBinding checks that the shim bound the upgraded token to the credential we
// actually hold, which is the same fail-closed check the client applies to Keycloak.
func (b *base) verifyPQBinding(tok *Token, member, want string) error {
	got, err := cnfMember(tok.Claims, member)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("%w: upgraded token cnf.%s=%s, post-quantum credential=%s", ErrBindingMismatch, member, got, want)
	}
	tok.Binding, tok.Thumbprint = member, got
	return nil
}
