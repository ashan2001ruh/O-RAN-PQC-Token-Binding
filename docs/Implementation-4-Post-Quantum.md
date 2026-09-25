# Implementation Part 4: Post-Quantum (ML-DSA signatures, ML-KEM key exchange)

The post-quantum phase replaces every signature and key exchange this project controls:

| Concern | Classical | Post-quantum |
|---|---|---|
| Token signature | RS256 (Keycloak) | **ML-DSA-65**, issued by the shim |
| xApp identity certificate | EC P-256 | **ML-DSA-65**, from the post-quantum branch of the RIC CA |
| DPoP proof | ES256 | **ML-DSA-44** |
| TLS key exchange | X25519 | **X25519MLKEM768** (hybrid ML-KEM-768), required |
| Confirmation claims | `x5t#S256`, `jkt` | unchanged: both are SHA-256 values |

**The constraint that shapes the design.** Keycloak 26.6 runs on Java 21 and can neither sign
with ML-DSA nor terminate TLS with an ML-DSA certificate or ML-KEM. It therefore stays
classical and keeps doing what it is good at: authenticating the xApp and applying the
authorization policy. A new service, the **pq-shim**, upgrades its token.

Every xApp therefore holds **two credentials**: a classical one used only for the Keycloak leg,
and an ML-DSA one used for the CA, the shim, the resource server and peer xApps.

All post-quantum primitives come from the Go 1.27 standard library (`crypto/mldsa`,
`crypto/x509`, `crypto/tls`); no third-party post-quantum library is used.

## Files in this part

| File | Lines | Purpose |
|---|---|---|
| `internal/pqbind/pqbind.go` | 9 | The constants shared by the client and the shim. |
| `xapp-client/pq.go` | 155 | The client side: the upgrade call and the two proof builders (certificate chain in `x5c`, or AKP key in `jwk`). |
| `pqshim/shim.go` | 536 | Configuration, the upgrade handler, proof verification, token issuance, JWKS and introspection. |
| `pqshim/cmd/pq-shim/main.go` | 98 | The service binary. Note the plain-HTTP health port: the kubelet probe client predates ML-KEM and cannot complete a handshake against a PQ-only TLS port. |
| `pqshim/k8s/pq-shim.yaml` | 79 | Deployment and Service in `ricsec`, with the ML-DSA server certificate and both trust bundles. |

---

## 1. The binding-transfer protocol

A token bound to a classical certificate cannot simply be re-labelled as bound to a post-quantum one: that would let anyone holding either credential move the binding. The shim therefore requires proof of possession of **both** credentials in a single request:

```
POST /v1/upgrade                         (mTLS with the CLASSICAL certificate)
Authorization: Bearer <keycloak token>   (or DPoP + classical proof, method C)
X-PQ-Proof: <ML-DSA JWS, typ=pq-binding+jwt>
    header : alg=ML-DSA-65, x5c=[post-quantum certificate chain]   (methods A/B)
             alg=ML-DSA-44, jwk={kty:AKP,...}                      (method C)
    claims : htm, htu, iat, jti, ath=SHA-256(keycloak token)
```

The shim then validates the Keycloak token and its classical binding with the **same validator a resource server uses**, verifies the ML-DSA proof, and only then mints the new token.

### `internal/pqbind/pqbind.go`

The constants shared by the client and the shim.

```go
// Package pqbind holds the constants shared by the post-quantum binding-transfer
// proof: the client builds it, the shim verifies it.
package pqbind

// ProofHeader carries the post-quantum binding proof on the upgrade request.
const ProofHeader = "X-PQ-Proof"

// ProofType is the "typ" of that proof JWT.
const ProofType = "pq-binding+jwt"
```

### `xapp-client/pq.go`

The client side: the upgrade call and the two proof builders (certificate chain in `x5c`, or AKP key in `jwk`).

```go
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
```

---

## 2. The shim

The shim makes no authorization decisions. It re-verifies the decision Keycloak already made, checks that the caller holds both credentials, and re-signs the same claims with ML-DSA while moving the `cnf` claim onto the post-quantum credential. Provenance is recorded in the token as `upgraded_from`. It also publishes its JWKS (an AKP key) and an introspection endpoint, so a resource server can compare local validation against introspection in post-quantum mode exactly as it does with Keycloak.

### `pqshim/shim.go`

Configuration, the upgrade handler, proof verification, token issuance, JWKS and introspection.

```go
// Package pqshim implements the post-quantum token shim that sits beside Keycloak.
//
// Keycloak (Java 21) can neither sign tokens with ML-DSA nor terminate TLS with
// ML-DSA certificates or ML-KEM key exchange, so it remains the classical
// authorization server: it authenticates the xApp, applies the realm's
// authorization policy, and issues a classical, sender-constrained token.
//
// The shim upgrades that token:
//
//	POST /v1/upgrade   exchange a classical Keycloak token for an ML-DSA-signed token
//	                   bound to the caller's post-quantum credential
//	GET  /v1/jwks      the shim's AKP (ML-DSA) public keys
//
// The exchange is a *binding transfer* and requires proof of possession of both
// credentials in the same request:
//
//  1. the classical binding is proved exactly as at any resource server - the
//     embedded xappresource.Validator checks the Keycloak token and its
//     cnf.x5t#S256 against the mTLS peer certificate (Methods A/B), or its cnf.jkt
//     against a classical DPoP proof (Method C);
//  2. the post-quantum binding is proved by an ML-DSA-signed proof JWT carrying the
//     new credential: the PQ certificate chain in x5c (Methods A/B) or the AKP
//     public key in jwk (Method C), plus ath over the presented Keycloak token.
//
// Only then does the shim mint a token signed with ML-DSA whose cnf names the
// post-quantum credential. All signing and verification is done by jwx.
package pqshim

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/config"
	"github.com/oran-ricsec/xapp-token-binding/internal/jose"
	"github.com/oran-ricsec/xapp-token-binding/internal/netx"
	"github.com/oran-ricsec/xapp-token-binding/internal/pki"
	"github.com/oran-ricsec/xapp-token-binding/internal/pqbind"
	xappresource "github.com/oran-ricsec/xapp-token-binding/xapp-resource"
)

// ProofType and ProofHeader are shared with the client library.
const (
	ProofType   = pqbind.ProofType
	ProofHeader = pqbind.ProofHeader
)

// Config is read from the environment by ConfigFromEnv.
type Config struct {
	ListenAddr      string
	ServerCert      string
	ServerKey       string
	Issuer          string   // iss of the tokens this shim issues
	SigningAlg      string   // ML-DSA-44 / ML-DSA-65 / ML-DSA-87
	PQTrustBundle   []string // trust anchors for the PQ certificate chains in x5c
	TokenLifetime   time.Duration
	ProofWindow     time.Duration
	ClockSkew       time.Duration
	ReplayCacheSize int
	PQKexOnly       bool
	// HealthAddr serves /healthz over plain HTTP for Kubernetes probes: the kubelet
	// predates ML-KEM and cannot complete a handshake on a PQ-only TLS port.
	HealthAddr string
}

// ConfigFromEnv loads the shim configuration.
func ConfigFromEnv() (Config, error) {
	e := &config.Env{}
	c := Config{
		ListenAddr:      e.Str("LISTEN_ADDR", ":8443"),
		ServerCert:      e.Req("SERVER_CERT"),
		ServerKey:       e.Req("SERVER_KEY"),
		Issuer:          e.Req("PQ_ISSUER"),
		SigningAlg:      e.Str("PQ_SIGNING_ALG", "ML-DSA-65"),
		PQTrustBundle:   e.List("PQ_TRUST_BUNDLE", nil),
		TokenLifetime:   e.Dur("PQ_TOKEN_LIFETIME", 5*time.Minute),
		ProofWindow:     e.Dur("DPOP_PROOF_WINDOW", 60*time.Second),
		ClockSkew:       e.Dur("CLOCK_SKEW", 30*time.Second),
		ReplayCacheSize: e.Int("DPOP_REPLAY_CACHE_SIZE", 100_000),
		PQKexOnly:       e.Bool("PQ_KEX_ONLY", false),
		HealthAddr:      e.Str("HEALTH_ADDR", ":8081"),
	}
	if len(c.PQTrustBundle) == 0 {
		e.Fail("PQ_TRUST_BUNDLE is required")
	}
	return c, e.Err()
}

// Server is the shim.
type Server struct {
	cfg       Config
	validator *xappresource.Validator // validates the incoming classical Keycloak token
	signer    jose.Signer             // ML-DSA signing key
	kid       string
	pqRoots   *x509.CertPool
	replay    *xappresource.ReplayCache
	log       *slog.Logger
	now       func() time.Time
}

// NewServer builds the shim. httpClient is used by the embedded validator to reach
// Keycloak (JWKS and introspection).
func NewServer(cfg Config, rcfg xappresource.Config, httpClient *http.Client, log *slog.Logger) (*Server, error) {
	validator, err := xappresource.NewValidator(rcfg, httpClient, log)
	if err != nil {
		return nil, fmt.Errorf("validator: %w", err)
	}
	signer, err := jose.GenerateSigner(cfg.SigningAlg)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	kid, err := signer.PublicJWK().Thumbprint()
	if err != nil {
		return nil, err
	}
	pqRoots, err := pki.LoadCertPool(cfg.PQTrustBundle...)
	if err != nil {
		return nil, fmt.Errorf("post-quantum trust bundle: %w", err)
	}
	return &Server{cfg: cfg, validator: validator, signer: signer, kid: kid, pqRoots: pqRoots,
		replay: xappresource.NewReplayCache(cfg.ReplayCacheSize), log: log, now: time.Now}, nil
}

// SigningAlg is the algorithm this shim signs with.
func (s *Server) SigningAlg() string { return s.signer.Alg() }

// KeyID is the kid of the shim's signing key.
func (s *Server) KeyID() string { return s.kid }

// TLSConfig serves the shim's (post-quantum) server certificate and requests the
// caller's classical client certificate, which the validator then checks.
func (s *Server) TLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(s.cfg.ServerCert, s.cfg.ServerKey)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{cert},
		ClientAuth:       tls.RequestClientCert,
		CurvePreferences: netx.CurvePreferences(s.cfg.PQKexOnly),
	}, nil
}

// Handler returns the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/upgrade", s.handleUpgrade)
	mux.HandleFunc("GET /v1/jwks", s.handleJWKS)
	mux.HandleFunc("POST /v1/introspect", s.handleIntrospect)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	return mux
}

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	key := jose.JWK{}
	for k, v := range s.signer.PublicJWK() {
		key[k] = v
	}
	key["kid"], key["use"] = s.kid, "sig"
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Cache-Control", "max-age=300")
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{key}})
}

// UpgradeResponse is the shim's answer.
type UpgradeResponse struct {
	AccessToken string         `json:"access_token"`
	TokenType   string         `json:"token_type"`
	ExpiresIn   int            `json:"expires_in"`
	Alg         string         `json:"alg"`
	Cnf         map[string]any `json:"cnf"`
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, status int, code, format string, args ...any) {
	detail := fmt.Sprintf(format, args...)
	s.log.Warn("upgrade_rejected", "reason_code", code, "reason", detail, "remote", r.RemoteAddr)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "reason": detail})
}

func (s *Server) handleUpgrade(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Step 1: the classical token and its classical binding, checked exactly as a
	// resource server would check them.
	principal, rej := s.validator.Authorize(r, xappresource.ModeLocal)
	if rej != nil {
		s.fail(w, r, rej.Status, rej.Code, "%s", rej.Detail)
		return
	}
	classicalToken, err := bearerToken(r)
	if err != nil {
		s.fail(w, r, http.StatusUnauthorized, "authorization_malformed", "%v", err)
		return
	}

	// Step 2: possession of the post-quantum credential, and the binding it asks for.
	binding, proofInfo, rej2 := s.verifyPQProof(r, classicalToken, principal.ClientID)
	if rej2 != nil {
		s.fail(w, r, rej2.Status, rej2.Code, "%s", rej2.Detail)
		return
	}

	// Step 3: mint the ML-DSA-signed token.
	token, exp, err := s.issue(principal, binding)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "issue_failed", "%v", err)
		return
	}
	tokenType := "Bearer"
	if _, isDPoP := binding["jkt"]; isDPoP {
		tokenType = "DPoP"
	}
	s.log.Info("token_upgraded",
		"client_id", principal.ClientID,
		"classical_binding", principal.Binding, "classical_cnf", principal.Thumbprint,
		"pq_binding", proofInfo.bindingName, "pq_cnf", proofInfo.thumbprint,
		"pq_credential", proofInfo.credential, "proof_alg", proofInfo.alg,
		"signing_alg", s.signer.Alg(), "kid", s.kid,
		"classical_token_bytes", len(classicalToken), "pq_token_bytes", len(token),
		"elapsed_ms", float64(time.Since(start).Microseconds())/1000)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(UpgradeResponse{
		AccessToken: token, TokenType: tokenType,
		ExpiresIn: int(time.Until(exp).Seconds()), Alg: s.signer.Alg(), Cnf: binding,
	})
}

func bearerToken(r *http.Request) (string, error) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", fmt.Errorf("expected exactly one Authorization header, got %d", len(values))
	}
	_, tok, ok := strings.Cut(strings.TrimSpace(values[0]), " ")
	if !ok || strings.TrimSpace(tok) == "" {
		return "", fmt.Errorf("Authorization header is not '<scheme> <token>'")
	}
	return strings.TrimSpace(tok), nil
}

type proofInfo struct {
	alg         string
	bindingName string
	thumbprint  string
	credential  string // certificate subject or JWK kind, for logging
}

// verifyPQProof checks the ML-DSA proof and returns the cnf it authorises.
func (s *Server) verifyPQProof(r *http.Request, classicalToken, clientID string) (map[string]any, proofInfo, *xappresource.Rejection) {
	var info proofInfo
	proofs := r.Header.Values(ProofHeader)
	if len(proofs) == 0 {
		return nil, info, reject(http.StatusBadRequest, "pq_proof_missing", "no %s header", ProofHeader)
	}
	if len(proofs) > 1 {
		return nil, info, reject(http.StatusBadRequest, "pq_proof_multiple", "more than one %s header", ProofHeader)
	}
	proof, err := jose.ParseCompact(proofs[0])
	if err != nil {
		return nil, info, reject(http.StatusBadRequest, "pq_proof_malformed", "proof is not a compact JWS: %v", err)
	}
	if proof.Typ() != ProofType {
		return nil, info, reject(http.StatusBadRequest, "pq_proof_wrong_typ", "proof typ is %q, expected %s", proof.Typ(), ProofType)
	}
	info.alg = proof.Alg()
	if !strings.HasPrefix(info.alg, "ML-DSA-") {
		return nil, info, reject(http.StatusBadRequest, "pq_proof_not_post_quantum",
			"proof alg %q is not an ML-DSA algorithm; the upgraded token would not be quantum-resistant", info.alg)
	}

	binding := map[string]any{}
	switch {
	case proof.Header["x5c"] != nil:
		// Methods A and B: the new binding is a post-quantum certificate.
		chain, rej := s.chainFromProof(proof)
		if rej != nil {
			return nil, info, rej
		}
		if kind, err := pki.VerifyChain(chain, s.pqRoots, s.now(), x509.ExtKeyUsageClientAuth); err != nil {
			return nil, info, reject(http.StatusUnauthorized, "pq_certificate_"+kind, "post-quantum certificate rejected: %v", err)
		}
		leaf := chain[0]
		if !pki.IsPostQuantum(leaf.PublicKey) {
			return nil, info, reject(http.StatusBadRequest, "pq_certificate_not_post_quantum",
				"certificate key is %s, not ML-DSA", pki.KeyAlgName(leaf.PublicKey))
		}
		// The post-quantum certificate must belong to the same xApp identity that
		// Keycloak authenticated, otherwise the binding could be moved to another xApp.
		if clientID != "" && leaf.Subject.CommonName != clientID {
			return nil, info, reject(http.StatusForbidden, "pq_identity_mismatch",
				"post-quantum certificate CN=%q does not match the authenticated client %q", leaf.Subject.CommonName, clientID)
		}
		if err := proof.VerifySignature(leaf.PublicKey); err != nil {
			return nil, info, reject(http.StatusUnauthorized, "pq_proof_signature_invalid",
				"proof is not signed by the certificate key: %v", err)
		}
		thumb := pki.ThumbprintS256(leaf)
		binding["x5t#S256"] = thumb
		info.bindingName, info.thumbprint = "x5t#S256", thumb
		info.credential = fmt.Sprintf("CN=%s %s", leaf.Subject.CommonName, pki.KeyAlgName(leaf.PublicKey))
	case proof.Header["jwk"] != nil:
		// Method C: the new binding is an ML-DSA DPoP key.
		rawJWK, ok := proof.Header["jwk"].(map[string]any)
		if !ok {
			return nil, info, reject(http.StatusBadRequest, "pq_proof_jwk_invalid", "jwk header is not an object")
		}
		key := jose.JWK(rawJWK)
		if key.Str("kty") != "AKP" {
			return nil, info, reject(http.StatusBadRequest, "pq_proof_jwk_not_post_quantum",
				"proof key type is %q, expected AKP (RFC 9964)", key.Str("kty"))
		}
		pub, err := key.PublicKey()
		if err != nil {
			return nil, info, reject(http.StatusBadRequest, "pq_proof_jwk_invalid", "proof jwk unusable: %v", err)
		}
		if err := proof.VerifySignature(pub); err != nil {
			return nil, info, reject(http.StatusUnauthorized, "pq_proof_signature_invalid", "proof signature invalid: %v", err)
		}
		thumb, err := key.Thumbprint()
		if err != nil {
			return nil, info, reject(http.StatusBadRequest, "pq_proof_jwk_invalid", "cannot compute JWK thumbprint: %v", err)
		}
		binding["jkt"] = thumb
		info.bindingName, info.thumbprint = "jkt", thumb
		info.credential = key.Str("alg") + " JWK"
	default:
		return nil, info, reject(http.StatusBadRequest, "pq_proof_no_credential",
			"proof carries neither x5c (certificate binding) nor jwk (DPoP binding)")
	}

	if rej := s.checkProofClaims(r, proof, classicalToken, info.thumbprint); rej != nil {
		return nil, info, rej
	}
	return binding, info, nil
}

func (s *Server) chainFromProof(proof *jose.JWS) ([]*x509.Certificate, *xappresource.Rejection) {
	raw, ok := proof.Header["x5c"].([]any)
	if !ok || len(raw) == 0 {
		return nil, reject(http.StatusBadRequest, "pq_proof_x5c_invalid", "x5c header is not a non-empty array")
	}
	var chain []*x509.Certificate
	for i, item := range raw {
		s64, ok := item.(string)
		if !ok {
			return nil, reject(http.StatusBadRequest, "pq_proof_x5c_invalid", "x5c[%d] is not a string", i)
		}
		der, err := base64.StdEncoding.DecodeString(s64)
		if err != nil {
			return nil, reject(http.StatusBadRequest, "pq_proof_x5c_invalid", "x5c[%d] is not base64 DER: %v", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, reject(http.StatusBadRequest, "pq_proof_x5c_invalid", "x5c[%d] is not a certificate: %v", i, err)
		}
		chain = append(chain, cert)
	}
	return chain, nil
}

// checkProofClaims verifies that the proof is bound to this token, this request and
// this moment, and that it has not been replayed.
func (s *Server) checkProofClaims(r *http.Request, proof *jose.JWS, classicalToken, thumbprint string) *xappresource.Rejection {
	claims, err := proof.Claims()
	if err != nil {
		return reject(http.StatusBadRequest, "pq_proof_malformed", "proof payload: %v", err)
	}
	ath, _ := claims["ath"].(string)
	sum := sha256.Sum256([]byte(classicalToken))
	want := jose.B64(sum[:])
	if ath == "" {
		return reject(http.StatusBadRequest, "pq_proof_ath_missing", "proof has no ath claim")
	}
	if subtle.ConstantTimeCompare([]byte(ath), []byte(want)) != 1 {
		return reject(http.StatusUnauthorized, "pq_proof_ath_mismatch",
			"proof ath %s is not the hash of the presented Keycloak token (%s)", ath, want)
	}
	if htm, _ := claims["htm"].(string); htm != r.Method {
		return reject(http.StatusBadRequest, "pq_proof_htm_mismatch", "proof htm %q does not match %q", htm, r.Method)
	}
	htuClaim, _ := claims["htu"].(string)
	got, errClaim := netx.NormalizeHTU(htuClaim)
	want2, errReq := netx.NormalizeHTU(s.cfg.Issuer + r.URL.EscapedPath())
	if errClaim != nil || errReq != nil || got != want2 {
		return reject(http.StatusBadRequest, "pq_proof_htu_mismatch", "proof htu %q does not match %q", htuClaim, want2)
	}
	iat, ok, err := numericClaim(claims, "iat")
	if err != nil || !ok {
		return reject(http.StatusBadRequest, "pq_proof_malformed", "proof has no numeric iat")
	}
	now, issued := s.now(), time.Unix(iat, 0)
	if issued.Before(now.Add(-s.cfg.ProofWindow-s.cfg.ClockSkew)) || issued.After(now.Add(s.cfg.ClockSkew)) {
		return reject(http.StatusBadRequest, "pq_proof_iat_out_of_window",
			"proof iat %s is outside the accepted window (%s)", issued.UTC().Format(time.RFC3339), s.cfg.ProofWindow)
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return reject(http.StatusBadRequest, "pq_proof_jti_missing", "proof has no jti")
	}
	expiry := issued.Add(s.cfg.ProofWindow + 2*s.cfg.ClockSkew)
	switch s.replay.CheckAndStore(thumbprint+":"+jti, expiry, now) {
	case xappresource.ReplaySeen:
		return reject(http.StatusUnauthorized, "pq_proof_replayed", "proof jti %s has already been used", jti)
	case xappresource.ReplayFull:
		return reject(http.StatusServiceUnavailable, "pq_replay_cache_full", "replay cache is full")
	}
	return nil
}

// issue mints the ML-DSA-signed access token.
func (s *Server) issue(p *xappresource.Principal, binding map[string]any) (string, time.Time, error) {
	now := s.now()
	exp := now.Add(s.cfg.TokenLifetime)
	// Never outlive the Keycloak token the authorization decision came from.
	if kcExp, ok, _ := numericClaim(p.Claims, "exp"); ok {
		if t := time.Unix(kcExp, 0); t.Before(exp) {
			exp = t
		}
	}
	jti := make([]byte, 18)
	if _, err := rand.Read(jti); err != nil {
		return "", time.Time{}, err
	}
	claims := map[string]any{
		"iss": s.cfg.Issuer,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": exp.Unix(),
		"jti": jose.B64(jti),
		"cnf": binding,
	}
	// Carry the authorization decision over unchanged.
	for _, name := range []string{"sub", "aud", "azp", "client_id", "scope", "realm_access", "resource_access"} {
		if v, ok := p.Claims[name]; ok {
			claims[name] = v
		}
	}
	// Provenance: which authorization server made the original decision.
	claims["upgraded_from"] = map[string]any{
		"iss":              p.Claims["iss"],
		"binding":          p.Binding,
		"cnf":              p.Thumbprint,
		"upgraded_at":      now.UTC().Format(time.RFC3339),
		"shim_signing_alg": s.signer.Alg(),
	}
	token, err := s.signer.SignCompact(map[string]any{"typ": "at+jwt", "kid": s.kid}, claims)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, exp, nil
}

func reject(status int, code, format string, args ...any) *xappresource.Rejection {
	return &xappresource.Rejection{Status: status, Code: code, Detail: fmt.Sprintf(format, args...)}
}

func numericClaim(claims map[string]any, name string) (int64, bool, error) {
	raw, ok := claims[name]
	if !ok {
		return 0, false, nil
	}
	switch n := raw.(type) {
	case json.Number:
		v, err := n.Int64()
		return v, err == nil, err
	case float64:
		return int64(n), true, nil
	case int64:
		return n, true, nil
	}
	return 0, false, fmt.Errorf("claim %q is not numeric", name)
}

// handleIntrospect is the RFC 7662 endpoint for the tokens this shim issued, so a
// resource server can compare local validation against introspection in PQ mode
// exactly as it does with Keycloak in classical mode. The caller must present a
// certificate issued by one of the trusted RIC CAs.
func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	inactive := func() {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"active": false})
	}
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "introspection_malformed", "%v", err)
		return
	}
	token := r.PostFormValue("token")
	if token == "" {
		s.fail(w, r, http.StatusBadRequest, "introspection_malformed", "no token parameter")
		return
	}
	parsed, err := jose.ParseCompact(token)
	if err != nil {
		inactive()
		return
	}
	if parsed.Kid() != s.kid {
		inactive()
		return
	}
	if err := parsed.VerifySignature(s.signer.PublicKey()); err != nil {
		s.log.Warn("introspection_signature_invalid", "error", err, "remote", r.RemoteAddr)
		inactive()
		return
	}
	claims, err := parsed.Claims()
	if err != nil {
		inactive()
		return
	}
	if exp, ok, _ := numericClaim(claims, "exp"); ok && s.now().After(time.Unix(exp, 0)) {
		inactive()
		return
	}
	out := map[string]any{"active": true}
	for k, v := range claims {
		out[k] = v
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}
```

### `pqshim/cmd/pq-shim/main.go`

The service binary. Note the plain-HTTP health port: the kubelet probe client predates ML-KEM and cannot complete a handshake against a PQ-only TLS port.

```go
// Command pq-shim runs the post-quantum token shim (see package pqshim).
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/config"
	"github.com/oran-ricsec/xapp-token-binding/internal/logx"
	"github.com/oran-ricsec/xapp-token-binding/internal/netx"
	"github.com/oran-ricsec/xapp-token-binding/internal/pki"
	"github.com/oran-ricsec/xapp-token-binding/pqshim"
	xappresource "github.com/oran-ricsec/xapp-token-binding/xapp-resource"
)

func main() {
	log := logx.New("pq-shim")
	cfg, err := pqshim.ConfigFromEnv()
	if err != nil {
		log.Error("invalid configuration", "error", err)
		os.Exit(2)
	}
	// The embedded validator checks the incoming classical Keycloak token, so it is
	// configured exactly like a resource server that trusts Keycloak.
	rcfg, err := xappresource.ConfigFromEnv()
	if err != nil {
		log.Error("invalid validator configuration", "error", err)
		os.Exit(2)
	}
	e := &config.Env{}
	overrides, err := netx.ParseDialOverrides(e.Str("DIAL_OVERRIDES", ""))
	if err != nil {
		log.Error("DIAL_OVERRIDES", "error", err)
		os.Exit(2)
	}
	// Client used to reach Keycloak (JWKS, introspection): classical trust anchors.
	roots, err := pki.LoadCertPool(rcfg.TrustBundle...)
	if err != nil {
		log.Error("trust bundle", "error", err)
		os.Exit(1)
	}
	httpClient := &http.Client{
		Transport: netx.NewTransport(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, overrides),
		Timeout:   20 * time.Second,
	}

	srv, err := pqshim.NewServer(cfg, rcfg, httpClient, log)
	if err != nil {
		log.Error("startup failed", "error", err)
		os.Exit(1)
	}
	tlsConf, err := srv.TLSConfig()
	if err != nil {
		log.Error("server TLS", "error", err)
		os.Exit(1)
	}
	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		TLSConfig:         tlsConf,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    256 << 10, // ML-DSA proofs with an x5c chain are large headers
	}
	// Plain-HTTP health endpoint for Kubernetes probes (see Config.HealthAddr).
	if cfg.HealthAddr != "" {
		healthMux := http.NewServeMux()
		healthMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
		healthSrv := &http.Server{Addr: cfg.HealthAddr, Handler: healthMux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := healthSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("health listener", "error", err)
			}
		}()
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdown)
	}()
	log.Info("listening",
		"addr", cfg.ListenAddr, "issuer", cfg.Issuer,
		"signing_alg", srv.SigningAlg(), "kid", srv.KeyID(),
		"upstream_issuer", rcfg.Issuer, "pq_kex_only", cfg.PQKexOnly)
	if err := httpSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
```

### `pqshim/k8s/pq-shim.yaml`

Deployment and Service in `ricsec`, with the ML-DSA server certificate and both trust bundles.

```yaml
# Post-quantum token shim: upgrades a classical Keycloak token into an ML-DSA-signed
# token bound to the caller post-quantum credential. Rendered from config/testbed.env.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${PQ_SHIM_SERVICE}
  namespace: ${RICSEC_NAMESPACE}
  labels: {app: ${PQ_SHIM_SERVICE}, part-of: xapp-token-binding}
spec:
  replicas: 1
  strategy: {type: Recreate}   # the signing key is generated per pod
  selector:
    matchLabels: {app: ${PQ_SHIM_SERVICE}}
  template:
    metadata:
      labels: {app: ${PQ_SHIM_SERVICE}, part-of: xapp-token-binding}
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        seccompProfile: {type: RuntimeDefault}
      containers:
        - name: pq-shim
          image: ricsec/pq-shim:${IMAGE_TAG}
          imagePullPolicy: Never
          ports:
            - {name: https, containerPort: ${PQ_SHIM_PORT}}
            - {name: health, containerPort: 8081}
          env:
            - {name: LISTEN_ADDR, value: ":${PQ_SHIM_PORT}"}
            # Post-quantum server certificate (ML-DSA) and the ML-KEM hybrid group.
            - {name: SERVER_CERT, value: /etc/pq-shim/server/tls.crt}
            - {name: SERVER_KEY, value: /etc/pq-shim/server/tls.key}
            - {name: PQ_KEX_ONLY, value: "${PQ_KEX_ONLY}"}
            # Identity of the tokens this shim issues.
            - {name: PQ_ISSUER, value: "${PQ_SHIM_URL}"}
            - {name: PQ_SIGNING_ALG, value: "${PQ_SIGNING_ALG}"}
            - {name: PQ_TOKEN_LIFETIME, value: "${PQ_TOKEN_LIFETIME}"}
            # Trust anchor for the post-quantum certificate chains presented in x5c.
            - {name: PQ_TRUST_BUNDLE, value: /etc/ric-trust/ric-intermediate-ca-pq.crt}
            # Embedded validator: checks the incoming classical Keycloak token.
            - {name: TOKEN_ISSUER, value: "${TOKEN_ISSUER}"}
            - {name: JWKS_URL, value: "${TOKEN_ISSUER}/protocol/openid-connect/certs"}
            - {name: TOKEN_AUDIENCE, value: "${TOKEN_AUDIENCE}"}
            - {name: REQUIRED_SCOPE, value: "${TOKEN_SCOPE}"}
            - {name: REQUIRED_ROLE, value: "${REQUIRED_ROLE}"}
            - {name: RIC_TRUST_BUNDLE, value: /etc/ric-trust/ric-intermediate-ca.crt}
          volumeMounts:
            - {name: server-tls, mountPath: /etc/pq-shim/server, readOnly: true}
            - {name: trust, mountPath: /etc/ric-trust, readOnly: true}
          readinessProbe:
            httpGet: {path: /healthz, port: health, scheme: HTTP}
            periodSeconds: 10
            timeoutSeconds: 5
          resources:
            requests: {cpu: 50m, memory: 32Mi}
            limits: {memory: 192Mi}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
      volumes:
        - name: server-tls
          secret: {secretName: pq-shim-server-tls, defaultMode: 0440}
        - name: trust
          configMap: {name: ric-trust}
---
apiVersion: v1
kind: Service
metadata:
  name: ${PQ_SHIM_SERVICE}
  namespace: ${RICSEC_NAMESPACE}
  labels: {app: ${PQ_SHIM_SERVICE}, part-of: xapp-token-binding}
spec:
  selector: {app: ${PQ_SHIM_SERVICE}}
  ports:
    - {name: https, port: ${PQ_SHIM_PORT}, targetPort: https}
```

---

## 3. What changed elsewhere

The post-quantum phase touched surprisingly little, because the phase-1 design read the algorithm from the token header and the keys from a configurable JWKS URL:

* `internal/pki` gained ML-DSA key generation and the helpers that let the CA pick an issuing branch;
* `internal/netx` gained `CurvePreferences`, which pins X25519MLKEM768 so a classical-only peer
  fails the handshake instead of silently negotiating a quantum-vulnerable key exchange;
* `ca/enroll` gained the second issuing branch, selected by the key type in the CSR;
* `internal/smo` gained `KeyAlg`, so onboarding itself is post-quantum;
* `xapp-client` gained the plane abstraction: one set of enrollment, renewal and rotation
  functions now serves both credentials;
* **`xapp-resource/validator.go` needed no change to its binding logic at all.**

All of those files are printed in Parts 1 and 3 in their current, post-quantum form.

---

## 4. Deploy and run

```bash
make pq-up                     # CA, shim and xApps redeployed with PQ_MODE=true
scripts/run-method-a.sh --pq
scripts/run-method-b.sh --pq
scripts/run-method-c.sh --pq
make classical-up              # switch back
```

Two operational notes. Secrets holding ML-DSA keys are created as `generic --type=kubernetes.io/tls`, because `kubectl create secret tls` parses the key client-side and kubectl 1.28 cannot read an ML-DSA private key. And the deployment mode must match the script flag: running a classical script against a PQ deployment fails at the first check with `token_key_unavailable`, since the validator then trusts only the shim as issuer.

Observed on the VM:

```
classical certificate:     CN=xapp-longterm key=EC-P-256  ... (565 bytes)
post-quantum certificate:  CN=xapp-longterm key=ML-DSA-65 ... (5660 bytes)
Keycloak token:            alg=RS256      binding=cnf.x5t#S256 bytes=1017
upgraded token:            alg=ML-DSA-65  binding=cnf.x5t#S256 bytes=5352
TLS key exchange:          X25519MLKEM768
```


---

## 5. When the shim goes away

The shim is a compatibility layer, not a design goal. It exists for exactly one reason:
no released authorization server can sign an access token with ML-DSA. It is worth
recording precisely what that claim rests on, because the claim is the justification for
the whole component.

### Keycloak, checked September 2026

| Evidence | Finding |
|---|---|
| Latest release | **26.7.4**. There is no 27.x build; the version often cited as the PQC one is a milestone, not a release. |
| PQC readiness epic, [keycloak#43690](https://github.com/keycloak/keycloak/issues/43690) | on the 27.0 milestone, **1 of 16 sub-issues complete** |
| PQC token signing, [keycloak#50355](https://github.com/keycloak/keycloak/issues/50355) | **open, unassigned, no milestone** |
| The deployed instance | Keycloak 26.6.0 on **JVM 21.0.10**; discovery advertises `PS384 RS384 EdDSA ES384 HS256 HS512 ES256 RS256 HS384 ES512 PS256 PS512 RS512` for `id_token_signing_alg_values_supported` and no ML-DSA in `dpop_signing_alg_values_supported` |

Removing the shim needs four things from the authorization server, and Keycloak has none
of them. Two are blocked below Keycloak, in the JVM:

| Leg | Requires | Available from |
|---|---|---|
| ML-DSA token signature | JOSE support plus a realm keys provider | not scheduled |
| ML-DSA client certificate for `client-x509` | JSSE parsing ML-DSA certificates | JDK 24 ([JEP 497](https://openjdk.org/jeps/497)) at the earliest; Keycloak ships JDK 21 |
| ML-KEM hybrid TLS key exchange | hybrid groups in JSSE | **JDK 27** ([JEP 527](https://openjdk.org/jeps/527), delivered) |
| ML-DSA DPoP proof verification | `dpop_signing_alg_values_supported` | not scheduled |

### The alternative that was evaluated

Duende IdentityServer was assessed as a replacement, because it is the one production
OAuth server that can sign with ML-DSA today: the community add-on
[Strathweb.Dilithium](https://github.com/filipw/Strathweb.Dilithium) registers an ML-DSA
signing credential (`AddMlDsaSigningCredential(new MlDsaSecurityKey("ML-DSA-65"))`,
FIPS 204, parameter sets 44/65/87) and publishes it in the JWKS as `"kty": "AKP"`,
`"alg": "ML-DSA-65"` - which is RFC 9964, and is exactly the form the validator in this
project already parses. It has liboqs, BouncyCastle and .NET 10 backends, so it does not
require the OpenSSL 3.5 that the native `System.Security.Cryptography.MLDsa` type needs.

It was not adopted, for three reasons:

1. **It solves one leg of four.** .NET 10 has no documented ML-DSA certificate support in
   SslStream or Kestrel - the API exposing ML-DSA to certificate selection is still an
   [open proposal](https://github.com/dotnet/runtime/issues/134630) - so Methods A and B
   cannot be certificate-bound to a post-quantum credential. ML-DSA DPoP verification is
   undocumented, and that is the binding this project is about.
2. **It is commercial.** Free for development and for small organisations, licensed for
   production. Keycloak is Apache-2.0 and is what O-RAN deployments actually run, so
   adopting Duende would weaken the deployability claim to buy one leg.
3. **The shim already provides that leg**, and does so for all three methods rather than
   one.

### The exit: `PQ_ISSUER`

Rather than leave the shim as a permanent structural dependency, the deployment carries
its own exit condition. `PQ_ISSUER` names the service that issues the post-quantum token:

```
PQ_ISSUER=shim       Keycloak issues a classical token; the shim re-issues it
                     ML-DSA-signed and bound to the post-quantum credential.  (default)

PQ_ISSUER=keycloak   The authorization server signs with ML-DSA and binds to the
                     post-quantum credential itself. The shim leaves the path.
```

Setting `keycloak` changes three things at once, with no code edit:

- the Makefile points `RESOURCE_TOKEN_ISSUER`, `RESOURCE_JWKS_URL` and
  `RESOURCE_INTROSPECTION_URL` at the authorization server instead of the shim, so every
  validator - in the xApps and in the sidecars - trusts it directly;
- the client uses the **post-quantum** credential on the authorization-server leg
  (`base.asIdentity`, `base.asClient`, and for Method C `dpopClient.asSigner`), so the
  token is bound to the ML-DSA certificate or the ML-DSA proof key at issuance;
- `base.requirePQToken` rejects any token that is not ML-DSA-signed, so a
  misconfiguration cannot silently downgrade the deployment to a classical signature.

Check what the flags resolve to before deploying:

```bash
make PQ_MODE=true show-config
make PQ_MODE=true PQ_ISSUER=keycloak show-config
```

Against today's Keycloak the second setting fails closed at the token request, which is
the correct behaviour and a useful demonstration that the path is wired end to end:

```
[3] Access token
    FAIL token: token endpoint: Post "https://keycloak.../token": remote error:
    tls: unexpected message [PQ_ISSUER=keycloak: the authorization server was offered
    the ML-DSA credential. No released Keycloak can parse an ML-DSA certificate or sign
    with ML-DSA; set PQ_ISSUER=shim]
```

The TLS handshake fails because Keycloak cannot parse the ML-DSA client certificate. When
an authorization server can, the same command succeeds and the shim is simply not called.
