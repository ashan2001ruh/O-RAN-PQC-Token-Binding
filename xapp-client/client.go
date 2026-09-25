package xappclient

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/jose"
	"github.com/oran-ricsec/xapp-token-binding/internal/netx"
	"github.com/oran-ricsec/xapp-token-binding/internal/pki"
)

// Client is the method-agnostic interface. Swap A/B/C with XAPP_METHOD, not code,
// and switch between classical and post-quantum credentials with PQ_MODE.
type Client interface {
	Method() Method
	ClientID() string
	// Start obtains the operational identity: loads a persisted one or enrolls with the
	// bootstrap credential. In post-quantum mode it obtains both credentials.
	Start(ctx context.Context) error
	// Token returns a cached token, renewing certificate/key material and re-issuing as
	// policy requires. In post-quantum mode it returns the ML-DSA-signed token.
	Token(ctx context.Context) (*Token, error)
	// IssueToken requests a new token, bypassing the cache.
	IssueToken(ctx context.Context) (*Token, error)
	// Authorize attaches the token (and, for DPoP, a fresh proof) to an outgoing resource request.
	Authorize(req *http.Request, tok *Token) error
	// Do sends a resource request with a valid token over the mTLS client.
	Do(req *http.Request) (*http.Response, error)
	// Rotate renews the operational certificate now (new key pair for method B).
	Rotate(ctx context.Context) (RotationStats, error)
	// Maintain renews the certificate before expiry until ctx is done (the rotation loop).
	Maintain(ctx context.Context)
	// HTTPClient is the mTLS client used for resource requests (post-quantum identity in PQ mode).
	HTTPClient() *http.Client
	ServerTLSConfig() *tls.Config
	// Identity is the classical credential; PQIdentity is the ML-DSA one (nil outside PQ mode).
	Identity() *Identity
	PQIdentity() *Identity
	TrustPool() *x509.CertPool
	// SetIssuer replaces the token issuance path (e.g. to insert a re-signing shim).
	SetIssuer(Issuer)
	// Describe summarises the credentials in use, for CLI output.
	Describe() Description
}

// Description summarises the credentials and algorithms a client is using.
type Description struct {
	Method         Method
	ClientID       string
	PQEnabled      bool
	ClassicalCert  string
	ClassicalAlg   string
	PQCert         string
	PQAlg          string
	PQIssuer       PQIssuer
	DPoPAlg        string
	PQDPoPAlg      string
	TokenIssuer    string
	CertLifetime   time.Duration
	PQCertLifetime time.Duration
}

// Token is an issued access token plus the binding the client verified on receipt.
type Token struct {
	Value        string
	Type         string
	IssuedAt     time.Time
	ExpiresAt    time.Time
	Claims       map[string]any
	Binding      string // "x5t#S256" or "jkt"
	Thumbprint   string // the cnf value the token is bound to
	CertNotAfter time.Time
	// Alg is the token signature algorithm (ES256/RS256 classical, ML-DSA-* after upgrade).
	Alg string
	// PostQuantum reports whether the token is signed with a post-quantum algorithm
	// and bound to a post-quantum credential.
	PostQuantum bool
	// Classical is the Keycloak token this one was upgraded from (PQ mode only).
	Classical *Token
}

// Errors returned when the authorization server issues a token without the expected binding.
var (
	ErrBindingMissing  = errors.New("issued token carries no sender-constraint binding")
	ErrBindingMismatch = errors.New("issued token is bound to different key material")
)

const expirySkew = 5 * time.Second

func (t *Token) usable(now time.Time) bool {
	limit := now.Add(expirySkew)
	if limit.After(t.ExpiresAt) {
		return false
	}
	return t.CertNotAfter.IsZero() || !limit.After(t.CertNotAfter)
}

// New builds a Client for cfg.Method.
func New(cfg Config, log *slog.Logger) (Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	b, err := newBase(cfg, log)
	if err != nil {
		return nil, err
	}
	switch cfg.Method {
	case MethodLongTerm:
		return &certBound{base: b}, nil
	case MethodEphemeral:
		b.rotateKeys = true
		return &certBound{base: b}, nil
	case MethodDPoP:
		// The classical DPoP key authenticates to Keycloak. In PQ mode an ML-DSA key
		// carries the binding that the shim writes into the upgraded token.
		signer, err := jose.GenerateSigner(cfg.DPoPAlg)
		if err != nil {
			return nil, err
		}
		jkt, err := signer.PublicJWK().Thumbprint()
		if err != nil {
			return nil, err
		}
		c := &dpopClient{base: b, signer: signer, jkt: jkt, nonces: map[string]string{}}
		if cfg.PQEnabled {
			pqSigner, err := jose.GenerateSigner(cfg.PQDPoPAlg)
			if err != nil {
				return nil, err
			}
			pqJKT, err := pqSigner.PublicJWK().Thumbprint()
			if err != nil {
				return nil, err
			}
			c.pqSigner, c.pqJKT = pqSigner, pqJKT
		}
		return c, nil
	}
	return nil, fmt.Errorf("unsupported method %q", cfg.Method)
}

type base struct {
	cfg        Config
	log        *slog.Logger
	roots      *x509.CertPool
	id         *Identity // classical credential (Keycloak leg)
	pqID       *Identity // ML-DSA credential (CA, shim, resource and peer legs)
	enroller   *Enroller
	transport  *http.Transport // presents the classical credential
	client     *http.Client
	pqTrans    *http.Transport // presents the ML-DSA credential, ML-KEM key exchange
	pqClient   *http.Client
	rotateKeys bool

	issuerMu sync.RWMutex
	issuer   Issuer

	mu           sync.Mutex // serialises enrollment, rotation and issuance
	cached       *Token
	tokensOnCert int
}

func newBase(cfg Config, log *slog.Logger) (*base, error) {
	roots, err := pki.LoadCertPool(cfg.TrustBundle...)
	if err != nil {
		return nil, fmt.Errorf("trust bundle: %w", err)
	}
	timeout := cfg.HTTPTimeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	b := &base{
		cfg:    cfg,
		log:    log.With("xapp_client", cfg.ClientID, "method", string(cfg.Method), "pq", cfg.PQEnabled),
		roots:  roots,
		id:     &Identity{},
		issuer: KeycloakIssuer{},
	}
	// Classical transport: used for Keycloak, which supports neither ML-DSA nor ML-KEM,
	// and for the shim upgrade call, where the classical binding is proved.
	b.transport = netx.NewTransport(clientTLS(b.id, roots, false), cfg.DialOverrides)
	b.client = &http.Client{Transport: b.transport, Timeout: timeout}
	b.enroller = &Enroller{BaseURL: cfg.CAURL, Roots: roots, Overrides: cfg.DialOverrides, Timeout: timeout, PQKexOnly: cfg.PQKexOnly}

	if cfg.PQEnabled {
		b.pqID = &Identity{}
		// Post-quantum transport: ML-DSA client certificate and the ML-KEM hybrid group.
		b.pqTrans = netx.NewTransport(clientTLS(b.pqID, roots, cfg.PQKexOnly), cfg.DialOverrides)
		b.pqClient = &http.Client{Transport: b.pqTrans, Timeout: timeout}
	}
	return b, nil
}

func clientTLS(id *Identity, roots *x509.CertPool, pqKexOnly bool) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if c := id.Current(); c != nil {
				return c, nil
			}
			return &tls.Certificate{}, nil
		},
		CurvePreferences: netx.CurvePreferences(pqKexOnly),
	}
}

func (b *base) Method() Method            { return b.cfg.Method }
func (b *base) ClientID() string          { return b.cfg.ClientID }
func (b *base) Identity() *Identity       { return b.id }
func (b *base) PQIdentity() *Identity     { return b.pqID }
func (b *base) TrustPool() *x509.CertPool { return b.roots }

// HTTPClient returns the client used for resource requests: the post-quantum identity
// in PQ mode, the classical one otherwise.
func (b *base) HTTPClient() *http.Client {
	if b.cfg.PQEnabled {
		return b.pqClient
	}
	return b.client
}

// ClassicalHTTPClient is always the classical-identity client (Keycloak and the shim).
func (b *base) ClassicalHTTPClient() *http.Client { return b.client }

// pqDirect reports whether the authorization server issues the post-quantum token
// itself. It is false today: no released Keycloak can sign with ML-DSA, so the shim
// is in the path. When one can, PQ_ISSUER=keycloak takes the shim out without any
// code change - the binding checks below are the same either way, only the credential
// the authorization server sees and the service that signs the token differ.
func (b *base) pqDirect() bool { return b.cfg.PQEnabled && b.cfg.PQIssuer == PQIssuerKeycloak }

// asIdentity is the credential the authorization server authenticates and binds the
// token to: the post-quantum one when the authorization server can handle it.
func (b *base) asIdentity() *Identity {
	if b.pqDirect() {
		return b.pqID
	}
	return b.id
}

// asClient is the HTTP client used for the authorization-server leg.
func (b *base) asClient() *http.Client {
	if b.pqDirect() {
		return b.pqClient
	}
	return b.client
}

// asLegError annotates a failure on the authorization-server leg. With
// PQ_ISSUER=keycloak the client presents its ML-DSA credential there, and no released
// Keycloak can parse an ML-DSA certificate or verify an ML-DSA proof, so the leg fails
// with a bare TLS or client-authentication error that says nothing about the cause.
func (b *base) asLegError(err error) error {
	if !b.pqDirect() || err == nil {
		return err
	}
	return fmt.Errorf("%w [PQ_ISSUER=%s: the authorization server was offered the ML-DSA credential. "+
		"No released Keycloak can parse an ML-DSA certificate or sign with ML-DSA; set PQ_ISSUER=shim]",
		err, b.cfg.PQIssuer)
}

// requirePQToken fails closed when an authorization server that is supposed to sign
// with ML-DSA returns something else. Without it, misconfiguring PQ_ISSUER would
// quietly downgrade every token to a classical signature.
func (b *base) requirePQToken(tok *Token) error {
	if !strings.HasPrefix(tok.Alg, "ML-DSA-") {
		return fmt.Errorf("%w: PQ_ISSUER=%s but the token is signed with %q, not ML-DSA",
			ErrBindingMismatch, b.cfg.PQIssuer, tok.Alg)
	}
	tok.PostQuantum = true
	return nil
}

func (b *base) SetIssuer(i Issuer) {
	b.issuerMu.Lock()
	b.issuer = i
	b.issuerMu.Unlock()
}

func (b *base) getIssuer() Issuer {
	b.issuerMu.RLock()
	defer b.issuerMu.RUnlock()
	return b.issuer
}

// activeIdentity is the credential a resource server will see.
func (b *base) activeIdentity() *Identity {
	if b.cfg.PQEnabled {
		return b.pqID
	}
	return b.id
}

// ServerTLSConfig serves the active identity certificate and requests (without
// verifying at handshake) the peer certificate; the resource validator verifies it.
func (b *base) ServerTLSConfig() *tls.Config {
	id := b.activeIdentity()
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			if c := id.Current(); c != nil {
				return c, nil
			}
			return nil, errors.New("no identity certificate yet")
		},
		ClientAuth:       tls.RequestClientCert,
		CurvePreferences: netx.CurvePreferences(b.cfg.PQKexOnly),
	}
}

// Describe summarises the credentials in use.
func (b *base) Describe() Description {
	d := Description{
		Method: b.cfg.Method, ClientID: b.cfg.ClientID, PQEnabled: b.cfg.PQEnabled,
		DPoPAlg: b.cfg.DPoPAlg, TokenIssuer: b.cfg.TokenURL,
		CertLifetime: b.cfg.CertLifetime, PQCertLifetime: b.cfg.pqCertLifetime(),
	}
	if b.cfg.PQEnabled {
		d.PQIssuer = b.cfg.PQIssuer
	}
	if leaf := b.id.Leaf(); leaf != nil {
		d.ClassicalCert = pki.DescribeCert(leaf)
		d.ClassicalAlg = pki.KeyAlgName(leaf.PublicKey)
	}
	if b.pqID != nil {
		if leaf := b.pqID.Leaf(); leaf != nil {
			d.PQCert = pki.DescribeCert(leaf)
			d.PQAlg = pki.KeyAlgName(leaf.PublicKey)
		}
		d.PQDPoPAlg = b.cfg.PQDPoPAlg
	}
	return d
}

func (b *base) Start(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.startIdentity(ctx, classicalPlane); err != nil {
		return err
	}
	if b.cfg.PQEnabled {
		if err := b.startIdentity(ctx, pqPlane); err != nil {
			return fmt.Errorf("post-quantum identity: %w", err)
		}
	}
	return nil
}

// plane distinguishes the classical credential from the post-quantum one. Both use
// the same enrollment, renewal and rotation code; only the key algorithm, the
// lifetime and the bootstrap credential differ.
type plane int

const (
	classicalPlane plane = iota
	pqPlane
)

func planeName(p plane) string {
	if p == pqPlane {
		return "post-quantum"
	}
	return "classical"
}

type planeConfig struct {
	id        *Identity
	keyAlg    string
	lifetime  time.Duration
	dir       string
	bootCert  string
	bootKey   string
	bootstrap *tls.Certificate
}

func (b *base) planeConfig(p plane) planeConfig {
	if p == pqPlane {
		return planeConfig{id: b.pqID, keyAlg: b.cfg.PQKeyAlg, lifetime: b.cfg.pqCertLifetime(),
			dir: b.cfg.PQIdentityDir, bootCert: b.cfg.PQBootstrapCert, bootKey: b.cfg.PQBootstrapKey, bootstrap: b.cfg.PQBootstrap}
	}
	return planeConfig{id: b.id, keyAlg: b.cfg.KeyAlg, lifetime: b.cfg.CertLifetime,
		dir: b.cfg.IdentityDir, bootCert: b.cfg.BootstrapCert, bootKey: b.cfg.BootstrapKey, bootstrap: b.cfg.Bootstrap}
}

func (b *base) startIdentity(ctx context.Context, p plane) error {
	pc := b.planeConfig(p)
	if pc.id.Current() != nil {
		return nil
	}
	if pc.dir != "" {
		c, err := loadCredential(filepath.Join(pc.dir, "tls.crt"), filepath.Join(pc.dir, "tls.key"))
		if err == nil && time.Now().Before(c.Leaf.NotAfter) {
			pc.id.set(c)
			b.log.Info("identity_loaded", "plane", planeName(p), "serial", c.Leaf.SerialNumber.Text(16),
				"key_alg", pki.KeyAlgName(c.Leaf.PublicKey), "not_after", c.Leaf.NotAfter.UTC().Format(time.RFC3339))
			if b.needsRenewalPlane(p) {
				_, err := b.rotatePlaneLocked(ctx, p)
				return err
			}
			return nil
		}
	}
	boot := pc.bootstrap
	if boot == nil {
		if pc.bootCert == "" || pc.bootKey == "" {
			return errors.New("no valid operational identity and no bootstrap credential configured")
		}
		var err error
		if boot, err = loadCredential(pc.bootCert, pc.bootKey); err != nil {
			return fmt.Errorf("bootstrap credential: %w", err)
		}
	}
	_, err := b.enrollLocked(ctx, p, boot, false, true)
	return err
}

func (b *base) needsRenewalPlane(p plane) bool {
	pc := b.planeConfig(p)
	leaf := pc.id.Leaf()
	return leaf == nil || time.Until(leaf.NotAfter) <= b.cfg.renewBeforeFor(pc.lifetime)
}

func (b *base) needsRenewal() bool {
	if b.needsRenewalPlane(classicalPlane) {
		return true
	}
	return b.cfg.PQEnabled && b.needsRenewalPlane(pqPlane)
}

// enrollLocked obtains a certificate for one plane, authenticated by auth. Must hold b.mu.
func (b *base) enrollLocked(ctx context.Context, p plane, auth *tls.Certificate, renew, newKey bool) (RotationStats, error) {
	pc := b.planeConfig(p)
	start := time.Now()
	var key crypto.Signer
	if newKey {
		k, err := pki.GenerateKey(pc.keyAlg)
		if err != nil {
			return RotationStats{}, err
		}
		key = k
	} else {
		k, ok := auth.PrivateKey.(crypto.Signer)
		if !ok {
			return RotationStats{}, errors.New("current private key is not a signer")
		}
		key = k
	}
	keygen := time.Since(start)
	rt := time.Now()
	cert, err := b.enroller.Enroll(ctx, auth, key, b.cfg.DNSNames, pc.lifetime, renew)
	roundTrip := time.Since(rt)
	if err != nil {
		return RotationStats{}, err
	}
	pc.id.set(cert)
	if err := persistCredential(pc.dir, cert); err != nil {
		b.log.Warn("identity_persist_failed", "plane", planeName(p), "error", err)
	}
	// A token bound to the previous certificate is useless now; drop it and any pooled
	// connection that would still present the old certificate.
	b.cached = nil
	b.tokensOnCert = 0
	b.transport.CloseIdleConnections()
	if b.pqTrans != nil {
		b.pqTrans.CloseIdleConnections()
	}
	stats := RotationStats{KeyGen: keygen, RoundTrip: roundTrip, Total: time.Since(start),
		Serial: cert.Leaf.SerialNumber.Text(16), NotAfter: cert.Leaf.NotAfter,
		KeyAlg: pki.KeyAlgName(cert.Leaf.PublicKey), CertBytes: len(cert.Leaf.Raw), Plane: planeName(p)}
	b.log.Info("identity_enrolled",
		"plane", stats.Plane, "endpoint", map[bool]string{true: "renew", false: "enroll"}[renew], "new_key", newKey,
		"serial", stats.Serial, "key_alg", stats.KeyAlg, "sig_alg", cert.Leaf.SignatureAlgorithm.String(),
		"cert_bytes", stats.CertBytes, "not_after", stats.NotAfter.UTC().Format(time.RFC3339),
		"x5t#S256", pki.ThumbprintS256(cert.Leaf),
		"keygen_ms", ms(keygen), "ca_roundtrip_ms", ms(roundTrip))
	return stats, nil
}

// rotatePlaneLocked renews one plane using its current certificate. Must hold b.mu.
func (b *base) rotatePlaneLocked(ctx context.Context, p plane) (RotationStats, error) {
	pc := b.planeConfig(p)
	cur := pc.id.Current()
	if cur == nil {
		return RotationStats{}, errors.New("no operational identity to renew")
	}
	if !time.Now().Before(cur.Leaf.NotAfter) {
		return RotationStats{}, fmt.Errorf("%s certificate expired at %s; renewal is impossible and a new bootstrap credential is required",
			planeName(p), cur.Leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return b.enrollLocked(ctx, p, cur, true, b.rotateKeys)
}

// rotateLocked renews every plane and reports the statistics of the credential a
// resource server sees (the post-quantum one in PQ mode).
func (b *base) rotateLocked(ctx context.Context) (RotationStats, error) {
	stats, err := b.rotatePlaneLocked(ctx, classicalPlane)
	if err != nil {
		return stats, err
	}
	if b.cfg.PQEnabled {
		return b.rotatePlaneLocked(ctx, pqPlane)
	}
	return stats, nil
}

// Rotate renews the operational certificates now.
func (b *base) Rotate(ctx context.Context) (RotationStats, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.rotateLocked(ctx)
}

// Maintain is the rotation loop: it renews each credential before it expires.
func (b *base) Maintain(ctx context.Context) {
	interval := b.cfg.renewBefore() / 4
	interval = max(time.Second, min(interval, time.Minute))
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			b.mu.Lock()
			for _, p := range b.planes() {
				if b.needsRenewalPlane(p) {
					if _, err := b.rotatePlaneLocked(ctx, p); err != nil {
						b.log.Error("rotation_failed", "plane", planeName(p), "error", err)
					}
				}
			}
			b.mu.Unlock()
		}
	}
}

func (b *base) planes() []plane {
	if b.cfg.PQEnabled {
		return []plane{classicalPlane, pqPlane}
	}
	return []plane{classicalPlane}
}

func newToken(resp *TokenResponse) (*Token, error) {
	jws, err := jose.ParseCompact(resp.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("access token is not a JWS: %w", err)
	}
	claims, err := jws.Claims()
	if err != nil {
		return nil, err
	}
	exp := resp.ReceivedAt.Add(time.Duration(resp.ExpiresIn) * time.Second)
	if n, ok := claims["exp"].(json.Number); ok {
		if v, err := n.Int64(); err == nil {
			exp = time.Unix(v, 0)
		}
	}
	return &Token{Value: resp.AccessToken, Type: resp.TokenType, IssuedAt: resp.ReceivedAt,
		ExpiresAt: exp, Claims: claims, Alg: jws.Alg()}, nil
}

// cnfMember returns a string member of the cnf claim.
func cnfMember(claims map[string]any, name string) (string, error) {
	cnf, ok := claims["cnf"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("%w: no cnf claim", ErrBindingMissing)
	}
	v, ok := cnf[name].(string)
	if !ok || v == "" {
		return "", fmt.Errorf("%w: cnf has no %q member", ErrBindingMissing, name)
	}
	return v, nil
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
