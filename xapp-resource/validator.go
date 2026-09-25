package xappresource

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/jose"
	"github.com/oran-ricsec/xapp-token-binding/internal/netx"
	"github.com/oran-ricsec/xapp-token-binding/internal/pki"
)

// Mode selects how token validity is established.
type Mode string

// Validation modes.
const (
	ModeLocal         Mode = "local"
	ModeIntrospection Mode = "introspection"
)

// Principal describes an authorized caller; it is stored in the request context.
type Principal struct {
	ClientID   string
	Subject    string
	Scopes     []string
	Binding    string // "x5t#S256" or "jkt"
	Thumbprint string
	Mode       Mode
	Claims     map[string]any
}

type principalKey struct{}

// PrincipalFrom returns the authorized caller placed in ctx by the middleware.
func PrincipalFrom(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(*Principal)
	return p, ok
}

// Validator is the resource-side enforcement point.
type Validator struct {
	cfg        Config
	log        *slog.Logger
	keys       *jose.KeySet
	roots      *x509.CertPool
	replay     *ReplayCache
	introspect *Introspector
	algs       map[string]bool
	now        func() time.Time
}

// NewValidator builds a validator. httpClient is the resource xApp's own mTLS client,
// used to fetch the JWKS and to call introspection.
func NewValidator(cfg Config, httpClient *http.Client, log *slog.Logger) (*Validator, error) {
	roots, err := pki.LoadCertPool(cfg.TrustBundle...)
	if err != nil {
		return nil, fmt.Errorf("client certificate trust bundle: %w", err)
	}
	v := &Validator{
		cfg:    cfg,
		log:    log.With("component", "xapp-resource"),
		keys:   jose.NewKeySet(cfg.JWKSURL, httpClient, cfg.JWKSCacheTTL, cfg.JWKSMinRefresh),
		roots:  roots,
		replay: NewReplayCache(cfg.ReplayCacheSize),
		algs:   map[string]bool{},
		now:    time.Now,
	}
	for _, a := range cfg.DPoPAllowedAlgs {
		v.algs[a] = true
	}
	if cfg.IntrospectionURL != "" {
		v.introspect = &Introspector{URL: cfg.IntrospectionURL, ClientID: cfg.IntrospectionClientID, Client: httpClient}
	}
	return v, nil
}

// Middleware enforces the token and its binding before calling next.
func (v *Validator) Middleware(mode Mode, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		p, rej := v.Authorize(r, mode)
		elapsed := float64(time.Since(start).Microseconds()) / 1000
		if rej != nil {
			v.log.Warn("authz_rejected",
				"reason_code", rej.Code, "reason", rej.Detail, "mode", mode,
				"http_method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr, "validation_ms", elapsed)
			writeRejection(w, rej)
			return
		}
		v.log.Debug("authz_granted",
			"client_id", p.ClientID, "binding", p.Binding, "cnf", p.Thumbprint, "mode", mode,
			"http_method", r.Method, "path", r.URL.Path, "validation_ms", elapsed)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	})
}

// Authorize runs every check and returns the caller or the first failure.
func (v *Validator) Authorize(r *http.Request, mode Mode) (*Principal, *Rejection) {
	scheme, token, rej := parseAuthorization(r)
	if rej != nil {
		return nil, rej
	}

	// 1. Token validity (signature/exp/nbf/iss/aud locally, or introspection).
	var claims map[string]any
	switch mode {
	case ModeLocal:
		claims, rej = v.validateLocally(r.Context(), token)
	case ModeIntrospection:
		if v.introspect == nil {
			return nil, reject(ReasonIntrospectionFailed, "introspection is not configured")
		}
		claims, rej = v.introspect.Introspect(r.Context(), token)
		if rej == nil {
			rej = v.checkIssuerAudience(claims)
		}
	default:
		return nil, reject(ReasonIntrospectionFailed, "unknown validation mode %q", mode)
	}
	if rej != nil {
		return nil, rej
	}

	// 2. Authorization claims.
	if rej := v.checkAuthorization(claims); rej != nil {
		return nil, rej
	}

	// 3. Sender constraint. Absent or unusable cnf is a rejection, never a pass-through.
	rawCnf, present := claims["cnf"]
	if !present {
		return nil, reject(ReasonCnfMissing, "access token has no cnf claim; unbound bearer tokens are not accepted")
	}
	cnf, ok := rawCnf.(map[string]any)
	if !ok {
		return nil, reject(ReasonCnfMalformed, "cnf claim is not a JSON object")
	}
	x5t, hasX5t, rej := cnfString(cnf, "x5t#S256")
	if rej != nil {
		return nil, rej
	}
	jkt, hasJkt, rej := cnfString(cnf, "jkt")
	if rej != nil {
		return nil, rej
	}
	if !hasX5t && !hasJkt {
		return nil, reject(ReasonCnfUnrecognized, "cnf carries no supported confirmation method (x5t#S256 or jkt)")
	}

	p := &Principal{Mode: mode, Claims: claims}
	p.ClientID = firstString(claims, "client_id", "azp")
	p.Subject, _ = claims["sub"].(string)
	if s, ok := claims["scope"].(string); ok {
		p.Scopes = strings.Fields(s)
	}
	if hasX5t {
		if rej := v.checkCertificateBinding(r, scheme, x5t, hasJkt); rej != nil {
			return nil, rej
		}
		p.Binding, p.Thumbprint = "x5t#S256", x5t
	}
	if hasJkt {
		if rej := v.checkDPoPBinding(r, scheme, token, jkt); rej != nil {
			return nil, rej
		}
		p.Binding, p.Thumbprint = "jkt", jkt
	}
	return p, nil
}

func parseAuthorization(r *http.Request) (scheme, token string, rej *Rejection) {
	values := r.Header.Values("Authorization")
	if len(values) == 0 {
		return "", "", reject(ReasonAuthorizationMissing, "no Authorization header")
	}
	if len(values) > 1 {
		return "", "", reject(ReasonAuthorizationMalformed, "multiple Authorization headers")
	}
	s, t, ok := strings.Cut(strings.TrimSpace(values[0]), " ")
	t = strings.TrimSpace(t)
	if !ok || t == "" {
		return "", "", reject(ReasonAuthorizationMalformed, "Authorization header is not '<scheme> <token>'")
	}
	switch strings.ToLower(s) {
	case "bearer":
		return "bearer", t, nil
	case "dpop":
		return "dpop", t, nil
	}
	return "", "", reject(ReasonSchemeUnsupported, "authorization scheme %q is not supported", s)
}

func (v *Validator) validateLocally(ctx context.Context, token string) (map[string]any, *Rejection) {
	jws, err := jose.ParseCompact(token)
	if err != nil {
		return nil, reject(ReasonTokenMalformed, "access token is not a compact JWS: %v", err)
	}
	// The algorithm comes from the JWS header and is dispatched through the jose
	// registry; the key comes from the configured JWKS URL.
	key, err := v.keys.Key(ctx, jws.Kid(), jws.Alg())
	if err != nil {
		return nil, reject(ReasonTokenKeyUnavailable, "no verification key: %v", err)
	}
	if err := jws.VerifySignature(key); err != nil {
		return nil, reject(ReasonTokenSignatureInvalid, "access token signature (alg %s) invalid: %v", jws.Alg(), err)
	}
	claims, err := jws.Claims()
	if err != nil {
		return nil, reject(ReasonTokenMalformed, "access token payload is not a JSON object: %v", err)
	}
	now := v.now()
	exp, hasExp, err := numericClaim(claims, "exp")
	if err != nil || !hasExp {
		return nil, reject(ReasonTokenMalformed, "access token has no valid exp claim")
	}
	if now.After(time.Unix(exp, 0).Add(v.cfg.ClockSkew)) {
		return nil, reject(ReasonTokenExpired, "access token expired at %s", time.Unix(exp, 0).UTC().Format(time.RFC3339))
	}
	if nbf, ok, err := numericClaim(claims, "nbf"); err != nil {
		return nil, reject(ReasonTokenMalformed, "nbf claim is not numeric")
	} else if ok && now.Add(v.cfg.ClockSkew).Before(time.Unix(nbf, 0)) {
		return nil, reject(ReasonTokenNotYetValid, "access token not valid before %s", time.Unix(nbf, 0).UTC().Format(time.RFC3339))
	}
	if rej := v.checkIssuerAudience(claims); rej != nil {
		return nil, rej
	}
	return claims, nil
}

func (v *Validator) checkIssuerAudience(claims map[string]any) *Rejection {
	if iss, _ := claims["iss"].(string); iss != v.cfg.Issuer {
		return reject(ReasonTokenIssuerMismatch, "iss %q is not the trusted issuer %q", iss, v.cfg.Issuer)
	}
	switch aud := claims["aud"].(type) {
	case string:
		if aud == v.cfg.Audience {
			return nil
		}
	case []any:
		for _, a := range aud {
			if s, _ := a.(string); s == v.cfg.Audience {
				return nil
			}
		}
	}
	return reject(ReasonTokenAudienceMismatch, "aud %v does not include %q", claims["aud"], v.cfg.Audience)
}

func (v *Validator) checkAuthorization(claims map[string]any) *Rejection {
	if want := v.cfg.RequiredScope; want != "" {
		scope, _ := claims["scope"].(string)
		if !slices.Contains(strings.Fields(scope), want) {
			return reject(ReasonInsufficientScope, "token scope %q lacks %q", scope, want)
		}
	}
	if want := v.cfg.RequiredRole; want != "" {
		var roles []any
		if ra, ok := claims["realm_access"].(map[string]any); ok {
			roles, _ = ra["roles"].([]any)
		}
		if !slices.ContainsFunc(roles, func(r any) bool { s, _ := r.(string); return s == want }) {
			return reject(ReasonInsufficientScope, "token realm roles %v lack %q", roles, want)
		}
	}
	return nil
}

// checkCertificateBinding implements RFC 8705 §3: the thumbprint of the certificate
// presented on this TLS session must equal cnf.x5t#S256.
func (v *Validator) checkCertificateBinding(r *http.Request, scheme, x5t string, alsoDPoP bool) *Rejection {
	if scheme != "bearer" && !alsoDPoP {
		return reject(ReasonCertBoundWrongScheme, "certificate-bound token must be sent with the Bearer scheme, got %q", scheme)
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return reject(ReasonClientCertMissing, "token is bound to certificate x5t#S256=%s but no client certificate was presented on the TLS session", x5t)
	}
	chain := r.TLS.PeerCertificates
	if kind, err := pki.VerifyChain(chain, v.roots, v.now(), x509.ExtKeyUsageClientAuth); err != nil {
		if kind == pki.ChainExpired {
			return reject(ReasonClientCertExpired, "%v", err)
		}
		return reject(ReasonClientCertInvalid, "client certificate rejected (%s): %v", kind, err)
	}
	got := pki.ThumbprintS256(chain[0])
	if subtle.ConstantTimeCompare([]byte(got), []byte(x5t)) != 1 {
		return reject(ReasonX5tMismatch, "presented certificate CN=%q x5t#S256=%s does not match token cnf.x5t#S256=%s",
			chain[0].Subject.CommonName, got, x5t)
	}
	return nil
}

// checkDPoPBinding implements RFC 9449 §4.3 and §7.1 for a protected resource request.
func (v *Validator) checkDPoPBinding(r *http.Request, scheme, token, jkt string) *Rejection {
	if scheme != "dpop" {
		return reject(ReasonDPoPAsBearer, "token is DPoP-bound (cnf.jkt=%s) but was presented with the %s scheme", jkt, scheme)
	}
	proofs := r.Header.Values("DPoP")
	if len(proofs) == 0 {
		return reject(ReasonDPoPProofMissing, "DPoP-bound token presented without a DPoP proof header")
	}
	if len(proofs) > 1 {
		return reject(ReasonDPoPProofMultiple, "more than one DPoP header")
	}
	proof, err := jose.ParseCompact(proofs[0])
	if err != nil {
		return reject(ReasonDPoPProofMalformed, "DPoP proof is not a compact JWS: %v", err)
	}
	if proof.Typ() != "dpop+jwt" {
		return reject(ReasonDPoPProofType, "DPoP proof typ is %q, expected dpop+jwt", proof.Typ())
	}
	if len(v.algs) > 0 && !v.algs[proof.Alg()] {
		return reject(ReasonDPoPProofAlg, "DPoP proof alg %q is not allowed", proof.Alg())
	}

	// (a) Proof signature, verified with the public key carried in its own jwk header.
	rawJWK, ok := proof.Header["jwk"].(map[string]any)
	if !ok {
		return reject(ReasonDPoPProofJWK, "DPoP proof header has no jwk")
	}
	jwk := jose.JWK(rawJWK)
	pub, err := jwk.PublicKey()
	if err != nil {
		return reject(ReasonDPoPProofJWK, "DPoP proof jwk unusable: %v", err)
	}
	if err := proof.VerifySignature(pub); err != nil {
		return reject(ReasonDPoPProofSignature, "DPoP proof signature (alg %s) invalid: %v", proof.Alg(), err)
	}

	// (b) The proof key is the key the token is bound to: JWK SHA-256 thumbprint == cnf.jkt.
	thumb, err := jwk.Thumbprint()
	if err != nil {
		return reject(ReasonDPoPProofJWK, "cannot compute JWK thumbprint: %v", err)
	}
	if subtle.ConstantTimeCompare([]byte(thumb), []byte(jkt)) != 1 {
		return reject(ReasonDPoPJktMismatch, "DPoP proof key thumbprint %s does not match token cnf.jkt %s", thumb, jkt)
	}

	claims, err := proof.Claims()
	if err != nil {
		return reject(ReasonDPoPProofMalformed, "DPoP proof payload: %v", err)
	}

	// (c) ath binds the proof to this access token.
	ath, _ := claims["ath"].(string)
	if ath == "" {
		return reject(ReasonDPoPAthMissing, "DPoP proof has no ath claim")
	}
	sum := sha256.Sum256([]byte(token))
	if want := jose.B64(sum[:]); subtle.ConstantTimeCompare([]byte(ath), []byte(want)) != 1 {
		return reject(ReasonDPoPAthMismatch, "DPoP proof ath %s is not the hash of the presented access token (%s)", ath, want)
	}

	// (d) htm/htu bind the proof to this request.
	if htm, _ := claims["htm"].(string); htm != r.Method {
		return reject(ReasonDPoPHtmMismatch, "DPoP proof htm %q does not match request method %q", htm, r.Method)
	}
	htuClaim, _ := claims["htu"].(string)
	gotHTU, errClaim := netx.NormalizeHTU(htuClaim)
	wantHTU, errReq := v.requestHTU(r)
	if errClaim != nil || errReq != nil || gotHTU != wantHTU {
		return reject(ReasonDPoPHtuMismatch, "DPoP proof htu %q does not match request URI %q", htuClaim, wantHTU)
	}

	// (e) Freshness and single use.
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return reject(ReasonDPoPJtiMissing, "DPoP proof has no jti")
	}
	iatUnix, ok, err := numericClaim(claims, "iat")
	if err != nil || !ok {
		return reject(ReasonDPoPProofMalformed, "DPoP proof has no numeric iat")
	}
	now, iat := v.now(), time.Unix(iatUnix, 0)
	if iat.Before(now.Add(-v.cfg.DPoPProofWindow-v.cfg.ClockSkew)) || iat.After(now.Add(v.cfg.ClockSkew)) {
		return reject(ReasonDPoPIatOutOfWindow, "DPoP proof iat %s is outside the accepted window (%s, skew %s)",
			iat.UTC().Format(time.RFC3339), v.cfg.DPoPProofWindow, v.cfg.ClockSkew)
	}
	expiry := iat.Add(v.cfg.DPoPProofWindow + 2*v.cfg.ClockSkew)
	switch v.replay.CheckAndStore(jkt+":"+jti, expiry, now) {
	case ReplaySeen:
		return reject(ReasonDPoPReplayed, "DPoP proof jti %s has already been used with key %s", jti, jkt)
	case ReplayFull:
		return reject(ReasonDPoPReplayCacheFull, "replay cache is full; refusing to accept unverifiable proofs")
	}
	return nil
}

func (v *Validator) requestHTU(r *http.Request) (string, error) {
	if base := v.cfg.PublicBaseURL; base != "" {
		return netx.NormalizeHTU(strings.TrimRight(base, "/") + r.URL.EscapedPath())
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return netx.NormalizeHTU(scheme + "://" + r.Host + r.URL.EscapedPath())
}

func cnfString(cnf map[string]any, name string) (string, bool, *Rejection) {
	raw, present := cnf[name]
	if !present {
		return "", false, nil
	}
	s, ok := raw.(string)
	if !ok || s == "" {
		return "", false, reject(ReasonCnfMalformed, "cnf member %q is not a non-empty string", name)
	}
	return s, true, nil
}

func numericClaim(claims map[string]any, name string) (int64, bool, error) {
	raw, ok := claims[name]
	if !ok {
		return 0, false, nil
	}
	switch n := raw.(type) {
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i, true, nil
		}
		f, err := n.Float64()
		return int64(f), err == nil, err
	case float64:
		return int64(n), true, nil
	}
	return 0, false, fmt.Errorf("claim %q is not numeric", name)
}

func firstString(claims map[string]any, names ...string) string {
	for _, n := range names {
		if s, ok := claims[n].(string); ok && s != "" {
			return s
		}
	}
	return ""
}
