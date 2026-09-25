// Package xappresource enforces sender-constrained access tokens at the resource xApp.
//
// Keycloak only issues bound tokens; nothing checks the binding unless the resource
// does. Validator.Middleware is the single enforcement point:
//
//	cnf.x5t#S256 (Methods A/B, RFC 8705): the TLS peer certificate's SHA-256 thumbprint must match.
//	cnf.jkt      (Method C, RFC 9449):    a valid DPoP proof signed by the key whose JWK thumbprint matches,
//	                                      with ath, htm, htu, iat and a never-seen jti.
//
// Token validity is established either locally (JWS signature via JWKS + exp/nbf/iss/aud)
// or by RFC 7662 introspection; the binding checks are identical in both modes.
// Everything fails closed: a missing, malformed or unrecognised cnf is a rejection.
package xappresource

import (
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/config"
)

// Config configures a Validator. ConfigFromEnv reads it from the environment.
type Config struct {
	Issuer        string
	Audience      string
	JWKSURL       string
	RequiredScope string
	RequiredRole  string
	TrustBundle   []string // PEM trust anchors for client certificates (RIC intermediate CAs)

	ClockSkew       time.Duration
	DPoPProofWindow time.Duration // accepted age of a proof's iat
	ReplayCacheSize int
	DPoPAllowedAlgs []string // empty = any asymmetric alg registered in the jose package

	PublicBaseURL string // optional external base URL used to reconstruct htu

	// ChannelMode selects how tunnel traffic is validated (AuthorizeChannel).
	ChannelMode Mode

	IntrospectionURL      string
	IntrospectionClientID string

	JWKSCacheTTL   time.Duration
	JWKSMinRefresh time.Duration
}

// ConfigFromEnv reads the validator configuration.
func ConfigFromEnv() (Config, error) {
	e := &config.Env{}
	c := Config{
		Issuer:                e.Req("TOKEN_ISSUER"),
		Audience:              e.Req("TOKEN_AUDIENCE"),
		JWKSURL:               e.Req("JWKS_URL"),
		RequiredScope:         e.Str("REQUIRED_SCOPE", ""),
		RequiredRole:          e.Str("REQUIRED_ROLE", ""),
		TrustBundle:           e.List("RIC_TRUST_BUNDLE", nil),
		ClockSkew:             e.Dur("CLOCK_SKEW", 30*time.Second),
		DPoPProofWindow:       e.Dur("DPOP_PROOF_WINDOW", 60*time.Second),
		ReplayCacheSize:       e.Int("DPOP_REPLAY_CACHE_SIZE", 1_000_000),
		DPoPAllowedAlgs:       e.List("DPOP_ALLOWED_ALGS", nil),
		PublicBaseURL:         e.Str("PUBLIC_BASE_URL", ""),
		ChannelMode:           Mode(e.Str("CHANNEL_VALIDATION_MODE", string(ModeLocal))),
		IntrospectionURL:      e.Str("INTROSPECTION_URL", ""),
		IntrospectionClientID: e.Str("XAPP_CLIENT_ID", ""),
		JWKSCacheTTL:          e.Dur("JWKS_CACHE_TTL", 5*time.Minute),
		JWKSMinRefresh:        e.Dur("JWKS_MIN_REFRESH", 10*time.Second),
	}
	if len(c.TrustBundle) == 0 {
		e.Fail("RIC_TRUST_BUNDLE is required")
	}
	return c, e.Err()
}
