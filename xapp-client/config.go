// Package xappclient is the xApp-side OAuth 2.0 client library for sender-constrained
// tokens. A caller selects the binding method by configuration (XAPP_METHOD) and uses
// the same Client interface regardless of method:
//
//	A  RFC 8705 certificate-bound token, long-term identity certificate
//	B  RFC 8705 certificate-bound token, ephemeral identity certificate (key rotated on every renewal)
//	C  RFC 9449 DPoP-bound token
//
// A and B are one implementation (certBound) parameterised by certificate lifetime and
// a key-rotation flag; Keycloak's client configuration for both is identical.
//
// With PQ_MODE=true the client additionally maintains a post-quantum credential
// (ML-DSA certificate, or ML-DSA DPoP key for method C) and upgrades every Keycloak
// token through the pq-shim into an ML-DSA-signed token bound to that credential.
// Keycloak remains on the classical credential because it supports neither ML-DSA nor
// ML-KEM; every other leg uses the post-quantum credential and the ML-KEM hybrid
// key exchange.
package xappclient

import (
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/config"
	"github.com/oran-ricsec/xapp-token-binding/internal/netx"
)

// Method selects the binding scheme.
type Method string

// Supported methods.
const (
	MethodLongTerm  Method = "A"
	MethodEphemeral Method = "B"
	MethodDPoP      Method = "C"
)

// PQIssuer names the service that issues the post-quantum access token.
type PQIssuer string

// Post-quantum issuers.
const (
	// PQIssuerShim: Keycloak issues a classical token and the pq-shim re-issues it
	// ML-DSA-signed and bound to the post-quantum credential. This is the only
	// option that works today, because no released Keycloak can sign with ML-DSA.
	PQIssuerShim PQIssuer = "shim"
	// PQIssuerKeycloak: the authorization server signs with ML-DSA itself and binds
	// the token to the post-quantum credential directly, so the shim leaves the
	// path entirely. Selecting it makes the client use the post-quantum credential
	// on the authorization-server leg as well, and refuse a token that is not
	// ML-DSA-signed. It is the exit condition for the shim, not a fallback: set it
	// only against an authorization server that advertises an ML-DSA signing key.
	PQIssuerKeycloak PQIssuer = "keycloak"
)

// RotationPolicy controls when Method B replaces its key pair.
type RotationPolicy string

// Rotation policies.
const (
	// RotateOnCertExpiry renews when the certificate approaches expiry (RenewBefore).
	RotateOnCertExpiry RotationPolicy = "cert-expiry"
	// RotateEveryToken renews the certificate before every token issuance.
	RotateEveryToken RotationPolicy = "every-token"
)

// Config configures a Client. ConfigFromEnv reads it from the environment.
type Config struct {
	Method      Method
	ClientID    string
	TokenURL    string
	Scope       string
	TrustBundle []string // PEM trust anchors for Keycloak, the RIC CA, the shim and peer xApps
	CAURL       string

	// Bootstrap credential (one-time) used for the first enrollment. Bootstrap, when
	// set, takes precedence over the file paths.
	BootstrapCert string
	BootstrapKey  string
	Bootstrap     *tls.Certificate

	IdentityDir  string        // where the operational credential is persisted ("" = memory only)
	KeyAlg       string        // identity key algorithm (EC-P256 default)
	CertLifetime time.Duration // requested operational certificate lifetime
	RenewBefore  time.Duration // renew when remaining lifetime <= RenewBefore (0 = 20% of lifetime)
	Rotation     RotationPolicy
	DNSNames     []string // requested SANs (must be granted by the bootstrap credential)

	DPoPAlg string // JWS alg for DPoP proofs (method C)

	// --- post-quantum --------------------------------------------------------
	PQEnabled        bool
	PQIssuer         PQIssuer // who issues the post-quantum token: the shim, or the AS itself
	PQShimURL        string   // base URL of the pq-shim (token upgrade + JWKS)
	PQKeyAlg         string   // ML-DSA parameter set for the identity certificate
	PQDPoPAlg        string   // ML-DSA parameter set for DPoP proofs (method C)
	PQCertLifetime   time.Duration
	PQBootstrapCert  string
	PQBootstrapKey   string
	PQBootstrap      *tls.Certificate
	PQIdentityDir    string
	PQKexOnly        bool // require the ML-KEM hybrid group on post-quantum legs
	PQProofValidity  time.Duration
	PQUpgradeTimeout time.Duration

	DialOverrides map[string]string
	HTTPTimeout   time.Duration
}

// DefaultLifetime returns the default certificate lifetime for a method.
func DefaultLifetime(m Method) time.Duration {
	if m == MethodEphemeral {
		return 15 * time.Minute
	}
	return 7 * 24 * time.Hour
}

// ConfigFromEnv reads the client configuration.
func ConfigFromEnv() (Config, error) {
	e := &config.Env{}
	method := Method(strings.ToUpper(e.Str("XAPP_METHOD", "A")))
	c := Config{
		Method:           method,
		ClientID:         e.Req("XAPP_CLIENT_ID"),
		TokenURL:         e.Req("KEYCLOAK_TOKEN_URL"),
		Scope:            e.Str("TOKEN_SCOPE", ""),
		TrustBundle:      e.List("RIC_TRUST_BUNDLE", nil),
		CAURL:            e.Req("RIC_CA_URL"),
		BootstrapCert:    e.Str("BOOTSTRAP_CERT", ""),
		BootstrapKey:     e.Str("BOOTSTRAP_KEY", ""),
		IdentityDir:      e.Str("IDENTITY_DIR", ""),
		KeyAlg:           e.Str("IDENTITY_KEY_ALG", "EC-P256"),
		CertLifetime:     e.Dur("CERT_LIFETIME", DefaultLifetime(method)),
		RenewBefore:      e.Dur("RENEW_BEFORE", 0),
		Rotation:         RotationPolicy(e.Str("ROTATION_POLICY", string(RotateOnCertExpiry))),
		DNSNames:         e.List("SERVER_DNS_NAMES", nil),
		DPoPAlg:          e.Str("DPOP_ALG", "ES256"),
		PQEnabled:        e.Bool("PQ_MODE", false),
		PQIssuer:         PQIssuer(e.Str("PQ_ISSUER", string(PQIssuerShim))),
		PQShimURL:        e.Str("PQ_SHIM_URL", ""),
		PQKeyAlg:         e.Str("PQ_IDENTITY_KEY_ALG", "ML-DSA-65"),
		PQDPoPAlg:        e.Str("PQ_DPOP_ALG", "ML-DSA-44"),
		PQCertLifetime:   e.Dur("PQ_CERT_LIFETIME", 0),
		PQBootstrapCert:  e.Str("PQ_BOOTSTRAP_CERT", ""),
		PQBootstrapKey:   e.Str("PQ_BOOTSTRAP_KEY", ""),
		PQIdentityDir:    e.Str("PQ_IDENTITY_DIR", ""),
		PQKexOnly:        e.Bool("PQ_KEX_ONLY", false),
		PQProofValidity:  e.Dur("PQ_PROOF_VALIDITY", 60*time.Second),
		PQUpgradeTimeout: e.Dur("PQ_UPGRADE_TIMEOUT", 30*time.Second),
		HTTPTimeout:      e.Dur("HTTP_TIMEOUT", 15*time.Second),
	}
	overrides, err := netx.ParseDialOverrides(e.Str("DIAL_OVERRIDES", ""))
	if err != nil {
		e.Fail("DIAL_OVERRIDES: %v", err)
	}
	c.DialOverrides = overrides
	if len(c.TrustBundle) == 0 {
		e.Fail("RIC_TRUST_BUNDLE is required")
	}
	if err := c.Validate(); err != nil {
		e.Fail("%v", err)
	}
	return c, e.Err()
}

// Validate checks method-independent invariants.
func (c Config) Validate() error {
	switch c.Method {
	case MethodLongTerm, MethodEphemeral, MethodDPoP:
	default:
		return fmt.Errorf("XAPP_METHOD must be A, B or C, got %q", c.Method)
	}
	switch c.Rotation {
	case RotateOnCertExpiry, RotateEveryToken:
	default:
		return fmt.Errorf("ROTATION_POLICY must be %q or %q", RotateOnCertExpiry, RotateEveryToken)
	}
	if c.CertLifetime <= 0 {
		return fmt.Errorf("CERT_LIFETIME must be positive")
	}
	if c.RenewBefore >= c.CertLifetime {
		return fmt.Errorf("RENEW_BEFORE (%s) must be shorter than CERT_LIFETIME (%s)", c.RenewBefore, c.CertLifetime)
	}
	if c.PQEnabled {
		switch c.PQIssuer {
		case PQIssuerShim:
			if c.PQShimURL == "" {
				return fmt.Errorf("PQ_SHIM_URL is required when PQ_ISSUER is %q", PQIssuerShim)
			}
		case PQIssuerKeycloak:
		default:
			return fmt.Errorf("PQ_ISSUER must be %q or %q, got %q", PQIssuerShim, PQIssuerKeycloak, c.PQIssuer)
		}
		if !strings.HasPrefix(c.PQKeyAlg, "ML-DSA-") {
			return fmt.Errorf("PQ_IDENTITY_KEY_ALG must be an ML-DSA parameter set, got %q", c.PQKeyAlg)
		}
		if c.Method == MethodDPoP && !strings.HasPrefix(c.PQDPoPAlg, "ML-DSA-") {
			return fmt.Errorf("PQ_DPOP_ALG must be an ML-DSA parameter set, got %q", c.PQDPoPAlg)
		}
	}
	return nil
}

func (c Config) renewBefore() time.Duration { return c.renewBeforeFor(c.CertLifetime) }

// renewBeforeFor is the renewal margin for a given certificate lifetime.
func (c Config) renewBeforeFor(lifetime time.Duration) time.Duration {
	if c.RenewBefore > 0 {
		return c.RenewBefore
	}
	return lifetime / 5
}

// pqCertLifetime is the lifetime requested for the post-quantum certificate; it
// defaults to the classical one so Method B rotates both on the same schedule.
func (c Config) pqCertLifetime() time.Duration {
	if c.PQCertLifetime > 0 {
		return c.PQCertLifetime
	}
	return c.CertLifetime
}

// upgradeURL is the shim endpoint that exchanges a classical token for a PQ one.
func (c Config) upgradeURL() string {
	return strings.TrimRight(c.PQShimURL, "/") + "/v1/upgrade"
}
