package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

// Signer produces compact JWS objects (DPoP proofs, shim-issued tokens). The whole
// JWS is produced by jwx; this project never assembles signing input or signature
// bytes itself.
type Signer interface {
	// Alg is the JWS "alg" value, e.g. ES256 or ML-DSA-65.
	Alg() string
	// PublicJWK is the public key as a JWK object (AKP for ML-DSA).
	PublicJWK() JWK
	// Key exposes the underlying private jwx key.
	Key() jwk.Key
	// PublicKey is the public jwx key, used as the DPoP "jwk" protected header.
	PublicKey() jwk.Key
	// SignCompact signs claims with the given protected headers.
	SignCompact(header map[string]any, claims any) (string, error)
}

type jwxSigner struct {
	alg    jwa.SignatureAlgorithm
	key    jwk.Key
	pubKey jwk.Key
	pub    JWK
}

// GenerateSigner creates a fresh key pair for alg and returns a Signer.
// Supported: ES256/384/512 (classical) and ML-DSA-44/65/87 (FIPS 204, RFC 9964).
func GenerateSigner(alg string) (Signer, error) {
	var raw any
	var err error
	switch alg {
	case "ES256":
		raw, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ES384":
		raw, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ES512":
		raw, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "ML-DSA-44":
		raw, err = mldsa.GenerateKey(mldsa.MLDSA44())
	case "ML-DSA-65":
		raw, err = mldsa.GenerateKey(mldsa.MLDSA65())
	case "ML-DSA-87":
		raw, err = mldsa.GenerateKey(mldsa.MLDSA87())
	default:
		return nil, fmt.Errorf("unsupported signing alg %q", alg)
	}
	if err != nil {
		return nil, err
	}
	return SignerFromKey(alg, raw)
}

// SignerFromKey wraps an existing private key.
func SignerFromKey(alg string, raw any) (Signer, error) {
	sa, err := LookupAlg(alg)
	if err != nil {
		return nil, err
	}
	key, err := asKey(raw)
	if err != nil {
		return nil, err
	}
	pubKey, err := key.PublicKey()
	if err != nil {
		return nil, err
	}
	pub, err := JWKFromKey(key)
	if err != nil {
		return nil, err
	}
	return &jwxSigner{alg: sa, key: key, pubKey: pubKey, pub: pub}, nil
}

func (s *jwxSigner) Alg() string    { return s.alg.String() }
func (s *jwxSigner) PublicJWK() JWK { return s.pub }
func (s *jwxSigner) Key() jwk.Key   { return s.key }

// PublicKey returns the public key as a jwx key.
func (s *jwxSigner) PublicKey() jwk.Key { return s.pubKey }

func (s *jwxSigner) SignCompact(header map[string]any, claims any) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	hdrs := jws.NewHeaders()
	for k, v := range header {
		if err := hdrs.Set(k, v); err != nil {
			return "", fmt.Errorf("protected header %q: %w", k, err)
		}
	}
	signed, err := jws.Sign(payload, jws.WithKey(s.alg, s.key, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}
