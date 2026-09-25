// Package jose is a thin adapter over github.com/lestrrat-go/jwx/v4.
//
// The library performs all JOSE work: JWS signing and verification, JWK parsing
// and serialisation, and RFC 7638 thumbprints. Because jwx v4 on Go 1.27
// implements ML-DSA natively (RFC 9964: alg ML-DSA-44/65/87, kty "AKP" with the
// thumbprint taken over alg, kty and pub), classical and post-quantum algorithms
// are handled by exactly the same code paths here and in the validator.
//
// What this package adds on top of the library is policy, not cryptography:
//   - "none" and symmetric (HS*) algorithms are never accepted,
//   - a JWK carrying private members is never usable as a verification key.
package jose

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

var b64 = base64.RawURLEncoding

// B64 encodes bytes as unpadded base64url.
func B64(b []byte) string { return b64.EncodeToString(b) }

// ErrAlgNotAllowed is returned for "none" and symmetric algorithms.
var ErrAlgNotAllowed = errors.New("algorithm not allowed")

// LookupAlg maps a JWS "alg" header to a jwx signature algorithm, refusing
// algorithms that must never be used to verify a sender-constrained token.
func LookupAlg(alg string) (jwa.SignatureAlgorithm, error) {
	if alg == "" {
		return jwa.SignatureAlgorithm{}, errors.New("JWS header has no alg")
	}
	if strings.EqualFold(alg, "none") || strings.HasPrefix(strings.ToUpper(alg), "HS") {
		return jwa.SignatureAlgorithm{}, fmt.Errorf("%w: %s", ErrAlgNotAllowed, alg)
	}
	sa, ok := jwa.LookupSignatureAlgorithm(alg)
	if !ok {
		return jwa.SignatureAlgorithm{}, fmt.Errorf("unsupported JWS alg %q", alg)
	}
	return sa, nil
}

// asKey accepts a jwk.Key, or any raw key the library can import.
func asKey(key any) (jwk.Key, error) {
	if k, ok := key.(jwk.Key); ok {
		return k, nil
	}
	return jwk.Import[jwk.Key](key)
}

// JWK is a JSON Web Key kept as a generic object, which is how DPoP proofs carry
// the proof key in their header. Conversion and thumbprinting are delegated to jwx.
type JWK map[string]any

// Str returns a string member or "".
func (k JWK) Str(name string) string {
	s, _ := k[name].(string)
	return s
}

// privateMembers must never appear in a key received from a peer. "priv" is the
// ML-DSA (AKP) private member from RFC 9964; the others are the classical ones.
var privateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "k", "priv"}

func (k JWK) parse() (jwk.Key, error) {
	raw, err := json.Marshal(map[string]any(k))
	if err != nil {
		return nil, err
	}
	return jwk.ParseKey(raw)
}

// PublicKey converts the JWK into a verification key. Keys carrying private
// material are refused outright.
func (k JWK) PublicKey() (crypto.PublicKey, error) {
	for _, m := range privateMembers {
		if _, has := k[m]; has {
			return nil, fmt.Errorf("jwk contains private member %q", m)
		}
	}
	key, err := k.parse()
	if err != nil {
		return nil, err
	}
	pub, err := key.PublicKey()
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// Thumbprint computes the RFC 7638 SHA-256 JWK thumbprint (base64url), the value
// carried in cnf.jkt. For AKP keys jwx applies the RFC 9964 member set (alg, kty, pub).
func (k JWK) Thumbprint() (string, error) {
	key, err := k.parse()
	if err != nil {
		return "", err
	}
	tp, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return B64(tp), nil
}

// JWKFromKey renders any key (raw or jwk.Key) as a public JWK object.
func JWKFromKey(key any) (JWK, error) {
	k, err := asKey(key)
	if err != nil {
		return nil, err
	}
	pub, err := k.PublicKey()
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(pub)
	if err != nil {
		return nil, err
	}
	var out JWK
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}
