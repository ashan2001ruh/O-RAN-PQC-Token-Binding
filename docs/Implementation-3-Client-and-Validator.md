# Implementation Part 3: Client Library, Resource Validator and the Demo xApps

This is the substantive part. Keycloak issues bound tokens, but **nothing checks the binding
unless the resource server does it**, and no authorization server can do that for you.

Two libraries:

* `xapp-client` obtains and renews certificates, requests tokens, verifies on receipt that the
  token really carries the expected binding, and attaches the token (and, for Method C, a fresh
  DPoP proof) to outgoing requests. One interface serves all three methods; the method is
  configuration, not code.
* `xapp-resource` is the enforcement point: one middleware that validates the token and then
  the binding, and rejects with a specific reason code. Everything fails closed.

## Files in this part

| File | Lines | Purpose |
|---|---|---|
| `internal/jose/jose.go` | 132 | Algorithm lookup with the refusal policy, the JWK type used for DPoP proof headers, thumbprints. |
| `internal/jose/jws.go` | 91 | Compact JWS parsing for inspection, and verification dispatched on the `alg` header. |
| `internal/jose/signer.go` | 110 | Signers for ES256/384/512 and ML-DSA-44/65/87. `SignCompact` produces the whole JWS; this project never assembles signing input or signature bytes itself. |
| `internal/jose/jwks.go` | 104 | The JWKS cache. Keys are never embedded: an unknown `kid` triggers a rate-limited refetch, which also covers key rotation and a change of signature algorithm. |
| `internal/jose/jose_test.go` | 133 | The RFC 7638 test vector, a sign/verify/thumbprint/forgery round trip for every supported algorithm, and the AKP (ML-DSA) key checks. |
| `xapp-client/config.go` | 202 | Configuration and validation, including the post-quantum settings used in Part 4. |
| `xapp-client/identity.go` | 178 | The credential holder read by TLS configurations on every handshake, so a rotation takes effect on the next connection; and the CA enrollment client. |
| `xapp-client/issuer.go` | 94 | The single token issuance path. A post-quantum re-signing shim is inserted by wrapping this interface, without touching any call site. |
| `xapp-client/client.go` | 533 | The `Client` interface, the shared base, enrollment, renewal, rotation and the maintenance loop. |
| `xapp-client/certbound.go` | 136 | Methods A and B: request the token, then check that `cnf.x5t#S256` equals the thumbprint of the certificate actually held. |
| `xapp-client/dpop.go` | 253 | Method C: DPoP proof construction (`htm`, `htu`, `jti`, `iat`, `ath`), nonce handling, and the same binding check against `cnf.jkt`. |
| `xapp-resource/config.go` | 68 | Validator configuration. |
| `xapp-resource/reasons.go` | 99 | Every rejection reason code and the response body. These strings are what the test suite asserts on and what the paper quotes. |
| `xapp-resource/replay.go` | 56 | The DPoP replay cache: bounded, swept, and fail-closed when full. |
| `xapp-resource/introspect.go` | 52 | RFC 7662 introspection, authenticated with the resource xApp own mTLS identity. |
| `xapp-resource/validator.go` | 445 | The middleware and every check. |
| `xapp-resource/validator_test.go` | 177 | Offline end-to-end tests with an in-memory CA, a JWKS server and a TLS resource server: wrong certificate, no certificate, missing `cnf`, foreign proof key, replay, `ath` mismatch, wrong `htm`, DPoP token used as bearer. |
| `demo-xapp/cmd/xapp/main.go` | 160 | Wires the client library and the validator together: enroll, serve the protected API under both validation modes, maintain the certificate, call the peer. |
| `demo-xapp/k8s/xapps.yaml` | 160 | The two Deployments and Services. `strategy: Recreate` matters: the bootstrap credential is single use, so an old and a new pod must never overlap. |

---

## 1. The JOSE layer

A thin adapter over `github.com/lestrrat-go/jwx/v4`. The library performs all JOSE work: signing, verification, JWK parsing and RFC 7638 thumbprints. What this package adds is policy, not cryptography: `none` and symmetric algorithms are never accepted, and a JWK carrying private members is never usable as a verification key.

Because jwx on Go 1.27 implements ML-DSA natively, the same code paths serve classical and post-quantum algorithms, which is what makes Part 4 a configuration change rather than a rewrite.

### `internal/jose/jose.go`

Algorithm lookup with the refusal policy, the JWK type used for DPoP proof headers, thumbprints.

```go
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
```

### `internal/jose/jws.go`

Compact JWS parsing for inspection, and verification dispatched on the `alg` header.

```go
package jose

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v4/jws"
)

// JWS is a compact JWS whose header and payload have been decoded for inspection
// but whose signature has NOT been checked yet. Verification is done by jwx in
// VerifySignature, which re-verifies the original compact serialisation.
type JWS struct {
	Compact string
	Header  map[string]any
	Payload []byte
}

// ParseCompact splits and decodes a compact JWS. It performs no verification.
func ParseCompact(token string) (*JWS, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("compact JWS must have 3 parts, got %d", len(parts))
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("header is not base64url: %w", err)
	}
	header, err := decodeObject(hb)
	if err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload is not base64url: %w", err)
	}
	if _, err := b64.DecodeString(parts[2]); err != nil {
		return nil, fmt.Errorf("signature is not base64url: %w", err)
	}
	return &JWS{Compact: token, Header: header, Payload: payload}, nil
}

func decodeObject(b []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("not a JSON object")
	}
	return m, nil
}

func (j *JWS) headerString(name string) string {
	s, _ := j.Header[name].(string)
	return s
}

// Alg returns the "alg" header.
func (j *JWS) Alg() string { return j.headerString("alg") }

// Kid returns the "kid" header.
func (j *JWS) Kid() string { return j.headerString("kid") }

// Typ returns the "typ" header.
func (j *JWS) Typ() string { return j.headerString("typ") }

// Claims decodes the payload as a JSON object (numbers kept as json.Number).
func (j *JWS) Claims() (map[string]any, error) { return decodeObject(j.Payload) }

// VerifySignature verifies the signature with key, dispatching on the "alg"
// header through jwx. The same call handles ES256 and ML-DSA-65 alike.
func (j *JWS) VerifySignature(key any) error {
	alg, err := LookupAlg(j.Alg())
	if err != nil {
		return err
	}
	k, err := asKey(key)
	if err != nil {
		return fmt.Errorf("verification key unusable: %w", err)
	}
	if _, err := jws.Verify([]byte(j.Compact), jws.WithKey(alg, k)); err != nil {
		return err
	}
	return nil
}
```

### `internal/jose/signer.go`

Signers for ES256/384/512 and ML-DSA-44/65/87. `SignCompact` produces the whole JWS; this project never assembles signing input or signature bytes itself.

```go
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
```

### `internal/jose/jwks.go`

The JWKS cache. Keys are never embedded: an unknown `kid` triggers a rate-limited refetch, which also covers key rotation and a change of signature algorithm.

```go
package jose

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

// KeySet caches the verification keys published at a JWKS URL. Keys are never
// embedded: an unknown kid triggers a rate-limited refetch, which also covers
// issuer key rotation and a change of signature algorithm (ES256 to ML-DSA).
// Parsing is done by jwx, so AKP (ML-DSA) keys need no special handling.
type KeySet struct {
	url        string
	client     *http.Client
	ttl        time.Duration
	minRefresh time.Duration

	mu          sync.RWMutex
	set         jwk.Set
	fetched     time.Time
	lastAttempt time.Time
}

// NewKeySet creates a cache for url.
func NewKeySet(url string, client *http.Client, ttl, minRefresh time.Duration) *KeySet {
	return &KeySet{url: url, client: client, ttl: ttl, minRefresh: minRefresh}
}

// Key returns the verification key for kid, checking it is a signing key usable with alg.
func (s *KeySet) Key(ctx context.Context, kid, alg string) (any, error) {
	if kid == "" {
		return nil, fmt.Errorf("JWS header has no kid")
	}
	key, ok := s.lookup(kid)
	if !ok || s.stale() {
		if err := s.refresh(ctx); err != nil && !ok {
			return nil, err
		}
		if key, ok = s.lookup(kid); !ok {
			return nil, fmt.Errorf("kid %q not found in JWKS %s", kid, s.url)
		}
	}
	if use, ok := key.KeyUsage(); ok && use != "" && use != "sig" {
		return nil, fmt.Errorf("kid %q has use %q, not sig", kid, use)
	}
	if ka, ok := key.Algorithm(); ok && ka != nil && ka.String() != "" && ka.String() != alg {
		return nil, fmt.Errorf("kid %q is bound to alg %q but token uses %q", kid, ka.String(), alg)
	}
	return key, nil
}

func (s *KeySet) lookup(kid string) (jwk.Key, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.set == nil {
		return nil, false
	}
	return s.set.LookupKeyID(kid)
}

func (s *KeySet) stale() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.fetched) > s.ttl
}

func (s *KeySet) refresh(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.lastAttempt.IsZero() && time.Since(s.lastAttempt) < s.minRefresh && time.Since(s.fetched) <= s.ttl {
		return nil
	}
	s.lastAttempt = time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	// ML-DSA public keys are kilobytes, not bytes: keep the limit generous.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch JWKS: HTTP %d", resp.StatusCode)
	}
	set, err := jwk.Parse(body)
	if err != nil {
		return fmt.Errorf("parse JWKS: %w", err)
	}
	s.set = set
	s.fetched = time.Now()
	return nil
}
```

### `internal/jose/jose_test.go`

The RFC 7638 test vector, a sign/verify/thumbprint/forgery round trip for every supported algorithm, and the AKP (ML-DSA) key checks.

```go
package jose

import (
	"strings"
	"testing"
)

// RFC 7638 section 3.1 example key and thumbprint, computed through the library.
func TestThumbprintRFC7638(t *testing.T) {
	k := JWK{
		"kty": "RSA",
		"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e":   "AQAB",
		"alg": "RS256",
		"kid": "2011-04-29",
	}
	got, err := k.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	if want := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"; got != want {
		t.Fatalf("thumbprint %s, want %s", got, want)
	}
}

// Every supported algorithm, classical and post-quantum, goes through the same code.
func TestSignVerifyAllAlgorithms(t *testing.T) {
	for _, alg := range []string{"ES256", "ES384", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} {
		t.Run(alg, func(t *testing.T) {
			signer, err := GenerateSigner(alg)
			if err != nil {
				t.Fatal(err)
			}
			if signer.Alg() != alg {
				t.Fatalf("signer alg %q, want %q", signer.Alg(), alg)
			}
			compact, err := signer.SignCompact(map[string]any{"typ": "dpop+jwt", "jwk": signer.PublicKey()}, map[string]any{"htm": "GET"})
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseCompact(compact)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Alg() != alg || parsed.Typ() != "dpop+jwt" {
				t.Fatalf("header alg=%q typ=%q", parsed.Alg(), parsed.Typ())
			}
			// The proof key travels in the header, exactly as a DPoP proof carries it.
			rawJWK, ok := parsed.Header["jwk"].(map[string]any)
			if !ok {
				t.Fatalf("jwk header missing: %#v", parsed.Header)
			}
			pub, err := JWK(rawJWK).PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			if err := parsed.VerifySignature(pub); err != nil {
				t.Fatalf("valid signature rejected: %v", err)
			}
			// Thumbprint of the header key must equal the signer's (cnf.jkt check).
			hdrThumb, err := JWK(rawJWK).Thumbprint()
			if err != nil {
				t.Fatal(err)
			}
			ownThumb, err := signer.PublicJWK().Thumbprint()
			if err != nil {
				t.Fatal(err)
			}
			if hdrThumb != ownThumb {
				t.Fatalf("thumbprint mismatch: header %s, signer %s", hdrThumb, ownThumb)
			}
			// A signature made by another key of the same algorithm must not verify.
			other, err := GenerateSigner(alg)
			if err != nil {
				t.Fatal(err)
			}
			forged, err := other.SignCompact(map[string]any{"typ": "dpop+jwt"}, map[string]any{"htm": "GET"})
			if err != nil {
				t.Fatal(err)
			}
			swapped, err := ParseCompact(strings.Join([]string{
				strings.Split(compact, ".")[0], strings.Split(compact, ".")[1], strings.Split(forged, ".")[2]}, "."))
			if err != nil {
				t.Fatal(err)
			}
			if err := swapped.VerifySignature(pub); err == nil {
				t.Fatal("signature from another key was accepted")
			}
		})
	}
}

// ML-DSA keys must serialise as RFC 9964 AKP keys.
func TestMLDSAKeyIsAKP(t *testing.T) {
	signer, err := GenerateSigner("ML-DSA-65")
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.PublicJWK()
	if pub.Str("kty") != "AKP" {
		t.Fatalf("kty %q, want AKP", pub.Str("kty"))
	}
	if pub.Str("alg") != "ML-DSA-65" {
		t.Fatalf("alg %q, want ML-DSA-65", pub.Str("alg"))
	}
	if pub.Str("pub") == "" {
		t.Fatal("AKP key has no pub member")
	}
	if _, has := pub["priv"]; has {
		t.Fatal("public AKP key leaked the priv member")
	}
	if _, err := pub.Thumbprint(); err != nil {
		t.Fatalf("AKP thumbprint: %v", err)
	}
}

func TestRejectsNoneSymmetricAndPrivateJWK(t *testing.T) {
	if _, err := LookupAlg("none"); err == nil {
		t.Fatal(`alg "none" accepted`)
	}
	if _, err := LookupAlg("HS256"); err == nil {
		t.Fatal("symmetric alg accepted")
	}
	signer, _ := GenerateSigner("ML-DSA-44")
	k := JWK{}
	for m, v := range signer.PublicJWK() {
		k[m] = v
	}
	k["priv"] = "AAAA"
	if _, err := k.PublicKey(); err == nil {
		t.Fatal("JWK carrying private material accepted as a verification key")
	}
}
```

---

## 2. The client library

Methods A and B are **one implementation** (`certbound.go`) parameterised by certificate lifetime and a key-rotation flag. Method C (`dpop.go`) adds proof generation. The client always verifies the binding of a token it receives, so a missing `cnf` is an error rather than a silent downgrade.

Rotation is driven by **certificate** expiry, not token expiry: when the certificate enters its renewal window the client obtains a new key and certificate first, drops the cached token (which is bound to the retired certificate) and closes pooled connections that would still present it.

### `xapp-client/config.go`

Configuration and validation, including the post-quantum settings used in Part 4.

```go
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
	PQShimURL        string // base URL of the pq-shim (token upgrade + JWKS)
	PQKeyAlg         string // ML-DSA parameter set for the identity certificate
	PQDPoPAlg        string // ML-DSA parameter set for DPoP proofs (method C)
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
		if c.PQShimURL == "" {
			return fmt.Errorf("PQ_SHIM_URL is required when PQ_MODE is set")
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
```

### `xapp-client/identity.go`

The credential holder read by TLS configurations on every handshake, so a rotation takes effect on the next connection; and the CA enrollment client.

```go
package xappclient

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/netx"
	"github.com/oran-ricsec/xapp-token-binding/internal/pki"
)

// Identity holds the xApp's current RIC-CA certificate. TLS configurations read it on
// every handshake (GetClientCertificate / GetCertificate), so a rotation takes effect
// on the next connection without rebuilding clients or servers.
type Identity struct {
	mu   sync.RWMutex
	cert *tls.Certificate
}

// Current returns the active credential or nil.
func (i *Identity) Current() *tls.Certificate {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.cert
}

// Leaf returns the active certificate or nil.
func (i *Identity) Leaf() *x509.Certificate {
	if c := i.Current(); c != nil {
		return c.Leaf
	}
	return nil
}

func (i *Identity) set(c *tls.Certificate) {
	i.mu.Lock()
	i.cert = c
	i.mu.Unlock()
}

// RotationStats describes one certificate enrollment/renewal, for measurement.
type RotationStats struct {
	KeyGen    time.Duration
	RoundTrip time.Duration // CSR build + HTTPS round trip to the RIC CA + response parsing
	Total     time.Duration
	Serial    string
	NotAfter  time.Time
	KeyAlg    string // EC-P256, ML-DSA-65, ...
	CertBytes int    // DER size of the issued certificate
	Plane     string // classical or post-quantum
}

// Enroller calls the RIC CA enrollment service.
type Enroller struct {
	BaseURL   string
	Roots     *x509.CertPool
	Overrides map[string]string
	Timeout   time.Duration
	// PQKexOnly requires the ML-KEM hybrid group for the CA connection.
	PQKexOnly bool
}

// Enroll sends a CSR for key, authenticated by auth. renew selects /v1/renew
// (operational credential) instead of /v1/enroll (bootstrap credential).
func (e *Enroller) Enroll(ctx context.Context, auth *tls.Certificate, key crypto.Signer, dnsNames []string, lifetime time.Duration, renew bool) (*tls.Certificate, error) {
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: auth.Leaf.Subject.CommonName},
		DNSNames: dnsNames,
	}, key)
	if err != nil {
		return nil, fmt.Errorf("build CSR: %w", err)
	}
	path := "/v1/enroll"
	if renew {
		path = "/v1/renew"
	}
	u := e.BaseURL + path + "?lifetime=" + url.QueryEscape(lifetime.String())

	// A dedicated, non-pooled transport: the authenticating certificate differs per call.
	tr := netx.NewTransport(&tls.Config{
		MinVersion:       tls.VersionTLS13,
		RootCAs:          e.Roots,
		Certificates:     []tls.Certificate{*auth},
		CurvePreferences: netx.CurvePreferences(e.PQKexOnly),
	}, e.Overrides)
	tr.DisableKeepAlives = true
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: e.Timeout}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u,
		bytes.NewReader(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/pkcs10")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("RIC CA %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RIC CA %s: HTTP %d: %s", path, resp.StatusCode, bytes.TrimSpace(body))
	}
	certs, err := pki.ParseCertsPEM(body)
	if err != nil {
		return nil, fmt.Errorf("RIC CA response: %w", err)
	}
	leafKey, ok := certs[0].PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !leafKey.Equal(key.Public()) {
		return nil, errors.New("RIC CA returned a certificate for a different key")
	}
	out := &tls.Certificate{PrivateKey: key, Leaf: certs[0]}
	for _, c := range certs {
		out.Certificate = append(out.Certificate, c.Raw)
	}
	return out, nil
}

func loadCredential(certPath, keyPath string) (*tls.Certificate, error) {
	c, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	if c.Leaf == nil {
		if c.Leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
			return nil, err
		}
	}
	return &c, nil
}

func persistCredential(dir string, c *tls.Certificate) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var chain []byte
	for _, der := range c.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyPEM, err := pki.EncodePrivateKeyPEM(c.PrivateKey)
	if err != nil {
		return err
	}
	// write key first, then certificate, each via rename for atomicity
	if err := writeAtomic(filepath.Join(dir, "tls.key"), keyPEM, 0o600); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, "tls.crt"), chain, 0o644)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
```

### `xapp-client/issuer.go`

The single token issuance path. A post-quantum re-signing shim is inserted by wrapping this interface, without touching any call site.

```go
package xappclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TokenRequest carries everything needed for one issuance call.
type TokenRequest struct {
	TokenURL   string
	ClientID   string
	Scope      string
	DPoPProof  string       // set for method C
	HTTPClient *http.Client // mTLS client presenting the xApp identity
}

// TokenResponse is the authorization server's answer.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	ReceivedAt  time.Time
}

// Issuer is the single token-issuance path used by every method. A later phase can
// insert a re-signing shim (e.g. ML-DSA) by wrapping it with Client.SetIssuer,
// without touching any call site.
type Issuer interface {
	Issue(ctx context.Context, req TokenRequest) (*TokenResponse, error)
}

// IssuerError is a non-200 token endpoint response.
type IssuerError struct {
	Status    int
	Body      string
	DPoPNonce string
}

func (e *IssuerError) Error() string {
	return fmt.Sprintf("token endpoint HTTP %d: %s", e.Status, e.Body)
}

// NeedsNonce reports whether the server demanded a DPoP nonce (RFC 9449 §8).
func (e *IssuerError) NeedsNonce() bool {
	return e.DPoPNonce != "" && strings.Contains(e.Body, "use_dpop_nonce")
}

// KeycloakIssuer performs the OAuth 2.0 client_credentials grant against Keycloak.
type KeycloakIssuer struct{}

// Issue implements Issuer.
func (KeycloakIssuer) Issue(ctx context.Context, r TokenRequest) (*TokenResponse, error) {
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {r.ClientID}}
	if r.Scope != "" {
		form.Set("scope", r.Scope)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if r.DPoPProof != "" {
		req.Header.Set("DPoP", r.DPoPProof)
	}
	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token endpoint: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &IssuerError{Status: resp.StatusCode, Body: strings.TrimSpace(string(body)), DPoPNonce: resp.Header.Get("DPoP-Nonce")}
	}
	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("token response: %w", err)
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("token response has no access_token")
	}
	tr.ReceivedAt = time.Now()
	return &tr, nil
}
```

### `xapp-client/client.go`

The `Client` interface, the shared base, enrollment, renewal, rotation and the maintenance loop.

```go
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
```

### `xapp-client/certbound.go`

Methods A and B: request the token, then check that `cnf.x5t#S256` equals the thumbprint of the certificate actually held.

```go
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
	leaf := c.id.Leaf()
	if leaf == nil {
		return nil, fmt.Errorf("client not started: no identity certificate")
	}
	resp, err := c.getIssuer().Issue(ctx, TokenRequest{
		TokenURL: c.cfg.TokenURL, ClientID: c.cfg.ClientID, Scope: c.cfg.Scope, HTTPClient: c.client,
	})
	if err != nil {
		return nil, err
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

	if c.cfg.PQEnabled {
		tok, err = c.upgradeCertBound(ctx, tok)
		if err != nil {
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
```

### `xapp-client/dpop.go`

Method C: DPoP proof construction (`htm`, `htu`, `jti`, `iat`, `ath`), nonce handling, and the same binding check against `cnf.jkt`.

```go
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
	var resp *TokenResponse
	for attempt := 0; ; attempt++ {
		proof, err := c.Proof(http.MethodPost, c.cfg.TokenURL, "")
		if err != nil {
			return nil, err
		}
		resp, err = c.getIssuer().Issue(ctx, TokenRequest{
			TokenURL: c.cfg.TokenURL, ClientID: c.cfg.ClientID, Scope: c.cfg.Scope, DPoPProof: proof, HTTPClient: c.client,
		})
		var ie *IssuerError
		if err != nil && attempt == 0 && errors.As(err, &ie) && ie.NeedsNonce() {
			c.setNonce(c.cfg.TokenURL, ie.DPoPNonce)
			continue
		}
		if err != nil {
			return nil, err
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
	if jkt != c.jkt {
		return nil, fmt.Errorf("%w: cnf.jkt=%s, proof key=%s", ErrBindingMismatch, jkt, c.jkt)
	}
	if !strings.EqualFold(resp.TokenType, "DPoP") {
		return nil, fmt.Errorf("%w: token_type is %q, expected DPoP", ErrBindingMismatch, resp.TokenType)
	}
	tok.Binding, tok.Thumbprint = "jkt", jkt
	c.log.Debug("token_issued", "binding", tok.Binding, "cnf", jkt, "alg", tok.Alg,
		"expires_at", tok.ExpiresAt.UTC().Format(time.RFC3339), "bytes", len(tok.Value))

	if c.cfg.PQEnabled {
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
```

---

## 3. The resource-side validator

`Validator.Middleware(mode, next)` is the single enforcement point. `mode` is `local` (verify the JWS with a key from the JWKS) or `introspection` (RFC 7662 call to the issuer). The binding checks are identical in both modes.

Order of checks:

1. token validity: signature, `exp`, `nbf`, `iss`, `aud`;
2. authorization: `scope` and realm role;
3. the sender constraint:
   * `cnf.x5t#S256` -> the TLS peer certificate must chain to the RIC CA and its SHA-256
     thumbprint must match, compared in constant time;
   * `cnf.jkt` -> a DPoP proof whose signature verifies under the key in its own `jwk` header,
     whose thumbprint equals `cnf.jkt`, whose `ath` is the hash of the presented token, whose
     `htm`/`htu` match the request, whose `iat` is inside the window and whose `jti` is unused.

A missing, malformed or unrecognised `cnf` is a rejection, never a pass-through.

### `xapp-resource/config.go`

Validator configuration.

```go
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
```

### `xapp-resource/reasons.go`

Every rejection reason code and the response body. These strings are what the test suite asserts on and what the paper quotes.

```go
package xappresource

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Rejection reason codes. Each rejection carries one code plus a human-readable detail.
const (
	ReasonAuthorizationMissing   = "authorization_missing"
	ReasonAuthorizationMalformed = "authorization_malformed"
	ReasonSchemeUnsupported      = "authorization_scheme_unsupported"

	ReasonTokenMalformed        = "token_malformed"
	ReasonTokenKeyUnavailable   = "token_key_unavailable"
	ReasonTokenSignatureInvalid = "token_signature_invalid"
	ReasonTokenExpired          = "token_expired"
	ReasonTokenNotYetValid      = "token_not_yet_valid"
	ReasonTokenIssuerMismatch   = "token_issuer_mismatch"
	ReasonTokenAudienceMismatch = "token_audience_mismatch"
	ReasonTokenInactive         = "token_inactive"
	ReasonIntrospectionFailed   = "introspection_failed"
	ReasonInsufficientScope     = "insufficient_scope"

	ReasonCnfMissing      = "cnf_missing"
	ReasonCnfMalformed    = "cnf_malformed"
	ReasonCnfUnrecognized = "cnf_unrecognized"

	ReasonClientCertMissing    = "client_certificate_missing"
	ReasonClientCertExpired    = "client_certificate_expired"
	ReasonClientCertInvalid    = "client_certificate_invalid"
	ReasonX5tMismatch          = "cnf_x5t_mismatch"
	ReasonCertBoundWrongScheme = "cert_bound_token_wrong_scheme"

	ReasonDPoPAsBearer        = "dpop_token_used_as_bearer"
	ReasonDPoPProofMissing    = "dpop_proof_missing"
	ReasonDPoPProofMultiple   = "dpop_proof_multiple"
	ReasonDPoPProofMalformed  = "dpop_proof_malformed"
	ReasonDPoPProofType       = "dpop_proof_wrong_typ"
	ReasonDPoPProofAlg        = "dpop_proof_alg_not_allowed"
	ReasonDPoPProofJWK        = "dpop_proof_jwk_invalid"
	ReasonDPoPProofSignature  = "dpop_proof_signature_invalid"
	ReasonDPoPJktMismatch     = "dpop_jkt_mismatch"
	ReasonDPoPAthMissing      = "dpop_ath_missing"
	ReasonDPoPAthMismatch     = "dpop_ath_mismatch"
	ReasonDPoPHtmMismatch     = "dpop_htm_mismatch"
	ReasonDPoPHtuMismatch     = "dpop_htu_mismatch"
	ReasonDPoPIatOutOfWindow  = "dpop_iat_out_of_window"
	ReasonDPoPJtiMissing      = "dpop_jti_missing"
	ReasonDPoPReplayed        = "dpop_proof_replayed"
	ReasonDPoPReplayCacheFull = "dpop_replay_cache_full"
)

// Rejection is a fail-closed authorization decision.
type Rejection struct {
	Status int
	Code   string
	Detail string
	DPoP   bool // challenge with the DPoP scheme
}

func (r *Rejection) Error() string { return r.Code + ": " + r.Detail }

func reject(code, format string, args ...any) *Rejection {
	status := http.StatusUnauthorized
	if code == ReasonInsufficientScope {
		status = http.StatusForbidden
	}
	return &Rejection{Status: status, Code: code, Detail: fmt.Sprintf(format, args...), DPoP: strings.HasPrefix(code, "dpop_")}
}

// RejectionBody is the JSON body returned with every rejection.
type RejectionBody struct {
	Error      string `json:"error"`
	ReasonCode string `json:"reason_code"`
	Reason     string `json:"reason"`
}

func writeRejection(w http.ResponseWriter, r *Rejection) {
	errCode := "invalid_token"
	switch {
	case r.Code == ReasonInsufficientScope:
		errCode = "insufficient_scope"
	case strings.HasPrefix(r.Code, "dpop_proof") || r.Code == ReasonDPoPJktMismatch || strings.HasPrefix(r.Code, "dpop_ath") ||
		r.Code == ReasonDPoPHtmMismatch || r.Code == ReasonDPoPHtuMismatch || r.Code == ReasonDPoPIatOutOfWindow || r.Code == ReasonDPoPJtiMissing:
		errCode = "invalid_dpop_proof"
	}
	scheme := "Bearer"
	if r.DPoP {
		scheme = "DPoP"
	}
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`%s error=%q, error_description=%q`, scheme, errCode, r.Code))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(r.Status)
	_ = json.NewEncoder(w).Encode(RejectionBody{Error: errCode, ReasonCode: r.Code, Reason: r.Detail})
}
```

### `xapp-resource/replay.go`

The DPoP replay cache: bounded, swept, and fail-closed when full.

```go
package xappresource

import (
	"sync"
	"time"
)

// ReplayCache remembers DPoP proof identifiers until their acceptance window has
// passed. When full it refuses new entries (fail closed) after sweeping expired ones.
type ReplayCache struct {
	mu        sync.Mutex
	entries   map[string]time.Time
	max       int
	lastSweep time.Time
}

// NewReplayCache creates a cache holding at most max identifiers.
func NewReplayCache(max int) *ReplayCache {
	return &ReplayCache{entries: make(map[string]time.Time), max: max}
}

// Result of CheckAndStore.
const (
	ReplayFresh = iota
	ReplaySeen
	ReplayFull
)

// CheckAndStore records key until expiry unless it is already present and unexpired.
func (c *ReplayCache) CheckAndStore(key string, expiry, now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if exp, ok := c.entries[key]; ok && now.Before(exp) {
		return ReplaySeen
	}
	if len(c.entries) >= c.max || now.Sub(c.lastSweep) > 10*time.Second {
		for k, exp := range c.entries {
			if !now.Before(exp) {
				delete(c.entries, k)
			}
		}
		c.lastSweep = now
		if len(c.entries) >= c.max {
			return ReplayFull
		}
	}
	c.entries[key] = expiry
	return ReplayFresh
}

// Len returns the number of stored identifiers.
func (c *ReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
```

### `xapp-resource/introspect.go`

RFC 7662 introspection, authenticated with the resource xApp own mTLS identity.

```go
package xappresource

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Introspector calls the RFC 7662 introspection endpoint, authenticating as the
// resource xApp's own client over its mTLS identity.
type Introspector struct {
	URL      string
	ClientID string
	Client   *http.Client
}

// Introspect returns the claims of an active token, or a rejection.
func (i *Introspector) Introspect(ctx context.Context, token string) (map[string]any, *Rejection) {
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}, "client_id": {i.ClientID}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, i.URL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, reject(ReasonIntrospectionFailed, "build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := i.Client.Do(req)
	if err != nil {
		return nil, reject(ReasonIntrospectionFailed, "introspection endpoint unreachable: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, reject(ReasonIntrospectionFailed, "read response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, reject(ReasonIntrospectionFailed, "introspection endpoint returned HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var claims map[string]any
	if err := dec.Decode(&claims); err != nil || claims == nil {
		return nil, reject(ReasonIntrospectionFailed, "introspection response is not a JSON object")
	}
	if active, _ := claims["active"].(bool); !active {
		return nil, reject(ReasonTokenInactive, "authorization server reports the token as inactive (expired, revoked, or not issued by it)")
	}
	return claims, nil
}
```

### `xapp-resource/validator.go`

The middleware and every check.

```go
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
```

### `xapp-resource/validator_test.go`

Offline end-to-end tests with an in-memory CA, a JWKS server and a TLS resource server: wrong certificate, no certificate, missing `cnf`, foreign proof key, replay, `ath` mismatch, wrong `htm`, DPoP token used as bearer.

```go
package xappresource

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/jose"
	"github.com/oran-ricsec/xapp-token-binding/internal/pki"
	xappclient "github.com/oran-ricsec/xapp-token-binding/xapp-client"
)

// Offline end-to-end check of the validator: in-memory CA, JWKS server, token signer
// and a TLS resource server requesting client certificates.

type fixture struct {
	t        *testing.T
	ca       *x509.Certificate
	caKey    *ecdsa.PrivateKey
	issuer   jose.Signer
	kid      string
	resource *httptest.Server
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, kid: "test-kid"}
	f.caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test RIC CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &f.caKey.PublicKey, f.caKey)
	f.ca, _ = x509.ParseCertificate(der)
	dir := t.TempDir()
	trust := filepath.Join(dir, "ca.crt")
	_ = os.WriteFile(trust, pki.EncodeCertsPEM(f.ca), 0o644)

	f.issuer, _ = jose.GenerateSigner("ES256")
	jwk := jose.JWK{}
	for k, v := range f.issuer.PublicJWK() {
		jwk[k] = v
	}
	jwk["kid"], jwk["use"], jwk["alg"] = f.kid, "sig", "ES256"
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk}})
	}))
	t.Cleanup(jwks.Close)

	v, err := NewValidator(Config{
		Issuer: "https://issuer.test/realms/ric", Audience: "ric-xapps", JWKSURL: jwks.URL,
		RequiredScope: "ric-sdl-access", TrustBundle: []string{trust}, ClockSkew: 5 * time.Second,
		DPoPProofWindow: 60 * time.Second, ReplayCacheSize: 1000, JWKSCacheTTL: time.Minute, JWKSMinRefresh: time.Second,
	}, jwks.Client(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	f.resource = httptest.NewUnstartedServer(v.Middleware(ModeLocal, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})))
	f.resource.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS13}
	f.resource.StartTLS()
	t.Cleanup(f.resource.Close)
	return f
}

func (f *fixture) leaf(cn string, lifetime time.Duration) *tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(lifetime),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, f.ca, &key.PublicKey, f.caKey)
	leaf, _ := x509.ParseCertificate(der)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func (f *fixture) token(cnf map[string]any) string {
	claims := map[string]any{"iss": "https://issuer.test/realms/ric", "aud": "ric-xapps", "scope": "ric-sdl-access",
		"exp": time.Now().Add(5 * time.Minute).Unix(), "azp": "xapp-test"}
	if cnf != nil {
		claims["cnf"] = cnf
	}
	tok, err := f.issuer.SignCompact(map[string]any{"kid": f.kid, "typ": "JWT"}, claims)
	if err != nil {
		f.t.Fatal(err)
	}
	return tok
}

func (f *fixture) do(cert *tls.Certificate, headers map[string]string) (int, string) {
	pool := x509.NewCertPool()
	pool.AddCert(f.resource.Certificate())
	conf := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	if cert != nil {
		conf.Certificates = []tls.Certificate{*cert}
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: conf, DisableKeepAlives: true}}
	req, _ := http.NewRequest(http.MethodGet, f.resource.URL+"/api/v1/sdl/k", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var body RejectionBody
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body.ReasonCode
}

func expect(t *testing.T, name string, status int, code string, wantStatus int, wantCode string) {
	t.Helper()
	if status != wantStatus || code != wantCode {
		t.Errorf("%s: got %d %q, want %d %q", name, status, code, wantStatus, wantCode)
	}
}

func TestCertificateBinding(t *testing.T) {
	f := newFixture(t)
	a, b := f.leaf("xapp-a", time.Hour), f.leaf("xapp-b", time.Hour)
	tok := f.token(map[string]any{"x5t#S256": pki.ThumbprintS256(a.Leaf)})
	auth := map[string]string{"Authorization": "Bearer " + tok}

	s, c := f.do(a, auth)
	expect(t, "own certificate", s, c, 200, "")
	s, c = f.do(b, auth)
	expect(t, "other certificate", s, c, 401, ReasonX5tMismatch)
	s, c = f.do(nil, auth)
	expect(t, "no certificate", s, c, 401, ReasonClientCertMissing)
	s, c = f.do(a, map[string]string{"Authorization": "Bearer " + f.token(nil)})
	expect(t, "no cnf", s, c, 401, ReasonCnfMissing)
	s, c = f.do(a, map[string]string{"Authorization": "Bearer " + f.token(map[string]any{"x5t#S256": 42})})
	expect(t, "malformed cnf", s, c, 401, ReasonCnfMalformed)
	s, c = f.do(a, map[string]string{"Authorization": "Bearer " + f.token(map[string]any{"foo": "bar"})})
	expect(t, "unrecognised cnf", s, c, 401, ReasonCnfUnrecognized)
}

func TestDPoPBinding(t *testing.T) {
	f := newFixture(t)
	key, _ := jose.GenerateSigner("ES256")
	jkt, _ := key.PublicJWK().Thumbprint()
	tok := f.token(map[string]any{"jkt": jkt})
	url := f.resource.URL + "/api/v1/sdl/k"

	proof, _ := xappclient.BuildDPoPProof(key, http.MethodGet, url, tok, "", time.Now())
	s, c := f.do(nil, map[string]string{"Authorization": "DPoP " + tok, "DPoP": proof})
	expect(t, "valid proof", s, c, 200, "")
	s, c = f.do(nil, map[string]string{"Authorization": "DPoP " + tok, "DPoP": proof})
	expect(t, "replayed proof", s, c, 401, ReasonDPoPReplayed)

	other, _ := jose.GenerateSigner("ES256")
	p2, _ := xappclient.BuildDPoPProof(other, http.MethodGet, url, tok, "", time.Now())
	s, c = f.do(nil, map[string]string{"Authorization": "DPoP " + tok, "DPoP": p2})
	expect(t, "foreign key", s, c, 401, ReasonDPoPJktMismatch)

	p3, _ := xappclient.BuildDPoPProof(key, http.MethodGet, url, f.token(map[string]any{"jkt": jkt}), "", time.Now())
	s, c = f.do(nil, map[string]string{"Authorization": "DPoP " + tok, "DPoP": p3})
	expect(t, "ath of other token", s, c, 401, ReasonDPoPAthMismatch)

	p4, _ := xappclient.BuildDPoPProof(key, http.MethodPost, url, tok, "", time.Now())
	s, c = f.do(nil, map[string]string{"Authorization": "DPoP " + tok, "DPoP": p4})
	expect(t, "wrong htm", s, c, 401, ReasonDPoPHtmMismatch)

	s, c = f.do(nil, map[string]string{"Authorization": "Bearer " + tok})
	expect(t, "used as bearer", s, c, 401, ReasonDPoPAsBearer)
}
```

---

## 4. The demo xApps

Each demo xApp is both a client and a resource server, and calls its peer every 30 seconds, so traffic flows in both directions. `xapp-a` runs Method A with a 168 hour certificate; `xapp-b` runs Method B with a 15 minute certificate that rotates.

### `demo-xapp/cmd/xapp/main.go`

Wires the client library and the validator together: enroll, serve the protected API under both validation modes, maintain the certificate, call the peer.

```go
// Command xapp is a demo xApp that is both an OAuth client and a protected resource:
// it exposes an SDL-style API guarded by the xappresource validator and periodically
// calls its peer xApp with a sender-constrained token, so traffic flows both ways.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/config"
	"github.com/oran-ricsec/xapp-token-binding/internal/logx"
	xappclient "github.com/oran-ricsec/xapp-token-binding/xapp-client"
	xappresource "github.com/oran-ricsec/xapp-token-binding/xapp-resource"
)

func main() {
	log := logx.New("xapp")
	e := &config.Env{}
	name := e.Req("XAPP_NAME")
	listen := e.Str("LISTEN_ADDR", ":8443")
	peerURL := e.Str("PEER_URL", "")
	peerInterval := e.Dur("PEER_INTERVAL", 30*time.Second)
	healthAddr := e.Str("HEALTH_ADDR", ":8081")
	if err := e.Err(); err != nil {
		log.Error("invalid configuration", "error", err)
		os.Exit(2)
	}
	ccfg, err := xappclient.ConfigFromEnv()
	if err != nil {
		log.Error("invalid client configuration", "error", err)
		os.Exit(2)
	}
	rcfg, err := xappresource.ConfigFromEnv()
	if err != nil {
		log.Error("invalid resource configuration", "error", err)
		os.Exit(2)
	}
	log = log.With("xapp", name)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	client, err := xappclient.New(ccfg, log)
	if err != nil {
		log.Error("client", "error", err)
		os.Exit(1)
	}
	for attempt := 1; ; attempt++ {
		if err = client.Start(ctx); err == nil {
			break
		}
		log.Warn("enrollment_retry", "attempt", attempt, "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(min(time.Duration(attempt)*2*time.Second, 30*time.Second)):
		}
	}
	go client.Maintain(ctx)

	validator, err := xappresource.NewValidator(rcfg, client.HTTPClient(), log)
	if err != nil {
		log.Error("validator", "error", err)
		os.Exit(1)
	}

	sdl := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := xappresource.PrincipalFrom(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"xapp":      name,
			"key":       strings.TrimPrefix(r.URL.Path[strings.LastIndex(r.URL.Path, "/"):], "/"),
			"value":     "demo-sdl-value",
			"caller":    p.ClientID,
			"binding":   p.Binding,
			"cnf":       p.Thumbprint,
			"validated": p.Mode,
		})
	})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	mux.Handle("/api/v1/sdl/", validator.Middleware(xappresource.ModeLocal, sdl))
	mux.Handle("/api/v1/introspect/sdl/", validator.Middleware(xappresource.ModeIntrospection, sdl))

	srv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		TLSConfig:         client.ServerTLSConfig(),
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          nil,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	// Plain-HTTP health endpoint for Kubernetes probes: the kubelet cannot complete a
	// handshake on a TLS port pinned to the ML-KEM hybrid group.
	if healthAddr != "" {
		healthMux := http.NewServeMux()
		healthMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
		healthSrv := &http.Server{Addr: healthAddr, Handler: healthMux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := healthSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("health listener", "error", err)
			}
		}()
	}
	if peerURL != "" {
		go peerLoop(ctx, client, peerURL, peerInterval, log)
	}
	log.Info("listening", "addr", listen, "method", string(ccfg.Method), "client_id", ccfg.ClientID,
		"cert_lifetime", ccfg.CertLifetime.String(), "peer", peerURL)
	if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server", "error", err)
		os.Exit(1)
	}
}

// peerLoop calls the peer xApp's protected API with a sender-constrained token.
func peerLoop(ctx context.Context, c xappclient.Client, url string, every time.Duration, log interface {
	Info(string, ...any)
	Warn(string, ...any)
}) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			log.Warn("peer_call_failed", "error", err)
			continue
		}
		start := time.Now()
		resp, err := c.Do(req)
		if err != nil {
			log.Warn("peer_call_failed", "url", url, "error", err)
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		leaf := c.Identity().Leaf()
		log.Info("peer_call", "url", url, "status", resp.StatusCode, "elapsed_ms", time.Since(start).Milliseconds(),
			"my_cert_serial", leaf.SerialNumber.Text(16), "my_cert_not_after", leaf.NotAfter.UTC().Format(time.RFC3339),
			"response", strings.TrimSpace(string(body)))
	}
}
```

### `demo-xapp/k8s/xapps.yaml`

The two Deployments and Services. `strategy: Recreate` matters: the bootstrap credential is single use, so an old and a new pod must never overlap.

```yaml
# Two demo xApps in ricxapp, rendered from config/testbed.env.
#   ${XAPP_A_NAME}: Method ${XAPP_A_METHOD} (client ${XAPP_A_CLIENT_ID}, certificate lifetime ${LONGTERM_CERT_LIFETIME})
#   ${XAPP_B_NAME}: Method ${XAPP_B_METHOD} (client ${XAPP_B_CLIENT_ID}, certificate lifetime ${EPHEMERAL_CERT_LIFETIME})
# Each calls the other's protected API every ${PEER_INTERVAL}.
apiVersion: v1
kind: ConfigMap
metadata:
  name: xapp-token-binding
  namespace: ${XAPP_NAMESPACE}
  labels: {part-of: xapp-token-binding}
data:
  KEYCLOAK_TOKEN_URL: "${TOKEN_ISSUER}/protocol/openid-connect/token"
  # The validator trusts whichever issuer is active for this deployment: Keycloak in
  # classical mode, the pq-shim in post-quantum mode (see RESOURCE_* in the Makefile).
  INTROSPECTION_URL: "${RESOURCE_INTROSPECTION_URL}"
  JWKS_URL: "${RESOURCE_JWKS_URL}"
  TOKEN_ISSUER: "${RESOURCE_TOKEN_ISSUER}"
  TOKEN_AUDIENCE: "${TOKEN_AUDIENCE}"
  TOKEN_SCOPE: "${TOKEN_SCOPE}"
  REQUIRED_SCOPE: "${TOKEN_SCOPE}"
  REQUIRED_ROLE: "${REQUIRED_ROLE}"
  RIC_CA_URL: "${RIC_CA_URL}"
  RIC_TRUST_BUNDLE: "/etc/ric-trust/ric-intermediate-ca.crt,/etc/ric-trust/ric-intermediate-ca-pq.crt"
  BOOTSTRAP_CERT: /etc/xapp/bootstrap/tls.crt
  BOOTSTRAP_KEY: /etc/xapp/bootstrap/tls.key
  IDENTITY_DIR: /var/run/xapp/identity
  PQ_MODE: "${PQ_MODE}"
  PQ_SHIM_URL: "${PQ_SHIM_URL}"
  PQ_IDENTITY_KEY_ALG: "${PQ_IDENTITY_KEY_ALG}"
  PQ_DPOP_ALG: "${PQ_DPOP_ALG}"
  PQ_KEX_ONLY: "${PQ_KEX_ONLY}"
  PQ_BOOTSTRAP_CERT: /etc/xapp/bootstrap-pq/tls.crt
  PQ_BOOTSTRAP_KEY: /etc/xapp/bootstrap-pq/tls.key
  PQ_IDENTITY_DIR: /var/run/xapp/identity-pq
  LISTEN_ADDR: ":${XAPP_PORT}"
  PEER_INTERVAL: "${PEER_INTERVAL}"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${XAPP_A_NAME}
  namespace: ${XAPP_NAMESPACE}
  labels: {app: ${XAPP_A_NAME}, part-of: xapp-token-binding}
spec:
  replicas: 1
  strategy: {type: Recreate}   # one-time bootstrap credential: old and new pods must never overlap
  selector:
    matchLabels: {app: ${XAPP_A_NAME}}
  template:
    metadata:
      labels: {app: ${XAPP_A_NAME}, part-of: xapp-token-binding}
    spec:
      securityContext: {runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532, fsGroup: 65532, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: xapp
          image: ricsec/xapp:${IMAGE_TAG}
          imagePullPolicy: Never
          envFrom: [{configMapRef: {name: xapp-token-binding}}]
          env:
            - {name: XAPP_NAME, value: "${XAPP_A_NAME}"}
            - {name: XAPP_METHOD, value: "${XAPP_A_METHOD}"}
            - {name: XAPP_CLIENT_ID, value: "${XAPP_A_CLIENT_ID}"}
            - {name: CERT_LIFETIME, value: "${LONGTERM_CERT_LIFETIME}"}
            - {name: SERVER_DNS_NAMES, value: "${XAPP_A_NAME}.${XAPP_NAMESPACE}.svc.${CLUSTER_DOMAIN},${XAPP_A_NAME}.${XAPP_NAMESPACE}.svc"}
            - {name: PEER_URL, value: "https://${XAPP_B_NAME}.${XAPP_NAMESPACE}.svc.${CLUSTER_DOMAIN}:${XAPP_PORT}/api/v1/sdl/demo-key"}
          ports:
            - {name: https, containerPort: ${XAPP_PORT}}
            - {name: health, containerPort: 8081}
          readinessProbe:
            httpGet: {path: /healthz, port: health, scheme: HTTP}
            periodSeconds: 10
            timeoutSeconds: 5
          volumeMounts:
            - {name: bootstrap, mountPath: /etc/xapp/bootstrap, readOnly: true}
            - {name: bootstrap-pq, mountPath: /etc/xapp/bootstrap-pq, readOnly: true}
            - {name: trust, mountPath: /etc/ric-trust, readOnly: true}
            - {name: identity, mountPath: /var/run/xapp/identity}
            - {name: identity-pq, mountPath: /var/run/xapp/identity-pq}
          resources:
            requests: {cpu: 20m, memory: 24Mi}
            limits: {memory: 96Mi}
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
      volumes:
        - {name: bootstrap, secret: {secretName: "${XAPP_A_NAME}-bootstrap", defaultMode: 0440}}
        - {name: bootstrap-pq, secret: {secretName: "${XAPP_A_NAME}-bootstrap-pq", defaultMode: 0440}}
        - {name: trust, configMap: {name: ric-trust}}
        - {name: identity, emptyDir: {medium: Memory}}
        - {name: identity-pq, emptyDir: {medium: Memory}}
---
apiVersion: v1
kind: Service
metadata:
  name: ${XAPP_A_NAME}
  namespace: ${XAPP_NAMESPACE}
  labels: {app: ${XAPP_A_NAME}, part-of: xapp-token-binding}
spec:
  selector: {app: ${XAPP_A_NAME}}
  ports: [{name: https, port: ${XAPP_PORT}, targetPort: https}]
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${XAPP_B_NAME}
  namespace: ${XAPP_NAMESPACE}
  labels: {app: ${XAPP_B_NAME}, part-of: xapp-token-binding}
spec:
  replicas: 1
  strategy: {type: Recreate}   # one-time bootstrap credential: old and new pods must never overlap
  selector:
    matchLabels: {app: ${XAPP_B_NAME}}
  template:
    metadata:
      labels: {app: ${XAPP_B_NAME}, part-of: xapp-token-binding}
    spec:
      securityContext: {runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532, fsGroup: 65532, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: xapp
          image: ricsec/xapp:${IMAGE_TAG}
          imagePullPolicy: Never
          envFrom: [{configMapRef: {name: xapp-token-binding}}]
          env:
            - {name: XAPP_NAME, value: "${XAPP_B_NAME}"}
            - {name: XAPP_METHOD, value: "${XAPP_B_METHOD}"}
            - {name: XAPP_CLIENT_ID, value: "${XAPP_B_CLIENT_ID}"}
            - {name: CERT_LIFETIME, value: "${EPHEMERAL_CERT_LIFETIME}"}
            - {name: SERVER_DNS_NAMES, value: "${XAPP_B_NAME}.${XAPP_NAMESPACE}.svc.${CLUSTER_DOMAIN},${XAPP_B_NAME}.${XAPP_NAMESPACE}.svc"}
            - {name: PEER_URL, value: "https://${XAPP_A_NAME}.${XAPP_NAMESPACE}.svc.${CLUSTER_DOMAIN}:${XAPP_PORT}/api/v1/sdl/demo-key"}
          ports:
            - {name: https, containerPort: ${XAPP_PORT}}
            - {name: health, containerPort: 8081}
          readinessProbe:
            httpGet: {path: /healthz, port: health, scheme: HTTP}
            periodSeconds: 10
            timeoutSeconds: 5
          volumeMounts:
            - {name: bootstrap, mountPath: /etc/xapp/bootstrap, readOnly: true}
            - {name: bootstrap-pq, mountPath: /etc/xapp/bootstrap-pq, readOnly: true}
            - {name: trust, mountPath: /etc/ric-trust, readOnly: true}
            - {name: identity, mountPath: /var/run/xapp/identity}
            - {name: identity-pq, mountPath: /var/run/xapp/identity-pq}
          resources:
            requests: {cpu: 20m, memory: 24Mi}
            limits: {memory: 96Mi}
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
      volumes:
        - {name: bootstrap, secret: {secretName: "${XAPP_B_NAME}-bootstrap", defaultMode: 0440}}
        - {name: bootstrap-pq, secret: {secretName: "${XAPP_B_NAME}-bootstrap-pq", defaultMode: 0440}}
        - {name: trust, configMap: {name: ric-trust}}
        - {name: identity, emptyDir: {medium: Memory}}
        - {name: identity-pq, emptyDir: {medium: Memory}}
---
apiVersion: v1
kind: Service
metadata:
  name: ${XAPP_B_NAME}
  namespace: ${XAPP_NAMESPACE}
  labels: {app: ${XAPP_B_NAME}, part-of: xapp-token-binding}
spec:
  selector: {app: ${XAPP_B_NAME}}
  ports: [{name: https, port: ${XAPP_PORT}, targetPort: https}]
```

Deploy and watch the peer calls:

```bash
make bootstrap-xapps deploy-xapps
make logs
```

```
"msg":"peer_call","xapp":"xapp-a","status":200,
"response":"{\"binding\":\"x5t#S256\",\"caller\":\"xapp-longterm\", ...}"
```

