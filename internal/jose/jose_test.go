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
