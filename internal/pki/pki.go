// Package pki holds certificate helpers shared by the CA, the client library and
// the resource-side validator: PEM I/O, chain verification with classified failure
// reasons, and the RFC 8705 certificate thumbprint.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"
)

// ThumbprintS256 returns base64url(SHA-256(DER)) of a certificate: the value of
// the cnf "x5t#S256" member defined by RFC 8705 §3.1. It is independent of the
// certificate's signature algorithm.
func ThumbprintS256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ParseCertsPEM decodes every CERTIFICATE block in b.
func ParseCertsPEM(b []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("no CERTIFICATE blocks found")
	}
	return certs, nil
}

// EncodeCertsPEM encodes certificates as concatenated PEM blocks.
func EncodeCertsPEM(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

// LoadCertPool builds a pool from one or more PEM files.
func LoadCertPool(paths ...string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("no certificates in %s", p)
		}
	}
	return pool, nil
}

// LoadCertsFile reads all certificates from a PEM file.
func LoadCertsFile(path string) ([]*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseCertsPEM(b)
}

// ParsePrivateKeyPEM accepts PKCS#8, SEC1 (EC) and PKCS#1 (RSA) keys.
func ParsePrivateKeyPEM(b []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("no PEM block in private key")
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported private key PEM type %q", block.Type)
	}
	if err != nil {
		return nil, err
	}
	s, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key is not a signer")
	}
	return s, nil
}

// LoadPrivateKeyFile reads a PEM private key.
func LoadPrivateKeyFile(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKeyPEM(b)
}

// EncodePrivateKeyPEM encodes a key as PKCS#8.
func EncodePrivateKeyPEM(key crypto.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// GenerateKey creates a fresh identity key. The algorithm is a parameter, so the
// same enrollment, rotation and binding code produces classical or post-quantum
// identities: ML-DSA keys come from crypto/mldsa (FIPS 204) in the standard library.
func GenerateKey(alg string) (crypto.Signer, error) {
	switch alg {
	case "", "EC-P256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "EC-P384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "Ed25519":
		_, k, err := ed25519.GenerateKey(rand.Reader)
		return k, err
	case "RSA-2048":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "ML-DSA-44":
		return mldsa.GenerateKey(mldsa.MLDSA44())
	case "ML-DSA-65":
		return mldsa.GenerateKey(mldsa.MLDSA65())
	case "ML-DSA-87":
		return mldsa.GenerateKey(mldsa.MLDSA87())
	default:
		return nil, fmt.Errorf("unsupported key algorithm %q", alg)
	}
}

// IsPostQuantum reports whether a public key is a post-quantum (ML-DSA) key.
func IsPostQuantum(pub crypto.PublicKey) bool {
	_, ok := pub.(*mldsa.PublicKey)
	return ok
}

// KeyAlgName names a public key for logs and CLI output.
func KeyAlgName(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *mldsa.PublicKey:
		switch k.Parameters() {
		case mldsa.MLDSA44():
			return "ML-DSA-44"
		case mldsa.MLDSA65():
			return "ML-DSA-65"
		case mldsa.MLDSA87():
			return "ML-DSA-87"
		}
		return "ML-DSA"
	case *ecdsa.PublicKey:
		return "EC-" + k.Curve.Params().Name
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return fmt.Sprintf("%T", pub)
}

// DescribeCert summarises a certificate for CLI output.
func DescribeCert(c *x509.Certificate) string {
	return fmt.Sprintf("CN=%s key=%s sig=%s serial=%s expires=%s (%d bytes)",
		c.Subject.CommonName, KeyAlgName(c.PublicKey), c.SignatureAlgorithm,
		c.SerialNumber.Text(16), c.NotAfter.UTC().Format(time.RFC3339), len(c.Raw))
}

// Chain verification failure classes, used to produce precise rejection reasons.
const (
	ChainExpired     = "expired"
	ChainNotYetValid = "not_yet_valid"
	ChainUntrusted   = "untrusted"
	ChainBadUsage    = "bad_usage"
	ChainInvalid     = "invalid"
)

// VerifyChain verifies chain[0] against roots using chain[1:] as intermediates at
// time now for the given extended key usage. On failure it returns a class and error.
func VerifyChain(chain []*x509.Certificate, roots *x509.CertPool, now time.Time, usage x509.ExtKeyUsage) (string, error) {
	if len(chain) == 0 {
		return ChainInvalid, errors.New("empty certificate chain")
	}
	leaf := chain[0]
	if now.After(leaf.NotAfter) {
		return ChainExpired, fmt.Errorf("certificate CN=%q serial=%s expired at %s (now %s)",
			leaf.Subject.CommonName, leaf.SerialNumber.Text(16),
			leaf.NotAfter.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	if now.Before(leaf.NotBefore) {
		return ChainNotYetValid, fmt.Errorf("certificate CN=%q not valid before %s",
			leaf.Subject.CommonName, leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{usage},
	})
	if err == nil {
		return "", nil
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		switch invalid.Reason {
		case x509.Expired:
			return ChainExpired, err
		case x509.IncompatibleUsage:
			return ChainBadUsage, err
		}
		return ChainInvalid, err
	}
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return ChainUntrusted, fmt.Errorf("certificate CN=%q is not issued by a trusted CA: %w", leaf.Subject.CommonName, err)
	}
	return ChainInvalid, err
}
