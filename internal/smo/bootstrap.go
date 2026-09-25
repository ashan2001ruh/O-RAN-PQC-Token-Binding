// Package smo simulates the SMO onboarding step: issuing a one-time bootstrap
// certificate for an xApp. In a real deployment this happens outside the RIC.
package smo

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/pki"
)

// Onboarding holds the SMO onboarding CA. KeyAlg selects the key type of the
// bootstrap credentials it issues: an ML-DSA onboarding CA must issue ML-DSA
// bootstrap keys, so that onboarding itself is post-quantum.
type Onboarding struct {
	cert   *x509.Certificate
	key    any
	org    string
	KeyAlg string
}

// LoadOnboarding reads the onboarding CA certificate and key.
func LoadOnboarding(certPath, keyPath, org string) (*Onboarding, error) {
	certs, err := pki.LoadCertsFile(certPath)
	if err != nil {
		return nil, err
	}
	key, err := pki.LoadPrivateKeyFile(keyPath)
	if err != nil {
		return nil, err
	}
	return &Onboarding{cert: certs[0], key: key, org: org, KeyAlg: "EC-P256"}, nil
}

// IssueBootstrap creates a fresh key and a bootstrap certificate for identity. The
// DNS names listed here are the only names the RIC CA will later put in the xApp's
// operational certificate.
func (o *Onboarding) IssueBootstrap(identity string, dnsNames []string, validity time.Duration) (*tls.Certificate, error) {
	alg := o.KeyAlg
	if alg == "" {
		alg = "EC-P256"
	}
	key, err := pki.GenerateKey(alg)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: identity, OrganizationalUnit: []string{"bootstrap"}, Organization: []string{o.org}},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, o.cert, key.Public(), o.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der, o.cert.Raw}, PrivateKey: key, Leaf: leaf}, nil
}

// WriteCredential stores a certificate chain and key as tls.crt / tls.key in dir.
func WriteCredential(dir string, c *tls.Certificate) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var chain []*x509.Certificate
	for _, der := range c.Certificate {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		chain = append(chain, cert)
	}
	keyPEM, err := pki.EncodePrivateKeyPEM(c.PrivateKey)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), pki.EncodeCertsPEM(chain...), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), keyPEM, 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	return nil
}
