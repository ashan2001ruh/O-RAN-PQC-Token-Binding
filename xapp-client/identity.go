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
