package pqtunnel

import (
	"crypto"
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/pki"
)

// Peer is the authenticated identity of the other end of a tunnel: the certificate
// chain it presented and proved possession of during the handshake.
type Peer struct {
	Chain []*x509.Certificate // leaf first, as presented
	Leaf  *x509.Certificate
	Alg   string // leaf public key algorithm, e.g. ML-DSA-65
	// Thumbprint is the RFC 8705 x5t#S256 of the leaf certificate, which is what a
	// certificate-bound access token carries in cnf.x5t#S256.
	Thumbprint string
}

// CommonName is the leaf subject CN, which the RIC CA sets to the xApp client id.
func (p *Peer) CommonName() string {
	if p == nil || p.Leaf == nil {
		return ""
	}
	return p.Leaf.Subject.CommonName
}

// encodeChain serialises a certificate chain as count || (len || DER)*.
func encodeChain(chain [][]byte) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(len(chain)))
	for _, der := range chain {
		out = appendField(out, der)
	}
	return out
}

func decodeChain(b []byte) ([]*x509.Certificate, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("certificate chain is empty")
	}
	n := int(binary.BigEndian.Uint32(b[:4]))
	if n == 0 || n > 8 {
		return nil, fmt.Errorf("certificate chain declares %d certificates", n)
	}
	r := &reader{buf: b, pos: 4}
	chain := make([]*x509.Certificate, 0, n)
	for i := 0; i < n; i++ {
		der, err := r.field(fmt.Sprintf("certificate %d", i))
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: %w", i, err)
		}
		chain = append(chain, cert)
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return chain, nil
}

// authenticate verifies a presented chain against the trust anchors and, when
// peerName is set, against the expected subject. It returns the authenticated peer.
// The caller has already verified that the leaf key signed the handshake transcript.
func authenticate(chain []*x509.Certificate, roots *x509.CertPool, peerName string, now time.Time, eku x509.ExtKeyUsage) (*Peer, error) {
	if kind, err := pki.VerifyChain(chain, roots, now, eku); err != nil {
		return nil, fmt.Errorf("peer certificate rejected (%s): %w", kind, err)
	}
	leaf := chain[0]
	if _, ok := leaf.PublicKey.(*mldsa.PublicKey); !ok {
		return nil, fmt.Errorf("peer certificate key is %s; the tunnel requires an ML-DSA key", pki.KeyAlgName(leaf.PublicKey))
	}
	if peerName != "" && !matchesName(leaf, peerName) {
		return nil, fmt.Errorf("peer certificate CN=%q SAN=%v is not the expected peer %q", leaf.Subject.CommonName, leaf.DNSNames, peerName)
	}
	return &Peer{Chain: chain, Leaf: leaf, Alg: pki.KeyAlgName(leaf.PublicKey), Thumbprint: pki.ThumbprintS256(leaf)}, nil
}

func matchesName(leaf *x509.Certificate, want string) bool {
	if strings.EqualFold(leaf.Subject.CommonName, want) {
		return true
	}
	for _, dns := range leaf.DNSNames {
		if strings.EqualFold(dns, want) {
			return true
		}
	}
	return false
}

// signerFor returns the ML-DSA private key and DER chain of a credential.
func signerFor(cert *tls.Certificate) (crypto.Signer, [][]byte, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return nil, nil, fmt.Errorf("no identity certificate available yet")
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("identity private key does not implement crypto.Signer")
	}
	if _, ok := signer.Public().(*mldsa.PublicKey); !ok {
		return nil, nil, fmt.Errorf("identity key is %s; the tunnel requires an ML-DSA key", pki.KeyAlgName(signer.Public()))
	}
	return signer, cert.Certificate, nil
}

// sign produces an ML-DSA signature over the transcript with a domain-separating
// context string, so a client hello signature can never be replayed as a server one.
func sign(key crypto.Signer, context string, transcript []byte) ([]byte, error) {
	return key.Sign(nil, transcript, &mldsa.Options{Context: context})
}

func verify(pub crypto.PublicKey, context string, transcript, sig []byte) error {
	key, ok := pub.(*mldsa.PublicKey)
	if !ok {
		return fmt.Errorf("peer key is not ML-DSA")
	}
	return mldsa.Verify(key, transcript, sig, &mldsa.Options{Context: context})
}
