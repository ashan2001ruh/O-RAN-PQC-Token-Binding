package pqtunnel

import (
	"context"
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// testPKI builds a self-signed ML-DSA root and issues leaves from it, which is the
// shape of the RIC intermediate CA the sidecars really use.
type testPKI struct {
	roots *x509.CertPool
	key   crypto.Signer
	cert  *x509.Certificate
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test RIC CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testPKI{roots: pool, key: key, cert: cert}
}

func (p *testPKI) leaf(t *testing.T, cn string) *tls.Certificate {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.cert, key.Public(), p.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func (p *testPKI) config(cred *tls.Certificate, peerName string) Config {
	return Config{
		Credential:       func() *tls.Certificate { return cred },
		Roots:            p.roots,
		PeerName:         peerName,
		HandshakeTimeout: 20 * time.Second,
	}
}

// handshake runs both halves over a socket pair and returns the two ends.
func handshake(t *testing.T, clientCfg, serverCfg Config) (*Conn, *Conn, error) {
	t.Helper()
	c, s := net.Pipe()
	type result struct {
		conn *Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := Server(context.Background(), s, serverCfg)
		ch <- result{conn, err}
	}()
	clientConn, clientErr := Client(context.Background(), c, clientCfg)
	res := <-ch
	if clientErr != nil {
		return nil, nil, clientErr
	}
	if res.err != nil {
		return nil, nil, res.err
	}
	return clientConn, res.conn, nil
}

func TestHandshakeAndRecords(t *testing.T) {
	pki := newTestPKI(t)
	client, server, err := handshake(t, pki.config(pki.leaf(t, "xapp-c"), "xapp-d"), pki.config(pki.leaf(t, "xapp-d"), ""))
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if got := server.Peer().CommonName(); got != "xapp-c" {
		t.Errorf("server sees peer %q, want xapp-c", got)
	}
	if got := client.Peer().CommonName(); got != "xapp-d" {
		t.Errorf("client sees peer %q, want xapp-d", got)
	}
	if got := client.Peer().Alg; got != "ML-DSA-65" {
		t.Errorf("peer algorithm %q, want ML-DSA-65", got)
	}
	if client.Peer().Thumbprint == "" || client.Peer().Thumbprint == server.Peer().Thumbprint {
		t.Error("each peer should expose the thumbprint of the other certificate")
	}

	// A payload larger than one record exercises the record splitting and the
	// sequence-numbered nonces in both directions.
	payload := strings.Repeat("o-ran", RecordSize/2)
	go func() {
		_, _ = io.WriteString(client, payload)
		_ = client.Close()
	}()
	got, err := io.ReadAll(server)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != payload {
		t.Errorf("payload round trip: got %d bytes, want %d", len(got), len(payload))
	}
}

func TestControlMessages(t *testing.T) {
	pki := newTestPKI(t)
	client, server, err := handshake(t, pki.config(pki.leaf(t, "xapp-c"), ""), pki.config(pki.leaf(t, "xapp-d"), ""))
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	go func() { _ = client.WriteMessage([]byte(`{"v":1}`)) }()
	msg, err := server.ReadMessage()
	if err != nil {
		t.Fatalf("read message: %v", err)
	}
	if string(msg) != `{"v":1}` {
		t.Errorf("control message round trip: %q", msg)
	}
}

func TestUntrustedPeerIsRejected(t *testing.T) {
	good, rogue := newTestPKI(t), newTestPKI(t)
	// The client presents a certificate from a CA the server does not trust.
	_, _, err := handshake(t, rogue.config(rogue.leaf(t, "xapp-c"), ""), good.config(good.leaf(t, "xapp-d"), ""))
	if err == nil {
		t.Fatal("a peer from an untrusted CA was accepted")
	}
}

func TestWrongPeerNameIsRejected(t *testing.T) {
	pki := newTestPKI(t)
	_, _, err := handshake(t, pki.config(pki.leaf(t, "xapp-c"), "xapp-e"), pki.config(pki.leaf(t, "xapp-d"), ""))
	if err == nil {
		t.Fatal("a peer with the wrong certificate subject was accepted")
	}
}

func TestTamperedRecordFailsAuthentication(t *testing.T) {
	pki := newTestPKI(t)
	// A raw pipe lets the test corrupt one byte of the ciphertext in flight.
	c, s := net.Pipe()
	type result struct {
		conn *Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := Server(context.Background(), s, pki.config(pki.leaf(t, "xapp-d"), ""))
		ch <- result{conn, err}
	}()
	client, err := Client(context.Background(), c, pki.config(pki.leaf(t, "xapp-c"), ""))
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	res := <-ch
	if res.err != nil {
		t.Fatalf("handshake: %v", res.err)
	}
	// Forge a record with a valid nonce but a corrupted body.
	forged := append(nonce(client.wIV, 0), []byte("not a valid ciphertext")...)
	go func() { _ = writeFrame(c, forged) }()
	buf := make([]byte, 64)
	if _, err := res.conn.Read(buf); err == nil {
		t.Fatal("a forged record was accepted")
	}
}

func TestCloseWritePropagatesEOF(t *testing.T) {
	pki := newTestPKI(t)
	client, server, err := handshake(t, pki.config(pki.leaf(t, "xapp-c"), ""), pki.config(pki.leaf(t, "xapp-d"), ""))
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	go func() {
		_, _ = io.WriteString(client, "RMR:one-shot")
		_ = client.CloseWrite()
	}()
	got, err := io.ReadAll(server)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "RMR:one-shot" {
		t.Errorf("payload %q", got)
	}
	// The reverse direction must still work after a half-close.
	go func() {
		_, _ = io.WriteString(server, "ack")
		_ = server.CloseWrite()
	}()
	back, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(back) != "ack" {
		t.Errorf("reverse payload %q", back)
	}
}
