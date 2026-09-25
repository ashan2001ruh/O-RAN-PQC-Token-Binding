// Package pqtunnel implements the post-quantum secure channel that carries xApp
// traffic between sidecars.
//
// It is the handshake used by the ORAN-PQC tunnel work, re-implemented on the Go
// standard library so the sidecar stays a static binary with no cgo and no liboqs:
//
//	key establishment   ML-KEM-768        (FIPS 203, crypto/mlkem)
//	peer authentication ML-DSA-65         (FIPS 204, crypto/mldsa) over the transcript
//	record protection   AES-256-GCM       (crypto/aes, crypto/cipher)
//	key derivation      HKDF-SHA-256      (RFC 5869, crypto/hkdf)
//
// It is not TLS: there is no cipher-suite negotiation, no session resumption and no
// classical fallback. Both peers authenticate with an ML-DSA certificate issued by
// the RIC intermediate CA, and the resulting Peer is what the token binding is
// checked against: the certificate that proved possession here is the certificate
// the access token must be bound to.
package pqtunnel

import (
	"context"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

// Wire constants.
const (
	magic   = "PQTB1"
	version = byte(1)
	// suiteMLKEM768MLDSAAESGCM identifies the fixed algorithm set; there is no negotiation.
	suiteMLKEM768MLDSAAESGCM = byte(1)

	contextClientHello = "PQTB1 client hello"
	contextServerHello = "PQTB1 server hello"
	infoClientToServer = "PQTB1 c2s"
	infoServerToClient = "PQTB1 s2c"
)

// Config is the tunnel configuration shared by both ends.
type Config struct {
	// Credential returns the current ML-DSA identity. It is called on every
	// handshake so a rotated certificate (method B) is picked up immediately.
	Credential func() *tls.Certificate
	// Roots are the trust anchors for the peer certificate (the RIC CA).
	Roots *x509.CertPool
	// PeerName, when set, is the CN or DNS SAN the peer certificate must carry.
	PeerName string
	// HandshakeTimeout bounds the whole handshake.
	HandshakeTimeout time.Duration
	// Now is the clock used for certificate validity; nil means time.Now.
	Now func() time.Time
}

func (c Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c Config) timeout() time.Duration {
	if c.HandshakeTimeout > 0 {
		return c.HandshakeTimeout
	}
	return 10 * time.Second
}

// Stats records what one handshake cost, for the measurement harness.
type Stats struct {
	Total     time.Duration
	KeyGen    time.Duration // ML-KEM key generation (client) or encapsulation (server)
	Sign      time.Duration
	Verify    time.Duration
	BytesSent int
	BytesRecv int
}

// Client performs the initiating half of the handshake over raw and returns the
// protected connection.
func Client(ctx context.Context, raw net.Conn, cfg Config) (*Conn, error) {
	start := time.Now()
	var st Stats
	if err := setDeadline(ctx, raw, cfg.timeout()); err != nil {
		return nil, err
	}
	key, chain, err := signerFor(cfg.Credential())
	if err != nil {
		return nil, err
	}

	t0 := time.Now()
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("ML-KEM-768 key generation: %w", err)
	}
	st.KeyGen = time.Since(t0)

	body := []byte(magic)
	body = append(body, version, suiteMLKEM768MLDSAAESGCM)
	body = appendField(body, encodeChain(chain))
	body = appendField(body, dk.EncapsulationKey().Bytes())

	t0 = time.Now()
	sig, err := sign(key, contextClientHello, body)
	if err != nil {
		return nil, fmt.Errorf("client hello signature: %w", err)
	}
	st.Sign = time.Since(t0)

	clientHello := appendField(body, sig)
	if err := writeFrame(raw, clientHello); err != nil {
		return nil, fmt.Errorf("write client hello: %w", err)
	}
	st.BytesSent = len(clientHello) + 4

	serverHello, err := readFrame(raw)
	if err != nil {
		return nil, fmt.Errorf("read server hello: %w", err)
	}
	st.BytesRecv = len(serverHello) + 4

	serverChain, ciphertext, serverSig, err := parseHello(serverHello, contextServerHello)
	if err != nil {
		return nil, err
	}
	// The server signature covers the client hello followed by everything in the
	// server hello up to the signature field, which binds the two messages together.
	signed := concat(clientHello, serverHello[:len(serverHello)-len(serverSig)-4])

	peer, err := authenticate(serverChain, cfg.Roots, cfg.PeerName, cfg.now(), x509.ExtKeyUsageServerAuth)
	if err != nil {
		return nil, err
	}
	t0 = time.Now()
	if err := verify(peer.Leaf.PublicKey, contextServerHello, signed, serverSig); err != nil {
		return nil, fmt.Errorf("server hello signature: %w", err)
	}
	st.Verify = time.Since(t0)

	shared, err := dk.Decapsulate(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM-768 decapsulation: %w", err)
	}
	st.Total = time.Since(start)
	return newConn(raw, shared, transcript(clientHello, serverHello), peer, true, st)
}

// Server performs the responding half of the handshake.
func Server(ctx context.Context, raw net.Conn, cfg Config) (*Conn, error) {
	start := time.Now()
	var st Stats
	if err := setDeadline(ctx, raw, cfg.timeout()); err != nil {
		return nil, err
	}
	key, chain, err := signerFor(cfg.Credential())
	if err != nil {
		return nil, err
	}

	clientHello, err := readFrame(raw)
	if err != nil {
		return nil, fmt.Errorf("read client hello: %w", err)
	}
	st.BytesRecv = len(clientHello) + 4

	clientChain, ekBytes, clientSig, err := parseHello(clientHello, contextClientHello)
	if err != nil {
		return nil, err
	}
	peer, err := authenticate(clientChain, cfg.Roots, cfg.PeerName, cfg.now(), x509.ExtKeyUsageClientAuth)
	if err != nil {
		return nil, err
	}
	t0 := time.Now()
	if err := verify(peer.Leaf.PublicKey, contextClientHello, clientHello[:len(clientHello)-len(clientSig)-4], clientSig); err != nil {
		return nil, fmt.Errorf("client hello signature: %w", err)
	}
	st.Verify = time.Since(t0)

	ek, err := mlkem.NewEncapsulationKey768(ekBytes)
	if err != nil {
		return nil, fmt.Errorf("client ML-KEM-768 encapsulation key: %w", err)
	}
	t0 = time.Now()
	shared, ciphertext := ek.Encapsulate()
	st.KeyGen = time.Since(t0)

	body := []byte(magic)
	body = append(body, version, suiteMLKEM768MLDSAAESGCM)
	body = appendField(body, encodeChain(chain))
	body = appendField(body, ciphertext)

	t0 = time.Now()
	sig, err := sign(key, contextServerHello, concat(clientHello, body))
	if err != nil {
		return nil, fmt.Errorf("server hello signature: %w", err)
	}
	st.Sign = time.Since(t0)

	serverHello := appendField(body, sig)
	if err := writeFrame(raw, serverHello); err != nil {
		return nil, fmt.Errorf("write server hello: %w", err)
	}
	st.BytesSent = len(serverHello) + 4
	st.Total = time.Since(start)
	return newConn(raw, shared, transcript(clientHello, serverHello), peer, false, st)
}

// parseHello splits a hello message into chain, key material and signature. The
// signature covers everything that precedes it, which is what the caller re-derives.
func parseHello(msg []byte, what string) (chain []*x509.Certificate, keyMaterial, sig []byte, err error) {
	if len(msg) < len(magic)+2 || string(msg[:len(magic)]) != magic {
		return nil, nil, nil, fmt.Errorf("%s: bad magic", what)
	}
	if msg[len(magic)] != version {
		return nil, nil, nil, fmt.Errorf("%s: protocol version %d is not supported", what, msg[len(magic)])
	}
	if msg[len(magic)+1] != suiteMLKEM768MLDSAAESGCM {
		return nil, nil, nil, fmt.Errorf("%s: algorithm suite %d is not supported", what, msg[len(magic)+1])
	}
	r := &reader{buf: msg, pos: len(magic) + 2}
	rawChain, err := r.field("certificate chain")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%s: %w", what, err)
	}
	keyMaterial, err = r.field("key material")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%s: %w", what, err)
	}
	sig, err = r.field("signature")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%s: %w", what, err)
	}
	if err := r.done(); err != nil {
		return nil, nil, nil, fmt.Errorf("%s: %w", what, err)
	}
	chain, err = decodeChain(rawChain)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%s: %w", what, err)
	}
	return chain, keyMaterial, sig, nil
}

// transcript is the handshake hash; it salts the key derivation so the record keys
// are bound to both certificates, the encapsulation key and both signatures.
func transcript(clientHello, serverHello []byte) []byte {
	h := sha256.New()
	h.Write(clientHello)
	h.Write(serverHello)
	return h.Sum(nil)
}

// deriveKeys splits the ML-KEM shared secret into one AES-256-GCM key per direction.
func deriveKeys(shared, transcript []byte) (c2s, s2c []byte, err error) {
	if c2s, err = hkdf.Key(sha256.New, shared, transcript, infoClientToServer, 32); err != nil {
		return nil, nil, err
	}
	if s2c, err = hkdf.Key(sha256.New, shared, transcript, infoServerToClient, 32); err != nil {
		return nil, nil, err
	}
	return c2s, s2c, nil
}

func concat(a, b []byte) []byte {
	out := make([]byte, 0, len(a)+len(b))
	return append(append(out, a...), b...)
}

func setDeadline(ctx context.Context, c net.Conn, d time.Duration) error {
	deadline := time.Now().Add(d)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	return c.SetDeadline(deadline)
}
