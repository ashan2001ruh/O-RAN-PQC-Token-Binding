# Implementation Part 6: The sidecar, Kyverno injection and dms_cli onboarding

Parts 1 to 5 put the token binding *inside* the xApp: the xApp imported the client
library to obtain a bound token and the validator library to enforce one. That proves the
mechanism, but it asks every xApp author to adopt two libraries and to keep them current.

This part moves the whole mechanism out of the xApp and into a **sidecar**: one extra
container in the pod, added at admission time by **Kyverno**, carrying the traffic of an
**unmodified** xApp over a post-quantum tunnel and enforcing the binding on it.

The two xApps used to demonstrate it are onboarded with **dms_cli**, the standard O-RAN
onboarding tool, and they run a **stock busybox image**. There is no project code in the
xApp image, in the xApp descriptor containers section, or anywhere the xApp author touches.

| | In-process integration (parts 1-5) | Sidecar (this part) |
|---|---|---|
| Where the client library runs | in the xApp process | in the sidecar container |
| Where the validator runs | in the xApp process | in the sidecar container |
| What the xApp must do | import two libraries, wire up middleware | nothing |
| Transport | TLS 1.3 with hybrid ML-KEM key exchange | the pqtunnel: ML-KEM-768 + ML-DSA-65 + AES-256-GCM, no TLS |
| Traffic covered | the HTTP API the xApp exposes | any TCP stream: HTTP and RMR alike |
| Unit of authorization | one HTTP request | one connection |

## Design decisions

**One sidecar, both directions.** The ORAN-PQC tunnel work uses a client-side and a
server-side tunnel process. Here a single binary runs both halves: an *egress* listener on
loopback that the xApp writes to, and an *ingress* listener on the pod address that peer
sidecars connect to. One container per pod, one image, one identity.

**The handshake is kept, the implementation is not.** The protocol is the same shape as the
existing custom tunnel - ML-KEM-768 for key establishment, ML-DSA for peer authentication,
AES-256-GCM records with an explicit nonce - but it is implemented on the Go 1.27 standard
library (`crypto/mlkem`, `crypto/mldsa`, `crypto/hkdf`) instead of liboqs-go. The sidecar is
therefore a static `scratch` image with no cgo, like everything else in this project.
Wire compatibility with the existing liboqs binary is *not* claimed: the field framing here
is explicit and the keys are derived with HKDF over the handshake transcript.

**The handshake carries certificates, not raw keys.** The existing tunnel authenticates with
pre-shared raw ML-DSA keys. This one presents the ML-DSA certificate chain the xApp enrolled
for with the RIC CA. That single change is what lets the token binding work without any
extra key distribution: the certificate that proved possession during the handshake is
exactly the certificate a certificate-bound token names in `cnf.x5t#S256`.

**Authorization is per connection.** A DPoP proof binds one HTTP request. A tunnel
connection carries an arbitrary byte stream, so the equivalent unit is the connection: the
first record on it is an authorization frame, and not a single application byte is relayed
until that frame has been accepted.

## Files in this part

| File | Lines | Purpose |
|---|---|---|
| `sidecar/pqtunnel/frame.go` | 81 | Length-prefixed framing and the field reader every handshake message is parsed with. |
| `sidecar/pqtunnel/identity.go` | 128 | Certificate chains on the wire, chain verification, and the ML-DSA sign and verify calls. |
| `sidecar/pqtunnel/handshake.go` | 280 | The handshake itself: ML-KEM-768 key establishment with ML-DSA-65 authentication over the transcript. |
| `sidecar/pqtunnel/conn.go` | 220 | The record layer: AES-256-GCM with per-direction keys and counter nonces, plus control messages and half-close. |
| `sidecar/pqtunnel/tunnel_test.go` | 241 | Offline tests: round trip, control messages, untrusted CA, wrong peer name, forged record, half-close. |
| `xapp-resource/channel.go` | 89 | The resource-side entry point for a channel that is not HTTP over TLS. |
| `xapp-resource/channel_test.go` | 112 | The channel binding cases: right certificate, wrong certificate, no certificate, unbound token, proof for another target, replay. |
| `sidecar/config.go` | 155 | The sidecar configuration, which the Kyverno policy fills in from the pod annotations. |
| `sidecar/auth.go` | 81 | The authorization frame and how the token and its proof of possession are obtained. |
| `sidecar/sidecar.go` | 218 | The process: enrolment, the listeners, the relay, the counters and the health port. |
| `sidecar/egress.go` | 86 | Outgoing: token, handshake, authorization frame, then bytes. |
| `sidecar/ingress.go` | 127 | Incoming: handshake, authorization frame, validator, then the application. |
| `sidecar/cmd/xapp-sidecar/main.go` | 51 | The binary. |
| `deploy/kyverno/sidecar-policy.yaml` | 118 | The Kyverno ClusterPolicy that injects the container, its credentials and its trust anchors. |
| `deploy/kyverno/sidecar-services.yaml` | 27 | One Service per xApp, published for the tunnel port only. |
| `xapps/xappc-config.json` | 43 | The xApp descriptor dms_cli onboards. It contains annotations and a stock image, and no security code. |
| `xapps/schema.json` | 9 | The controls schema the descriptor is validated against. |
| `scripts/install-kyverno.sh` | 31 | Installs the admission controller. |
| `scripts/onboard-sidecar-xapps.sh` | 49 | Renders the descriptors, onboards them and installs the charts. |

---

## 1. The tunnel

### The wire protocol

```
ClientHello   "PQTB1" | version | suite
              | len32(certificate chain) | len32(ML-KEM-768 encapsulation key)
              | len32(ML-DSA signature over everything above, context "PQTB1 client hello")

ServerHello   "PQTB1" | version | suite
              | len32(certificate chain) | len32(ML-KEM-768 ciphertext)
              | len32(ML-DSA signature over ClientHello || everything above,
                      context "PQTB1 server hello")

transcript    SHA-256(ClientHello || ServerHello)
keys          HKDF-SHA-256(shared secret, salt = transcript, info = "PQTB1 c2s" / "PQTB1 s2c")
record        len32 | nonce[12] | AES-256-GCM(plaintext)
```

Four properties are worth naming, because each one closes a specific hole:

1. **The server signature covers the client hello.** Neither hello can be lifted into another
   session, and the two are bound to each other.
2. **The signature contexts differ** (`crypto/mldsa` takes a context string), so a client
   hello signature is not a valid server hello signature even on identical bytes.
3. **The record keys are salted with the transcript**, so they depend on both certificates
   and the encapsulated key, not on the ML-KEM shared secret alone.
4. **The nonce is a counter**, and the receiver recomputes the one it expects. A reordered,
   duplicated or dropped record fails to decrypt rather than being quietly accepted.

There is no negotiation. One suite, one version; anything else is refused.

### `sidecar/pqtunnel/frame.go`

Length-prefixed framing and the field reader every handshake message is parsed with.

```go
package pqtunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// MaxFrame caps a single wire frame. Handshake messages carry ML-DSA certificate
// chains (a few tens of kilobytes); data records are capped at RecordSize.
const MaxFrame = 1 << 20

// ErrFrameTooLarge is returned when a peer announces a frame beyond MaxFrame.
var ErrFrameTooLarge = errors.New("pqtunnel: frame exceeds maximum size")

// writeFrame writes a 4-byte big-endian length followed by the payload.
func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFrame {
		return ErrFrameTooLarge
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// readFrame reads one length-prefixed frame.
func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrame {
		return nil, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// appendField appends a 4-byte length-prefixed field; the handshake messages are
// built from these so that every parsed message is unambiguous.
func appendField(dst, field []byte) []byte {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(field)))
	return append(append(dst, hdr[:]...), field...)
}

// reader walks a handshake message field by field.
type reader struct {
	buf []byte
	pos int
}

func (r *reader) field(name string) ([]byte, error) {
	if r.pos+4 > len(r.buf) {
		return nil, fmt.Errorf("truncated handshake: no length for %s", name)
	}
	n := int(binary.BigEndian.Uint32(r.buf[r.pos:]))
	r.pos += 4
	if n < 0 || r.pos+n > len(r.buf) {
		return nil, fmt.Errorf("truncated handshake: %s declares %d bytes, %d remain", name, n, len(r.buf)-r.pos)
	}
	out := r.buf[r.pos : r.pos+n]
	r.pos += n
	return out, nil
}

func (r *reader) done() error {
	if r.pos != len(r.buf) {
		return fmt.Errorf("handshake message has %d trailing bytes", len(r.buf)-r.pos)
	}
	return nil
}
```

### `sidecar/pqtunnel/identity.go`

Certificate chains on the wire, chain verification, and the ML-DSA sign and verify calls.
`authenticate` is where a peer becomes a `Peer`: the chain must verify to the RIC CA, the
leaf key must be ML-DSA, and the subject must be the expected peer when one was named.

```go
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
```

### `sidecar/pqtunnel/handshake.go`

```go
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
```

### `sidecar/pqtunnel/conn.go`

`CloseWrite` deserves a note. A one-shot RMR send (`echo ... | nc`) ends with a half-close,
and the receiving application only acts when it sees end-of-stream. TLS cannot express a
half-close; here it is an authenticated empty record that consumes a sequence number, which
the reader turns into `io.EOF`. Without it the relay works for request/response HTTP and
silently stalls for one-shot messages - which is exactly what the first deployment did.

```go
package pqtunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// RecordSize is the largest plaintext carried by one AES-GCM record.
const RecordSize = 16 * 1024

// Conn is a net.Conn whose payload is protected with AES-256-GCM under keys derived
// from the ML-KEM shared secret. Each direction has its own key and its own record
// sequence number, and the nonce is a counter, so a reordered, duplicated or dropped
// record fails to decrypt instead of being silently accepted.
type Conn struct {
	net.Conn
	peer  *Peer
	stats Stats

	wmu      sync.Mutex
	seal     cipher.AEAD
	wIV      [4]byte
	wSeq     uint64
	wClosed  bool

	rmu    sync.Mutex
	open   cipher.AEAD
	rIV    [4]byte
	rSeq   uint64
	rEOF   bool
	buffer []byte
}

func newConn(raw net.Conn, shared, transcript []byte, peer *Peer, isClient bool, st Stats) (*Conn, error) {
	c2s, s2c, err := deriveKeys(shared, transcript)
	if err != nil {
		return nil, fmt.Errorf("key derivation: %w", err)
	}
	c2sIV, err := hkdf.Key(sha256.New, shared, transcript, infoClientToServer+" iv", 4)
	if err != nil {
		return nil, err
	}
	s2cIV, err := hkdf.Key(sha256.New, shared, transcript, infoServerToClient+" iv", 4)
	if err != nil {
		return nil, err
	}
	sealKey, openKey, sealIV, openIV := c2s, s2c, c2sIV, s2cIV
	if !isClient {
		sealKey, openKey, sealIV, openIV = s2c, c2s, s2cIV, c2sIV
	}
	seal, err := newGCM(sealKey)
	if err != nil {
		return nil, err
	}
	open, err := newGCM(openKey)
	if err != nil {
		return nil, err
	}
	c := &Conn{Conn: raw, peer: peer, stats: st, seal: seal, open: open}
	copy(c.wIV[:], sealIV)
	copy(c.rIV[:], openIV)
	// Clear the handshake deadline; the proxy sets its own.
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return c, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Peer is the authenticated identity of the other end.
func (c *Conn) Peer() *Peer { return c.peer }

// HandshakeStats reports what the handshake cost.
func (c *Conn) HandshakeStats() Stats { return c.stats }

func nonce(iv [4]byte, seq uint64) []byte {
	var n [12]byte
	copy(n[:4], iv[:])
	binary.BigEndian.PutUint64(n[4:], seq)
	return n[:]
}

// Write splits p into records and writes each as [length][nonce][ciphertext].
func (c *Conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.wClosed {
		return 0, net.ErrClosed
	}
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > RecordSize {
			chunk = chunk[:RecordSize]
		}
		n := nonce(c.wIV, c.wSeq)
		record := make([]byte, 0, len(n)+len(chunk)+c.seal.Overhead())
		record = append(record, n...)
		record = c.seal.Seal(record, n, chunk, nil)
		if err := writeFrame(c.Conn, record); err != nil {
			return written, err
		}
		c.wSeq++
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

// Read returns plaintext from the next record, buffering any remainder.
func (c *Conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.buffer) == 0 {
		if c.rEOF {
			return 0, io.EOF
		}
		plain, err := c.readRecord()
		if err != nil {
			return 0, err
		}
		// An empty record is the end-of-stream marker written by CloseWrite.
		if len(plain) == 0 {
			c.rEOF = true
			return 0, io.EOF
		}
		c.buffer = plain
	}
	n := copy(p, c.buffer)
	c.buffer = c.buffer[n:]
	return n, nil
}

func (c *Conn) readRecord() ([]byte, error) {
	record, err := readFrame(c.Conn)
	if err != nil {
		return nil, err
	}
	if len(record) < 12+c.open.Overhead() {
		return nil, io.ErrUnexpectedEOF
	}
	got, body := record[:12], record[12:]
	want := nonce(c.rIV, c.rSeq)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return nil, fmt.Errorf("pqtunnel: record %d carries an out-of-sequence nonce", c.rSeq)
	}
	plain, err := c.open.Open(nil, want, body, nil)
	if err != nil {
		return nil, fmt.Errorf("pqtunnel: record %d failed authentication: %w", c.rSeq, err)
	}
	c.rSeq++
	return plain, nil
}

// CloseWrite ends this direction of the stream without tearing down the connection,
// so a half-close by the application reaches the peer application. TLS has no way to
// express this; here it is an authenticated empty record, which the reader turns into
// io.EOF. It cannot be forged or replayed, because it consumes a sequence number.
func (c *Conn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.wClosed {
		return nil
	}
	c.wClosed = true
	n := nonce(c.wIV, c.wSeq)
	c.wSeq++
	record := make([]byte, 0, len(n)+c.seal.Overhead())
	record = append(record, n...)
	record = c.seal.Seal(record, n, nil, nil)
	return writeFrame(c.Conn, record)
}

// MaxMessage caps a control message read with ReadMessage.
const MaxMessage = 64 * 1024

// WriteMessage writes one length-prefixed control message inside the protected
// channel. The sidecar uses it for the authorization frame and its acknowledgement.
func (c *Conn) WriteMessage(b []byte) error {
	if len(b) > MaxMessage {
		return ErrFrameTooLarge
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	_, err := c.Write(append(hdr[:], b...))
	return err
}

// ReadMessage reads one control message written by WriteMessage.
func (c *Conn) ReadMessage() ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxMessage {
		return nil, fmt.Errorf("%w: control message of %d bytes", ErrFrameTooLarge, n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
```

### `sidecar/pqtunnel/tunnel_test.go`

```go
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
```

---

## 2. The resource side: authorizing a channel

The validator built in part 3 takes an `*http.Request`. A tunnel connection is not one. The
temptation is to write a second validator for the tunnel - and that is precisely how two
enforcement points drift apart.

Instead, `AuthorizeChannel` assembles the request the checks expect and calls the *same*
`Authorize`: the peer certificate chain from the handshake goes where the TLS peer
certificate would be, and the authorization frame supplies the `Authorization` and `DPoP`
headers. Every check - issuer, audience, expiry, scope, role, `cnf.x5t#S256` against the
presented certificate, `cnf.jkt` against the proof key, `ath`, `htm`, `htu`, `iat`, `jti`
replay - runs unchanged, with one code path and one set of rejection reasons.

`htm` is `TUNNEL`, not an HTTP method. A proof minted for the tunnel therefore cannot be
replayed against an HTTP resource, or the other way round.

### `xapp-resource/channel.go`

```go
package xappresource

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// ChannelRequest is one authorization attempt on a channel that is not HTTP over
// TLS: the sidecar post-quantum tunnel, which carries RMR and HTTP alike.
//
// The checks are identical to the HTTP ones, because they are the same checks: the
// certificate the peer proved possession of during the tunnel handshake takes the
// place of the TLS peer certificate, and the authorization frame sent as the first
// record on the tunnel takes the place of the Authorization and DPoP headers.
type ChannelRequest struct {
	// Token is the access token the peer presented.
	Token string
	// Proof is the DPoP proof for a jkt-bound token (method C); empty for a
	// certificate-bound token (methods A and B).
	Proof string
	// PeerChain is the certificate chain the peer authenticated with, leaf first.
	PeerChain []*x509.Certificate
	// Target is the canonical URI of the destination, for example
	// https://xapp-b.ricxapp.svc.cluster.local:4570/rmr. It is what the proof
	// must carry in htu.
	Target string
	// Operation is what the proof must carry in htm; the sidecar uses TUNNEL.
	Operation string
}

// ChannelOperation is the htm value used for a tunnel authorization frame. It is not
// an HTTP method precisely because this is not an HTTP request, so a proof minted for
// a tunnel can never be replayed against an HTTP resource and the other way round.
const ChannelOperation = "TUNNEL"

// AuthorizeChannel runs every check Authorize runs, against a tunnel peer instead of
// a TLS peer. It returns the authorized caller or the first failure.
func (v *Validator) AuthorizeChannel(ctx context.Context, cr ChannelRequest) (*Principal, *Rejection) {
	if cr.Token == "" {
		return nil, reject(ReasonAuthorizationMissing, "authorization frame carries no access token")
	}
	u, err := url.Parse(cr.Target)
	if err != nil || u.Host == "" {
		return nil, reject(ReasonDPoPHtuMismatch, "channel target %q is not an absolute URI", cr.Target)
	}
	op := cr.Operation
	if op == "" {
		op = ChannelOperation
	}
	scheme := "Bearer"
	if cr.Proof != "" {
		scheme = "DPoP"
	}
	req := &http.Request{
		Method: op,
		URL:    u,
		Host:   u.Host,
		Header: http.Header{"Authorization": {scheme + " " + cr.Token}},
		// A non-nil TLS state is how the validator learns the peer certificate. The
		// tunnel established it with ML-KEM and ML-DSA rather than with TLS, but the
		// binding check is the same comparison against the same chain.
		TLS: &tls.ConnectionState{PeerCertificates: cr.PeerChain},
	}
	if cr.Proof != "" {
		req.Header.Set("DPoP", cr.Proof)
	}
	return v.Authorize(req.WithContext(ctx), v.channelMode())
}

// channelMode is the validation mode used for tunnel traffic.
func (v *Validator) channelMode() Mode {
	if v.introspect != nil && v.cfg.ChannelMode == ModeIntrospection {
		return ModeIntrospection
	}
	return ModeLocal
}

// ChannelTarget builds the canonical target URI for a tunnel route.
func ChannelTarget(host string, port int, route string) string {
	return fmt.Sprintf("https://%s:%d/%s", host, port, route)
}

// ChannelProofWindow is the accepted age of a tunnel authorization proof.
func (v *Validator) ChannelProofWindow() time.Duration { return v.cfg.DPoPProofWindow }
```

### `xapp-resource/channel_test.go`

```go
package xappresource

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"testing"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/jose"
	"github.com/oran-ricsec/xapp-token-binding/internal/pki"
)

const channelTarget = "https://xapp-d-sidecar.ricxapp.svc.cluster.local:4570/rmr"

func chain(c ...*x509.Certificate) []*x509.Certificate { return c }

// The tunnel carries RMR and HTTP alike, so these cases are what protects both.
func TestChannelCertificateBinding(t *testing.T) {
	f := newFixture(t)
	peer := f.leaf("xapp-sidecar-c", time.Hour)
	other := f.leaf("xapp-sidecar-e", time.Hour)
	bound := f.token(map[string]any{"x5t#S256": pki.ThumbprintS256(peer.Leaf)})

	cases := []struct {
		name     string
		req      ChannelRequest
		wantCode string
	}{
		{"token bound to the handshake certificate is accepted",
			ChannelRequest{Token: bound, PeerChain: chain(peer.Leaf), Target: channelTarget}, ""},
		{"token bound to another certificate is refused",
			ChannelRequest{Token: bound, PeerChain: chain(other.Leaf), Target: channelTarget}, ReasonX5tMismatch},
		{"no peer certificate at all is refused",
			ChannelRequest{Token: bound, Target: channelTarget}, ReasonClientCertMissing},
		{"an unbound bearer token is refused",
			ChannelRequest{Token: f.token(nil), PeerChain: chain(peer.Leaf), Target: channelTarget}, ReasonCnfMissing},
	}
	for _, tc := range cases {
		p, rej := f.v.AuthorizeChannel(context.Background(), tc.req)
		switch {
		case tc.wantCode == "" && rej != nil:
			t.Errorf("%s: rejected with %s (%s)", tc.name, rej.Code, rej.Detail)
		case tc.wantCode == "" && p.Binding != "x5t#S256":
			t.Errorf("%s: binding is %q", tc.name, p.Binding)
		case tc.wantCode != "" && (rej == nil || rej.Code != tc.wantCode):
			t.Errorf("%s: got %v, want %s", tc.name, rej, tc.wantCode)
		}
	}
}

func TestChannelProofBinding(t *testing.T) {
	f := newFixture(t)
	peer := f.leaf("xapp-sidecar-d", time.Hour)
	signer, err := jose.GenerateSigner("ES256")
	if err != nil {
		t.Fatal(err)
	}
	jkt, err := signer.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	tok := f.token(map[string]any{"jkt": jkt})

	proof := func(target string, at time.Time) string {
		sum := jose.B64(sha256Sum(tok))
		p, err := signer.SignCompact(
			map[string]any{"typ": "dpop+jwt", "jwk": signer.PublicKey()},
			map[string]any{"jti": jose.B64([]byte(target + at.String())), "htm": ChannelOperation,
				"htu": target, "iat": at.Unix(), "ath": sum})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	if _, rej := f.v.AuthorizeChannel(context.Background(), ChannelRequest{
		Token: tok, Proof: proof(channelTarget, time.Now()), PeerChain: chain(peer.Leaf), Target: channelTarget,
	}); rej != nil {
		t.Errorf("a valid channel proof was rejected: %s (%s)", rej.Code, rej.Detail)
	}

	// A proof minted for a different destination must not open this one.
	elsewhere := "https://xapp-x-sidecar.ricxapp.svc.cluster.local:4570/rmr"
	if _, rej := f.v.AuthorizeChannel(context.Background(), ChannelRequest{
		Token: tok, Proof: proof(elsewhere, time.Now()), PeerChain: chain(peer.Leaf), Target: channelTarget,
	}); rej == nil || rej.Code != ReasonDPoPHtuMismatch {
		t.Errorf("proof for another target: got %v, want %s", rej, ReasonDPoPHtuMismatch)
	}

	// The same proof twice is a replay.
	replayed := proof(channelTarget, time.Now())
	req := ChannelRequest{Token: tok, Proof: replayed, PeerChain: chain(peer.Leaf), Target: channelTarget}
	if _, rej := f.v.AuthorizeChannel(context.Background(), req); rej != nil {
		t.Fatalf("first use rejected: %s", rej.Code)
	}
	if _, rej := f.v.AuthorizeChannel(context.Background(), req); rej == nil || rej.Code != ReasonDPoPReplayed {
		t.Errorf("replayed proof: got %v, want %s", rej, ReasonDPoPReplayed)
	}

	// A jkt-bound token presented with no proof at all is refused.
	if _, rej := f.v.AuthorizeChannel(context.Background(), ChannelRequest{
		Token: tok, PeerChain: chain(peer.Leaf), Target: channelTarget,
	}); rej == nil || rej.Code != ReasonDPoPAsBearer {
		t.Errorf("proofless jkt token: got %v, want %s", rej, ReasonDPoPAsBearer)
	}
}

func sha256Sum(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}
```

---

## 3. The sidecar

### `sidecar/config.go`

```go
// Package sidecar is the xApp sidecar: one container, injected next to an unmodified
// xApp, that carries the xApp traffic over a post-quantum tunnel and enforces
// sender-constrained access tokens on it.
//
// One process runs both directions:
//
//	egress   a plain TCP listener on loopback that the xApp writes to. The sidecar
//	         obtains a bound access token, opens a pqtunnel connection to the peer
//	         sidecar, sends an authorization frame and then relays bytes.
//	ingress  a pqtunnel listener on the pod address. The sidecar completes the
//	         handshake, validates the authorization frame with the resource-side
//	         validator and only then connects to the local application port.
//
// The relay is byte-transparent, so HTTP and RMR both work and neither the xApp nor
// the RMR library knows any of this is happening. Authorization is per connection:
// the tunnel handshake proves possession of the ML-DSA credential, and the
// authorization frame proves the access token is bound to that same credential.
package sidecar

import (
	"fmt"
	"strings"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/config"
)

// EgressRoute forwards one local listener to one peer sidecar.
type EgressRoute struct {
	Name     string // route label, matched against the peer ingress routes
	Listen   string // local address the xApp connects to
	Peer     string // peer sidecar address, host:port
	PeerName string // CN or DNS SAN the peer certificate must carry
}

// IngressRoute delivers one route label to one local application address.
type IngressRoute struct {
	Name  string
	Local string
}

// Config configures the sidecar. ConfigFromEnv reads it from the environment, which
// is what the Kyverno injection policy fills in from the pod annotations.
type Config struct {
	Name          string // this sidecar identity, the xApp client id
	Authority     string // host:port peers reach this sidecar on, as it appears in the proof htu
	IngressListen string // address the peer sidecars connect to ("" disables ingress)
	IngressRoutes []IngressRoute
	EgressRoutes  []EgressRoute

	HandshakeTimeout time.Duration
	AuthTimeout      time.Duration
	IdleTimeout      time.Duration
	DialTimeout      time.Duration
	TokenTimeout     time.Duration

	HealthListen string // plain HTTP health and metrics port for kubelet probes
}

// ConfigFromEnv reads the sidecar configuration.
//
//	SIDECAR_NAME            xapp-c
//	SIDECAR_AUTHORITY       xapp-c-sidecar.ricxapp.svc.cluster.local:4570
//	SIDECAR_INGRESS_LISTEN  :4570
//	SIDECAR_INGRESS_ROUTES  http|127.0.0.1:8080,rmr|127.0.0.1:4560
//	SIDECAR_EGRESS_ROUTES   http|127.0.0.1:18080|xapp-d-sidecar.ricxapp.svc.cluster.local:4570|xapp-d
func ConfigFromEnv() (Config, error) {
	e := &config.Env{}
	c := Config{
		Name:             e.Req("SIDECAR_NAME"),
		Authority:        e.Str("SIDECAR_AUTHORITY", ""),
		IngressListen:    e.Str("SIDECAR_INGRESS_LISTEN", ""),
		HandshakeTimeout: e.Dur("SIDECAR_HANDSHAKE_TIMEOUT", 15*time.Second),
		AuthTimeout:      e.Dur("SIDECAR_AUTH_TIMEOUT", 15*time.Second),
		IdleTimeout:      e.Dur("SIDECAR_IDLE_TIMEOUT", 0),
		DialTimeout:      e.Dur("SIDECAR_DIAL_TIMEOUT", 10*time.Second),
		TokenTimeout:     e.Dur("SIDECAR_TOKEN_TIMEOUT", 30*time.Second),
		HealthListen:     e.Str("SIDECAR_HEALTH_LISTEN", ":8081"),
	}
	ingress, err := parseIngress(e.Str("SIDECAR_INGRESS_ROUTES", ""))
	if err != nil {
		e.Fail("SIDECAR_INGRESS_ROUTES: %v", err)
	}
	c.IngressRoutes = ingress
	egress, err := parseEgress(e.Str("SIDECAR_EGRESS_ROUTES", ""))
	if err != nil {
		e.Fail("SIDECAR_EGRESS_ROUTES: %v", err)
	}
	c.EgressRoutes = egress
	if c.IngressListen == "" && len(c.EgressRoutes) == 0 {
		e.Fail("the sidecar has neither an ingress listener nor an egress route; nothing to do")
	}
	if c.IngressListen != "" && len(c.IngressRoutes) == 0 {
		e.Fail("SIDECAR_INGRESS_LISTEN is set but SIDECAR_INGRESS_ROUTES is empty")
	}
	if c.IngressListen != "" && c.Authority == "" {
		e.Fail("SIDECAR_AUTHORITY is required with an ingress listener: it is the host:port peers address this sidecar by")
	}
	return c, e.Err()
}

// IngressAuthority is the canonical authority and path of one served route; it must
// equal what the peer used to mint the proof.
func (c Config) IngressAuthority(route string) string { return c.Authority + "/" + route }

// IngressTarget returns the local address for a route label.
func (c Config) IngressTarget(name string) (string, bool) {
	for _, r := range c.IngressRoutes {
		if r.Name == name {
			return r.Local, true
		}
	}
	return "", false
}

func parseIngress(s string) ([]IngressRoute, error) {
	var out []IngressRoute
	for _, spec := range splitList(s) {
		f := strings.Split(spec, "|")
		if len(f) != 2 || f[0] == "" || f[1] == "" {
			return nil, fmt.Errorf("route %q is not name|host:port", spec)
		}
		out = append(out, IngressRoute{Name: f[0], Local: f[1]})
	}
	return out, nil
}

func parseEgress(s string) ([]EgressRoute, error) {
	var out []EgressRoute
	for _, spec := range splitList(s) {
		f := strings.Split(spec, "|")
		if len(f) < 3 || len(f) > 4 {
			return nil, fmt.Errorf("route %q is not name|listen|peer[|peerName]", spec)
		}
		r := EgressRoute{Name: f[0], Listen: f[1], Peer: f[2]}
		if len(f) == 4 {
			r.PeerName = f[3]
		}
		if r.Name == "" || r.Listen == "" || r.Peer == "" {
			return nil, fmt.Errorf("route %q has an empty field", spec)
		}
		out = append(out, r)
	}
	return out, nil
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
```

### `sidecar/auth.go`

The authorization frame is JSON inside the encrypted channel:

```json
{"v":1,"client_id":"xapp-sidecar-c","route":"rmr",
 "target":"https://xapp-sidecar-d-sidecar.ricxapp.svc.cluster.local:4570/rmr",
 "token":"<ML-DSA-65 signed access token>","proof":"<DPoP proof, method C only>"}
```

Methods A and B send no proof: the handshake already proved possession of the certificate
the token is bound to. Method C sends a proof signed by the ML-DSA key that `cnf.jkt` names.
The reply is an ack carrying the validator reason code on refusal, so the sending side logs
*why* it was refused instead of seeing a connection close.

```go
package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	xappclient "github.com/oran-ricsec/xapp-token-binding/xapp-client"
	xappresource "github.com/oran-ricsec/xapp-token-binding/xapp-resource"
)

// authFrame is the first control message on every tunnel connection. It carries the
// access token and, for a jkt-bound token, the proof of possession of the key the
// token is bound to. Nothing else flows until the peer has accepted it.
type authFrame struct {
	Version  int    `json:"v"`
	ClientID string `json:"client_id"`
	Route    string `json:"route"`
	Target   string `json:"target"`
	Token    string `json:"token"`
	Proof    string `json:"proof,omitempty"`
}

// authAck is the reply. A rejection carries the validator reason code, so the sending
// side logs exactly why it was refused instead of seeing a closed connection.
type authAck struct {
	OK      bool   `json:"ok"`
	Binding string `json:"binding,omitempty"`
	Peer    string `json:"peer,omitempty"`
	Code    string `json:"code,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

const authFrameVersion = 1

// target is the canonical URI of one egress route, used as the proof htu.
func (r EgressRoute) target() string {
	return "https://" + r.Peer + "/" + r.Name
}

// buildAuthFrame obtains a currently valid bound token and, when the token is bound
// to a key rather than to a certificate, a fresh proof of possession of that key.
func (s *Sidecar) buildAuthFrame(ctx context.Context, route EgressRoute) (*authFrame, *xappclient.Token, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.TokenTimeout)
	defer cancel()
	tok, err := s.client.Token(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("access token: %w", err)
	}
	f := &authFrame{
		Version:  authFrameVersion,
		ClientID: s.client.ClientID(),
		Route:    route.Name,
		Target:   route.target(),
		Token:    tok.Value,
	}
	if tok.Binding == "jkt" {
		d, ok := s.client.(xappclient.DPoP)
		if !ok {
			return nil, nil, fmt.Errorf("token is bound to cnf.jkt but this client holds no proof key")
		}
		signer := d.Signer()
		if tok.PostQuantum {
			if d.PQSigner() == nil {
				return nil, nil, fmt.Errorf("post-quantum token but no ML-DSA proof key")
			}
			signer = d.PQSigner()
		}
		proof, err := xappclient.BuildDPoPProof(signer, xappresource.ChannelOperation, f.Target, tok.Value, "", time.Now())
		if err != nil {
			return nil, nil, fmt.Errorf("channel proof: %w", err)
		}
		f.Proof = proof
	}
	return f, tok, nil
}

func encodeJSON(v any) ([]byte, error) { return json.Marshal(v) }

func decodeJSON(b []byte, v any) error { return json.Unmarshal(b, v) }
```

### `sidecar/sidecar.go`

```go
package sidecar

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/sidecar/pqtunnel"
	xappclient "github.com/oran-ricsec/xapp-token-binding/xapp-client"
	xappresource "github.com/oran-ricsec/xapp-token-binding/xapp-resource"
)

// Sidecar is the injected process: an egress half that authorizes outgoing
// connections and an ingress half that enforces authorization on incoming ones.
type Sidecar struct {
	cfg       Config
	log       *slog.Logger
	client    xappclient.Client
	validator *xappresource.Validator

	mu      sync.Mutex
	counter map[string]int
}

// New builds a sidecar from the three configurations: its own, the token client and
// the resource validator. The client and the validator are the same ones the
// in-process integration uses; the sidecar only changes where they are applied.
func New(cfg Config, clientCfg xappclient.Config, resCfg xappresource.Config, log *slog.Logger) (*Sidecar, error) {
	if !clientCfg.PQEnabled {
		return nil, errors.New("the sidecar tunnel requires PQ_MODE=true: it authenticates peers with ML-DSA certificates")
	}
	client, err := xappclient.New(clientCfg, log)
	if err != nil {
		return nil, fmt.Errorf("token client: %w", err)
	}
	s := &Sidecar{cfg: cfg, log: log.With("component", "sidecar", "sidecar", cfg.Name), client: client, counter: map[string]int{}}
	if cfg.IngressListen != "" {
		v, err := xappresource.NewValidator(resCfg, client.HTTPClient(), log)
		if err != nil {
			return nil, fmt.Errorf("resource validator: %w", err)
		}
		s.validator = v
	}
	return s, nil
}

// Client exposes the token client, for the CLI walkthrough.
func (s *Sidecar) Client() xappclient.Client { return s.client }

// Run starts every listener and blocks until ctx is done.
func (s *Sidecar) Run(ctx context.Context) error {
	// The CA and Keycloak may still be starting; enrollment is retried rather than
	// crash-looping, which would burn the one-time bootstrap credential.
	for attempt := 1; ; attempt++ {
		err := s.client.Start(ctx)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if attempt >= 30 {
			return fmt.Errorf("obtain identity: %w", err)
		}
		s.log.Warn("enrollment_retry", "attempt", attempt, "error", err.Error())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	d := s.client.Describe()
	s.log.Info("sidecar_ready",
		"method", d.Method, "client_id", d.ClientID, "pq_cert", d.PQCert, "pq_alg", d.PQAlg,
		"ingress", s.cfg.IngressListen, "egress_routes", len(s.cfg.EgressRoutes))

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go s.client.Maintain(ctx)

	var wg sync.WaitGroup
	errs := make(chan error, len(s.cfg.EgressRoutes)+2)
	run := func(name string, f func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f(); err != nil && ctx.Err() == nil {
				errs <- fmt.Errorf("%s: %w", name, err)
				cancel()
			}
		}()
	}

	if s.cfg.IngressListen != "" {
		run("ingress", func() error { return s.serveIngress(ctx) })
	}
	for _, route := range s.cfg.EgressRoutes {
		r := route
		run("egress "+r.Name, func() error { return s.serveEgress(ctx, r) })
	}
	if s.cfg.HealthListen != "" {
		run("health", func() error { return s.serveHealth(ctx) })
	}

	<-ctx.Done()
	wg.Wait()
	select {
	case err := <-errs:
		return err
	default:
		return nil
	}
}

// tunnelConfig is the handshake configuration; Credential is read on every handshake
// so a rotated certificate takes effect on the next connection.
func (s *Sidecar) tunnelConfig(peerName string) pqtunnel.Config {
	return pqtunnel.Config{
		Credential: func() *tls.Certificate {
			if id := s.client.PQIdentity(); id != nil {
				return id.Current()
			}
			return nil
		},
		Roots:            s.client.TrustPool(),
		PeerName:         peerName,
		HandshakeTimeout: s.cfg.HandshakeTimeout,
	}
}

// relay copies in both directions and returns when either side closes.
func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

// acceptLoop runs fn for every accepted connection until ctx is done.
func (s *Sidecar) acceptLoop(ctx context.Context, l net.Listener, fn func(net.Conn)) error {
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go fn(conn)
	}
}

func (s *Sidecar) count(name string) {
	s.mu.Lock()
	s.counter[name]++
	s.mu.Unlock()
}

// Counters returns a snapshot of the connection counters.
func (s *Sidecar) Counters() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.counter))
	for k, v := range s.counter {
		out[k] = v
	}
	return out
}

// serveHealth exposes liveness and the counters over plain HTTP. It is plain because
// the kubelet cannot speak the post-quantum tunnel, and it carries no traffic.
func (s *Sidecar) serveHealth(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if s.client.PQIdentity() == nil || s.client.PQIdentity().Current() == nil {
			http.Error(w, "no identity yet", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		d := s.client.Describe()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sidecar": s.cfg.Name, "method": d.Method, "client_id": d.ClientID,
			"pq_cert": d.PQCert, "pq_alg": d.PQAlg, "counters": s.Counters(),
		})
	})
	srv := &http.Server{Addr: s.cfg.HealthListen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
```

### `sidecar/egress.go`

```go
package sidecar

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/sidecar/pqtunnel"
)

// serveEgress listens on the loopback address the xApp was pointed at and carries
// every connection to the peer sidecar over an authorized tunnel.
func (s *Sidecar) serveEgress(ctx context.Context, route EgressRoute) error {
	l, err := net.Listen("tcp", route.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", route.Listen, err)
	}
	s.log.Info("egress_listening", "route", route.Name, "listen", route.Listen, "peer", route.Peer, "peer_name", route.PeerName)
	return s.acceptLoop(ctx, l, func(local net.Conn) {
		defer local.Close()
		if err := s.forward(ctx, route, local); err != nil {
			s.count("egress_failed_" + route.Name)
			s.log.Warn("egress_failed", "route", route.Name, "peer", route.Peer, "error", err.Error())
		}
	})
}

func (s *Sidecar) forward(ctx context.Context, route EgressRoute, local net.Conn) error {
	start := time.Now()
	frame, tok, err := s.buildAuthFrame(ctx, route)
	if err != nil {
		return err
	}

	dialer := &net.Dialer{Timeout: s.cfg.DialTimeout}
	raw, err := dialer.DialContext(ctx, "tcp", route.Peer)
	if err != nil {
		return fmt.Errorf("dial peer sidecar %s: %w", route.Peer, err)
	}
	defer raw.Close()

	tun, err := pqtunnel.Client(ctx, raw, s.tunnelConfig(route.PeerName))
	if err != nil {
		return fmt.Errorf("tunnel handshake with %s: %w", route.Peer, err)
	}
	hs := tun.HandshakeStats()

	if err := tun.SetDeadline(time.Now().Add(s.cfg.AuthTimeout)); err != nil {
		return err
	}
	payload, err := encodeJSON(frame)
	if err != nil {
		return err
	}
	if err := tun.WriteMessage(payload); err != nil {
		return fmt.Errorf("send authorization frame: %w", err)
	}
	raw2, err := tun.ReadMessage()
	if err != nil {
		return fmt.Errorf("read authorization reply: %w", err)
	}
	var ack authAck
	if err := decodeJSON(raw2, &ack); err != nil {
		return fmt.Errorf("authorization reply is not JSON: %w", err)
	}
	if !ack.OK {
		s.count("egress_rejected_" + ack.Code)
		return fmt.Errorf("peer refused the token: %s (%s)", ack.Code, ack.Detail)
	}
	if err := tun.SetDeadline(time.Time{}); err != nil {
		return err
	}

	s.count("egress_ok_" + route.Name)
	s.log.Info("egress_authorized",
		"route", route.Name, "peer", route.Peer, "peer_cert", tun.Peer().CommonName(),
		"binding", tok.Binding, "cnf", tok.Thumbprint, "token_alg", tok.Alg, "post_quantum", tok.PostQuantum,
		"kex", "ML-KEM-768", "peer_sig_alg", tun.Peer().Alg,
		"handshake_ms", ms(hs.Total), "setup_ms", ms(time.Since(start)))

	relay(tun, local)
	return nil
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
```

### `sidecar/ingress.go`

Two checks here are not in the HTTP path, and both exist because a connection is a longer
lived thing than a request:

- **the target must be this sidecar and this route.** The proof carries an `htu`; if it names
  a different destination the frame is refused, so a proof collected from one peer cannot
  open a tunnel to another.
- **the token holder must be the handshake peer.** The `client_id` in the accepted token must
  equal the CN of the certificate that completed the handshake. A token that leaked to
  another xApp cannot be presented over that xApp own tunnel.

```go
package sidecar

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/sidecar/pqtunnel"
	xappresource "github.com/oran-ricsec/xapp-token-binding/xapp-resource"
)

// serveIngress accepts tunnel connections from peer sidecars. A connection reaches
// the application only after the handshake authenticated the peer certificate and the
// validator accepted the access token bound to it.
func (s *Sidecar) serveIngress(ctx context.Context) error {
	l, err := net.Listen("tcp", s.cfg.IngressListen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.cfg.IngressListen, err)
	}
	s.log.Info("ingress_listening", "listen", s.cfg.IngressListen, "routes", len(s.cfg.IngressRoutes))
	return s.acceptLoop(ctx, l, func(raw net.Conn) {
		defer raw.Close()
		if err := s.accept(ctx, raw); err != nil {
			s.log.Warn("ingress_failed", "remote", raw.RemoteAddr().String(), "error", err.Error())
		}
	})
}

func (s *Sidecar) accept(ctx context.Context, raw net.Conn) error {
	start := time.Now()
	tun, err := pqtunnel.Server(ctx, raw, s.tunnelConfig(""))
	if err != nil {
		s.count("ingress_handshake_failed")
		return fmt.Errorf("tunnel handshake: %w", err)
	}
	peer := tun.Peer()
	hs := tun.HandshakeStats()

	if err := tun.SetDeadline(time.Now().Add(s.cfg.AuthTimeout)); err != nil {
		return err
	}
	payload, err := tun.ReadMessage()
	if err != nil {
		s.count("ingress_no_auth_frame")
		return fmt.Errorf("read authorization frame: %w", err)
	}
	var frame authFrame
	if err := decodeJSON(payload, &frame); err != nil {
		return s.refuse(tun, "authorization_frame_malformed", err.Error())
	}
	if frame.Version != authFrameVersion {
		return s.refuse(tun, "authorization_frame_version", fmt.Sprintf("frame version %d is not supported", frame.Version))
	}
	local, ok := s.cfg.IngressTarget(frame.Route)
	if !ok {
		return s.refuse(tun, "route_unknown", fmt.Sprintf("route %q is not served here", frame.Route))
	}

	// The target the proof was minted for must be this sidecar and this route, not
	// some other destination the peer also talks to.
	want := "https://" + s.cfg.IngressAuthority(frame.Route)
	if frame.Target != want {
		return s.refuse(tun, "channel_target_mismatch", fmt.Sprintf("authorization frame targets %q, this route is %q", frame.Target, want))
	}

	p, rej := s.validator.AuthorizeChannel(ctx, xappresource.ChannelRequest{
		Token:     frame.Token,
		Proof:     frame.Proof,
		PeerChain: peer.Chain,
		Target:    frame.Target,
		Operation: xappresource.ChannelOperation,
	})
	if rej != nil {
		s.count("ingress_rejected_" + rej.Code)
		s.log.Warn("ingress_rejected",
			"route", frame.Route, "peer_cert", peer.CommonName(), "client_id", frame.ClientID,
			"reason_code", rej.Code, "reason", rej.Detail, "validation_ms", ms(time.Since(start)))
		return s.refuse(tun, rej.Code, rej.Detail)
	}

	// The token was accepted; the caller it names must also be the peer that
	// completed the handshake, so a stolen token cannot be presented over a tunnel
	// authenticated with a different certificate.
	if p.ClientID != "" && peer.CommonName() != "" && p.ClientID != peer.CommonName() {
		s.count("ingress_rejected_peer_identity_mismatch")
		return s.refuse(tun, "peer_identity_mismatch",
			fmt.Sprintf("token names client %q but the tunnel peer certificate is CN=%q", p.ClientID, peer.CommonName()))
	}

	if err := s.reply(tun, authAck{OK: true, Binding: p.Binding, Peer: s.cfg.Name}); err != nil {
		return err
	}
	if err := tun.SetDeadline(time.Time{}); err != nil {
		return err
	}
	s.count("ingress_ok_" + frame.Route)
	s.log.Info("ingress_authorized",
		"route", frame.Route, "client_id", p.ClientID, "peer_cert", peer.CommonName(), "peer_sig_alg", peer.Alg,
		"binding", p.Binding, "cnf", p.Thumbprint, "kex", "ML-KEM-768",
		"handshake_ms", ms(hs.Total), "authz_ms", ms(time.Since(start)), "target", local)

	app, err := (&net.Dialer{Timeout: s.cfg.DialTimeout}).DialContext(ctx, "tcp", local)
	if err != nil {
		s.count("ingress_app_unreachable")
		return fmt.Errorf("connect to the application at %s: %w", local, err)
	}
	defer app.Close()
	relay(app, tun)
	return nil
}

// refuse sends the reason to the peer and closes the connection.
func (s *Sidecar) refuse(tun *pqtunnel.Conn, code, detail string) error {
	if err := s.reply(tun, authAck{OK: false, Code: code, Detail: detail}); err != nil {
		return err
	}
	return fmt.Errorf("refused: %s (%s)", code, detail)
}

func (s *Sidecar) reply(tun *pqtunnel.Conn, ack authAck) error {
	b, err := encodeJSON(ack)
	if err != nil {
		return err
	}
	return tun.WriteMessage(b)
}
```

### `sidecar/cmd/xapp-sidecar/main.go`

```go
// Command xapp-sidecar is the token-binding sidecar injected next to an xApp.
//
// It is configured entirely from the environment, which the Kyverno injection policy
// fills in from the pod annotations, so the xApp image and the xApp source stay
// untouched. See the sidecar package documentation for the traffic path.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/oran-ricsec/xapp-token-binding/internal/logx"
	"github.com/oran-ricsec/xapp-token-binding/sidecar"
	xappclient "github.com/oran-ricsec/xapp-token-binding/xapp-client"
	xappresource "github.com/oran-ricsec/xapp-token-binding/xapp-resource"
)

func main() {
	log := logx.New("xapp-sidecar")
	cfg, err := sidecar.ConfigFromEnv()
	if err != nil {
		log.Error("invalid sidecar configuration", "error", err)
		os.Exit(2)
	}
	clientCfg, err := xappclient.ConfigFromEnv()
	if err != nil {
		log.Error("invalid client configuration", "error", err)
		os.Exit(2)
	}
	resourceCfg, err := xappresource.ConfigFromEnv()
	if err != nil {
		log.Error("invalid resource configuration", "error", err)
		os.Exit(2)
	}

	s, err := sidecar.New(cfg, clientCfg, resourceCfg, log)
	if err != nil {
		log.Error("sidecar", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if err := s.Run(ctx); err != nil {
		log.Error("sidecar stopped", "error", err)
		os.Exit(1)
	}
	log.Info("sidecar stopped")
}
```

---

## 4. Kyverno injection

Kyverno was not installed on this cluster. It is installed here with the **admission
controller only** - this testbed uses one mutation rule on pod creation and none of the
background, reports or cleanup controllers, and the lab node has little memory to spare.

### `scripts/install-kyverno.sh`

```bash
#!/usr/bin/env bash
# Installs the Kyverno admission controller, which is what injects the sidecar.
#
# Only the admission controller is installed: this testbed uses one mutation rule on
# pod creation and none of the background, reports or cleanup controllers, and the
# lab node has little memory to spare.
set -euo pipefail
CHART_VERSION=${KYVERNO_CHART_VERSION:-3.3.9}

if kubectl get deploy -n kyverno kyverno-admission-controller >/dev/null 2>&1; then
  echo "kyverno already installed:"
  kubectl -n kyverno get deploy kyverno-admission-controller
  exit 0
fi

helm repo add kyverno https://kyverno.github.io/kyverno/ >/dev/null
helm repo update kyverno >/dev/null
helm install kyverno kyverno/kyverno \
  --version "$CHART_VERSION" \
  --namespace kyverno --create-namespace \
  --set admissionController.replicas=1 \
  --set admissionController.container.resources.requests.cpu=100m \
  --set admissionController.container.resources.requests.memory=128Mi \
  --set admissionController.container.resources.limits.memory=384Mi \
  --set backgroundController.enabled=false \
  --set reportsController.enabled=false \
  --set cleanupController.enabled=false \
  --set crds.migration.enabled=false \
  --timeout 10m --wait

kubectl -n kyverno get pods
```

### `deploy/kyverno/sidecar-policy.yaml`

The policy reads five annotations and produces a container, five volumes and a label. The
label is what the sidecar Service selects on, so the Service works whatever the onboarding
chart decides to call the pod.

```yaml
# Kyverno injects the token-binding sidecar into any xApp pod that asks for it with
# annotations. The xApp image, the xApp source and the xApp descriptor containers
# section stay untouched; the descriptor only carries the annotations below, which
# dms_cli passes straight through to the pod template.
#
#   pq.oran/inject     "true"
#   pq.oran/client-id  the OAuth client id, which is also the certificate CN and the
#                      name of the bootstrap secrets (<id>-bootstrap, <id>-bootstrap-pq)
#   pq.oran/method     A, B or C
#   pq.oran/ingress    route|localAddr[,route|localAddr...]
#   pq.oran/egress     route|listenAddr|peerHost:port|peerName[,...]
#
# Everything else - issuer URLs, trust bundle, PQ settings - comes from the
# xapp-token-binding ConfigMap that already exists in the namespace.
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: xapp-token-binding-sidecar
  labels: {part-of: xapp-token-binding}
  annotations:
    policies.kyverno.io/title: xApp token-binding sidecar injection
    policies.kyverno.io/subject: Pod
    policies.kyverno.io/description: >-
      Adds the post-quantum token-binding sidecar, its credentials and its trust
      anchors to annotated xApp pods, so that an unmodified xApp gets
      sender-constrained authorization on both its HTTP and its RMR traffic.
spec:
  background: false
  rules:
    - name: inject-token-binding-sidecar
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: ["${XAPP_NAMESPACE}"]
              annotations:
                pq.oran/inject: "true"
      context:
        - name: clientID
          variable:
            jmesPath: 'request.object.metadata.annotations."pq.oran/client-id"'
        - name: method
          variable:
            jmesPath: 'request.object.metadata.annotations."pq.oran/method" || ''A'''
        - name: ingressRoutes
          variable:
            jmesPath: 'request.object.metadata.annotations."pq.oran/ingress" || '''''
        - name: egressRoutes
          variable:
            jmesPath: 'request.object.metadata.annotations."pq.oran/egress" || '''''
      preconditions:
        all:
          - key: "{{ clientID || '' }}"
            operator: NotEquals
            value: ""
      mutate:
        patchStrategicMerge:
          metadata:
            labels:
              # The sidecar Service selects on this label, so it works whatever the
              # onboarding chart happens to call the pod.
              pq.oran/sidecar: "{{ clientID }}"
          spec:
            volumes:
              - name: pq-bootstrap
                secret:
                  secretName: "{{ clientID }}-bootstrap"
                  defaultMode: 288
              - name: pq-bootstrap-pq
                secret:
                  secretName: "{{ clientID }}-bootstrap-pq"
                  defaultMode: 288
              - name: pq-trust
                configMap:
                  name: ric-trust
              - name: pq-identity
                emptyDir: {medium: Memory}
              - name: pq-identity-pq
                emptyDir: {medium: Memory}
            containers:
              - name: pq-sidecar
                image: ${SIDECAR_IMAGE}
                imagePullPolicy: ${SIDECAR_PULL_POLICY}
                envFrom:
                  - configMapRef: {name: xapp-token-binding}
                env:
                  - {name: SIDECAR_NAME, value: "{{ clientID }}"}
                  - {name: XAPP_CLIENT_ID, value: "{{ clientID }}"}
                  - {name: XAPP_METHOD, value: "{{ method }}"}
                  - {name: SIDECAR_AUTHORITY, value: "{{ clientID }}-sidecar.${XAPP_NAMESPACE}.svc.${CLUSTER_DOMAIN}:${SIDECAR_PORT}"}
                  - {name: SIDECAR_INGRESS_LISTEN, value: ":${SIDECAR_PORT}"}
                  - {name: SIDECAR_INGRESS_ROUTES, value: "{{ ingressRoutes }}"}
                  - {name: SIDECAR_EGRESS_ROUTES, value: "{{ egressRoutes }}"}
                  - {name: SIDECAR_HEALTH_LISTEN, value: ":${SIDECAR_HEALTH_PORT}"}
                ports:
                  - {name: pq-tunnel, containerPort: ${SIDECAR_PORT}}
                  - {name: pq-health, containerPort: ${SIDECAR_HEALTH_PORT}}
                readinessProbe:
                  httpGet: {path: /healthz, port: pq-health, scheme: HTTP}
                  initialDelaySeconds: 5
                  periodSeconds: 10
                  timeoutSeconds: 5
                  failureThreshold: 12
                volumeMounts:
                  - {name: pq-bootstrap, mountPath: /etc/xapp/bootstrap, readOnly: true}
                  - {name: pq-bootstrap-pq, mountPath: /etc/xapp/bootstrap-pq, readOnly: true}
                  - {name: pq-trust, mountPath: /etc/ric-trust, readOnly: true}
                  - {name: pq-identity, mountPath: /var/run/xapp/identity}
                  - {name: pq-identity-pq, mountPath: /var/run/xapp/identity-pq}
                resources:
                  requests: {cpu: 20m, memory: 32Mi}
                  limits: {memory: 128Mi}
                securityContext:
                  runAsNonRoot: true
                  runAsUser: 65532
                  allowPrivilegeEscalation: false
                  readOnlyRootFilesystem: true
                  capabilities: {drop: [ALL]}
```

### `deploy/kyverno/sidecar-services.yaml`

```yaml
# One Service per onboarded xApp, pointing at the injected sidecar rather than at the
# application. It selects on the label the Kyverno policy adds, so it works whatever
# the onboarding chart names the pod, and it publishes only the tunnel port: the
# application ports are never exposed outside the pod.
apiVersion: v1
kind: Service
metadata:
  name: ${SIDECAR_C_CLIENT_ID}-sidecar
  namespace: ${XAPP_NAMESPACE}
  labels: {part-of: xapp-token-binding}
spec:
  selector:
    pq.oran/sidecar: ${SIDECAR_C_CLIENT_ID}
  ports:
    - {name: pq-tunnel, port: ${SIDECAR_PORT}, targetPort: pq-tunnel}
---
apiVersion: v1
kind: Service
metadata:
  name: ${SIDECAR_D_CLIENT_ID}-sidecar
  namespace: ${XAPP_NAMESPACE}
  labels: {part-of: xapp-token-binding}
spec:
  selector:
    pq.oran/sidecar: ${SIDECAR_D_CLIENT_ID}
  ports:
    - {name: pq-tunnel, port: ${SIDECAR_PORT}, targetPort: pq-tunnel}
```

---

## 5. Onboarding with dms_cli

Two prerequisites were missing on the cluster and are set up by this part:

- **ChartMuseum** was not running. `dms_cli` pushes the chart it builds to `CHART_REPO_URL`;
  it is now a systemd unit on port 8090 with local storage under `~/chartstorage`.
- **The local registry** had no image for these xApps. `make demo-app-image` pulls stock
  busybox and pushes it to `127.0.0.1:5000`, which is the registry the descriptors name.

### `xapps/xappc-config.json`

The whole point of this file is what it does *not* contain. The image is stock busybox, the
command is a shell loop that speaks plain HTTP and plain TCP to loopback addresses, and the
only mention of security anywhere is the five annotations that Kyverno reads.

```json
{
  "name": "${SIDECAR_C_XAPP}",
  "version": "1.0.0",
  "annotations": {
    "pq.oran/inject": "true",
    "pq.oran/client-id": "${SIDECAR_C_CLIENT_ID}",
    "pq.oran/method": "${SIDECAR_C_METHOD}",
    "pq.oran/ingress": "http|127.0.0.1:${SIDECAR_APP_HTTP_PORT},rmr|127.0.0.1:${SIDECAR_APP_RMR_PORT}",
    "pq.oran/egress": "http|127.0.0.1:${SIDECAR_LOCAL_HTTP_PORT}|${SIDECAR_D_CLIENT_ID}-sidecar.${XAPP_NAMESPACE}.svc.${CLUSTER_DOMAIN}:${SIDECAR_PORT}|${SIDECAR_D_CLIENT_ID},rmr|127.0.0.1:${SIDECAR_LOCAL_RMR_PORT}|${SIDECAR_D_CLIENT_ID}-sidecar.${XAPP_NAMESPACE}.svc.${CLUSTER_DOMAIN}:${SIDECAR_PORT}|${SIDECAR_D_CLIENT_ID}"
  },
  "containers": [
    {
      "name": "${SIDECAR_C_XAPP}",
      "image": {
        "registry": "${LOCAL_REGISTRY}",
        "name": "${DEMO_APP_IMAGE_NAME}",
        "tag": "${DEMO_APP_IMAGE_TAG}"
      },
      "command": ["/bin/sh"],
      "args": [
        "-c",
        "mkdir -p /tmp/www; echo 'hello from xappc, served over the post-quantum tunnel' > /tmp/www/index.html; httpd -p ${SIDECAR_APP_HTTP_PORT} -h /tmp/www; while true; do nc -l -p ${SIDECAR_APP_RMR_PORT} | sed 's/^/[rmr-in] /'; done & sleep 25; while true; do echo '[http-out] calling the peer xApp through the sidecar'; wget -q -T 25 -O - http://127.0.0.1:${SIDECAR_LOCAL_HTTP_PORT}/ | sed 's/^/[http-in] /'; echo '[rmr-out] sending an RMR message through the sidecar'; echo 'RMR:xappc:hello' | nc -w 10 127.0.0.1 ${SIDECAR_LOCAL_RMR_PORT}; sleep 15; done"
      ]
    }
  ],
  "messaging": {
    "ports": [
      {
        "name": "http",
        "container": "${SIDECAR_C_XAPP}",
        "port": ${SIDECAR_APP_HTTP_PORT},
        "description": "application HTTP port, reachable only through the sidecar"
      },
      {
        "name": "rmr-data",
        "container": "${SIDECAR_C_XAPP}",
        "port": ${SIDECAR_APP_RMR_PORT},
        "description": "RMR data port, reachable only through the sidecar"
      }
    ]
  },
  "controls": {}
}
```

`xapps/xappd-config.json` is the mirror image of it: the same file with C and D exchanged, so
each xApp is both a client and a server and traffic flows both ways.

### `xapps/schema.json`

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "http://o-ran-sc.org/xapp-token-binding-controls.json",
  "type": "object",
  "title": "Controls section of the token-binding demo xApps",
  "description": "These xApps carry no configuration of their own: every security parameter belongs to the sidecar, which Kyverno injects from the pod annotations.",
  "properties": {},
  "additionalProperties": false
}
```

### `scripts/onboard-sidecar-xapps.sh`

The `shcema_file_path` spelling is not a typo in this script; it is the spelling
`xapp_onboarder` uses on the command line.

```bash
#!/usr/bin/env bash
# Onboards the two sidecar demo xApps the way an operator would: render the
# descriptors, hand them to dms_cli, then install the resulting Helm charts.
#
# Nothing here mentions the sidecar. The descriptors carry annotations; Kyverno turns
# those into a container at admission time.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

: "${XAPP_NAMESPACE:?}" "${SIDECAR_C_XAPP:?}" "${SIDECAR_D_XAPP:?}" "${CHART_REPO_URL:?}"
export CHART_REPO_URL

out=out/rendered/xapps
mkdir -p "$out"
build/render.sh xapps/schema.json > "$out/schema.json"

onboard() {
  local xapp=$1 src=$2
  build/render.sh "$src" > "$out/$xapp-config.json"
  python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$out/$xapp-config.json"
  echo "== onboarding $xapp"
  # The flag really is spelled shcema_file_path in xapp_onboarder.
  dms_cli onboard --config_file_path="$ROOT/$out/$xapp-config.json" --shcema_file_path="$ROOT/$out/schema.json"
}

install() {
  local xapp=$1
  if helm status -n "$XAPP_NAMESPACE" "$xapp" >/dev/null 2>&1; then
    echo "== removing the previous $xapp release"
    dms_cli uninstall --xapp_chart_name="$xapp" --namespace="$XAPP_NAMESPACE" || true
    # The bootstrap credential is one-time, so the old pod must be gone before the new
    # one starts; a second enrollment with the same credential is refused, by design.
    kubectl -n "$XAPP_NAMESPACE" wait --for=delete pod \
      -l "app=$XAPP_NAMESPACE-$xapp" --timeout=120s >/dev/null 2>&1 || true
  fi
  echo "== installing $xapp into $XAPP_NAMESPACE"
  dms_cli install --xapp_chart_name="$xapp" --version=1.0.0 --namespace="$XAPP_NAMESPACE"
}

onboard "$SIDECAR_C_XAPP" xapps/xappc-config.json
onboard "$SIDECAR_D_XAPP" xapps/xappd-config.json

install "$SIDECAR_C_XAPP"
install "$SIDECAR_D_XAPP"

echo
echo "onboarded xApps:"
kubectl -n "$XAPP_NAMESPACE" get pods -l 'pq.oran/sidecar' -o wide
```

---

## 6. Configuration and build

`config/testbed.env` gained one block, and everything else is derived from it:

```
SIDECAR_PORT=4570              SIDECAR_HEALTH_PORT=8081
SIDECAR_IMAGE=ricsec/xapp-sidecar:0.1.0
LOCAL_REGISTRY=127.0.0.1:5000  CHART_REPO_URL=http://localhost:8090
SIDECAR_C_XAPP=xappc  SIDECAR_C_CLIENT_ID=xapp-sidecar-c  SIDECAR_C_METHOD=A
SIDECAR_D_XAPP=xappd  SIDECAR_D_CLIENT_ID=xapp-sidecar-d  SIDECAR_D_METHOD=C
SIDECAR_APP_HTTP_PORT=8080     SIDECAR_LOCAL_HTTP_PORT=18080
SIDECAR_APP_RMR_PORT=4560      SIDECAR_LOCAL_RMR_PORT=14560
DEMO_APP_IMAGE_NAME=oran/busybox  DEMO_APP_IMAGE_TAG=1.36
KYVERNO_CHART_VERSION=3.3.9
```

C uses method A and D uses method C deliberately: one deployment then exercises both binding
checks on the tunnel, the certificate one in one direction and the proof one in the other.

The realm gained two clients, `xapp-sidecar-c` (certificate-bound) and `xapp-sidecar-d`
(DPoP-bound), configured exactly like their in-process counterparts.

New targets:

```bash
make sidecar-up        # build, install Kyverno, apply the policy, onboard both xApps
make kyverno           # the admission controller, idempotent
make demo-app-image    # publish stock busybox to the local registry
make sidecar-policy    # the ClusterPolicy and the two Services
make bootstrap-sidecar-xapps   # one-time SMO bootstrap credentials
make onboard-xapps     # dms_cli onboard + install
make sidecar-status    # pods and services
make sidecar-logs      # the authorization decisions
make sidecar-down      # remove all of it
```

The sidecar requires `PQ_MODE=true`: the tunnel authenticates peers with ML-DSA
certificates, and it refuses to start without one rather than falling back to anything
classical.

---

## 7. What it looks like when it runs

The pods come up with two containers each, and neither xApp image knows why:

```
NAME                             READY   STATUS    RESTARTS   AGE
ricxapp-xappc-6d554d74f8-hfjqp   2/2     Running   0          4m42s
ricxapp-xappd-655f989cf4-nls92   2/2     Running   0          4m8s
```

The sidecar enrols both credentials and starts its listeners:

```json
{"msg":"identity_enrolled","plane":"post-quantum","key_alg":"ML-DSA-65",
 "cert_bytes":5662,"x5t#S256":"-9TYdBaNW7WrK73ABKP7Sn-v3qfNAWpR1BLN9u9md6g","ca_roundtrip_ms":642.9}
{"msg":"sidecar_ready","sidecar":"xapp-sidecar-c","method":"A","ingress":":4570","egress_routes":2}
{"msg":"egress_listening","route":"http","listen":"127.0.0.1:18080",
 "peer":"xapp-sidecar-d-sidecar.ricxapp.svc.cluster.local:4570","peer_name":"xapp-sidecar-d"}
```

Outgoing, method A, certificate-bound:

```json
{"msg":"egress_authorized","route":"http","peer_cert":"xapp-sidecar-d",
 "binding":"x5t#S256","cnf":"-9TYdBaNW7WrK73ABKP7Sn-v3qfNAWpR1BLN9u9md6g",
 "token_alg":"ML-DSA-65","post_quantum":true,"kex":"ML-KEM-768","peer_sig_alg":"ML-DSA-65",
 "handshake_ms":5.61,"setup_ms":717.5}
```

Incoming from the other xApp, method C, proof-bound:

```json
{"msg":"ingress_authorized","route":"rmr","client_id":"xapp-sidecar-d",
 "peer_cert":"xapp-sidecar-d","binding":"jkt","cnf":"6F_NSrkzvAOrOB5mZI_4G2Nq_qTldlCp6p4XTI5Htos",
 "kex":"ML-KEM-768","handshake_ms":4.18,"authz_ms":6.17,"target":"127.0.0.1:4560"}
```

And the two unmodified applications, which see nothing but plain HTTP and plain TCP:

```
[http-out] calling the peer xApp through the sidecar
[http-in] hello from xappd, served over the post-quantum tunnel
[rmr-out] sending an RMR message through the sidecar
[rmr-in] RMR:xappd:hello
```

A connection that is not a tunnel gets nowhere near the application:

```
$ kubectl -n ricxapp run pq-probe --image=...busybox --command -- \
    sh -c 'echo NOT-A-PQ-HANDSHAKE | nc -w 5 xapp-sidecar-d-sidecar.ricxapp.svc.cluster.local 4570'

{"level":"WARN","msg":"ingress_failed","sidecar":"xapp-sidecar-d","remote":"10.244.0.148:35677",
 "error":"tunnel handshake: read client hello: pqtunnel: frame exceeds maximum size"}
```

Handshake cost, measured in the pod: **2 to 13 ms**, which is the ML-KEM key generation or
encapsulation plus one ML-DSA-65 signature and one verification. First connection setup is
higher (about 700 ms) because it includes obtaining the token and upgrading it at the shim;
subsequent connections reuse the cached token.

---

## 8. Tests

```bash
go test ./sidecar/... ./xapp-resource/...
```

| Test | What it establishes |
|---|---|
| `TestHandshakeAndRecords` | Both peers authenticate, and a payload larger than one record survives the split, the counters and both keys. |
| `TestControlMessages` | The authorization frame framing round trips. |
| `TestUntrustedPeerIsRejected` | A certificate from another CA does not complete a handshake. |
| `TestWrongPeerNameIsRejected` | Connecting to the wrong peer fails, so a hijacked Service address is not enough. |
| `TestTamperedRecordFailsAuthentication` | A forged record with a valid nonce is refused. |
| `TestCloseWritePropagatesEOF` | A half-close reaches the peer application, and the reverse direction still works. |
| `TestChannelCertificateBinding` | A token bound to another certificate, or presented with no certificate, or with no `cnf` at all, is refused on the tunnel. |
| `TestChannelProofBinding` | A proof for another target is refused, a replayed proof is refused, and a `jkt` token with no proof is refused. |

The 46-case suite from part 5 still covers the HTTP path; it is classical-only and now says
so instead of failing for the wrong reason when the deployment is post-quantum.

---

## 9. Scope and limits

**Out of scope, as agreed:** SDL and Redis. The sidecar relays opaque TCP, so SDL traffic
would ride the same path, but nothing here is specific to it.

**One tunnel per application connection.** There is no connection pool. It costs one
handshake, measured above at a few milliseconds, and it keeps the authorization decision and
the connection one-to-one - two streams can never share one authorization.

**The application ports are not firewalled.** The sidecar is the only path *in through the
tunnel*, but the busybox demo binds its ports on all interfaces and the onboarding chart
publishes Services for them, so another pod in the cluster could reach the application
directly. In a real deployment a NetworkPolicy restricting the application ports to loopback
is what closes that, and the demo does not ship one.

**Interoperability with the existing liboqs tunnel is untested.** The algorithms and the
message shape match; the exact field framing and the key schedule do not, so the two would
need a byte-level reconciliation to talk to each other.
