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

	wmu     sync.Mutex
	seal    cipher.AEAD
	wIV     [4]byte
	wSeq    uint64
	wClosed bool

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
