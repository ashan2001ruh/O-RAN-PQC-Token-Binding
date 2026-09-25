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
