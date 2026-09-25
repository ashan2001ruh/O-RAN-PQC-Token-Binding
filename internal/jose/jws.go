package jose

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v4/jws"
)

// JWS is a compact JWS whose header and payload have been decoded for inspection
// but whose signature has NOT been checked yet. Verification is done by jwx in
// VerifySignature, which re-verifies the original compact serialisation.
type JWS struct {
	Compact string
	Header  map[string]any
	Payload []byte
}

// ParseCompact splits and decodes a compact JWS. It performs no verification.
func ParseCompact(token string) (*JWS, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("compact JWS must have 3 parts, got %d", len(parts))
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("header is not base64url: %w", err)
	}
	header, err := decodeObject(hb)
	if err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload is not base64url: %w", err)
	}
	if _, err := b64.DecodeString(parts[2]); err != nil {
		return nil, fmt.Errorf("signature is not base64url: %w", err)
	}
	return &JWS{Compact: token, Header: header, Payload: payload}, nil
}

func decodeObject(b []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("not a JSON object")
	}
	return m, nil
}

func (j *JWS) headerString(name string) string {
	s, _ := j.Header[name].(string)
	return s
}

// Alg returns the "alg" header.
func (j *JWS) Alg() string { return j.headerString("alg") }

// Kid returns the "kid" header.
func (j *JWS) Kid() string { return j.headerString("kid") }

// Typ returns the "typ" header.
func (j *JWS) Typ() string { return j.headerString("typ") }

// Claims decodes the payload as a JSON object (numbers kept as json.Number).
func (j *JWS) Claims() (map[string]any, error) { return decodeObject(j.Payload) }

// VerifySignature verifies the signature with key, dispatching on the "alg"
// header through jwx. The same call handles ES256 and ML-DSA-65 alike.
func (j *JWS) VerifySignature(key any) error {
	alg, err := LookupAlg(j.Alg())
	if err != nil {
		return err
	}
	k, err := asKey(key)
	if err != nil {
		return fmt.Errorf("verification key unusable: %w", err)
	}
	if _, err := jws.Verify([]byte(j.Compact), jws.WithKey(alg, k)); err != nil {
		return err
	}
	return nil
}
