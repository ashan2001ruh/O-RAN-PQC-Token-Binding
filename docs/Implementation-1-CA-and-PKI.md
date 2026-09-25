# Implementation Part 1: Configuration, PKI and the RIC CA

This series documents the complete implementation of sender-constrained (bound) access tokens
for O-RAN xApps, with every source file included so the system can be rebuilt from these
documents alone.

| Part | Contents |
|---|---|
| 1 (this file) | module layout, configuration, shared packages, PKI generation, SMO onboarding, the RIC CA service |
| 2 | Keycloak as the authorization server: manifest, realm, rendering helpers, verification |
| 3 | the xApp client library, the resource-side validator, and the demo xApps |
| 4 | the post-quantum phase: ML-DSA, ML-KEM and the token shim |
| 5 | build orchestration, the walkthrough CLI, the security suite and the benchmarks |

**What this part builds.** A two-level PKI (a simulated SMO root, an onboarding CA for
one-time bootstrap credentials, and a RIC intermediate CA), and an enrollment service that
issues xApp identity certificates. The certificate lifetime is a request parameter, which is
the only thing that separates Method A (long-lived identity) from Method B (ephemeral,
rotated identity). The same service has two issuing branches, classical and ML-DSA, and picks
one from the key type in the CSR.

**Prerequisites**: a working OSC Near-RT RIC, `kubectl`, `docker`, `ctr`, `openssl`, `jq`,
`envsubst`, `make`, and Go 1.27 or newer (needed for `crypto/mldsa`).

## Files in this part

| File | Lines | Purpose |
|---|---|---|
| `go.mod` | 11 | One dependency: `lestrrat-go/jwx/v4` for JOSE. Everything cryptographic comes from the Go 1.27 standard library. |
| `config/testbed.env` | 71 | The single source of configuration. The Makefile exports these and renders the manifests and the realm from them. |
| `internal/config/env.go` | 107 | Environment parsing. Errors accumulate so a misconfigured pod reports every problem in one message. |
| `internal/logx/logx.go` | 23 | Structured JSON logging. Every authorization decision is logged through this. |
| `internal/netx/netx.go` | 94 | HTTP transports, the dial overrides that let node-side tools reach cluster Services by their in-cluster DNS names, RFC 9449 `htu` normalisation, and the ML-KEM curve preference. |
| `internal/pki/pki.go` | 249 | PEM handling, key generation (EC and ML-DSA), the RFC 8705 `x5t#S256` thumbprint, and chain verification that classifies the failure (expired, untrusted, bad usage) so the validator can produce a precise reason code. |
| `ca/scripts/openssl.cnf` | 27 | Extension profiles for the classical branch. |
| `ca/scripts/gen-pki.sh` | 83 | Generates the classical hierarchy and the server certificates, verifies the chains with `openssl verify`, then calls `pki-gen` for the post-quantum branch. |
| `ca/cmd/pki-gen/main.go` | 216 | The post-quantum PKI generator: ML-DSA root, onboarding CA, RIC intermediate CA and TLS server certificates, all through `crypto/x509`. |
| `internal/smo/bootstrap.go` | 104 | Issues a bootstrap certificate for one identity. `KeyAlg` selects EC or ML-DSA, so onboarding itself can be post-quantum. |
| `ca/cmd/smo-sim/main.go` | 55 | CLI wrapper used by the Makefile to mint bootstrap credentials and write them as `tls.crt` / `tls.key`. |
| `ca/enroll/server.go` | 393 | The issuing logic, the dual issuing branches (an ML-DSA CSR is signed by the ML-DSA CA), the key policy and the rejection reasons. |
| `ca/enroll/ledger.go` | 72 | The append-only ledger that makes every bootstrap credential single use. The entry is written and fsynced before the certificate is signed. |
| `ca/cmd/ric-ca/main.go` | 53 | The service binary: TLS 1.3, `RequestClientCert` so the handler can verify the chain against the pool that matches the endpoint. |
| `build/Dockerfile` | 6 | One image recipe for all binaries, selected with `--build-arg BIN=`. |
| `ca/k8s/ric-ca.yaml` | 84 | Deployment and Service in `ricsec`. Both issuing branches are mounted, and both trust anchors are configured. |
| `build/verify-ca.sh` | 51 | Issues a leaf with a bootstrap credential, verifies the chain with `openssl verify`, proves the bootstrap credential is refused the second time, and obtains a long-lived certificate from the same code path through `/v1/renew`. |

---

## 1. Module and configuration

The project is a single Go module with exactly one third-party dependency, and a single configuration file from which every manifest, certificate and URL is derived. No hostname, port or distinguished name is hard-coded anywhere else.

### `go.mod`

One dependency: `lestrrat-go/jwx/v4` for JOSE. Everything cryptographic comes from the Go 1.27 standard library.

```go
module github.com/oran-ricsec/xapp-token-binding

go 1.27

require github.com/lestrrat-go/jwx/v4 v4.5.0

require (
	github.com/lestrrat-go/dsig v1.4.0 // indirect
	github.com/lestrrat-go/option/v3 v3.0.0-alpha1 // indirect
	github.com/valyala/fastjson v1.6.10 // indirect
)
```

### `config/testbed.env`

The single source of configuration. The Makefile exports these and renders the manifests and the realm from them.

```bash
# Single source of configuration for the testbed.
# The Makefile exports every variable below; Kubernetes manifests, the realm export
# and the PKI script are rendered from them. Nothing else carries hostnames, ports or DNs.

# --- Kubernetes -------------------------------------------------------------
RICSEC_NAMESPACE=ricsec
XAPP_NAMESPACE=ricxapp
CLUSTER_DOMAIN=cluster.local
IMAGE_TAG=0.1.0

# --- Identity / PKI ---------------------------------------------------------
ORG=O-RAN-RIC
XAPP_OU=xApps
ROOT_CA_DAYS=3650
INTERMEDIATE_CA_DAYS=1825
SERVER_CERT_DAYS=365
BOOTSTRAP_CERT_VALIDITY=24h

# --- RIC intermediate CA (enrollment service) --------------------------------
RIC_CA_SERVICE=ric-ca
RIC_CA_PORT=8443
CA_DEFAULT_LEAF_LIFETIME=24h
CA_MIN_LEAF_LIFETIME=5s
CA_MAX_LEAF_LIFETIME=720h
# Method A: long-term identity; Method B: ephemeral identity (same code path, different parameter)
LONGTERM_CERT_LIFETIME=168h
EPHEMERAL_CERT_LIFETIME=15m

# --- Keycloak (XRF) ----------------------------------------------------------
KEYCLOAK_SERVICE=keycloak
KEYCLOAK_PORT=8443
KEYCLOAK_XFCC_PORT=9443
KEYCLOAK_REALM=ric-realm
# Keycloak 26.6.0 (image already present on the lab VM; DPoP is fully supported from 26.4)
KEYCLOAK_IMAGE=quay.io/keycloak/keycloak@sha256:b0e5dbced1775de4d629f103c0a9cfc057decc62ce8d3cb1c54f8849a6c6eb62
KEYCLOAK_HEAP=-Xms256m -Xmx512m
ACCESS_TOKEN_LIFESPAN=300

# --- Authorization -----------------------------------------------------------
TOKEN_AUDIENCE=ric-xapps
TOKEN_SCOPE=ric-sdl-access
REQUIRED_ROLE=ric-sdl-access

# --- Demo xApps --------------------------------------------------------------
XAPP_PORT=8443
XAPP_A_NAME=xapp-a
XAPP_A_METHOD=A
XAPP_A_CLIENT_ID=xapp-longterm
XAPP_B_NAME=xapp-b
XAPP_B_METHOD=B
XAPP_B_CLIENT_ID=xapp-ephemeral
PEER_INTERVAL=30s

# --- Post-quantum phase (ML-DSA signatures, ML-KEM key exchange) ---------------
# PQ_MODE switches the demo xApps and the scripts to post-quantum credentials.
# Keycloak stays classical: Java 21 supports neither ML-DSA nor ML-KEM.
PQ_MODE=false
PQ_SHIM_SERVICE=pq-shim
PQ_SHIM_PORT=8443
# Token signature algorithm used by the shim (FIPS 204 / RFC 9964)
PQ_SIGNING_ALG=ML-DSA-65
# xApp post-quantum identity certificate and DPoP proof key
PQ_IDENTITY_KEY_ALG=ML-DSA-65
PQ_DPOP_ALG=ML-DSA-44
# Post-quantum PKI parameter sets
PQ_ROOT_ALG=ML-DSA-87
PQ_CA_ALG=ML-DSA-65
PQ_SERVER_ALG=ML-DSA-65
# Require the hybrid ML-KEM group (X25519MLKEM768) on every post-quantum TLS leg
PQ_KEX_ONLY=true
PQ_TOKEN_LIFETIME=300s
```

---

## 2. Shared internal packages

Four small packages used by every component: environment parsing that reports all errors at once, a JSON logger, HTTP transports plus the DPoP `htu` normalisation, and the certificate helpers (thumbprints, chain verification with classified failures, key generation).

### `internal/config/env.go`

Environment parsing. Errors accumulate so a misconfigured pod reports every problem in one message.

```go
// Package config reads component configuration from environment variables,
// collecting every problem so a misconfigured pod reports all of them at once.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Env accumulates parse errors while reading variables.
type Env struct {
	errs []error
}

func (e *Env) lookup(key string) (string, bool) {
	v, ok := os.LookupEnv(key)
	v = strings.TrimSpace(v)
	return v, ok && v != ""
}

// Str returns the variable or def when unset.
func (e *Env) Str(key, def string) string {
	if v, ok := e.lookup(key); ok {
		return v
	}
	return def
}

// Req returns the variable and records an error when it is unset.
func (e *Env) Req(key string) string {
	v, ok := e.lookup(key)
	if !ok {
		e.errs = append(e.errs, fmt.Errorf("%s is required", key))
	}
	return v
}

// Dur parses a Go duration (e.g. 15m, 168h).
func (e *Env) Dur(key string, def time.Duration) time.Duration {
	v, ok := e.lookup(key)
	if !ok {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s: %w", key, err))
		return def
	}
	return d
}

// Int parses a decimal integer.
func (e *Env) Int(key string, def int) int {
	v, ok := e.lookup(key)
	if !ok {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s: %w", key, err))
		return def
	}
	return n
}

// Bool parses true/false/1/0.
func (e *Env) Bool(key string, def bool) bool {
	v, ok := e.lookup(key)
	if !ok {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s: %w", key, err))
		return def
	}
	return b
}

// List splits a comma-separated variable, dropping empty items.
func (e *Env) List(key string, def []string) []string {
	v, ok := e.lookup(key)
	if !ok {
		return def
	}
	var out []string
	for _, item := range strings.Split(v, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// Fail records a validation error discovered by the caller.
func (e *Env) Fail(format string, args ...any) {
	e.errs = append(e.errs, fmt.Errorf(format, args...))
}

// Err returns all accumulated errors, or nil.
func (e *Env) Err() error {
	return errors.Join(e.errs...)
}
```

### `internal/logx/logx.go`

Structured JSON logging. Every authorization decision is logged through this.

```go
// Package logx builds the structured (JSON) logger used by every component.
package logx

import (
	"log/slog"
	"os"
	"strings"
)

// New returns a JSON logger tagged with the component name. LOG_LEVEL selects the level.
func New(component string) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	return slog.New(h).With("component", component)
}
```

### `internal/netx/netx.go`

HTTP transports, the dial overrides that let node-side tools reach cluster Services by their in-cluster DNS names, RFC 9449 `htu` normalisation, and the ML-KEM curve preference.

```go
// Package netx provides HTTP transports and the DPoP htu normalisation shared by
// the client and the resource server.
package netx

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ParseDialOverrides parses "host:port=ip:port,host2:port=ip:port". It lets tools
// running on the node reach cluster Services by their in-cluster DNS names (so TLS
// server-name checks and DPoP htu values stay identical) without editing /etc/hosts.
func ParseDialOverrides(spec string) (map[string]string, error) {
	out := map[string]string{}
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		from, to, ok := strings.Cut(item, "=")
		if !ok {
			return nil, fmt.Errorf("dial override %q is not host:port=ip:port", item)
		}
		out[strings.TrimSpace(from)] = strings.TrimSpace(to)
	}
	return out, nil
}

// NewTransport returns an HTTP/1.1 transport using tlsConf and the dial overrides.
func NewTransport(tlsConf *tls.Config, overrides map[string]string) *http.Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if target, ok := overrides[addr]; ok {
				addr = target
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:     tlsConf,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        256,
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout:     90 * time.Second,
	}
}

// NormalizeHTU canonicalises a URL for DPoP htu comparison (RFC 9449 §4.3): scheme
// and host lower-cased, default port removed, query and fragment dropped.
func NormalizeHTU(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("htu %q is not an absolute URL", raw)
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path, nil
}

// CurvePreferences returns the TLS key-exchange groups to offer. With pqOnly the
// connection must use the hybrid ML-KEM group X25519MLKEM768 (RFC 9370 style hybrid
// of X25519 and ML-KEM-768), so a classical-only peer fails the handshake instead of
// silently negotiating a quantum-vulnerable key exchange. Otherwise Go's default
// order applies, which already prefers X25519MLKEM768 and falls back to X25519.
func CurvePreferences(pqOnly bool) []tls.CurveID {
	if pqOnly {
		return []tls.CurveID{tls.X25519MLKEM768}
	}
	return nil
}

// IsPQKex reports whether a negotiated group provides post-quantum key exchange.
func IsPQKex(id tls.CurveID) bool { return id == tls.X25519MLKEM768 }
```

### `internal/pki/pki.go`

PEM handling, key generation (EC and ML-DSA), the RFC 8705 `x5t#S256` thumbprint, and chain verification that classifies the failure (expired, untrusted, bad usage) so the validator can produce a precise reason code.

```go
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
```

---

## 3. PKI generation

The classical hierarchy is generated with OpenSSL, the post-quantum one with `crypto/x509`, because OpenSSL 1.1.1 on the lab VM predates ML-DSA. Both write into `out/pki`.

Hierarchy:

```
SMO Root CA (offline, key never enters the cluster)
 |- SMO Onboarding CA   -> one-time bootstrap certificates (OU=bootstrap)
 |- RIC Intermediate CA -> xApp operational identity certificates
```

The same shape is generated a second time with ML-DSA keys for the post-quantum branch.

### `ca/scripts/openssl.cnf`

Extension profiles for the classical branch.

```ini
# Extension profiles for the simulated SMO / RIC PKI (used by gen-pki.sh).
SAN = DNS:unused

[ req ]
distinguished_name = dn
prompt             = no

[ dn ]

[ v3_root ]
basicConstraints     = critical, CA:TRUE
keyUsage             = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash

[ v3_intermediate ]
basicConstraints       = critical, CA:TRUE, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always

[ v3_server ]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature
extendedKeyUsage       = serverAuth
subjectAltName         = ${ENV::SAN}
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
```

### `ca/scripts/gen-pki.sh`

Generates the classical hierarchy and the server certificates, verifies the chains with `openssl verify`, then calls `pki-gen` for the post-quantum branch.

```bash
#!/usr/bin/env bash
# Generates the testbed PKI:
#   smo-root-ca          simulated SMO root CA (offline: its key never enters the cluster)
#   smo-onboarding-ca    simulated SMO onboarding CA, issues one-time bootstrap certificates
#   ric-intermediate-ca  RIC intermediate CA, issues xApp operational identity certificates
#   keycloak-server      TLS server certificate for Keycloak (XRF)
#   ric-ca-server        TLS server certificate for the enrollment service
# Configuration comes from config/testbed.env (exported by the Makefile).
set -euo pipefail

OUT=${1:?usage: gen-pki.sh <out-dir>}
: "${ORG:?}" "${RICSEC_NAMESPACE:?}" "${CLUSTER_DOMAIN:?}" "${KEYCLOAK_SERVICE:?}" "${RIC_CA_SERVICE:?}"
: "${ROOT_CA_DAYS:=3650}" "${INTERMEDIATE_CA_DAYS:=1825}" "${SERVER_CERT_DAYS:=365}"

HERE=$(cd "$(dirname "$0")" && pwd)
CNF="$HERE/openssl.cnf"
mkdir -p "$OUT"

generate_classical=1
if [[ -f "$OUT/ric-intermediate-ca.crt" ]]; then
  echo "classical PKI already present in $OUT (remove the directory to regenerate)"
  generate_classical=0
fi

if [[ $generate_classical == 1 ]]; then

newkey() { # newkey <file> <curve>
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:"$2" -out "$1"
  chmod 600 "$1"
}

sign() { # sign <name> <subject> <extension-section> <days> <issuer-name> <curve>
  local name=$1 subj=$2 ext=$3 days=$4 issuer=$5 curve=$6
  newkey "$OUT/$name.key" "$curve"
  openssl req -new -key "$OUT/$name.key" -subj "$subj" -config "$CNF" -out "$OUT/$name.csr"
  openssl x509 -req -in "$OUT/$name.csr" -CA "$OUT/$issuer.crt" -CAkey "$OUT/$issuer.key" \
    -set_serial "0x$(openssl rand -hex 16)" -days "$days" -sha384 \
    -extfile "$CNF" -extensions "$ext" -out "$OUT/$name.crt"
  rm -f "$OUT/$name.csr"
}

export SAN="DNS:unused"

echo "==> SMO root CA (simulated)"
newkey "$OUT/smo-root-ca.key" P-384
openssl req -x509 -new -key "$OUT/smo-root-ca.key" -sha384 -days "$ROOT_CA_DAYS" \
  -subj "/O=${ORG}/OU=SMO/CN=SMO Root CA (simulated)" \
  -config "$CNF" -extensions v3_root -out "$OUT/smo-root-ca.crt"

echo "==> SMO onboarding CA (bootstrap credentials)"
sign smo-onboarding-ca "/O=${ORG}/OU=SMO/CN=SMO Onboarding CA (simulated)" v3_intermediate "$INTERMEDIATE_CA_DAYS" smo-root-ca P-384

echo "==> RIC intermediate CA"
sign ric-intermediate-ca "/O=${ORG}/OU=Near-RT RIC/CN=RIC Intermediate CA" v3_intermediate "$INTERMEDIATE_CA_DAYS" smo-root-ca P-384

svc_sans() { # svc_sans <service> -> SAN list for an in-cluster Service
  local s=$1 ns=$RICSEC_NAMESPACE
  echo "DNS:${s}.${ns}.svc.${CLUSTER_DOMAIN},DNS:${s}.${ns}.svc,DNS:${s}.${ns},DNS:${s},DNS:localhost,IP:127.0.0.1"
}

echo "==> Keycloak server certificate"
export SAN; SAN=$(svc_sans "$KEYCLOAK_SERVICE")
sign keycloak-server "/O=${ORG}/OU=XRF/CN=${KEYCLOAK_SERVICE}.${RICSEC_NAMESPACE}.svc.${CLUSTER_DOMAIN}" v3_server "$SERVER_CERT_DAYS" ric-intermediate-ca P-256

echo "==> RIC CA enrollment service server certificate"
SAN=$(svc_sans "$RIC_CA_SERVICE")
sign ric-ca-server "/O=${ORG}/OU=RIC CA/CN=${RIC_CA_SERVICE}.${RICSEC_NAMESPACE}.svc.${CLUSTER_DOMAIN}" v3_server "$SERVER_CERT_DAYS" ric-intermediate-ca P-256

# Chains: servers present leaf+intermediate; relying parties trust the RIC intermediate.
cat "$OUT/keycloak-server.crt" "$OUT/ric-intermediate-ca.crt" > "$OUT/keycloak-server-chain.crt"
cat "$OUT/ric-ca-server.crt" "$OUT/ric-intermediate-ca.crt" > "$OUT/ric-ca-server-chain.crt"
cat "$OUT/ric-intermediate-ca.crt" "$OUT/smo-root-ca.crt" > "$OUT/ric-ca-bundle.crt"
rm -f "$OUT"/*.srl

echo "==> Verifying chains"
openssl verify -CAfile "$OUT/smo-root-ca.crt" "$OUT/ric-intermediate-ca.crt" "$OUT/smo-onboarding-ca.crt"
openssl verify -CAfile "$OUT/smo-root-ca.crt" -untrusted "$OUT/ric-intermediate-ca.crt" "$OUT/keycloak-server.crt" "$OUT/ric-ca-server.crt"
fi

# Post-quantum branch: ML-DSA root, onboarding CA, RIC intermediate CA and server
# certificates. OpenSSL 1.1.1 on this VM predates ML-DSA, so crypto/x509 does it.
echo "==> Post-quantum branch (ML-DSA, crypto/x509)"
"${PKI_GEN:-out/bin/pki-gen}" -out "$OUT" -org "$ORG" -cluster-domain "$CLUSTER_DOMAIN"   -root-alg "${PQ_ROOT_ALG:-ML-DSA-87}" -ca-alg "${PQ_CA_ALG:-ML-DSA-65}" -server-alg "${PQ_SERVER_ALG:-ML-DSA-65}"   -service "${RIC_CA_SERVICE}:${RICSEC_NAMESPACE}" -service "${PQ_SHIM_SERVICE:-pq-shim}:${RICSEC_NAMESPACE}"
```

### `ca/cmd/pki-gen/main.go`

The post-quantum PKI generator: ML-DSA root, onboarding CA, RIC intermediate CA and TLS server certificates, all through `crypto/x509`.

```go
// Command pki-gen generates the post-quantum branch of the testbed PKI with
// crypto/x509 and crypto/mldsa: a simulated SMO root, an SMO onboarding CA, the RIC
// intermediate CA and TLS server certificates, all signed with ML-DSA (FIPS 204).
//
// The classical branch is still generated by ca/scripts/gen-pki.sh with OpenSSL;
// OpenSSL 1.1.1 on the lab VM predates ML-DSA, which is why this tool exists.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/pki"
)

type serviceFlag []string

func (s *serviceFlag) String() string { return strings.Join(*s, ",") }
func (s *serviceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	out := flag.String("out", "out/pki", "output directory")
	org := flag.String("org", "O-RAN-RIC", "organization")
	clusterDomain := flag.String("cluster-domain", "cluster.local", "Kubernetes cluster domain")
	rootAlg := flag.String("root-alg", "ML-DSA-87", "root CA key algorithm")
	caAlg := flag.String("ca-alg", "ML-DSA-65", "intermediate CA key algorithm")
	serverAlg := flag.String("server-alg", "ML-DSA-65", "server certificate key algorithm")
	rootDays := flag.Int("root-days", 3650, "root CA validity in days")
	caDays := flag.Int("ca-days", 1825, "intermediate CA validity in days")
	serverDays := flag.Int("server-days", 365, "server certificate validity in days")
	var services serviceFlag
	flag.Var(&services, "service", "server certificate to issue, as name:namespace (repeatable)")
	flag.Parse()

	if err := run(*out, *org, *clusterDomain, *rootAlg, *caAlg, *serverAlg, *rootDays, *caDays, *serverDays, services); err != nil {
		fmt.Fprintln(os.Stderr, "pki-gen:", err)
		os.Exit(1)
	}
}

type issuer struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func run(out, org, clusterDomain, rootAlg, caAlg, serverAlg string, rootDays, caDays, serverDays int, services []string) error {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(out, "ric-intermediate-ca-pq.crt")); err == nil {
		fmt.Printf("post-quantum PKI already present in %s (remove the files to regenerate)\n", out)
		return nil
	}

	root, err := selfSignedCA(out, "smo-root-ca-pq", rootAlg,
		pkix.Name{Organization: []string{org}, OrganizationalUnit: []string{"SMO"}, CommonName: "SMO Root CA PQ (simulated)"}, rootDays)
	if err != nil {
		return fmt.Errorf("root CA: %w", err)
	}
	onboarding, err := subCA(out, "smo-onboarding-ca-pq", caAlg,
		pkix.Name{Organization: []string{org}, OrganizationalUnit: []string{"SMO"}, CommonName: "SMO Onboarding CA PQ (simulated)"}, caDays, root)
	if err != nil {
		return fmt.Errorf("onboarding CA: %w", err)
	}
	intermediate, err := subCA(out, "ric-intermediate-ca-pq", caAlg,
		pkix.Name{Organization: []string{org}, OrganizationalUnit: []string{"Near-RT RIC"}, CommonName: "RIC Intermediate CA PQ"}, caDays, root)
	if err != nil {
		return fmt.Errorf("intermediate CA: %w", err)
	}
	_ = onboarding

	for _, svc := range services {
		name, ns, ok := strings.Cut(svc, ":")
		if !ok {
			return fmt.Errorf("-service %q is not name:namespace", svc)
		}
		dns := []string{
			fmt.Sprintf("%s.%s.svc.%s", name, ns, clusterDomain),
			fmt.Sprintf("%s.%s.svc", name, ns),
			fmt.Sprintf("%s.%s", name, ns),
			name, "localhost",
		}
		if err := serverCert(out, name+"-server-pq", serverAlg,
			pkix.Name{Organization: []string{org}, OrganizationalUnit: []string{"Near-RT RIC"}, CommonName: dns[0]},
			dns, serverDays, intermediate); err != nil {
			return fmt.Errorf("%s server certificate: %w", name, err)
		}
	}

	// Trust bundle: the RIC intermediate is the anchor relying parties are configured with.
	bundle := append(pki.EncodeCertsPEM(intermediate.cert), pki.EncodeCertsPEM(root.cert)...)
	if err := os.WriteFile(filepath.Join(out, "ric-ca-bundle-pq.crt"), bundle, 0o644); err != nil {
		return err
	}
	fmt.Printf("post-quantum PKI written to %s (root %s, CAs %s, servers %s)\n", out, rootAlg, caAlg, serverAlg)
	return nil
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func write(out, name string, cert *x509.Certificate, key crypto.Signer, chain ...*x509.Certificate) error {
	if err := os.WriteFile(filepath.Join(out, name+".crt"), pki.EncodeCertsPEM(cert), 0o644); err != nil {
		return err
	}
	keyPEM, err := pki.EncodePrivateKeyPEM(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, name+".key"), keyPEM, 0o600); err != nil {
		return err
	}
	if len(chain) > 0 {
		full := append(pki.EncodeCertsPEM(cert), pki.EncodeCertsPEM(chain...)...)
		if err := os.WriteFile(filepath.Join(out, name+"-chain.crt"), full, 0o644); err != nil {
			return err
		}
	}
	fmt.Println("  ", name+":", pki.DescribeCert(cert))
	return nil
}

func selfSignedCA(out, name, alg string, subject pkix.Name, days int) (*issuer, error) {
	key, err := pki.GenerateKey(alg)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn, Subject: subject,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 0, days),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &issuer{cert: cert, key: key}, write(out, name, cert, key)
}

func subCA(out, name, alg string, subject pkix.Name, days int, parent *issuer) (*issuer, error) {
	key, err := pki.GenerateKey(alg)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn, Subject: subject,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 0, days),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.cert, key.Public(), parent.key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &issuer{cert: cert, key: key}, write(out, name, cert, key, parent.cert)
}

func serverCert(out, name, alg string, subject pkix.Name, dnsNames []string, days int, parent *issuer) error {
	key, err := pki.GenerateKey(alg)
	if err != nil {
		return err
	}
	sn, err := serial()
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn, Subject: subject,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 0, days),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.cert, key.Public(), parent.key)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	return write(out, name, cert, key, parent.cert)
}
```

---

## 4. SMO onboarding (bootstrap credentials)

Before an xApp can ask the RIC CA for an identity it must present a credential issued out-of-band by the SMO. That credential is single use, and the DNS names it carries are the only names the xApp can later obtain in its operational certificate.

### `internal/smo/bootstrap.go`

Issues a bootstrap certificate for one identity. `KeyAlg` selects EC or ML-DSA, so onboarding itself can be post-quantum.

```go
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
```

### `ca/cmd/smo-sim/main.go`

CLI wrapper used by the Makefile to mint bootstrap credentials and write them as `tls.crt` / `tls.key`.

```go
// Command smo-sim issues one-time bootstrap credentials from the simulated SMO onboarding CA.
//
//	smo-sim -cn xapp-longterm -dns xapp-a.ricxapp.svc.cluster.local,xapp-a.ricxapp.svc -out out/bootstrap/xapp-a
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/pki"
	"github.com/oran-ricsec/xapp-token-binding/internal/smo"
)

func main() {
	cn := flag.String("cn", "", "xApp identity (certificate CN, must equal the Keycloak client id)")
	dns := flag.String("dns", "", "comma-separated DNS names granted to the xApp")
	out := flag.String("out", "", "output directory (tls.crt, tls.key)")
	caCert := flag.String("ca-cert", os.Getenv("SMO_ONBOARDING_CERT"), "onboarding CA certificate")
	caKey := flag.String("ca-key", os.Getenv("SMO_ONBOARDING_KEY"), "onboarding CA key")
	org := flag.String("org", os.Getenv("ORG"), "organization")
	validity := flag.Duration("validity", 24*time.Hour, "bootstrap certificate validity")
	keyAlg := flag.String("key-alg", "EC-P256", "bootstrap key algorithm (EC-P256, ML-DSA-44/65/87)")
	flag.Parse()
	if *cn == "" || *out == "" || *caCert == "" || *caKey == "" {
		flag.Usage()
		os.Exit(2)
	}
	ob, err := smo.LoadOnboarding(*caCert, *caKey, *org)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load onboarding CA:", err)
		os.Exit(1)
	}
	var names []string
	for _, n := range strings.Split(*dns, ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	ob.KeyAlg = *keyAlg
	cred, err := ob.IssueBootstrap(*cn, names, *validity)
	if err != nil {
		fmt.Fprintln(os.Stderr, "issue:", err)
		os.Exit(1)
	}
	if err := smo.WriteCredential(*out, cred); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}
	fmt.Printf("bootstrap credential for %s (%s, serial %s, expires %s) written to %s\n",
		*cn, pki.KeyAlgName(cred.Leaf.PublicKey), cred.Leaf.SerialNumber.Text(16),
		cred.Leaf.NotAfter.UTC().Format(time.RFC3339), *out)
}
```

---

## 5. The RIC CA enrollment service

Two endpoints share one code path. `POST /v1/enroll` is authenticated by a bootstrap credential and consumes it; `POST /v1/renew` is authenticated by a currently valid operational certificate. In both cases the CA sets the subject from the authenticated identity and ignores the subject in the CSR, checks proof of possession, enforces the lifetime policy, and only grants DNS names the caller was already granted.

### `ca/enroll/server.go`

The issuing logic, the dual issuing branches (an ML-DSA CSR is signed by the ML-DSA CA), the key policy and the rejection reasons.

```go
// Package enroll implements the RIC intermediate CA enrollment service.
//
//	POST /v1/enroll?lifetime=<dur>  first enrollment, authenticated by a one-time SMO bootstrap certificate
//	POST /v1/renew?lifetime=<dur>   rotation/renewal, authenticated by a currently valid RIC operational certificate
//	GET  /v1/ca-chain               issuing chain (PEM)
//	GET  /healthz
//
// Both issuing endpoints share one code path; the leaf lifetime is a request
// parameter bounded by CA policy, which is what distinguishes Method A (long-term)
// from Method B (ephemeral) certificates.
package enroll

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/config"
	"github.com/oran-ricsec/xapp-token-binding/internal/netx"
	"github.com/oran-ricsec/xapp-token-binding/internal/pki"
)

// Config is read from the environment by ConfigFromEnv.
type Config struct {
	ListenAddr         string
	ServerCert         string // PEM chain presented by the service
	ServerKey          string
	IssuerCert         string // RIC intermediate CA certificate (classical branch)
	IssuerKey          string
	IssuerCertPQ       string // RIC intermediate CA certificate (ML-DSA branch, optional)
	IssuerKeyPQ        string
	BootstrapTrust     []string // SMO onboarding CAs: authenticate /v1/enroll
	OperationalTrust   []string // RIC intermediate CAs: authenticate /v1/renew
	StateDir           string
	Organization       string
	OrganizationalUnit string
	DefaultLifetime    time.Duration
	MinLifetime        time.Duration
	MaxLifetime        time.Duration
	AllowedDNSSuffixes []string
	Backdate           time.Duration
	PQKexOnly          bool // require the ML-KEM hybrid group for incoming TLS
}

// ConfigFromEnv loads the service configuration.
func ConfigFromEnv() (Config, error) {
	e := &config.Env{}
	c := Config{
		ListenAddr:         e.Str("LISTEN_ADDR", ":8443"),
		ServerCert:         e.Req("SERVER_CERT"),
		ServerKey:          e.Req("SERVER_KEY"),
		IssuerCert:         e.Req("ISSUER_CERT"),
		IssuerKey:          e.Req("ISSUER_KEY"),
		IssuerCertPQ:       e.Str("ISSUER_CERT_PQ", ""),
		IssuerKeyPQ:        e.Str("ISSUER_KEY_PQ", ""),
		BootstrapTrust:     e.List("BOOTSTRAP_TRUST_BUNDLE", nil),
		OperationalTrust:   e.List("OPERATIONAL_TRUST_BUNDLE", nil),
		StateDir:           e.Req("STATE_DIR"),
		Organization:       e.Req("ORG"),
		OrganizationalUnit: e.Req("XAPP_OU"),
		DefaultLifetime:    e.Dur("CA_DEFAULT_LEAF_LIFETIME", 24*time.Hour),
		MinLifetime:        e.Dur("CA_MIN_LEAF_LIFETIME", 5*time.Second),
		MaxLifetime:        e.Dur("CA_MAX_LEAF_LIFETIME", 30*24*time.Hour),
		AllowedDNSSuffixes: e.List("ALLOWED_DNS_SUFFIXES", nil),
		Backdate:           e.Dur("CA_BACKDATE", 2*time.Second),
		PQKexOnly:          e.Bool("PQ_KEX_ONLY", false),
	}
	if c.MinLifetime > c.MaxLifetime {
		e.Fail("CA_MIN_LEAF_LIFETIME must not exceed CA_MAX_LEAF_LIFETIME")
	}
	if len(c.BootstrapTrust) == 0 {
		e.Fail("BOOTSTRAP_TRUST_BUNDLE is required")
	}
	if len(c.OperationalTrust) == 0 {
		e.Fail("OPERATIONAL_TRUST_BUNDLE is required")
	}
	if (c.IssuerCertPQ == "") != (c.IssuerKeyPQ == "") {
		e.Fail("ISSUER_CERT_PQ and ISSUER_KEY_PQ must be set together")
	}
	return c, e.Err()
}

type profile string

const (
	profileBootstrap profile = "bootstrap"
	profileRenew     profile = "renew"
)

var identityPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// branch is one issuing CA: the classical one or the post-quantum (ML-DSA) one.
type branch struct {
	name string
	cert *x509.Certificate
	key  crypto.Signer
}

// Server issues xApp identity certificates. It holds one issuing branch per
// signature family; the key type of the CSR selects the branch, so the same
// enrollment, lifetime and rotation logic serves classical and ML-DSA identities.
type Server struct {
	cfg         Config
	classical   *branch
	postQuantum *branch
	bootPool    *x509.CertPool
	opPool      *x509.CertPool
	used        *UsedCredentials
	log         *slog.Logger
	now         func() time.Time
}

func loadBranch(name, certPath, keyPath string) (*branch, error) {
	certs, err := pki.LoadCertsFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("%s issuer certificate: %w", name, err)
	}
	key, err := pki.LoadPrivateKeyFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("%s issuer key: %w", name, err)
	}
	return &branch{name: name, cert: certs[0], key: key}, nil
}

// NewServer loads key material and the one-time-credential ledger.
func NewServer(cfg Config, log *slog.Logger) (*Server, error) {
	classical, err := loadBranch("classical", cfg.IssuerCert, cfg.IssuerKey)
	if err != nil {
		return nil, err
	}
	var postQuantum *branch
	if cfg.IssuerCertPQ != "" {
		if postQuantum, err = loadBranch("post-quantum", cfg.IssuerCertPQ, cfg.IssuerKeyPQ); err != nil {
			return nil, err
		}
	}
	bootPool, err := pki.LoadCertPool(cfg.BootstrapTrust...)
	if err != nil {
		return nil, fmt.Errorf("bootstrap trust: %w", err)
	}
	opPool, err := pki.LoadCertPool(cfg.OperationalTrust...)
	if err != nil {
		return nil, fmt.Errorf("operational trust: %w", err)
	}
	used, err := OpenUsedCredentials(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, classical: classical, postQuantum: postQuantum, bootPool: bootPool, opPool: opPool,
		used: used, log: log, now: time.Now}, nil
}

// branchFor selects the issuing CA from the public key in the CSR.
func (s *Server) branchFor(pub crypto.PublicKey) (*branch, error) {
	if pki.IsPostQuantum(pub) {
		if s.postQuantum == nil {
			return nil, fmt.Errorf("no post-quantum issuing branch configured (set ISSUER_CERT_PQ/ISSUER_KEY_PQ)")
		}
		return s.postQuantum, nil
	}
	return s.classical, nil
}

// TLSConfig requests (but does not verify at handshake) a client certificate; the
// handler verifies it against the pool that matches the endpoint.
func (s *Server) TLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(s.cfg.ServerCert, s.cfg.ServerKey)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{cert},
		ClientAuth:       tls.RequestClientCert,
		CurvePreferences: netx.CurvePreferences(s.cfg.PQKexOnly),
	}, nil
}

// Handler returns the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", func(w http.ResponseWriter, r *http.Request) { s.issue(w, r, profileBootstrap) })
	mux.HandleFunc("POST /v1/renew", func(w http.ResponseWriter, r *http.Request) { s.issue(w, r, profileRenew) })
	mux.HandleFunc("GET /v1/ca-chain", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		certs := []*x509.Certificate{s.classical.cert}
		if s.postQuantum != nil {
			certs = append(certs, s.postQuantum.cert)
		}
		_, _ = w.Write(pki.EncodeCertsPEM(certs...))
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	return mux
}

type rejection struct {
	status int
	code   string
	detail string
}

func (s *Server) reject(w http.ResponseWriter, r *http.Request, p profile, rej rejection) {
	s.log.Warn("enrollment_rejected", "profile", p, "reason_code", rej.code, "reason", rej.detail, "remote", r.RemoteAddr)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(rej.status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": rej.code, "reason": rej.detail})
}

func (s *Server) issue(w http.ResponseWriter, r *http.Request, p profile) {
	start := time.Now()
	now := s.now()

	// 1. Authenticate the caller with the credential class this endpoint accepts.
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		s.reject(w, r, p, rejection{http.StatusUnauthorized, "client_certificate_missing", "no client certificate on the TLS session"})
		return
	}
	chain := r.TLS.PeerCertificates
	pool := s.opPool
	if p == profileBootstrap {
		pool = s.bootPool
	}
	if kind, err := pki.VerifyChain(chain, pool, now, x509.ExtKeyUsageClientAuth); err != nil {
		s.reject(w, r, p, rejection{http.StatusUnauthorized, "client_certificate_" + kind, fmt.Sprintf("%s credential rejected: %v", p, err)})
		return
	}
	caller := chain[0]
	identity := caller.Subject.CommonName
	if !identityPattern.MatchString(identity) {
		s.reject(w, r, p, rejection{http.StatusForbidden, "identity_invalid", fmt.Sprintf("CN %q is not a valid xApp identity", identity)})
		return
	}

	// 2. Lifetime policy.
	lifetime := s.cfg.DefaultLifetime
	if v := r.URL.Query().Get("lifetime"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			s.reject(w, r, p, rejection{http.StatusBadRequest, "lifetime_invalid", err.Error()})
			return
		}
		lifetime = d
	}
	if lifetime < s.cfg.MinLifetime || lifetime > s.cfg.MaxLifetime {
		s.reject(w, r, p, rejection{http.StatusBadRequest, "lifetime_out_of_policy",
			fmt.Sprintf("lifetime %s outside [%s, %s]", lifetime, s.cfg.MinLifetime, s.cfg.MaxLifetime)})
		return
	}
	notAfter := now.Add(lifetime)

	// 3. CSR: proof of possession and key policy. The subject is set by the CA from
	// the authenticated identity; the CSR subject is ignored.
	csr, rej := s.parseCSR(r)
	if rej != nil {
		s.reject(w, r, p, *rej)
		return
	}
	// The key type in the CSR selects the issuing CA: an ML-DSA key is signed by the
	// post-quantum branch, anything classical by the classical branch.
	br, err := s.branchFor(csr.PublicKey)
	if err != nil {
		s.reject(w, r, p, rejection{http.StatusBadRequest, "key_not_allowed", err.Error()})
		return
	}
	if notAfter.After(br.cert.NotAfter) {
		s.reject(w, r, p, rejection{http.StatusBadRequest, "lifetime_exceeds_issuer",
			fmt.Sprintf("requested lifetime outlives the %s issuing CA", br.name)})
		return
	}
	// DNS names must have been granted to the caller (bootstrap or current identity).
	for _, name := range csr.DNSNames {
		if !slices.Contains(caller.DNSNames, name) || !s.dnsSuffixAllowed(name) {
			s.reject(w, r, p, rejection{http.StatusForbidden, "dns_name_not_authorized",
				fmt.Sprintf("DNS name %q is not granted to identity %q", name, identity)})
			return
		}
	}

	// 4. One-time bootstrap: consume the credential before signing.
	if p == profileBootstrap {
		if err := s.used.Consume(caller); err != nil {
			s.reject(w, r, p, rejection{http.StatusForbidden, "bootstrap_credential_reused", err.Error()})
			return
		}
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		s.reject(w, r, p, rejection{http.StatusInternalServerError, "internal", err.Error()})
		return
	}
	keyUsage := x509.KeyUsageDigitalSignature
	if _, isRSA := csr.PublicKey.(*rsa.PublicKey); isRSA {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         identity,
			OrganizationalUnit: []string{s.cfg.OrganizationalUnit},
			Organization:       []string{s.cfg.Organization},
		},
		NotBefore:             now.Add(-s.cfg.Backdate),
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              csr.DNSNames,
		URIs:                  []*url.URL{{Scheme: "urn", Opaque: "oran:ric:xapp:" + identity}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, br.cert, csr.PublicKey, br.key)
	if err != nil {
		s.reject(w, r, p, rejection{http.StatusInternalServerError, "internal", err.Error()})
		return
	}
	leaf, _ := x509.ParseCertificate(der)

	s.log.Info("certificate_issued",
		"profile", p, "identity", identity, "serial", leaf.SerialNumber.Text(16),
		"issuer_branch", br.name, "key_alg", pki.KeyAlgName(csr.PublicKey), "sig_alg", leaf.SignatureAlgorithm.String(),
		"cert_bytes", len(leaf.Raw),
		"lifetime", lifetime.String(), "not_after", leaf.NotAfter.UTC().Format(time.RFC3339),
		"x5t#S256", pki.ThumbprintS256(leaf), "authenticated_by_serial", caller.SerialNumber.Text(16),
		"elapsed_ms", float64(time.Since(start).Microseconds())/1000)

	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	_, _ = w.Write(pki.EncodeCertsPEM(leaf, br.cert))
}

func (s *Server) parseCSR(r *http.Request) (*x509.CertificateRequest, *rejection) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		return nil, &rejection{http.StatusBadRequest, "csr_unreadable", err.Error()}
	}
	block, _ := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, &rejection{http.StatusBadRequest, "csr_malformed", "body is not a PEM CERTIFICATE REQUEST"}
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, &rejection{http.StatusBadRequest, "csr_malformed", err.Error()}
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, &rejection{http.StatusBadRequest, "csr_signature_invalid", "CSR proof of possession failed: " + err.Error()}
	}
	switch k := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return nil, &rejection{http.StatusBadRequest, "key_not_allowed", "EC keys must use P-256 or P-384"}
		}
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return nil, &rejection{http.StatusBadRequest, "key_not_allowed", "RSA keys must be at least 2048 bits"}
		}
	case ed25519.PublicKey:
	case *mldsa.PublicKey:
		// ML-DSA-44/65/87 (FIPS 204). All parameter sets are acceptable.
	default:
		return nil, &rejection{http.StatusBadRequest, "key_not_allowed", fmt.Sprintf("unsupported key type %T", k)}
	}
	return csr, nil
}

func (s *Server) dnsSuffixAllowed(name string) bool {
	if len(s.cfg.AllowedDNSSuffixes) == 0 {
		return true
	}
	for _, suffix := range s.cfg.AllowedDNSSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}
```

### `ca/enroll/ledger.go`

The append-only ledger that makes every bootstrap credential single use. The entry is written and fsynced before the certificate is signed.

```go
package enroll

import (
	"bufio"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// UsedCredentials is an append-only ledger of consumed bootstrap certificates,
// keyed by issuer + serial, which makes every bootstrap credential single-use.
type UsedCredentials struct {
	mu   sync.Mutex
	path string
	used map[string]bool
}

// OpenUsedCredentials loads (or creates) the ledger in dir.
func OpenUsedCredentials(dir string) (*UsedCredentials, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	u := &UsedCredentials{path: filepath.Join(dir, "used-bootstrap-credentials.log"), used: map[string]bool{}}
	f, err := os.Open(u.path)
	if err != nil {
		if os.IsNotExist(err) {
			return u, nil
		}
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if key, _, ok := strings.Cut(sc.Text(), " "); ok {
			u.used[key] = true
		}
	}
	return u, sc.Err()
}

func credentialKey(c *x509.Certificate) string {
	return hex.EncodeToString(c.RawIssuer) + ":" + c.SerialNumber.Text(16)
}

// Consume marks the credential used, failing if it was already used. The entry is
// written to disk before the certificate is issued.
func (u *UsedCredentials) Consume(c *x509.Certificate) error {
	key := credentialKey(c)
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.used[key] {
		return fmt.Errorf("bootstrap certificate serial %s for %q has already been used", c.SerialNumber.Text(16), c.Subject.CommonName)
	}
	f, err := os.OpenFile(u.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "%s %s %s\n", key, c.Subject.CommonName, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	u.used[key] = true
	return nil
}
```

### `ca/cmd/ric-ca/main.go`

The service binary: TLS 1.3, `RequestClientCert` so the handler can verify the chain against the pool that matches the endpoint.

```go
// Command ric-ca runs the RIC intermediate CA enrollment service.
package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/ca/enroll"
	"github.com/oran-ricsec/xapp-token-binding/internal/logx"
)

func main() {
	log := logx.New("ric-ca")
	cfg, err := enroll.ConfigFromEnv()
	if err != nil {
		log.Error("invalid configuration", "error", err)
		os.Exit(2)
	}
	srv, err := enroll.NewServer(cfg, log)
	if err != nil {
		log.Error("startup failed", "error", err)
		os.Exit(1)
	}
	tlsConf, err := srv.TLSConfig()
	if err != nil {
		log.Error("server TLS", "error", err)
		os.Exit(1)
	}
	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		TLSConfig:         tlsConf,
		ReadHeaderTimeout: 10 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdown)
	}()
	log.Info("listening", "addr", cfg.ListenAddr, "min_lifetime", cfg.MinLifetime.String(), "max_lifetime", cfg.MaxLifetime.String())
	if err := httpSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
```

---

## 6. Container image and Kubernetes manifest

Every binary ships in a `scratch` image: a static Go binary and nothing else, running as a non-root user with a read-only root filesystem.

### `build/Dockerfile`

One image recipe for all binaries, selected with `--build-arg BIN=`.

```dockerfile
# Minimal image for one statically linked binary from out/bin (the build context).
FROM scratch
ARG BIN
COPY ${BIN} /app
USER 65532:65532
ENTRYPOINT ["/app"]
```

### `ca/k8s/ric-ca.yaml`

Deployment and Service in `ricsec`. Both issuing branches are mounted, and both trust anchors are configured.

```yaml
# RIC intermediate CA enrollment service (rendered with envsubst from config/testbed.env).
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${RIC_CA_SERVICE}
  namespace: ${RICSEC_NAMESPACE}
  labels: {app: ${RIC_CA_SERVICE}, part-of: xapp-token-binding}
spec:
  replicas: 1   # the one-time bootstrap ledger is local to the pod
  selector:
    matchLabels: {app: ${RIC_CA_SERVICE}}
  template:
    metadata:
      labels: {app: ${RIC_CA_SERVICE}, part-of: xapp-token-binding}
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        seccompProfile: {type: RuntimeDefault}
      containers:
        - name: ric-ca
          image: ricsec/ric-ca:${IMAGE_TAG}
          imagePullPolicy: Never
          ports:
            - {name: https, containerPort: ${RIC_CA_PORT}}
          env:
            - {name: LISTEN_ADDR, value: ":${RIC_CA_PORT}"}
            - {name: SERVER_CERT, value: /etc/ric-ca/server/tls.crt}
            - {name: SERVER_KEY, value: /etc/ric-ca/server/tls.key}
            - {name: ISSUER_CERT, value: /etc/ric-ca/issuer/tls.crt}
            - {name: ISSUER_KEY, value: /etc/ric-ca/issuer/tls.key}
            # Post-quantum issuing branch: an ML-DSA CSR is signed by this CA.
            - {name: ISSUER_CERT_PQ, value: /etc/ric-ca/issuer-pq/tls.crt}
            - {name: ISSUER_KEY_PQ, value: /etc/ric-ca/issuer-pq/tls.key}
            - {name: BOOTSTRAP_TRUST_BUNDLE, value: "/etc/ric-trust/smo-onboarding-ca.crt,/etc/ric-trust/smo-onboarding-ca-pq.crt"}
            - {name: OPERATIONAL_TRUST_BUNDLE, value: "/etc/ric-trust/ric-intermediate-ca.crt,/etc/ric-trust/ric-intermediate-ca-pq.crt"}
            - {name: PQ_KEX_ONLY, value: "false"}
            - {name: STATE_DIR, value: /var/lib/ric-ca}
            - {name: ORG, value: "${ORG}"}
            - {name: XAPP_OU, value: "${XAPP_OU}"}
            - {name: CA_DEFAULT_LEAF_LIFETIME, value: "${CA_DEFAULT_LEAF_LIFETIME}"}
            - {name: CA_MIN_LEAF_LIFETIME, value: "${CA_MIN_LEAF_LIFETIME}"}
            - {name: CA_MAX_LEAF_LIFETIME, value: "${CA_MAX_LEAF_LIFETIME}"}
            - {name: ALLOWED_DNS_SUFFIXES, value: ".${XAPP_NAMESPACE}.svc.${CLUSTER_DOMAIN},.${XAPP_NAMESPACE}.svc"}
          volumeMounts:
            - {name: server-tls, mountPath: /etc/ric-ca/server, readOnly: true}
            - {name: issuer, mountPath: /etc/ric-ca/issuer, readOnly: true}
            - {name: issuer-pq, mountPath: /etc/ric-ca/issuer-pq, readOnly: true}
            - {name: trust, mountPath: /etc/ric-trust, readOnly: true}
            - {name: state, mountPath: /var/lib/ric-ca}
          readinessProbe:
            httpGet: {path: /healthz, port: https, scheme: HTTPS}
            periodSeconds: 5
          resources:
            requests: {cpu: 20m, memory: 16Mi}
            limits: {memory: 64Mi}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
      volumes:
        - name: server-tls
          secret: {secretName: ric-ca-server-tls, defaultMode: 0440}
        - name: issuer
          secret: {secretName: ric-ca-issuer, defaultMode: 0440}
        - name: issuer-pq
          secret: {secretName: ric-ca-issuer-pq, defaultMode: 0440}
        - name: trust
          configMap: {name: ric-trust}
        - name: state
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: ${RIC_CA_SERVICE}
  namespace: ${RICSEC_NAMESPACE}
  labels: {app: ${RIC_CA_SERVICE}, part-of: xapp-token-binding}
spec:
  selector: {app: ${RIC_CA_SERVICE}}
  ports:
    - {name: https, port: ${RIC_CA_PORT}, targetPort: https}
```

---

## 7. Build, deploy and verify

```bash
export KUBECONFIG=$HOME/.kube/config
export PATH=$HOME/tools/go/bin:$PATH

make pki          # generate both hierarchies into out/pki
make build        # compile every binary into out/bin
make images       # scratch images, imported into containerd
make deploy-ca    # namespace, trust anchors, secrets, Deployment
make verify-ca    # the milestone check below
```

### `build/verify-ca.sh`

Issues a leaf with a bootstrap credential, verifies the chain with `openssl verify`, proves the bootstrap credential is refused the second time, and obtains a long-lived certificate from the same code path through `/v1/renew`.

```bash
#!/usr/bin/env bash
# Milestone 1 check: the RIC CA issues a leaf on demand, the chain verifies with
# openssl, lifetime is a parameter, and a bootstrap credential works exactly once.
set -euo pipefail
: "${RIC_CA_URL:?run via make verify-ca}"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
PKI=out/pki
HOSTPORT=${RIC_CA_URL#https://}
RESOLVE=$(tr ',' '\n' <<<"$DIAL_OVERRIDES" | awk -F= -v hp="$HOSTPORT" '$1==hp {split($2,a,":"); print hp":"a[1]}')
[[ -n "$RESOLVE" ]] || { echo "no ClusterIP for $HOSTPORT in DIAL_OVERRIDES"; exit 1; }

enroll() { # enroll <cred-dir> <lifetime> <out-cert> -> prints HTTP status
  curl -sS --tlsv1.3 --resolve "$RESOLVE" --cacert "$RIC_TRUST_BUNDLE" \
    --cert "$1/tls.crt" --key "$1/tls.key" \
    -H 'Content-Type: application/pkcs10' --data-binary @"$WORK/req.csr" \
    -o "$3" -w '%{http_code}' "$RIC_CA_URL/v1/enroll?lifetime=$2"
}

echo "==> SMO onboarding: bootstrap credential for identity 'ca-smoke-test'"
out/bin/smo-sim -cn ca-smoke-test -validity 10m -out "$WORK/boot" -org "$ORG" \
  -ca-cert "$SMO_ONBOARDING_CERT" -ca-key "$SMO_ONBOARDING_KEY"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/leaf.key" 2>/dev/null
openssl req -new -key "$WORK/leaf.key" -subj "/CN=ignored-by-ca" -out "$WORK/req.csr"

echo "==> Enroll with bootstrap credential (lifetime=$EPHEMERAL_CERT_LIFETIME)"
code=$(enroll "$WORK/boot" "$EPHEMERAL_CERT_LIFETIME" "$WORK/leaf.pem")
[[ "$code" == 200 ]] || { echo "FAIL: enroll returned $code: $(cat "$WORK/leaf.pem")"; exit 1; }
openssl x509 -in "$WORK/leaf.pem" -noout -subject -issuer -serial -startdate -enddate -ext subjectAltName,extendedKeyUsage 2>/dev/null \
  || openssl x509 -in "$WORK/leaf.pem" -noout -subject -issuer -serial -startdate -enddate

echo "==> openssl verify (trust anchor: SMO root, untrusted intermediate: RIC CA)"
openssl verify -CAfile "$SMO_ROOT_CERT" -untrusted "$PKI/ric-intermediate-ca.crt" -purpose sslclient "$WORK/leaf.pem"

echo "==> Reusing the same bootstrap credential must be rejected"
code=$(enroll "$WORK/boot" "$EPHEMERAL_CERT_LIFETIME" "$WORK/reuse.json")
echo "HTTP $code $(cat "$WORK/reuse.json")"
[[ "$code" == 403 ]] || { echo "FAIL: bootstrap reuse was not rejected"; exit 1; }

echo "==> Long-term lifetime from the same code path via /v1/renew (authenticated by the new operational cert)"
cat "$WORK/leaf.pem" > "$WORK/op.crt"; cp "$WORK/leaf.key" "$WORK/op.key"
mkdir -p "$WORK/op" && cp "$WORK/op.crt" "$WORK/op/tls.crt" && cp "$WORK/op.key" "$WORK/op/tls.key"
code=$(curl -sS --tlsv1.3 --resolve "$RESOLVE" --cacert "$RIC_TRUST_BUNDLE" --cert "$WORK/op/tls.crt" --key "$WORK/op/tls.key" \
  -H 'Content-Type: application/pkcs10' --data-binary @"$WORK/req.csr" -o "$WORK/long.pem" -w '%{http_code}' \
  "$RIC_CA_URL/v1/renew?lifetime=$LONGTERM_CERT_LIFETIME")
[[ "$code" == 200 ]] || { echo "FAIL: renew returned $code: $(cat "$WORK/long.pem")"; exit 1; }
openssl x509 -in "$WORK/long.pem" -noout -subject -startdate -enddate
openssl verify -CAfile "$SMO_ROOT_CERT" -untrusted "$PKI/ric-intermediate-ca.crt" "$WORK/long.pem"
echo "MILESTONE 1 PASSED"
```

Expected output:

```
==> Enroll with bootstrap credential (lifetime=15m)
subject=O = O-RAN-RIC, OU = xApps, CN = ca-smoke-test
issuer=O = O-RAN-RIC, OU = Near-RT RIC, CN = RIC Intermediate CA
==> openssl verify (trust anchor: SMO root, untrusted intermediate: RIC CA)
leaf.pem: OK
==> Reusing the same bootstrap credential must be rejected
HTTP 403 {"error":"bootstrap_credential_reused", ...}
MILESTONE 1 PASSED
```

