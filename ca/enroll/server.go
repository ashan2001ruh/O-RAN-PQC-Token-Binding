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
