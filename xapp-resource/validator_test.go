package xappresource

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/jose"
	"github.com/oran-ricsec/xapp-token-binding/internal/pki"
	xappclient "github.com/oran-ricsec/xapp-token-binding/xapp-client"
)

// Offline end-to-end check of the validator: in-memory CA, JWKS server, token signer
// and a TLS resource server requesting client certificates.

type fixture struct {
	t        *testing.T
	ca       *x509.Certificate
	caKey    *ecdsa.PrivateKey
	issuer   jose.Signer
	kid      string
	v        *Validator
	resource *httptest.Server
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, kid: "test-kid"}
	f.caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test RIC CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &f.caKey.PublicKey, f.caKey)
	f.ca, _ = x509.ParseCertificate(der)
	dir := t.TempDir()
	trust := filepath.Join(dir, "ca.crt")
	_ = os.WriteFile(trust, pki.EncodeCertsPEM(f.ca), 0o644)

	f.issuer, _ = jose.GenerateSigner("ES256")
	jwk := jose.JWK{}
	for k, v := range f.issuer.PublicJWK() {
		jwk[k] = v
	}
	jwk["kid"], jwk["use"], jwk["alg"] = f.kid, "sig", "ES256"
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk}})
	}))
	t.Cleanup(jwks.Close)

	v, err := NewValidator(Config{
		Issuer: "https://issuer.test/realms/ric", Audience: "ric-xapps", JWKSURL: jwks.URL,
		RequiredScope: "ric-sdl-access", TrustBundle: []string{trust}, ClockSkew: 5 * time.Second,
		DPoPProofWindow: 60 * time.Second, ReplayCacheSize: 1000, JWKSCacheTTL: time.Minute, JWKSMinRefresh: time.Second,
	}, jwks.Client(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	f.v = v
	f.resource = httptest.NewUnstartedServer(v.Middleware(ModeLocal, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})))
	f.resource.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS13}
	f.resource.StartTLS()
	t.Cleanup(f.resource.Close)
	return f
}

func (f *fixture) leaf(cn string, lifetime time.Duration) *tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(lifetime),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, f.ca, &key.PublicKey, f.caKey)
	leaf, _ := x509.ParseCertificate(der)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func (f *fixture) token(cnf map[string]any) string {
	claims := map[string]any{"iss": "https://issuer.test/realms/ric", "aud": "ric-xapps", "scope": "ric-sdl-access",
		"exp": time.Now().Add(5 * time.Minute).Unix(), "azp": "xapp-test"}
	if cnf != nil {
		claims["cnf"] = cnf
	}
	tok, err := f.issuer.SignCompact(map[string]any{"kid": f.kid, "typ": "JWT"}, claims)
	if err != nil {
		f.t.Fatal(err)
	}
	return tok
}

func (f *fixture) do(cert *tls.Certificate, headers map[string]string) (int, string) {
	pool := x509.NewCertPool()
	pool.AddCert(f.resource.Certificate())
	conf := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	if cert != nil {
		conf.Certificates = []tls.Certificate{*cert}
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: conf, DisableKeepAlives: true}}
	req, _ := http.NewRequest(http.MethodGet, f.resource.URL+"/api/v1/sdl/k", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var body RejectionBody
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body.ReasonCode
}

func expect(t *testing.T, name string, status int, code string, wantStatus int, wantCode string) {
	t.Helper()
	if status != wantStatus || code != wantCode {
		t.Errorf("%s: got %d %q, want %d %q", name, status, code, wantStatus, wantCode)
	}
}

func TestCertificateBinding(t *testing.T) {
	f := newFixture(t)
	a, b := f.leaf("xapp-a", time.Hour), f.leaf("xapp-b", time.Hour)
	tok := f.token(map[string]any{"x5t#S256": pki.ThumbprintS256(a.Leaf)})
	auth := map[string]string{"Authorization": "Bearer " + tok}

	s, c := f.do(a, auth)
	expect(t, "own certificate", s, c, 200, "")
	s, c = f.do(b, auth)
	expect(t, "other certificate", s, c, 401, ReasonX5tMismatch)
	s, c = f.do(nil, auth)
	expect(t, "no certificate", s, c, 401, ReasonClientCertMissing)
	s, c = f.do(a, map[string]string{"Authorization": "Bearer " + f.token(nil)})
	expect(t, "no cnf", s, c, 401, ReasonCnfMissing)
	s, c = f.do(a, map[string]string{"Authorization": "Bearer " + f.token(map[string]any{"x5t#S256": 42})})
	expect(t, "malformed cnf", s, c, 401, ReasonCnfMalformed)
	s, c = f.do(a, map[string]string{"Authorization": "Bearer " + f.token(map[string]any{"foo": "bar"})})
	expect(t, "unrecognised cnf", s, c, 401, ReasonCnfUnrecognized)
}

func TestDPoPBinding(t *testing.T) {
	f := newFixture(t)
	key, _ := jose.GenerateSigner("ES256")
	jkt, _ := key.PublicJWK().Thumbprint()
	tok := f.token(map[string]any{"jkt": jkt})
	url := f.resource.URL + "/api/v1/sdl/k"

	proof, _ := xappclient.BuildDPoPProof(key, http.MethodGet, url, tok, "", time.Now())
	s, c := f.do(nil, map[string]string{"Authorization": "DPoP " + tok, "DPoP": proof})
	expect(t, "valid proof", s, c, 200, "")
	s, c = f.do(nil, map[string]string{"Authorization": "DPoP " + tok, "DPoP": proof})
	expect(t, "replayed proof", s, c, 401, ReasonDPoPReplayed)

	other, _ := jose.GenerateSigner("ES256")
	p2, _ := xappclient.BuildDPoPProof(other, http.MethodGet, url, tok, "", time.Now())
	s, c = f.do(nil, map[string]string{"Authorization": "DPoP " + tok, "DPoP": p2})
	expect(t, "foreign key", s, c, 401, ReasonDPoPJktMismatch)

	p3, _ := xappclient.BuildDPoPProof(key, http.MethodGet, url, f.token(map[string]any{"jkt": jkt}), "", time.Now())
	s, c = f.do(nil, map[string]string{"Authorization": "DPoP " + tok, "DPoP": p3})
	expect(t, "ath of other token", s, c, 401, ReasonDPoPAthMismatch)

	p4, _ := xappclient.BuildDPoPProof(key, http.MethodPost, url, tok, "", time.Now())
	s, c = f.do(nil, map[string]string{"Authorization": "DPoP " + tok, "DPoP": p4})
	expect(t, "wrong htm", s, c, 401, ReasonDPoPHtmMismatch)

	s, c = f.do(nil, map[string]string{"Authorization": "Bearer " + tok})
	expect(t, "used as bearer", s, c, 401, ReasonDPoPAsBearer)
}
