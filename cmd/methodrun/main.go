// Command methodrun walks one binding method end to end and prints every step, so a
// single command shows the whole flow on the CLI: onboarding, enrollment, token
// issuance, the post-quantum upgrade, the negotiated TLS key exchange, resource calls
// under both validation modes, and the negative test that proves the binding is
// enforced.
//
//	methodrun -method A            classical run
//	methodrun -method A -pq        post-quantum run (ML-DSA tokens, ML-KEM key exchange)
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/config"
	"github.com/oran-ricsec/xapp-token-binding/internal/jose"
	"github.com/oran-ricsec/xapp-token-binding/internal/logx"
	"github.com/oran-ricsec/xapp-token-binding/internal/netx"
	"github.com/oran-ricsec/xapp-token-binding/internal/pki"
	"github.com/oran-ricsec/xapp-token-binding/internal/smo"
	xappclient "github.com/oran-ricsec/xapp-token-binding/xapp-client"
	xappresource "github.com/oran-ricsec/xapp-token-binding/xapp-resource"
)

var (
	bold   = "\033[1m"
	dim    = "\033[2m"
	green  = "\033[32m"
	red    = "\033[31m"
	cyan   = "\033[36m"
	yellow = "\033[33m"
	reset  = "\033[0m"
)

func init() {
	if os.Getenv("NO_COLOR") != "" {
		bold, dim, green, red, cyan, yellow, reset = "", "", "", "", "", "", ""
	}
}

var stepNo int

func step(format string, args ...any) {
	stepNo++
	fmt.Printf("\n%s%s[%d] %s%s\n", bold, cyan, stepNo, fmt.Sprintf(format, args...), reset)
}

func item(label string, format string, args ...any) {
	fmt.Printf("    %-26s %s\n", label+":", fmt.Sprintf(format, args...))
}

func ok(format string, args ...any) {
	fmt.Printf("    %sOK%s  %s\n", green, reset, fmt.Sprintf(format, args...))
}
func warn(format string, args ...any) {
	fmt.Printf("    %s!%s   %s\n", yellow, reset, fmt.Sprintf(format, args...))
}
func fail(format string, args ...any) {
	fmt.Printf("    %sFAIL%s %s\n", red, reset, fmt.Sprintf(format, args...))
}

type runner struct {
	ctx        context.Context
	log        *slog.Logger
	cfg        xappclient.Config
	onboarding *smo.Onboarding
	pqOnboard  *smo.Onboarding
	roots      *x509.CertPool
	overrides  map[string]string
	resource   string
	pq         bool
	failures   int
}

func main() {
	method := flag.String("method", "A", "binding method: A, B or C")
	pq := flag.Bool("pq", false, "run in post-quantum mode (ML-DSA tokens and certificates, ML-KEM key exchange)")
	flag.Parse()

	m := xappclient.Method(strings.ToUpper(*method))
	r, err := newRunner(m, *pq)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		os.Exit(2)
	}
	if err := r.run(m); err != nil {
		fail("%v", err)
		os.Exit(1)
	}
	fmt.Println()
	if r.failures > 0 {
		fmt.Printf("%s%d check(s) failed%s\n", red, r.failures, reset)
		os.Exit(1)
	}
	fmt.Printf("%s%sAll checks passed.%s\n", bold, green, reset)
}

func newRunner(m xappclient.Method, pq bool) (*runner, error) {
	e := &config.Env{}
	r := &runner{ctx: context.Background(), log: logx.New("methodrun"), pq: pq}
	r.resource = strings.TrimRight(e.Req("RESOURCE_URL"), "/")
	clientID := map[xappclient.Method]string{
		xappclient.MethodLongTerm:  e.Req("LONGTERM_CLIENT_ID"),
		xappclient.MethodEphemeral: e.Req("EPHEMERAL_CLIENT_ID"),
		xappclient.MethodDPoP:      e.Req("DPOP_CLIENT_ID"),
	}[m]
	lifetime := e.Dur("LONGTERM_CERT_LIFETIME", 168*time.Hour)
	if m == xappclient.MethodEphemeral {
		lifetime = e.Dur("EPHEMERAL_CERT_LIFETIME", 15*time.Minute)
	}
	r.cfg = xappclient.Config{
		Method: m, ClientID: clientID,
		TokenURL:         e.Req("KEYCLOAK_TOKEN_URL"),
		Scope:            e.Str("TOKEN_SCOPE", ""),
		TrustBundle:      e.List("RIC_TRUST_BUNDLE", nil),
		CAURL:            e.Req("RIC_CA_URL"),
		KeyAlg:           e.Str("IDENTITY_KEY_ALG", "EC-P256"),
		CertLifetime:     lifetime,
		Rotation:         xappclient.RotateOnCertExpiry,
		DPoPAlg:          e.Str("DPOP_ALG", "ES256"),
		PQEnabled:        pq,
		PQIssuer:         xappclient.PQIssuer(e.Str("PQ_ISSUER", string(xappclient.PQIssuerShim))),
		PQShimURL:        e.Str("PQ_SHIM_URL", ""),
		PQKeyAlg:         e.Str("PQ_IDENTITY_KEY_ALG", "ML-DSA-65"),
		PQDPoPAlg:        e.Str("PQ_DPOP_ALG", "ML-DSA-44"),
		PQKexOnly:        e.Bool("PQ_KEX_ONLY", true),
		PQUpgradeTimeout: 60 * time.Second,
		HTTPTimeout:      30 * time.Second,
	}
	onbCert, onbKey, org := e.Req("SMO_ONBOARDING_CERT"), e.Req("SMO_ONBOARDING_KEY"), e.Req("ORG")
	pqOnbCert := e.Str("SMO_ONBOARDING_CERT_PQ", "")
	pqOnbKey := e.Str("SMO_ONBOARDING_KEY_PQ", "")
	overrides, err := netx.ParseDialOverrides(e.Str("DIAL_OVERRIDES", ""))
	if err != nil {
		e.Fail("DIAL_OVERRIDES: %v", err)
	}
	if err := e.Err(); err != nil {
		return nil, err
	}
	r.overrides, r.cfg.DialOverrides = overrides, overrides
	if r.roots, err = pki.LoadCertPool(r.cfg.TrustBundle...); err != nil {
		return nil, err
	}
	if r.onboarding, err = smo.LoadOnboarding(onbCert, onbKey, org); err != nil {
		return nil, err
	}
	if pq {
		if pqOnbCert == "" || pqOnbKey == "" {
			return nil, fmt.Errorf("SMO_ONBOARDING_CERT_PQ/KEY_PQ are required in post-quantum mode")
		}
		if r.pqOnboard, err = smo.LoadOnboarding(pqOnbCert, pqOnbKey, org); err != nil {
			return nil, err
		}
		r.pqOnboard.KeyAlg = r.cfg.PQKeyAlg
	}
	return r, nil
}

// newClient onboards a fresh identity and starts a client.
func (r *runner) newClient() (xappclient.Client, error) {
	cfg := r.cfg
	boot, err := r.onboarding.IssueBootstrap(cfg.ClientID, nil, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	cfg.Bootstrap = boot
	if r.pq {
		pqBoot, err := r.pqOnboard.IssueBootstrap(cfg.ClientID, nil, 10*time.Minute)
		if err != nil {
			return nil, err
		}
		cfg.PQBootstrap = pqBoot
	}
	c, err := xappclient.New(cfg, r.log)
	if err != nil {
		return nil, err
	}
	return c, c.Start(r.ctx)
}

func (r *runner) path(mode xappresource.Mode) string {
	if mode == xappresource.ModeIntrospection {
		return r.resource + "/api/v1/introspect/sdl/demo"
	}
	return r.resource + "/api/v1/sdl/demo"
}

func (r *runner) check(cond bool, format string, args ...any) {
	if cond {
		ok(format, args...)
		return
	}
	r.failures++
	fail(format, args...)
}

func (r *runner) run(m xappclient.Method) error {
	mode := "classical"
	if r.pq {
		mode = "post-quantum"
	}
	fmt.Printf("%s%sMethod %s walkthrough (%s)%s\n", bold, cyan, m, mode, reset)

	step("Configuration")
	item("method", "%s (%s)", m, methodDescription(m))
	item("keycloak client", "%s", r.cfg.ClientID)
	item("identity key", "%s", r.cfg.KeyAlg)
	item("certificate lifetime", "%s", r.cfg.CertLifetime)
	if m == xappclient.MethodDPoP {
		item("DPoP proof key", "%s", r.cfg.DPoPAlg)
	}
	if r.pq {
		item("post-quantum identity", "%s", r.cfg.PQKeyAlg)
		if m == xappclient.MethodDPoP {
			item("post-quantum DPoP key", "%s", r.cfg.PQDPoPAlg)
		}
		if r.cfg.PQIssuer == xappclient.PQIssuerKeycloak {
			item("post-quantum token issuer", "the authorization server itself (no shim in the path)")
		} else {
			item("post-quantum token issuer", "pq-shim at %s", r.cfg.PQShimURL)
		}
		item("TLS key exchange", "X25519MLKEM768 required: %v", r.cfg.PQKexOnly)
	}
	item("resource xApp", "%s", r.resource)

	step("SMO onboarding and enrollment with the RIC CA")
	start := time.Now()
	client, err := r.newClient()
	if err != nil {
		return fmt.Errorf("enrollment: %w", err)
	}
	enrollMS := float64(time.Since(start).Microseconds()) / 1000
	d := client.Describe()
	item("classical certificate", "%s", d.ClassicalCert)
	if r.pq {
		item("post-quantum certificate", "%s", d.PQCert)
		r.check(strings.HasPrefix(d.PQAlg, "ML-DSA"), "identity certificate uses %s", d.PQAlg)
	}
	item("enrollment time", "%.1f ms", enrollMS)

	step("Access token")
	start = time.Now()
	tok, err := client.Token(r.ctx)
	if err != nil {
		return fmt.Errorf("token: %w", err)
	}
	tokenMS := float64(time.Since(start).Microseconds()) / 1000
	if tok.Classical != nil {
		item("Keycloak token", "alg=%s binding=cnf.%s bytes=%d", tok.Classical.Alg, tok.Classical.Binding, len(tok.Classical.Value))
		item("upgraded token", "alg=%s binding=cnf.%s bytes=%d", tok.Alg, tok.Binding, len(tok.Value))
		item("size change", "%+d bytes (%.1fx)", len(tok.Value)-len(tok.Classical.Value),
			float64(len(tok.Value))/float64(len(tok.Classical.Value)))
		r.check(strings.HasPrefix(tok.Alg, "ML-DSA"), "token is signed with %s", tok.Alg)
	} else {
		item("token", "alg=%s binding=cnf.%s bytes=%d", tok.Alg, tok.Binding, len(tok.Value))
	}
	item("cnf value", "%s", tok.Thumbprint)
	item("expires", "%s (in %s)", tok.ExpiresAt.UTC().Format(time.RFC3339), time.Until(tok.ExpiresAt).Round(time.Second))
	item("issue time", "%.1f ms", tokenMS)
	printClaims(tok)

	step("Resource request with local validation")
	status, body, state, err := r.call(client, r.path(xappresource.ModeLocal))
	if err != nil {
		return err
	}
	r.check(status == http.StatusOK, "HTTP %d %s", status, strings.TrimSpace(body))
	if state != nil {
		item("TLS key exchange", "%s", state.CurveID)
		item("TLS version", "0x%x", state.Version)
		if len(state.PeerCertificates) > 0 {
			item("server certificate", "%s", pki.KeyAlgName(state.PeerCertificates[0].PublicKey))
		}
		if r.pq {
			r.check(netx.IsPQKex(state.CurveID), "key exchange is post-quantum (%s)", state.CurveID)
		}
	}

	step("Resource request validated by introspection")
	status, body, _, err = r.call(client, r.path(xappresource.ModeIntrospection))
	if err != nil {
		return err
	}
	r.check(status == http.StatusOK, "HTTP %d %s", status, strings.TrimSpace(body))

	if err := r.methodSpecific(m, client, tok); err != nil {
		return err
	}
	return r.negative(m, client, tok)
}

func methodDescription(m xappclient.Method) string {
	switch m {
	case xappclient.MethodLongTerm:
		return "RFC 8705 certificate-bound, long-term identity key"
	case xappclient.MethodEphemeral:
		return "RFC 8705 certificate-bound, ephemeral identity key"
	case xappclient.MethodDPoP:
		return "RFC 9449 DPoP"
	}
	return string(m)
}

func printClaims(tok *xappclient.Token) {
	interesting := []string{"iss", "aud", "azp", "scope", "realm_access"}
	parts := make([]string, 0, len(interesting))
	for _, name := range interesting {
		if v, ok := tok.Claims[name]; ok {
			raw, _ := json.Marshal(v)
			parts = append(parts, fmt.Sprintf("%s=%s", name, raw))
		}
	}
	item("claims", "%s", strings.Join(parts, " "))
	if up, ok := tok.Claims["upgraded_from"].(map[string]any); ok {
		raw, _ := json.Marshal(up)
		item("provenance", "%s", raw)
	}
}

// call sends a resource request through the client and returns the TLS state.
func (r *runner) call(c xappclient.Client, url string) (int, string, *tls.ConnectionState, error) {
	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, string(body), resp.TLS, nil
}

// send crafts a request with explicit credentials, for the negative tests.
func (r *runner) send(url string, cert *tls.Certificate, headers map[string]string) (int, xappresource.RejectionBody, error) {
	conf := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: r.roots}
	if cert != nil {
		conf.Certificates = []tls.Certificate{*cert}
	}
	tr := netx.NewTransport(conf, r.overrides)
	tr.DisableKeepAlives = true
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, xappresource.RejectionBody{}, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Transport: tr, Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return 0, xappresource.RejectionBody{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var rb xappresource.RejectionBody
	if resp.StatusCode != http.StatusOK {
		_ = json.Unmarshal(raw, &rb)
	}
	return resp.StatusCode, rb, nil
}

// methodSpecific shows what makes each method different.
func (r *runner) methodSpecific(m xappclient.Method, client xappclient.Client, tok *xappclient.Token) error {
	switch m {
	case xappclient.MethodEphemeral:
		step("Key rotation (Method B)")
		before := client.Identity().Leaf().SerialNumber.Text(16)
		stats, err := client.Rotate(r.ctx)
		if err != nil {
			return fmt.Errorf("rotate: %w", err)
		}
		item("previous certificate", "serial %s", before)
		item("new certificate", "serial %s (%s, %d bytes)", stats.Serial, stats.KeyAlg, stats.CertBytes)
		item("rotation cost", "keygen %.2f ms, CA round trip %.2f ms", msOf(stats.KeyGen), msOf(stats.RoundTrip))
		// The token issued before rotation is bound to the retired certificate.
		status, rb, err := r.send(r.path(xappresource.ModeLocal), r.activeCert(client), bearer(tok))
		if err != nil {
			return err
		}
		r.check(status == http.StatusUnauthorized && rb.ReasonCode == xappresource.ReasonX5tMismatch,
			"token from before the rotation is rejected: HTTP %d %s", status, rb.ReasonCode)
		item("reason", "%s", rb.Reason)
		if _, err := client.Token(r.ctx); err != nil {
			return fmt.Errorf("token after rotation: %w", err)
		}
		status, body, _, err := r.call(client, r.path(xappresource.ModeLocal))
		if err != nil {
			return err
		}
		r.check(status == http.StatusOK, "a token bound to the new certificate is accepted: HTTP %d %s", status, strings.TrimSpace(body))

	case xappclient.MethodDPoP:
		step("DPoP proof (Method C)")
		dp := client.(xappclient.DPoP)
		signer := dp.Signer()
		if tok.PostQuantum {
			signer = dp.PQSigner()
		}
		proof, err := xappclient.BuildDPoPProof(signer, http.MethodGet, r.path(xappresource.ModeLocal), tok.Value, "", time.Now())
		if err != nil {
			return err
		}
		parsed, err := jose.ParseCompact(proof)
		if err != nil {
			return err
		}
		item("proof algorithm", "%s", parsed.Alg())
		item("proof size", "%d bytes", len(proof))
		item("proof key thumbprint", "%s", tok.Thumbprint)
		// First use is accepted, the replay of the same proof is not.
		status, _, err := r.send(r.path(xappresource.ModeLocal), r.activeCert(client), dpopHeaders(tok, proof))
		if err != nil {
			return err
		}
		r.check(status == http.StatusOK, "first use of the proof is accepted (HTTP %d)", status)
		status, rb, err := r.send(r.path(xappresource.ModeLocal), r.activeCert(client), dpopHeaders(tok, proof))
		if err != nil {
			return err
		}
		r.check(status == http.StatusUnauthorized && rb.ReasonCode == xappresource.ReasonDPoPReplayed,
			"replaying the same proof is rejected: HTTP %d %s", status, rb.ReasonCode)
		item("reason", "%s", rb.Reason)
	}
	return nil
}

// negative is the core security claim for the method: the token alone is not enough.
func (r *runner) negative(m xappclient.Method, client xappclient.Client, tok *xappclient.Token) error {
	step("Negative test: the token alone must not be enough")
	other, err := r.newClient()
	if err != nil {
		return fmt.Errorf("second client: %w", err)
	}
	fresh, err := client.Token(r.ctx)
	if err != nil {
		return err
	}
	if m == xappclient.MethodDPoP {
		// Present the DPoP-bound token with a proof signed by another key.
		dp := other.(xappclient.DPoP)
		signer := dp.Signer()
		if fresh.PostQuantum {
			signer = dp.PQSigner()
		}
		proof, err := xappclient.BuildDPoPProof(signer, http.MethodGet, r.path(xappresource.ModeLocal), fresh.Value, "", time.Now())
		if err != nil {
			return err
		}
		status, rb, err := r.send(r.path(xappresource.ModeLocal), r.activeCert(other), dpopHeaders(fresh, proof))
		if err != nil {
			return err
		}
		r.check(status == http.StatusUnauthorized && rb.ReasonCode == xappresource.ReasonDPoPJktMismatch,
			"stolen token with the attacker proof key is rejected: HTTP %d %s", status, rb.ReasonCode)
		item("reason", "%s", rb.Reason)
		return nil
	}
	// Methods A and B: present the token over another certificate, and with none.
	status, rb, err := r.send(r.path(xappresource.ModeLocal), r.activeCert(other), bearer(fresh))
	if err != nil {
		return err
	}
	r.check(status == http.StatusUnauthorized && rb.ReasonCode == xappresource.ReasonX5tMismatch,
		"stolen token over another certificate is rejected: HTTP %d %s", status, rb.ReasonCode)
	item("reason", "%s", rb.Reason)

	status, rb, err = r.send(r.path(xappresource.ModeLocal), nil, bearer(fresh))
	if err != nil {
		return err
	}
	r.check(status == http.StatusUnauthorized && rb.ReasonCode == xappresource.ReasonClientCertMissing,
		"stolen token with no certificate is rejected: HTTP %d %s", status, rb.ReasonCode)
	item("reason", "%s", rb.Reason)
	return nil
}

// activeCert is the credential a resource server expects to see.
func (r *runner) activeCert(c xappclient.Client) *tls.Certificate {
	if r.pq && c.PQIdentity() != nil {
		return c.PQIdentity().Current()
	}
	return c.Identity().Current()
}

func bearer(tok *xappclient.Token) map[string]string {
	return map[string]string{"Authorization": "Bearer " + tok.Value}
}

func dpopHeaders(tok *xappclient.Token, proof string) map[string]string {
	return map[string]string{"Authorization": "DPoP " + tok.Value, "DPoP": proof}
}

func msOf(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
