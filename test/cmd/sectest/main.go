// Command sectest is the security test suite. It runs against the deployed testbed
// (RIC CA, Keycloak, demo resource xApp) and prints, for every case, the HTTP status
// and the validator's specific rejection reason so results can be quoted directly.
// Results are also written as CSV. Exit status is non-zero if any case fails.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
	"errors"
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

type result struct {
	ID          string
	Category    string
	Description string
	Mode        string
	Expected    string
	Status      int
	ReasonCode  string
	Reason      string
	Pass        bool
}

type harness struct {
	ctx         context.Context
	log         *slog.Logger
	base        xappclient.Config
	onboarding  *smo.Onboarding
	roots       *x509.CertPool
	overrides   map[string]string
	resourceURL string
	ids         struct{ longterm, ephemeral, dpop, unbound string }
	results     []result
}

var modes = []xappresource.Mode{xappresource.ModeLocal, xappresource.ModeIntrospection}

func main() {
	out := flag.String("out", "results/security-tests.csv", "CSV output")
	expiryLifetime := flag.Duration("expiry-lifetime", 12*time.Second, "certificate lifetime used by the Method B expiry test")
	flag.Parse()

	log := logx.New("sectest")
	h, err := newHarness(log)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		os.Exit(2)
	}
	// This suite drives the classical HTTP path: it presents Keycloak-issued tokens
	// directly to the resource xApp. Against a post-quantum deployment the resource
	// trusts the shim instead, so every case would fail for the wrong reason. Say so
	// once rather than reporting three dozen misleading failures.
	if os.Getenv("PQ_MODE") == "true" {
		fmt.Fprintf(os.Stderr,
			"this deployment is in post-quantum mode (the resource xApps trust %s).\n"+
				"The security suite drives the classical path; run 'make classical-up' first,\n"+
				"or exercise the post-quantum path with 'make run-a', 'make run-b', 'make run-c'.\n", os.Getenv("PQ_SHIM_URL"))
		os.Exit(2)
	}
	fmt.Printf("Security test suite against %s\n\n", h.resourceURL)

	steps := []struct {
		name string
		fn   func() error
	}{
		{"positive controls (A, B, C)", h.positive},
		{"N1 token over another xApp's mTLS session", h.n1WrongCertificate},
		{"N2 token without client certificate", h.n2NoCertificate},
		{"N3 DPoP proof signed by a different key", h.n3ForeignDPoPKey},
		{"N4 DPoP proof replay", h.n4Replay},
		{"N5 DPoP ath from a different token", h.n5AthOtherToken},
		{"N6 Method B token after certificate expiry", func() error { return h.n6ExpiredCertificate(*expiryLifetime) }},
		{"N7 bearer-style use", h.n7BearerStyle},
		{"X  additional proof-of-possession checks", h.extraDPoP},
		{"X  Method B rotation and token tampering", h.extraRotationAndTamper},
		{"X  enrollment and authorization-server checks", h.extraIssuance},
	}
	for _, s := range steps {
		fmt.Printf("== %s\n", s.name)
		if err := s.fn(); err != nil {
			h.add(result{ID: "ERR", Category: "harness", Description: s.name, Expected: "no harness error", Reason: err.Error()})
			fmt.Printf("  [FAIL] harness error: %v\n", err)
		}
	}

	failed := 0
	for _, r := range h.results {
		if !r.Pass {
			failed++
		}
	}
	if err := writeCSV(*out, h.results); err != nil {
		fmt.Fprintln(os.Stderr, "write results:", err)
	}
	fmt.Printf("\n%d cases, %d passed, %d failed. Results: %s\n", len(h.results), len(h.results)-failed, failed, *out)
	if failed > 0 {
		os.Exit(1)
	}
}

func newHarness(log *slog.Logger) (*harness, error) {
	e := &config.Env{}
	h := &harness{ctx: context.Background(), log: log}
	h.resourceURL = strings.TrimRight(e.Req("RESOURCE_URL"), "/")
	h.ids.longterm = e.Req("LONGTERM_CLIENT_ID")
	h.ids.ephemeral = e.Req("EPHEMERAL_CLIENT_ID")
	h.ids.dpop = e.Req("DPOP_CLIENT_ID")
	h.ids.unbound = e.Req("UNBOUND_CLIENT_ID")
	h.base = xappclient.Config{
		TokenURL:    e.Req("KEYCLOAK_TOKEN_URL"),
		Scope:       e.Str("TOKEN_SCOPE", ""),
		TrustBundle: e.List("RIC_TRUST_BUNDLE", nil),
		CAURL:       e.Req("RIC_CA_URL"),
		KeyAlg:      "EC-P256",
		DPoPAlg:     e.Str("DPOP_ALG", "ES256"),
		Rotation:    xappclient.RotateOnCertExpiry,
		HTTPTimeout: 20 * time.Second,
	}
	onbCert, onbKey, org := e.Req("SMO_ONBOARDING_CERT"), e.Req("SMO_ONBOARDING_KEY"), e.Req("ORG")
	overrides, err := netx.ParseDialOverrides(e.Str("DIAL_OVERRIDES", ""))
	if err != nil {
		e.Fail("DIAL_OVERRIDES: %v", err)
	}
	if err := e.Err(); err != nil {
		return nil, err
	}
	h.overrides, h.base.DialOverrides = overrides, overrides
	if h.roots, err = pki.LoadCertPool(h.base.TrustBundle...); err != nil {
		return nil, err
	}
	if h.onboarding, err = smo.LoadOnboarding(onbCert, onbKey, org); err != nil {
		return nil, err
	}
	return h, nil
}

// client onboards (fresh one-time bootstrap credential) and starts a client.
func (h *harness) client(m xappclient.Method, clientID string, lifetime time.Duration) (xappclient.Client, error) {
	cfg := h.base
	cfg.Method, cfg.ClientID, cfg.CertLifetime = m, clientID, lifetime
	boot, err := h.onboarding.IssueBootstrap(clientID, nil, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	cfg.Bootstrap = boot
	c, err := xappclient.New(cfg, h.log)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(h.ctx, time.Minute)
	defer cancel()
	if err := c.Start(ctx); err != nil {
		return nil, fmt.Errorf("start %s: %w", clientID, err)
	}
	return c, nil
}

func (h *harness) path(mode xappresource.Mode) string {
	if mode == xappresource.ModeIntrospection {
		return h.resourceURL + "/api/v1/introspect/sdl/sectest"
	}
	return h.resourceURL + "/api/v1/sdl/sectest"
}

// send performs a GET over a fresh TLS connection presenting cert (nil: no client certificate).
func (h *harness) send(url string, cert *tls.Certificate, headers map[string]string) (int, xappresource.RejectionBody, error) {
	conf := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: h.roots}
	if cert != nil {
		conf.Certificates = []tls.Certificate{*cert}
	}
	tr := netx.NewTransport(conf, h.overrides)
	tr.DisableKeepAlives = true
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(h.ctx, http.MethodGet, url, nil)
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
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var rb xappresource.RejectionBody
	if resp.StatusCode != http.StatusOK {
		_ = json.Unmarshal(body, &rb)
	}
	return resp.StatusCode, rb, nil
}

func (h *harness) add(r result) {
	h.results = append(h.results, r)
	verdict := "PASS"
	if !r.Pass {
		verdict = "FAIL"
	}
	mode := r.Mode
	if mode == "" {
		mode = "-"
	}
	code := r.ReasonCode
	if code == "" {
		code = fmt.Sprintf("HTTP %d", r.Status)
	}
	fmt.Printf("  [%s] %-4s %-13s %-30s %s\n", verdict, r.ID, mode, code, r.Reason)
	if !r.Pass {
		fmt.Printf("         expected: %s\n", r.Expected)
	}
}

// expectAccepted records a positive case.
func (h *harness) expectAccepted(id, desc string, mode xappresource.Mode, status int, rb xappresource.RejectionBody, err error) {
	r := result{ID: id, Category: "positive", Description: desc, Mode: string(mode), Expected: "HTTP 200", Status: status}
	switch {
	case err != nil:
		r.Reason = err.Error()
	case status == http.StatusOK:
		r.Pass, r.Reason = true, "accepted"
	default:
		r.ReasonCode, r.Reason = rb.ReasonCode, rb.Reason
	}
	h.add(r)
}

// expectRejected records a negative case: HTTP 401/403 with the given reason code.
func (h *harness) expectRejected(id, desc string, mode xappresource.Mode, want string, status int, rb xappresource.RejectionBody, err error) {
	r := result{ID: id, Category: "negative", Description: desc, Mode: string(mode), Expected: "rejected with " + want, Status: status,
		ReasonCode: rb.ReasonCode, Reason: rb.Reason}
	if err != nil {
		r.Reason = err.Error()
	}
	r.Pass = err == nil && (status == http.StatusUnauthorized || status == http.StatusForbidden) && rb.ReasonCode == want
	h.add(r)
}

func bearer(tok string) map[string]string { return map[string]string{"Authorization": "Bearer " + tok} }

func dpopHeaders(tok, proof string) map[string]string {
	return map[string]string{"Authorization": "DPoP " + tok, "DPoP": proof}
}

// ---------------------------------------------------------------------------------

func (h *harness) positive() error {
	for _, spec := range []struct {
		id     string
		method xappclient.Method
		client string
		life   time.Duration
	}{
		{"P1", xappclient.MethodLongTerm, h.ids.longterm, 168 * time.Hour},
		{"P2", xappclient.MethodEphemeral, h.ids.ephemeral, 15 * time.Minute},
		{"P3", xappclient.MethodDPoP, h.ids.dpop, 168 * time.Hour},
	} {
		c, err := h.client(spec.method, spec.client, spec.life)
		if err != nil {
			return err
		}
		tok, err := c.Token(h.ctx)
		if err != nil {
			return fmt.Errorf("%s token: %w", spec.client, err)
		}
		// Milestone 2 guard, recorded explicitly: the binding Keycloak put in the token.
		h.add(result{ID: spec.id + "-cnf", Category: "positive", Description: fmt.Sprintf("Method %s token carries cnf.%s matching the client's key material", spec.method, tok.Binding),
			Expected: "cnf present and equal to certificate/JWK thumbprint", Pass: true, ReasonCode: "cnf." + tok.Binding, Reason: tok.Thumbprint})
		for _, mode := range modes {
			var status int
			var rb xappresource.RejectionBody
			if spec.method == xappclient.MethodDPoP {
				proof, perr := c.(xappclient.DPoP).Proof(http.MethodGet, h.path(mode), tok.Value)
				if perr != nil {
					return perr
				}
				status, rb, err = h.send(h.path(mode), c.Identity().Current(), dpopHeaders(tok.Value, proof))
			} else {
				status, rb, err = h.send(h.path(mode), c.Identity().Current(), bearer(tok.Value))
			}
			h.expectAccepted(spec.id, fmt.Sprintf("Method %s: token presented by its legitimate holder", spec.method), mode, status, rb, err)
		}
	}
	return nil
}

func (h *harness) n1WrongCertificate() error {
	a, err := h.client(xappclient.MethodLongTerm, h.ids.longterm, 168*time.Hour)
	if err != nil {
		return err
	}
	b, err := h.client(xappclient.MethodEphemeral, h.ids.ephemeral, 15*time.Minute)
	if err != nil {
		return err
	}
	tokA, err := a.Token(h.ctx)
	if err != nil {
		return err
	}
	for _, mode := range modes {
		status, rb, err := h.send(h.path(mode), b.Identity().Current(), bearer(tokA.Value))
		h.expectRejected("N1", "Token issued to xApp A presented over xApp B's mTLS session", mode, xappresource.ReasonX5tMismatch, status, rb, err)
	}
	return nil
}

func (h *harness) n2NoCertificate() error {
	a, err := h.client(xappclient.MethodLongTerm, h.ids.longterm, 168*time.Hour)
	if err != nil {
		return err
	}
	tokA, err := a.Token(h.ctx)
	if err != nil {
		return err
	}
	for _, mode := range modes {
		status, rb, err := h.send(h.path(mode), nil, bearer(tokA.Value))
		h.expectRejected("N2", "Token issued to xApp A presented with no client certificate", mode, xappresource.ReasonClientCertMissing, status, rb, err)
	}
	return nil
}

func (h *harness) dpopClient() (xappclient.Client, *xappclient.Token, error) {
	c, err := h.client(xappclient.MethodDPoP, h.ids.dpop, 168*time.Hour)
	if err != nil {
		return nil, nil, err
	}
	tok, err := c.Token(h.ctx)
	return c, tok, err
}

func (h *harness) n3ForeignDPoPKey() error {
	c, tok, err := h.dpopClient()
	if err != nil {
		return err
	}
	attacker, err := jose.GenerateSigner(h.base.DPoPAlg)
	if err != nil {
		return err
	}
	for _, mode := range modes {
		// Well-formed proof (correct htm, htu, ath, fresh jti) but signed by the attacker's key.
		proof, err := xappclient.BuildDPoPProof(attacker, http.MethodGet, h.path(mode), tok.Value, "", time.Now())
		if err != nil {
			return err
		}
		status, rb, err := h.send(h.path(mode), c.Identity().Current(), dpopHeaders(tok.Value, proof))
		h.expectRejected("N3", "DPoP token presented with a proof signed by a different key", mode, xappresource.ReasonDPoPJktMismatch, status, rb, err)
	}
	return nil
}

func (h *harness) n4Replay() error {
	c, tok, err := h.dpopClient()
	if err != nil {
		return err
	}
	for _, mode := range modes {
		proof, err := c.(xappclient.DPoP).Proof(http.MethodGet, h.path(mode), tok.Value)
		if err != nil {
			return err
		}
		status, rb, err := h.send(h.path(mode), c.Identity().Current(), dpopHeaders(tok.Value, proof))
		h.expectAccepted("N4-1", "DPoP proof first use (control for replay test)", mode, status, rb, err)
		status, rb, err = h.send(h.path(mode), c.Identity().Current(), dpopHeaders(tok.Value, proof))
		h.expectRejected("N4", "DPoP proof replayed (same jti)", mode, xappresource.ReasonDPoPReplayed, status, rb, err)
	}
	return nil
}

func (h *harness) n5AthOtherToken() error {
	c, tok1, err := h.dpopClient()
	if err != nil {
		return err
	}
	tok2, err := c.IssueToken(h.ctx)
	if err != nil {
		return err
	}
	for _, mode := range modes {
		proof, err := c.(xappclient.DPoP).Proof(http.MethodGet, h.path(mode), tok1.Value) // ath of token 1
		if err != nil {
			return err
		}
		status, rb, err := h.send(h.path(mode), c.Identity().Current(), dpopHeaders(tok2.Value, proof)) // presenting token 2
		h.expectRejected("N5", "DPoP proof whose ath is the hash of a different token", mode, xappresource.ReasonDPoPAthMismatch, status, rb, err)
	}
	return nil
}

func (h *harness) n6ExpiredCertificate(lifetime time.Duration) error {
	b, err := h.client(xappclient.MethodEphemeral, h.ids.ephemeral, lifetime)
	if err != nil {
		return err
	}
	tok, err := b.IssueToken(h.ctx)
	if err != nil {
		return err
	}
	cert := b.Identity().Current()
	status, rb, err := h.send(h.path(xappresource.ModeLocal), cert, bearer(tok.Value))
	h.expectAccepted("N6-1", "Method B: token accepted while its short-lived certificate is valid (control)", xappresource.ModeLocal, status, rb, err)

	wait := time.Until(cert.Leaf.NotAfter) + 2*time.Second
	fmt.Printf("  ...waiting %s for the %s certificate to expire (token still valid until %s)\n",
		wait.Round(time.Second), lifetime, tok.ExpiresAt.Format(time.TimeOnly))
	time.Sleep(wait)
	for _, mode := range modes {
		status, rb, err := h.send(h.path(mode), cert, bearer(tok.Value))
		h.expectRejected("N6", "Method B: unexpired token presented after its short-lived certificate expired", mode, xappresource.ReasonClientCertExpired, status, rb, err)
	}
	return nil
}

func (h *harness) n7BearerStyle() error {
	c, tok, err := h.dpopClient()
	if err != nil {
		return err
	}
	a, err := h.client(xappclient.MethodLongTerm, h.ids.longterm, 168*time.Hour)
	if err != nil {
		return err
	}
	tokA, err := a.Token(h.ctx)
	if err != nil {
		return err
	}
	for _, mode := range modes {
		status, rb, err := h.send(h.path(mode), nil, bearer(tokA.Value))
		h.expectRejected("N7a", "Bearer-style use of a certificate-bound token (token only, no certificate)", mode, xappresource.ReasonClientCertMissing, status, rb, err)
		status, rb, err = h.send(h.path(mode), c.Identity().Current(), bearer(tok.Value))
		h.expectRejected("N7b", "Bearer-style use of a DPoP-bound token (Bearer scheme, no proof)", mode, xappresource.ReasonDPoPAsBearer, status, rb, err)
		status, rb, err = h.send(h.path(mode), c.Identity().Current(), map[string]string{"Authorization": "DPoP " + tok.Value})
		h.expectRejected("N7c", "DPoP-bound token with DPoP scheme but no proof header", mode, xappresource.ReasonDPoPProofMissing, status, rb, err)
	}

	// A genuinely unbound token (test-only client with both binding switches off),
	// presented over a valid mTLS session: the validator must still refuse it.
	u, err := h.client(xappclient.MethodLongTerm, h.ids.unbound, time.Hour)
	if err != nil {
		return err
	}
	_, err = u.Token(h.ctx)
	if !errors.Is(err, xappclient.ErrBindingMissing) {
		return fmt.Errorf("expected the client library to refuse an unbound token, got %v", err)
	}
	h.add(result{ID: "N7d-client", Category: "negative", Description: "Client library refuses a token issued without cnf (Keycloak issues it anyway)",
		Expected: "ErrBindingMissing", Pass: true, ReasonCode: "binding_missing", Reason: err.Error()})
	raw, err := rawToken(h, u)
	if err != nil {
		return err
	}
	for _, mode := range modes {
		status, rb, err := h.send(h.path(mode), u.Identity().Current(), bearer(raw))
		h.expectRejected("N7d", "Unbound bearer token (no cnf) presented over a valid mTLS session", mode, xappresource.ReasonCnfMissing, status, rb, err)
	}
	return nil
}

// rawToken fetches a token without the client-side binding check.
func rawToken(h *harness, c xappclient.Client) (string, error) {
	resp, err := xappclient.KeycloakIssuer{}.Issue(h.ctx, xappclient.TokenRequest{
		TokenURL: h.base.TokenURL, ClientID: c.ClientID(), Scope: h.base.Scope, HTTPClient: c.HTTPClient(),
	})
	if err != nil {
		return "", err
	}
	return resp.AccessToken, nil
}

func (h *harness) extraDPoP() error {
	c, tok, err := h.dpopClient()
	if err != nil {
		return err
	}
	signer := c.(xappclient.DPoP).Signer()
	cert := c.Identity().Current()
	for _, mode := range modes {
		proof, _ := xappclient.BuildDPoPProof(signer, http.MethodPost, h.path(mode), tok.Value, "", time.Now())
		status, rb, err := h.send(h.path(mode), cert, dpopHeaders(tok.Value, proof))
		h.expectRejected("X1", "DPoP proof for a different HTTP method (htm)", mode, xappresource.ReasonDPoPHtmMismatch, status, rb, err)

		proof, _ = xappclient.BuildDPoPProof(signer, http.MethodGet, h.resourceURL+"/api/v1/sdl/other-resource", tok.Value, "", time.Now())
		status, rb, err = h.send(h.path(mode), cert, dpopHeaders(tok.Value, proof))
		h.expectRejected("X2", "DPoP proof for a different URI (htu)", mode, xappresource.ReasonDPoPHtuMismatch, status, rb, err)

		proof, _ = xappclient.BuildDPoPProof(signer, http.MethodGet, h.path(mode), tok.Value, "", time.Now().Add(-10*time.Minute))
		status, rb, err = h.send(h.path(mode), cert, dpopHeaders(tok.Value, proof))
		h.expectRejected("X3", "Stale DPoP proof (iat 10 minutes old)", mode, xappresource.ReasonDPoPIatOutOfWindow, status, rb, err)
	}
	return nil
}

func (h *harness) extraRotationAndTamper() error {
	b, err := h.client(xappclient.MethodEphemeral, h.ids.ephemeral, 15*time.Minute)
	if err != nil {
		return err
	}
	oldTok, err := b.Token(h.ctx)
	if err != nil {
		return err
	}
	if _, err := b.Rotate(h.ctx); err != nil {
		return err
	}
	for _, mode := range modes {
		status, rb, err := h.send(h.path(mode), b.Identity().Current(), bearer(oldTok.Value))
		h.expectRejected("X4", "Method B: token bound to the previous certificate, presented after key rotation", mode, xappresource.ReasonX5tMismatch, status, rb, err)
	}

	newTok, err := b.Token(h.ctx)
	if err != nil {
		return err
	}
	parts := strings.Split(newTok.Value, ".")
	sig := []byte(parts[2])
	if sig[10] == 'A' {
		sig[10] = 'B'
	} else {
		sig[10] = 'A'
	}
	tampered := parts[0] + "." + parts[1] + "." + string(sig)
	status, rb, err := h.send(h.path(xappresource.ModeLocal), b.Identity().Current(), bearer(tampered))
	h.expectRejected("X5", "Access token with a modified signature", xappresource.ModeLocal, xappresource.ReasonTokenSignatureInvalid, status, rb, err)
	status, rb, err = h.send(h.path(xappresource.ModeIntrospection), b.Identity().Current(), bearer(tampered))
	h.expectRejected("X5", "Access token with a modified signature", xappresource.ModeIntrospection, xappresource.ReasonTokenInactive, status, rb, err)
	return nil
}

func (h *harness) extraIssuance() error {
	// X6: one-time bootstrap credential.
	boot, err := h.onboarding.IssueBootstrap("sectest-onetime", nil, 10*time.Minute)
	if err != nil {
		return err
	}
	enr := &xappclient.Enroller{BaseURL: h.base.CAURL, Roots: h.roots, Overrides: h.overrides, Timeout: 20 * time.Second}
	key, _ := pki.GenerateKey("EC-P256")
	if _, err := enr.Enroll(h.ctx, boot, key, nil, time.Hour, false); err != nil {
		return fmt.Errorf("first enrollment should succeed: %w", err)
	}
	_, err = enr.Enroll(h.ctx, boot, key, nil, time.Hour, false)
	h.add(result{ID: "X6", Category: "negative", Description: "RIC CA: bootstrap credential used a second time", Expected: "HTTP 403 bootstrap_credential_reused",
		Status: statusOf(err), ReasonCode: codeOf(err, "bootstrap_credential_reused"), Reason: errString(err),
		Pass: err != nil && strings.Contains(err.Error(), "bootstrap_credential_reused")})

	// X7: Keycloak must not issue a token to a certificate outside the RIC trust anchor.
	status, detail, got := h.tokenWith(h.ids.longterm, boot)
	h.add(result{ID: "X7", Category: "negative", Description: "Keycloak: token request authenticated with a certificate not issued by the RIC CA",
		Expected: "no token", Status: status, ReasonCode: "no_token", Reason: detail, Pass: !got})

	// X8: a valid RIC certificate for another identity cannot obtain this client's token.
	b, err := h.client(xappclient.MethodEphemeral, h.ids.ephemeral, 15*time.Minute)
	if err != nil {
		return err
	}
	status, detail, got = h.tokenWith(h.ids.longterm, b.Identity().Current())
	h.add(result{ID: "X8", Category: "negative", Description: "Keycloak: client_id xapp-longterm requested with xapp-ephemeral's certificate (subject DN mismatch)",
		Expected: "no token", Status: status, ReasonCode: "no_token", Reason: detail, Pass: !got})
	return nil
}

func (h *harness) tokenWith(clientID string, cert *tls.Certificate) (int, string, bool) {
	conf := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: h.roots, Certificates: []tls.Certificate{*cert}}
	tr := netx.NewTransport(conf, h.overrides)
	tr.DisableKeepAlives = true
	defer tr.CloseIdleConnections()
	resp, err := xappclient.KeycloakIssuer{}.Issue(h.ctx, xappclient.TokenRequest{
		TokenURL: h.base.TokenURL, ClientID: clientID, Scope: h.base.Scope, HTTPClient: &http.Client{Transport: tr, Timeout: 30 * time.Second},
	})
	if err != nil {
		var ie *xappclient.IssuerError
		if errors.As(err, &ie) {
			return ie.Status, ie.Body, false
		}
		return 0, err.Error(), false
	}
	return http.StatusOK, "token issued", resp.AccessToken != ""
}

func statusOf(err error) int {
	if err == nil {
		return http.StatusOK
	}
	var code int
	if i := strings.Index(err.Error(), "HTTP "); i >= 0 {
		fmt.Sscanf(err.Error()[i:], "HTTP %d", &code)
	}
	return code
}

func codeOf(err error, want string) string {
	if err != nil && strings.Contains(err.Error(), want) {
		return want
	}
	return ""
}

func errString(err error) string {
	if err == nil {
		return "accepted"
	}
	return err.Error()
}

func writeCSV(path string, rs []result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	_ = w.Write([]string{"id", "category", "description", "validation_mode", "expected", "http_status", "reason_code", "reason", "verdict"})
	for _, r := range rs {
		verdict := "PASS"
		if !r.Pass {
			verdict = "FAIL"
		}
		_ = w.Write([]string{r.ID, r.Category, r.Description, r.Mode, r.Expected, fmt.Sprint(r.Status), r.ReasonCode, r.Reason, verdict})
	}
	w.Flush()
	return w.Error()
}
