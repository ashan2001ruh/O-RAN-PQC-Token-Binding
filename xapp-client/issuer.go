package xappclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TokenRequest carries everything needed for one issuance call.
type TokenRequest struct {
	TokenURL   string
	ClientID   string
	Scope      string
	DPoPProof  string       // set for method C
	HTTPClient *http.Client // mTLS client presenting the xApp identity
}

// TokenResponse is the authorization server's answer.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	ReceivedAt  time.Time
}

// Issuer is the single token-issuance path used by every method. A later phase can
// insert a re-signing shim (e.g. ML-DSA) by wrapping it with Client.SetIssuer,
// without touching any call site.
type Issuer interface {
	Issue(ctx context.Context, req TokenRequest) (*TokenResponse, error)
}

// IssuerError is a non-200 token endpoint response.
type IssuerError struct {
	Status    int
	Body      string
	DPoPNonce string
}

func (e *IssuerError) Error() string {
	return fmt.Sprintf("token endpoint HTTP %d: %s", e.Status, e.Body)
}

// NeedsNonce reports whether the server demanded a DPoP nonce (RFC 9449 §8).
func (e *IssuerError) NeedsNonce() bool {
	return e.DPoPNonce != "" && strings.Contains(e.Body, "use_dpop_nonce")
}

// KeycloakIssuer performs the OAuth 2.0 client_credentials grant against Keycloak.
type KeycloakIssuer struct{}

// Issue implements Issuer.
func (KeycloakIssuer) Issue(ctx context.Context, r TokenRequest) (*TokenResponse, error) {
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {r.ClientID}}
	if r.Scope != "" {
		form.Set("scope", r.Scope)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if r.DPoPProof != "" {
		req.Header.Set("DPoP", r.DPoPProof)
	}
	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token endpoint: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &IssuerError{Status: resp.StatusCode, Body: strings.TrimSpace(string(body)), DPoPNonce: resp.Header.Get("DPoP-Nonce")}
	}
	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("token response: %w", err)
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("token response has no access_token")
	}
	tr.ReceivedAt = time.Now()
	return &tr, nil
}
