package xappresource

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Introspector calls the RFC 7662 introspection endpoint, authenticating as the
// resource xApp's own client over its mTLS identity.
type Introspector struct {
	URL      string
	ClientID string
	Client   *http.Client
}

// Introspect returns the claims of an active token, or a rejection.
func (i *Introspector) Introspect(ctx context.Context, token string) (map[string]any, *Rejection) {
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}, "client_id": {i.ClientID}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, i.URL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, reject(ReasonIntrospectionFailed, "build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := i.Client.Do(req)
	if err != nil {
		return nil, reject(ReasonIntrospectionFailed, "introspection endpoint unreachable: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, reject(ReasonIntrospectionFailed, "read response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, reject(ReasonIntrospectionFailed, "introspection endpoint returned HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var claims map[string]any
	if err := dec.Decode(&claims); err != nil || claims == nil {
		return nil, reject(ReasonIntrospectionFailed, "introspection response is not a JSON object")
	}
	if active, _ := claims["active"].(bool); !active {
		return nil, reject(ReasonTokenInactive, "authorization server reports the token as inactive (expired, revoked, or not issued by it)")
	}
	return claims, nil
}
