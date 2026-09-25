package jose

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

// KeySet caches the verification keys published at a JWKS URL. Keys are never
// embedded: an unknown kid triggers a rate-limited refetch, which also covers
// issuer key rotation and a change of signature algorithm (ES256 to ML-DSA).
// Parsing is done by jwx, so AKP (ML-DSA) keys need no special handling.
type KeySet struct {
	url        string
	client     *http.Client
	ttl        time.Duration
	minRefresh time.Duration

	mu          sync.RWMutex
	set         jwk.Set
	fetched     time.Time
	lastAttempt time.Time
}

// NewKeySet creates a cache for url.
func NewKeySet(url string, client *http.Client, ttl, minRefresh time.Duration) *KeySet {
	return &KeySet{url: url, client: client, ttl: ttl, minRefresh: minRefresh}
}

// Key returns the verification key for kid, checking it is a signing key usable with alg.
func (s *KeySet) Key(ctx context.Context, kid, alg string) (any, error) {
	if kid == "" {
		return nil, fmt.Errorf("JWS header has no kid")
	}
	key, ok := s.lookup(kid)
	if !ok || s.stale() {
		if err := s.refresh(ctx); err != nil && !ok {
			return nil, err
		}
		if key, ok = s.lookup(kid); !ok {
			return nil, fmt.Errorf("kid %q not found in JWKS %s", kid, s.url)
		}
	}
	if use, ok := key.KeyUsage(); ok && use != "" && use != "sig" {
		return nil, fmt.Errorf("kid %q has use %q, not sig", kid, use)
	}
	if ka, ok := key.Algorithm(); ok && ka != nil && ka.String() != "" && ka.String() != alg {
		return nil, fmt.Errorf("kid %q is bound to alg %q but token uses %q", kid, ka.String(), alg)
	}
	return key, nil
}

func (s *KeySet) lookup(kid string) (jwk.Key, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.set == nil {
		return nil, false
	}
	return s.set.LookupKeyID(kid)
}

func (s *KeySet) stale() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.fetched) > s.ttl
}

func (s *KeySet) refresh(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.lastAttempt.IsZero() && time.Since(s.lastAttempt) < s.minRefresh && time.Since(s.fetched) <= s.ttl {
		return nil
	}
	s.lastAttempt = time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	// ML-DSA public keys are kilobytes, not bytes: keep the limit generous.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch JWKS: HTTP %d", resp.StatusCode)
	}
	set, err := jwk.Parse(body)
	if err != nil {
		return fmt.Errorf("parse JWKS: %w", err)
	}
	s.set = set
	s.fetched = time.Now()
	return nil
}
