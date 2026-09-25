package xappresource

import (
	"sync"
	"time"
)

// ReplayCache remembers DPoP proof identifiers until their acceptance window has
// passed. When full it refuses new entries (fail closed) after sweeping expired ones.
type ReplayCache struct {
	mu        sync.Mutex
	entries   map[string]time.Time
	max       int
	lastSweep time.Time
}

// NewReplayCache creates a cache holding at most max identifiers.
func NewReplayCache(max int) *ReplayCache {
	return &ReplayCache{entries: make(map[string]time.Time), max: max}
}

// Result of CheckAndStore.
const (
	ReplayFresh = iota
	ReplaySeen
	ReplayFull
)

// CheckAndStore records key until expiry unless it is already present and unexpired.
func (c *ReplayCache) CheckAndStore(key string, expiry, now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if exp, ok := c.entries[key]; ok && now.Before(exp) {
		return ReplaySeen
	}
	if len(c.entries) >= c.max || now.Sub(c.lastSweep) > 10*time.Second {
		for k, exp := range c.entries {
			if !now.Before(exp) {
				delete(c.entries, k)
			}
		}
		c.lastSweep = now
		if len(c.entries) >= c.max {
			return ReplayFull
		}
	}
	c.entries[key] = expiry
	return ReplayFresh
}

// Len returns the number of stored identifiers.
func (c *ReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
