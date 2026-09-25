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
