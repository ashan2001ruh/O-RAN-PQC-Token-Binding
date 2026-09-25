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
