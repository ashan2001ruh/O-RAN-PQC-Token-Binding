// Package sidecar is the xApp sidecar: one container, injected next to an unmodified
// xApp, that carries the xApp traffic over a post-quantum tunnel and enforces
// sender-constrained access tokens on it.
//
// One process runs both directions:
//
//	egress   a plain TCP listener on loopback that the xApp writes to. The sidecar
//	         obtains a bound access token, opens a pqtunnel connection to the peer
//	         sidecar, sends an authorization frame and then relays bytes.
//	ingress  a pqtunnel listener on the pod address. The sidecar completes the
//	         handshake, validates the authorization frame with the resource-side
//	         validator and only then connects to the local application port.
//
// The relay is byte-transparent, so HTTP and RMR both work and neither the xApp nor
// the RMR library knows any of this is happening. Authorization is per connection:
// the tunnel handshake proves possession of the ML-DSA credential, and the
// authorization frame proves the access token is bound to that same credential.
package sidecar

import (
	"fmt"
	"strings"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/config"
)

// EgressRoute forwards one local listener to one peer sidecar.
type EgressRoute struct {
	Name     string // route label, matched against the peer ingress routes
	Listen   string // local address the xApp connects to
	Peer     string // peer sidecar address, host:port
	PeerName string // CN or DNS SAN the peer certificate must carry
}

// IngressRoute delivers one route label to one local application address.
type IngressRoute struct {
	Name  string
	Local string
}

// Config configures the sidecar. ConfigFromEnv reads it from the environment, which
// is what the Kyverno injection policy fills in from the pod annotations.
type Config struct {
	Name          string // this sidecar identity, the xApp client id
	Authority     string // host:port peers reach this sidecar on, as it appears in the proof htu
	IngressListen string // address the peer sidecars connect to ("" disables ingress)
	IngressRoutes []IngressRoute
	EgressRoutes  []EgressRoute

	HandshakeTimeout time.Duration
	AuthTimeout      time.Duration
	IdleTimeout      time.Duration
	DialTimeout      time.Duration
	TokenTimeout     time.Duration

	HealthListen string // plain HTTP health and metrics port for kubelet probes
}

// ConfigFromEnv reads the sidecar configuration.
//
//	SIDECAR_NAME            xapp-c
//	SIDECAR_AUTHORITY       xapp-c-sidecar.ricxapp.svc.cluster.local:4570
//	SIDECAR_INGRESS_LISTEN  :4570
//	SIDECAR_INGRESS_ROUTES  http|127.0.0.1:8080,rmr|127.0.0.1:4560
//	SIDECAR_EGRESS_ROUTES   http|127.0.0.1:18080|xapp-d-sidecar.ricxapp.svc.cluster.local:4570|xapp-d
func ConfigFromEnv() (Config, error) {
	e := &config.Env{}
	c := Config{
		Name:             e.Req("SIDECAR_NAME"),
		Authority:        e.Str("SIDECAR_AUTHORITY", ""),
		IngressListen:    e.Str("SIDECAR_INGRESS_LISTEN", ""),
		HandshakeTimeout: e.Dur("SIDECAR_HANDSHAKE_TIMEOUT", 15*time.Second),
		AuthTimeout:      e.Dur("SIDECAR_AUTH_TIMEOUT", 15*time.Second),
		IdleTimeout:      e.Dur("SIDECAR_IDLE_TIMEOUT", 0),
		DialTimeout:      e.Dur("SIDECAR_DIAL_TIMEOUT", 10*time.Second),
		TokenTimeout:     e.Dur("SIDECAR_TOKEN_TIMEOUT", 30*time.Second),
		HealthListen:     e.Str("SIDECAR_HEALTH_LISTEN", ":8081"),
	}
	ingress, err := parseIngress(e.Str("SIDECAR_INGRESS_ROUTES", ""))
	if err != nil {
		e.Fail("SIDECAR_INGRESS_ROUTES: %v", err)
	}
	c.IngressRoutes = ingress
	egress, err := parseEgress(e.Str("SIDECAR_EGRESS_ROUTES", ""))
	if err != nil {
		e.Fail("SIDECAR_EGRESS_ROUTES: %v", err)
	}
	c.EgressRoutes = egress
	if c.IngressListen == "" && len(c.EgressRoutes) == 0 {
		e.Fail("the sidecar has neither an ingress listener nor an egress route; nothing to do")
	}
	if c.IngressListen != "" && len(c.IngressRoutes) == 0 {
		e.Fail("SIDECAR_INGRESS_LISTEN is set but SIDECAR_INGRESS_ROUTES is empty")
	}
	if c.IngressListen != "" && c.Authority == "" {
		e.Fail("SIDECAR_AUTHORITY is required with an ingress listener: it is the host:port peers address this sidecar by")
	}
	return c, e.Err()
}

// IngressAuthority is the canonical authority and path of one served route; it must
// equal what the peer used to mint the proof.
func (c Config) IngressAuthority(route string) string { return c.Authority + "/" + route }

// IngressTarget returns the local address for a route label.
func (c Config) IngressTarget(name string) (string, bool) {
	for _, r := range c.IngressRoutes {
		if r.Name == name {
			return r.Local, true
		}
	}
	return "", false
}

func parseIngress(s string) ([]IngressRoute, error) {
	var out []IngressRoute
	for _, spec := range splitList(s) {
		f := strings.Split(spec, "|")
		if len(f) != 2 || f[0] == "" || f[1] == "" {
			return nil, fmt.Errorf("route %q is not name|host:port", spec)
		}
		out = append(out, IngressRoute{Name: f[0], Local: f[1]})
	}
	return out, nil
}

func parseEgress(s string) ([]EgressRoute, error) {
	var out []EgressRoute
	for _, spec := range splitList(s) {
		f := strings.Split(spec, "|")
		if len(f) < 3 || len(f) > 4 {
			return nil, fmt.Errorf("route %q is not name|listen|peer[|peerName]", spec)
		}
		r := EgressRoute{Name: f[0], Listen: f[1], Peer: f[2]}
		if len(f) == 4 {
			r.PeerName = f[3]
		}
		if r.Name == "" || r.Listen == "" || r.Peer == "" {
			return nil, fmt.Errorf("route %q has an empty field", spec)
		}
		out = append(out, r)
	}
	return out, nil
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
