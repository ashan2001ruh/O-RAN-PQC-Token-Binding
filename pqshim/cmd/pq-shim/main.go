// Command pq-shim runs the post-quantum token shim (see package pqshim).
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/config"
	"github.com/oran-ricsec/xapp-token-binding/internal/logx"
	"github.com/oran-ricsec/xapp-token-binding/internal/netx"
	"github.com/oran-ricsec/xapp-token-binding/internal/pki"
	"github.com/oran-ricsec/xapp-token-binding/pqshim"
	xappresource "github.com/oran-ricsec/xapp-token-binding/xapp-resource"
)

func main() {
	log := logx.New("pq-shim")
	cfg, err := pqshim.ConfigFromEnv()
	if err != nil {
		log.Error("invalid configuration", "error", err)
		os.Exit(2)
	}
	// The embedded validator checks the incoming classical Keycloak token, so it is
	// configured exactly like a resource server that trusts Keycloak.
	rcfg, err := xappresource.ConfigFromEnv()
	if err != nil {
		log.Error("invalid validator configuration", "error", err)
		os.Exit(2)
	}
	e := &config.Env{}
	overrides, err := netx.ParseDialOverrides(e.Str("DIAL_OVERRIDES", ""))
	if err != nil {
		log.Error("DIAL_OVERRIDES", "error", err)
		os.Exit(2)
	}
	// Client used to reach Keycloak (JWKS, introspection): classical trust anchors.
	roots, err := pki.LoadCertPool(rcfg.TrustBundle...)
	if err != nil {
		log.Error("trust bundle", "error", err)
		os.Exit(1)
	}
	httpClient := &http.Client{
		Transport: netx.NewTransport(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, overrides),
		Timeout:   20 * time.Second,
	}

	srv, err := pqshim.NewServer(cfg, rcfg, httpClient, log)
	if err != nil {
		log.Error("startup failed", "error", err)
		os.Exit(1)
	}
	tlsConf, err := srv.TLSConfig()
	if err != nil {
		log.Error("server TLS", "error", err)
		os.Exit(1)
	}
	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		TLSConfig:         tlsConf,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    256 << 10, // ML-DSA proofs with an x5c chain are large headers
	}
	// Plain-HTTP health endpoint for Kubernetes probes (see Config.HealthAddr).
	if cfg.HealthAddr != "" {
		healthMux := http.NewServeMux()
		healthMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
		healthSrv := &http.Server{Addr: cfg.HealthAddr, Handler: healthMux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := healthSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("health listener", "error", err)
			}
		}()
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdown)
	}()
	log.Info("listening",
		"addr", cfg.ListenAddr, "issuer", cfg.Issuer,
		"signing_alg", srv.SigningAlg(), "kid", srv.KeyID(),
		"upstream_issuer", rcfg.Issuer, "pq_kex_only", cfg.PQKexOnly)
	if err := httpSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
