// Command xapp is a demo xApp that is both an OAuth client and a protected resource:
// it exposes an SDL-style API guarded by the xappresource validator and periodically
// calls its peer xApp with a sender-constrained token, so traffic flows both ways.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/config"
	"github.com/oran-ricsec/xapp-token-binding/internal/logx"
	xappclient "github.com/oran-ricsec/xapp-token-binding/xapp-client"
	xappresource "github.com/oran-ricsec/xapp-token-binding/xapp-resource"
)

func main() {
	log := logx.New("xapp")
	e := &config.Env{}
	name := e.Req("XAPP_NAME")
	listen := e.Str("LISTEN_ADDR", ":8443")
	peerURL := e.Str("PEER_URL", "")
	peerInterval := e.Dur("PEER_INTERVAL", 30*time.Second)
	healthAddr := e.Str("HEALTH_ADDR", ":8081")
	if err := e.Err(); err != nil {
		log.Error("invalid configuration", "error", err)
		os.Exit(2)
	}
	ccfg, err := xappclient.ConfigFromEnv()
	if err != nil {
		log.Error("invalid client configuration", "error", err)
		os.Exit(2)
	}
	rcfg, err := xappresource.ConfigFromEnv()
	if err != nil {
		log.Error("invalid resource configuration", "error", err)
		os.Exit(2)
	}
	log = log.With("xapp", name)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	client, err := xappclient.New(ccfg, log)
	if err != nil {
		log.Error("client", "error", err)
		os.Exit(1)
	}
	for attempt := 1; ; attempt++ {
		if err = client.Start(ctx); err == nil {
			break
		}
		log.Warn("enrollment_retry", "attempt", attempt, "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(min(time.Duration(attempt)*2*time.Second, 30*time.Second)):
		}
	}
	go client.Maintain(ctx)

	validator, err := xappresource.NewValidator(rcfg, client.HTTPClient(), log)
	if err != nil {
		log.Error("validator", "error", err)
		os.Exit(1)
	}

	sdl := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := xappresource.PrincipalFrom(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"xapp":      name,
			"key":       strings.TrimPrefix(r.URL.Path[strings.LastIndex(r.URL.Path, "/"):], "/"),
			"value":     "demo-sdl-value",
			"caller":    p.ClientID,
			"binding":   p.Binding,
			"cnf":       p.Thumbprint,
			"validated": p.Mode,
		})
	})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	mux.Handle("/api/v1/sdl/", validator.Middleware(xappresource.ModeLocal, sdl))
	mux.Handle("/api/v1/introspect/sdl/", validator.Middleware(xappresource.ModeIntrospection, sdl))

	srv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		TLSConfig:         client.ServerTLSConfig(),
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          nil,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	// Plain-HTTP health endpoint for Kubernetes probes: the kubelet cannot complete a
	// handshake on a TLS port pinned to the ML-KEM hybrid group.
	if healthAddr != "" {
		healthMux := http.NewServeMux()
		healthMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
		healthSrv := &http.Server{Addr: healthAddr, Handler: healthMux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := healthSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("health listener", "error", err)
			}
		}()
	}
	if peerURL != "" {
		go peerLoop(ctx, client, peerURL, peerInterval, log)
	}
	log.Info("listening", "addr", listen, "method", string(ccfg.Method), "client_id", ccfg.ClientID,
		"cert_lifetime", ccfg.CertLifetime.String(), "peer", peerURL)
	if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server", "error", err)
		os.Exit(1)
	}
}

// peerLoop calls the peer xApp's protected API with a sender-constrained token.
func peerLoop(ctx context.Context, c xappclient.Client, url string, every time.Duration, log interface {
	Info(string, ...any)
	Warn(string, ...any)
}) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			log.Warn("peer_call_failed", "error", err)
			continue
		}
		start := time.Now()
		resp, err := c.Do(req)
		if err != nil {
			log.Warn("peer_call_failed", "url", url, "error", err)
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		leaf := c.Identity().Leaf()
		log.Info("peer_call", "url", url, "status", resp.StatusCode, "elapsed_ms", time.Since(start).Milliseconds(),
			"my_cert_serial", leaf.SerialNumber.Text(16), "my_cert_not_after", leaf.NotAfter.UTC().Format(time.RFC3339),
			"response", strings.TrimSpace(string(body)))
	}
}
