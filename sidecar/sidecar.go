package sidecar

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/sidecar/pqtunnel"
	xappclient "github.com/oran-ricsec/xapp-token-binding/xapp-client"
	xappresource "github.com/oran-ricsec/xapp-token-binding/xapp-resource"
)

// Sidecar is the injected process: an egress half that authorizes outgoing
// connections and an ingress half that enforces authorization on incoming ones.
type Sidecar struct {
	cfg       Config
	log       *slog.Logger
	client    xappclient.Client
	validator *xappresource.Validator

	mu      sync.Mutex
	counter map[string]int
}

// New builds a sidecar from the three configurations: its own, the token client and
// the resource validator. The client and the validator are the same ones the
// in-process integration uses; the sidecar only changes where they are applied.
func New(cfg Config, clientCfg xappclient.Config, resCfg xappresource.Config, log *slog.Logger) (*Sidecar, error) {
	if !clientCfg.PQEnabled {
		return nil, errors.New("the sidecar tunnel requires PQ_MODE=true: it authenticates peers with ML-DSA certificates")
	}
	client, err := xappclient.New(clientCfg, log)
	if err != nil {
		return nil, fmt.Errorf("token client: %w", err)
	}
	s := &Sidecar{cfg: cfg, log: log.With("component", "sidecar", "sidecar", cfg.Name), client: client, counter: map[string]int{}}
	if cfg.IngressListen != "" {
		v, err := xappresource.NewValidator(resCfg, client.HTTPClient(), log)
		if err != nil {
			return nil, fmt.Errorf("resource validator: %w", err)
		}
		s.validator = v
	}
	return s, nil
}

// Client exposes the token client, for the CLI walkthrough.
func (s *Sidecar) Client() xappclient.Client { return s.client }

// Run starts every listener and blocks until ctx is done.
func (s *Sidecar) Run(ctx context.Context) error {
	// The CA and Keycloak may still be starting; enrollment is retried rather than
	// crash-looping, which would burn the one-time bootstrap credential.
	for attempt := 1; ; attempt++ {
		err := s.client.Start(ctx)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if attempt >= 30 {
			return fmt.Errorf("obtain identity: %w", err)
		}
		s.log.Warn("enrollment_retry", "attempt", attempt, "error", err.Error())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	d := s.client.Describe()
	s.log.Info("sidecar_ready",
		"method", d.Method, "client_id", d.ClientID, "pq_cert", d.PQCert, "pq_alg", d.PQAlg,
		"ingress", s.cfg.IngressListen, "egress_routes", len(s.cfg.EgressRoutes))

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go s.client.Maintain(ctx)

	var wg sync.WaitGroup
	errs := make(chan error, len(s.cfg.EgressRoutes)+2)
	run := func(name string, f func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f(); err != nil && ctx.Err() == nil {
				errs <- fmt.Errorf("%s: %w", name, err)
				cancel()
			}
		}()
	}

	if s.cfg.IngressListen != "" {
		run("ingress", func() error { return s.serveIngress(ctx) })
	}
	for _, route := range s.cfg.EgressRoutes {
		r := route
		run("egress "+r.Name, func() error { return s.serveEgress(ctx, r) })
	}
	if s.cfg.HealthListen != "" {
		run("health", func() error { return s.serveHealth(ctx) })
	}

	<-ctx.Done()
	wg.Wait()
	select {
	case err := <-errs:
		return err
	default:
		return nil
	}
}

// tunnelConfig is the handshake configuration; Credential is read on every handshake
// so a rotated certificate takes effect on the next connection.
func (s *Sidecar) tunnelConfig(peerName string) pqtunnel.Config {
	return pqtunnel.Config{
		Credential: func() *tls.Certificate {
			if id := s.client.PQIdentity(); id != nil {
				return id.Current()
			}
			return nil
		},
		Roots:            s.client.TrustPool(),
		PeerName:         peerName,
		HandshakeTimeout: s.cfg.HandshakeTimeout,
	}
}

// relay copies in both directions and returns when either side closes.
func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

// acceptLoop runs fn for every accepted connection until ctx is done.
func (s *Sidecar) acceptLoop(ctx context.Context, l net.Listener, fn func(net.Conn)) error {
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go fn(conn)
	}
}

func (s *Sidecar) count(name string) {
	s.mu.Lock()
	s.counter[name]++
	s.mu.Unlock()
}

// Counters returns a snapshot of the connection counters.
func (s *Sidecar) Counters() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.counter))
	for k, v := range s.counter {
		out[k] = v
	}
	return out
}

// serveHealth exposes liveness and the counters over plain HTTP. It is plain because
// the kubelet cannot speak the post-quantum tunnel, and it carries no traffic.
func (s *Sidecar) serveHealth(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if s.client.PQIdentity() == nil || s.client.PQIdentity().Current() == nil {
			http.Error(w, "no identity yet", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		d := s.client.Describe()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sidecar": s.cfg.Name, "method": d.Method, "client_id": d.ClientID,
			"pq_cert": d.PQCert, "pq_alg": d.PQAlg, "counters": s.Counters(),
		})
	})
	srv := &http.Server{Addr: s.cfg.HealthListen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
