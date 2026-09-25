// Command ric-ca runs the RIC intermediate CA enrollment service.
package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/ca/enroll"
	"github.com/oran-ricsec/xapp-token-binding/internal/logx"
)

func main() {
	log := logx.New("ric-ca")
	cfg, err := enroll.ConfigFromEnv()
	if err != nil {
		log.Error("invalid configuration", "error", err)
		os.Exit(2)
	}
	srv, err := enroll.NewServer(cfg, log)
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
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdown)
	}()
	log.Info("listening", "addr", cfg.ListenAddr, "min_lifetime", cfg.MinLifetime.String(), "max_lifetime", cfg.MaxLifetime.String())
	if err := httpSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
