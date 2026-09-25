// Command xapp-sidecar is the token-binding sidecar injected next to an xApp.
//
// It is configured entirely from the environment, which the Kyverno injection policy
// fills in from the pod annotations, so the xApp image and the xApp source stay
// untouched. See the sidecar package documentation for the traffic path.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/oran-ricsec/xapp-token-binding/internal/logx"
	"github.com/oran-ricsec/xapp-token-binding/sidecar"
	xappclient "github.com/oran-ricsec/xapp-token-binding/xapp-client"
	xappresource "github.com/oran-ricsec/xapp-token-binding/xapp-resource"
)

func main() {
	log := logx.New("xapp-sidecar")
	cfg, err := sidecar.ConfigFromEnv()
	if err != nil {
		log.Error("invalid sidecar configuration", "error", err)
		os.Exit(2)
	}
	clientCfg, err := xappclient.ConfigFromEnv()
	if err != nil {
		log.Error("invalid client configuration", "error", err)
		os.Exit(2)
	}
	resourceCfg, err := xappresource.ConfigFromEnv()
	if err != nil {
		log.Error("invalid resource configuration", "error", err)
		os.Exit(2)
	}

	s, err := sidecar.New(cfg, clientCfg, resourceCfg, log)
	if err != nil {
		log.Error("sidecar", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if err := s.Run(ctx); err != nil {
		log.Error("sidecar stopped", "error", err)
		os.Exit(1)
	}
	log.Info("sidecar stopped")
}
