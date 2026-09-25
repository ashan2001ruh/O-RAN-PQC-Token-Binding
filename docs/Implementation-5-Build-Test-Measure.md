# Implementation Part 5: Build Orchestration, Walkthroughs, Security Tests and Benchmarks

Everything is reproducible from one command per task. This part contains the Makefile, the
walkthrough CLI used by the three run scripts, the security test suite and the measurement
harness.

## Files in this part

| File | Lines | Purpose |
|---|---|---|
| `Makefile` | 197 | All targets. `make help` lists them. |
| `cmd/methodrun/main.go` | 500 | The walkthrough itself. |
| `scripts/_run-method.sh` | 72 | The shared driver: sources `out/host.env`, runs `methodrun`, then prints the matching log lines from the resource xApp, the shim and the CA. |
| `scripts/run-method-a.sh` | 3 | Method A wrapper. |
| `scripts/run-method-b.sh` | 3 | Method B wrapper. |
| `scripts/run-method-c.sh` | 3 | Method C wrapper. |
| `test/cmd/sectest/main.go` | 632 | The suite. |
| `bench/cmd/bench/main.go` | 407 | The harness. |

---

## 1. The Makefile

`make up` brings up the whole testbed from nothing. The mode-dependent variables at the top are what switch the testbed between classical and post-quantum: they decide which issuer the resource validator trusts and which server certificate the CA presents.

### `Makefile`

All targets. `make help` lists them.

```make
SHELL := /bin/bash
.SHELLFLAGS := -eo pipefail -c

include config/testbed.env
KEYCLOAK_HOST := $(KEYCLOAK_SERVICE).$(RICSEC_NAMESPACE).svc.$(CLUSTER_DOMAIN)
KEYCLOAK_URL  := https://$(KEYCLOAK_HOST):$(KEYCLOAK_PORT)
TOKEN_ISSUER  := $(KEYCLOAK_URL)/realms/$(KEYCLOAK_REALM)
RIC_CA_HOST   := $(RIC_CA_SERVICE).$(RICSEC_NAMESPACE).svc.$(CLUSTER_DOMAIN)
RIC_CA_URL    := https://$(RIC_CA_HOST):$(RIC_CA_PORT)
PQ_SHIM_HOST  := $(PQ_SHIM_SERVICE).$(RICSEC_NAMESPACE).svc.$(CLUSTER_DOMAIN)
PQ_SHIM_URL   := https://$(PQ_SHIM_HOST):$(PQ_SHIM_PORT)

# The resource validator trusts Keycloak in classical mode and the shim in PQ mode,
# and the RIC CA presents an ML-DSA server certificate in PQ mode.
ifeq ($(PQ_MODE),true)
RESOURCE_TOKEN_ISSUER      := $(PQ_SHIM_URL)
RESOURCE_JWKS_URL          := $(PQ_SHIM_URL)/v1/jwks
RESOURCE_INTROSPECTION_URL := $(PQ_SHIM_URL)/v1/introspect
RIC_CA_SERVER_CERT         := ric-ca-server-pq
else
RESOURCE_TOKEN_ISSUER      := $(TOKEN_ISSUER)
RESOURCE_JWKS_URL          := $(TOKEN_ISSUER)/protocol/openid-connect/certs
RESOURCE_INTROSPECTION_URL := $(TOKEN_ISSUER)/protocol/openid-connect/token/introspect
RIC_CA_SERVER_CERT         := ric-ca-server
endif
export

GO       ?= $(shell command -v go 2>/dev/null || echo $(HOME)/tools/go/bin/go)
JAVA_HOME ?=
KUBECTL  ?= kubectl
SUDO     ?= sudo
OUT      := out
BIN      := $(OUT)/bin
PKI      := $(OUT)/pki
IMAGES   := ric-ca xapp pq-shim
LABEL    := part-of=xapp-token-binding
# kubectl create ... --dry-run | label | apply  (idempotent and labelled for `make down`)
APPLY    := $(KUBECTL) label --local -f - $(LABEL) -o yaml | $(KUBECTL) apply -f -
HOSTENV  := set -a; source $(OUT)/host.env; set +a;

.PHONY: help up down pki build unit images namespaces trust deploy-ca deploy-keycloak \
        import-realm deploy-shim bootstrap-xapps deploy-xapps wait host-env verify-ca verify-keycloak test bench \
        run-a run-b run-c pq-up verify-pq \
        restart-keycloak restart-xapps status logs clean

help: ## list targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | sed 's/:.*## /\t/' | column -t -s $$'\t'

up: pki build images namespaces trust deploy-ca deploy-keycloak deploy-shim bootstrap-xapps deploy-xapps wait host-env ## CA + Keycloak + PQ shim + two demo xApps, from scratch
	@echo "testbed is up: run 'make verify-ca verify-keycloak test bench'"

pki: ## generate the classical and post-quantum PKI (milestone 1 and the PQ phase)
	mkdir -p $(BIN)
	CGO_ENABLED=0 $(GO) build -trimpath -o $(BIN)/pki-gen ./ca/cmd/pki-gen
	PKI_GEN=$(CURDIR)/$(BIN)/pki-gen ca/scripts/gen-pki.sh $(PKI)

build: ## build all binaries (static)
	mkdir -p $(BIN)
	CGO_ENABLED=0 GOFLAGS=-p=2 $(GO) build -trimpath -ldflags='-s -w' -o $(BIN)/ \
	  ./ca/cmd/ric-ca ./ca/cmd/smo-sim ./ca/cmd/pki-gen ./demo-xapp/cmd/xapp \
	  ./pqshim/cmd/pq-shim ./test/cmd/sectest ./bench/cmd/bench ./cmd/methodrun

unit: ## offline unit tests
	GOFLAGS=-p=2 $(GO) test ./...

images: build ## build scratch images and import them into containerd
	for img in $(IMAGES); do \
	  $(SUDO) docker build -q --build-arg BIN=$$img -t ricsec/$$img:$(IMAGE_TAG) -f build/Dockerfile $(BIN); \
	  $(SUDO) docker save ricsec/$$img:$(IMAGE_TAG) | $(SUDO) ctr -n k8s.io images import - >/dev/null; \
	done

namespaces:
	$(KUBECTL) create namespace $(RICSEC_NAMESPACE) --dry-run=client -o yaml | $(APPLY)

trust: ## publish the trust anchors (public certificates only) to ricsec and ricxapp
	for ns in $(RICSEC_NAMESPACE) $(XAPP_NAMESPACE); do \
	  $(KUBECTL) -n $$ns create configmap ric-trust \
	    --from-file=$(PKI)/ric-intermediate-ca.crt --from-file=$(PKI)/smo-onboarding-ca.crt --from-file=$(PKI)/smo-root-ca.crt \
	    --from-file=$(PKI)/ric-intermediate-ca-pq.crt --from-file=$(PKI)/smo-onboarding-ca-pq.crt --from-file=$(PKI)/smo-root-ca-pq.crt \
	    --dry-run=client -o yaml | $(APPLY); \
	done

deploy-ca: ## deploy the RIC CA enrollment service to ricsec
	$(KUBECTL) -n $(RICSEC_NAMESPACE) create secret generic ric-ca-server-tls --type=kubernetes.io/tls \
	  --from-file=tls.crt=$(PKI)/$(RIC_CA_SERVER_CERT)-chain.crt --from-file=tls.key=$(PKI)/$(RIC_CA_SERVER_CERT).key \
	  --dry-run=client -o yaml | $(APPLY)
	$(KUBECTL) -n $(RICSEC_NAMESPACE) create secret tls ric-ca-issuer \
	  --cert=$(PKI)/ric-intermediate-ca.crt --key=$(PKI)/ric-intermediate-ca.key --dry-run=client -o yaml | $(APPLY)
	$(KUBECTL) -n $(RICSEC_NAMESPACE) create secret generic ric-ca-issuer-pq --type=kubernetes.io/tls \
	  --from-file=tls.crt=$(PKI)/ric-intermediate-ca-pq.crt --from-file=tls.key=$(PKI)/ric-intermediate-ca-pq.key \
	  --dry-run=client -o yaml | $(APPLY)
	build/render.sh ca/k8s/ric-ca.yaml | $(KUBECTL) apply -f -
	$(KUBECTL) -n $(RICSEC_NAMESPACE) rollout status deploy/$(RIC_CA_SERVICE) --timeout=180s

deploy-keycloak: ## deploy Keycloak (XRF) with mTLS and the ric-realm import to ricsec
	mkdir -p $(OUT)/secrets $(OUT)/rendered
	[[ -s $(OUT)/secrets/keycloak-admin-password ]] || (umask 077; openssl rand -hex 16 | tr -d '\n' > $(OUT)/secrets/keycloak-admin-password)
	$(KUBECTL) -n $(RICSEC_NAMESPACE) create secret generic keycloak-admin \
	  --from-literal=username=admin --from-file=password=$(OUT)/secrets/keycloak-admin-password --dry-run=client -o yaml | $(APPLY)
	$(KUBECTL) -n $(RICSEC_NAMESPACE) create secret tls keycloak-tls \
	  --cert=$(PKI)/keycloak-server-chain.crt --key=$(PKI)/keycloak-server.key --dry-run=client -o yaml | $(APPLY)
	build/render.sh keycloak/k8s/keycloak.yaml | $(KUBECTL) apply -f -
	$(KUBECTL) -n $(RICSEC_NAMESPACE) rollout status deploy/$(KEYCLOAK_SERVICE) --timeout=900s
	$(MAKE) --no-print-directory import-realm

import-realm: host-env ## create ric-realm via the admin API (REPLACE=1 to recreate)
	build/render.sh keycloak/ric-realm.json > $(OUT)/rendered/ric-realm.json
	$(HOSTENV) build/import-realm.sh $(OUT)/rendered/ric-realm.json

deploy-shim: ## deploy the post-quantum token shim to ricsec
	$(KUBECTL) -n $(RICSEC_NAMESPACE) create secret generic pq-shim-server-tls --type=kubernetes.io/tls \
	  --from-file=tls.crt=$(PKI)/$(PQ_SHIM_SERVICE)-server-pq-chain.crt --from-file=tls.key=$(PKI)/$(PQ_SHIM_SERVICE)-server-pq.key \
	  --dry-run=client -o yaml | $(APPLY)
	build/render.sh pqshim/k8s/pq-shim.yaml | $(KUBECTL) apply -f -
	$(KUBECTL) -n $(RICSEC_NAMESPACE) rollout status deploy/$(PQ_SHIM_SERVICE) --timeout=180s

define bootstrap_xapp # $(1)=deployment name $(2)=client id
	$(BIN)/smo-sim -cn $(2) -dns $(1).$(XAPP_NAMESPACE).svc.$(CLUSTER_DOMAIN),$(1).$(XAPP_NAMESPACE).svc \
	  -validity $(BOOTSTRAP_CERT_VALIDITY) -org $(ORG) -out $(OUT)/bootstrap/$(1) \
	  -ca-cert $(PKI)/smo-onboarding-ca.crt -ca-key $(PKI)/smo-onboarding-ca.key
	$(KUBECTL) -n $(XAPP_NAMESPACE) create secret tls $(1)-bootstrap \
	  --cert=$(OUT)/bootstrap/$(1)/tls.crt --key=$(OUT)/bootstrap/$(1)/tls.key --dry-run=client -o yaml | $(APPLY)
	$(BIN)/smo-sim -cn $(2) -dns $(1).$(XAPP_NAMESPACE).svc.$(CLUSTER_DOMAIN),$(1).$(XAPP_NAMESPACE).svc \
	  -validity $(BOOTSTRAP_CERT_VALIDITY) -org $(ORG) -out $(OUT)/bootstrap/$(1)-pq -key-alg $(PQ_IDENTITY_KEY_ALG) \
	  -ca-cert $(PKI)/smo-onboarding-ca-pq.crt -ca-key $(PKI)/smo-onboarding-ca-pq.key
	$(KUBECTL) -n $(XAPP_NAMESPACE) create secret generic $(1)-bootstrap-pq --type=kubernetes.io/tls \
	  --from-file=tls.crt=$(OUT)/bootstrap/$(1)-pq/tls.crt --from-file=tls.key=$(OUT)/bootstrap/$(1)-pq/tls.key \
	  --dry-run=client -o yaml | $(APPLY)
endef

bootstrap-xapps: ## SMO onboarding: issue fresh one-time bootstrap credentials for the demo xApps
	$(call bootstrap_xapp,$(XAPP_A_NAME),$(XAPP_A_CLIENT_ID))
	$(call bootstrap_xapp,$(XAPP_B_NAME),$(XAPP_B_CLIENT_ID))

deploy-xapps: ## deploy the two demo xApps to ricxapp (they enroll with their bootstrap credential)
	existing=$$({ $(KUBECTL) -n $(XAPP_NAMESPACE) get deploy $(XAPP_A_NAME) $(XAPP_B_NAME) -o name 2>/dev/null || true; } | wc -l); \
	build/render.sh demo-xapp/k8s/xapps.yaml | $(KUBECTL) apply -f -; \
	if [[ $$existing -gt 0 ]]; then $(KUBECTL) -n $(XAPP_NAMESPACE) rollout restart deploy/$(XAPP_A_NAME) deploy/$(XAPP_B_NAME); fi

wait:
	$(KUBECTL) -n $(RICSEC_NAMESPACE) rollout status deploy/$(RIC_CA_SERVICE) --timeout=180s
	$(KUBECTL) -n $(RICSEC_NAMESPACE) rollout status deploy/$(PQ_SHIM_SERVICE) --timeout=180s
	$(KUBECTL) -n $(RICSEC_NAMESPACE) rollout status deploy/$(KEYCLOAK_SERVICE) --timeout=900s
	$(KUBECTL) -n $(XAPP_NAMESPACE) rollout status deploy/$(XAPP_A_NAME) --timeout=300s
	$(KUBECTL) -n $(XAPP_NAMESPACE) rollout status deploy/$(XAPP_B_NAME) --timeout=300s

host-env: ## write out/host.env for tools run on the node
	build/host-env.sh $(OUT)/host.env

verify-ca: host-env ## milestone 1: issue a leaf on demand, verify the chain with openssl, prove bootstrap is one-time
	$(HOSTENV) build/verify-ca.sh

verify-keycloak: host-env ## milestone 2: token over mTLS must carry cnf.x5t#S256 (automated)
	$(HOSTENV) build/verify-keycloak.sh

test: host-env ## security test suite (positive + negative), writes results/security-tests.csv
	mkdir -p results
	$(HOSTENV) $(BIN)/sectest -out results/security-tests.csv

bench: host-env ## measurement harness, writes results/bench.csv
	mkdir -p results
	$(HOSTENV) $(BIN)/bench -out results/bench.csv -env-out results/bench-env.csv

restart-keycloak: ## new Keycloak pod + realm re-import (dev-file DB lives in the pod)
	$(KUBECTL) -n $(RICSEC_NAMESPACE) rollout restart deploy/$(KEYCLOAK_SERVICE)
	$(KUBECTL) -n $(RICSEC_NAMESPACE) rollout status deploy/$(KEYCLOAK_SERVICE) --timeout=900s
	$(MAKE) --no-print-directory import-realm

restart-xapps: bootstrap-xapps deploy-xapps ## re-onboard and restart the demo xApps

pq-up: ## redeploy the CA, the shim and the demo xApps in post-quantum mode
	$(MAKE) PQ_MODE=true deploy-ca deploy-shim bootstrap-xapps deploy-xapps wait host-env

classical-up: ## redeploy the same components in classical mode
	$(MAKE) PQ_MODE=false deploy-ca deploy-shim bootstrap-xapps deploy-xapps wait host-env

run-a: ## end-to-end walkthrough of Method A (RUN_ARGS=--pq for post-quantum)
	scripts/run-method-a.sh $(RUN_ARGS)

run-b: ## end-to-end walkthrough of Method B
	scripts/run-method-b.sh $(RUN_ARGS)

run-c: ## end-to-end walkthrough of Method C
	scripts/run-method-c.sh $(RUN_ARGS)

status: ## show testbed pods
	$(KUBECTL) get pods -A -l $(LABEL) -o wide

logs: ## tail validator decisions from the demo xApps
	$(KUBECTL) -n $(XAPP_NAMESPACE) logs -l $(LABEL) --tail=50 --prefix

down: ## remove everything this project deployed (leaves the RIC untouched)
	-$(KUBECTL) -n $(XAPP_NAMESPACE) delete deploy,svc,secret,configmap -l $(LABEL)
	-$(KUBECTL) delete namespace $(RICSEC_NAMESPACE)

clean: ## remove build outputs (keeps the PKI)
	rm -rf $(BIN) $(OUT)/rendered $(OUT)/bootstrap $(OUT)/host.env
```

---

## 2. The walkthrough CLI and the run scripts

One command shows the whole flow for one method: configuration, onboarding and enrollment, the token and (in PQ mode) its upgrade with the size change, the negotiated TLS group, resource calls under both validation modes, the method-specific behaviour, and the negative test that proves the token alone is not enough.

### `cmd/methodrun/main.go`

The walkthrough itself.

```go
// Command methodrun walks one binding method end to end and prints every step, so a
// single command shows the whole flow on the CLI: onboarding, enrollment, token
// issuance, the post-quantum upgrade, the negotiated TLS key exchange, resource calls
// under both validation modes, and the negative test that proves the binding is
// enforced.
//
//	methodrun -method A            classical run
//	methodrun -method A -pq        post-quantum run (ML-DSA tokens, ML-KEM key exchange)
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/config"
	"github.com/oran-ricsec/xapp-token-binding/internal/jose"
	"github.com/oran-ricsec/xapp-token-binding/internal/logx"
	"github.com/oran-ricsec/xapp-token-binding/internal/netx"
	"github.com/oran-ricsec/xapp-token-binding/internal/pki"
	"github.com/oran-ricsec/xapp-token-binding/internal/smo"
	xappclient "github.com/oran-ricsec/xapp-token-binding/xapp-client"
	xappresource "github.com/oran-ricsec/xapp-token-binding/xapp-resource"
)

var (
	bold   = "\033[1m"
	dim    = "\033[2m"
	green  = "\033[32m"
	red    = "\033[31m"
	cyan   = "\033[36m"
	yellow = "\033[33m"
	reset  = "\033[0m"
)

func init() {
	if os.Getenv("NO_COLOR") != "" {
		bold, dim, green, red, cyan, yellow, reset = "", "", "", "", "", "", ""
	}
}

var stepNo int

func step(format string, args ...any) {
	stepNo++
	fmt.Printf("\n%s%s[%d] %s%s\n", bold, cyan, stepNo, fmt.Sprintf(format, args...), reset)
}

func item(label string, format string, args ...any) {
	fmt.Printf("    %-26s %s\n", label+":", fmt.Sprintf(format, args...))
}

func ok(format string, args ...any) {
	fmt.Printf("    %sOK%s  %s\n", green, reset, fmt.Sprintf(format, args...))
}
func warn(format string, args ...any) {
	fmt.Printf("    %s!%s   %s\n", yellow, reset, fmt.Sprintf(format, args...))
}
func fail(format string, args ...any) {
	fmt.Printf("    %sFAIL%s %s\n", red, reset, fmt.Sprintf(format, args...))
}

type runner struct {
	ctx        context.Context
	log        *slog.Logger
	cfg        xappclient.Config
	onboarding *smo.Onboarding
	pqOnboard  *smo.Onboarding
	roots      *x509.CertPool
	overrides  map[string]string
	resource   string
	pq         bool
	failures   int
}

func main() {
	method := flag.String("method", "A", "binding method: A, B or C")
	pq := flag.Bool("pq", false, "run in post-quantum mode (ML-DSA tokens and certificates, ML-KEM key exchange)")
	flag.Parse()

	m := xappclient.Method(strings.ToUpper(*method))
	r, err := newRunner(m, *pq)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		os.Exit(2)
	}
	if err := r.run(m); err != nil {
		fail("%v", err)
		os.Exit(1)
	}
	fmt.Println()
	if r.failures > 0 {
		fmt.Printf("%s%d check(s) failed%s\n", red, r.failures, reset)
		os.Exit(1)
	}
	fmt.Printf("%s%sAll checks passed.%s\n", bold, green, reset)
}

func newRunner(m xappclient.Method, pq bool) (*runner, error) {
	e := &config.Env{}
	r := &runner{ctx: context.Background(), log: logx.New("methodrun"), pq: pq}
	r.resource = strings.TrimRight(e.Req("RESOURCE_URL"), "/")
	clientID := map[xappclient.Method]string{
		xappclient.MethodLongTerm:  e.Req("LONGTERM_CLIENT_ID"),
		xappclient.MethodEphemeral: e.Req("EPHEMERAL_CLIENT_ID"),
		xappclient.MethodDPoP:      e.Req("DPOP_CLIENT_ID"),
	}[m]
	lifetime := e.Dur("LONGTERM_CERT_LIFETIME", 168*time.Hour)
	if m == xappclient.MethodEphemeral {
		lifetime = e.Dur("EPHEMERAL_CERT_LIFETIME", 15*time.Minute)
	}
	r.cfg = xappclient.Config{
		Method: m, ClientID: clientID,
		TokenURL:         e.Req("KEYCLOAK_TOKEN_URL"),
		Scope:            e.Str("TOKEN_SCOPE", ""),
		TrustBundle:      e.List("RIC_TRUST_BUNDLE", nil),
		CAURL:            e.Req("RIC_CA_URL"),
		KeyAlg:           e.Str("IDENTITY_KEY_ALG", "EC-P256"),
		CertLifetime:     lifetime,
		Rotation:         xappclient.RotateOnCertExpiry,
		DPoPAlg:          e.Str("DPOP_ALG", "ES256"),
		PQEnabled:        pq,
		PQShimURL:        e.Str("PQ_SHIM_URL", ""),
		PQKeyAlg:         e.Str("PQ_IDENTITY_KEY_ALG", "ML-DSA-65"),
		PQDPoPAlg:        e.Str("PQ_DPOP_ALG", "ML-DSA-44"),
		PQKexOnly:        e.Bool("PQ_KEX_ONLY", true),
		PQUpgradeTimeout: 60 * time.Second,
		HTTPTimeout:      30 * time.Second,
	}
	onbCert, onbKey, org := e.Req("SMO_ONBOARDING_CERT"), e.Req("SMO_ONBOARDING_KEY"), e.Req("ORG")
	pqOnbCert := e.Str("SMO_ONBOARDING_CERT_PQ", "")
	pqOnbKey := e.Str("SMO_ONBOARDING_KEY_PQ", "")
	overrides, err := netx.ParseDialOverrides(e.Str("DIAL_OVERRIDES", ""))
	if err != nil {
		e.Fail("DIAL_OVERRIDES: %v", err)
	}
	if err := e.Err(); err != nil {
		return nil, err
	}
	r.overrides, r.cfg.DialOverrides = overrides, overrides
	if r.roots, err = pki.LoadCertPool(r.cfg.TrustBundle...); err != nil {
		return nil, err
	}
	if r.onboarding, err = smo.LoadOnboarding(onbCert, onbKey, org); err != nil {
		return nil, err
	}
	if pq {
		if pqOnbCert == "" || pqOnbKey == "" {
			return nil, fmt.Errorf("SMO_ONBOARDING_CERT_PQ/KEY_PQ are required in post-quantum mode")
		}
		if r.pqOnboard, err = smo.LoadOnboarding(pqOnbCert, pqOnbKey, org); err != nil {
			return nil, err
		}
		r.pqOnboard.KeyAlg = r.cfg.PQKeyAlg
	}
	return r, nil
}

// newClient onboards a fresh identity and starts a client.
func (r *runner) newClient() (xappclient.Client, error) {
	cfg := r.cfg
	boot, err := r.onboarding.IssueBootstrap(cfg.ClientID, nil, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	cfg.Bootstrap = boot
	if r.pq {
		pqBoot, err := r.pqOnboard.IssueBootstrap(cfg.ClientID, nil, 10*time.Minute)
		if err != nil {
			return nil, err
		}
		cfg.PQBootstrap = pqBoot
	}
	c, err := xappclient.New(cfg, r.log)
	if err != nil {
		return nil, err
	}
	return c, c.Start(r.ctx)
}

func (r *runner) path(mode xappresource.Mode) string {
	if mode == xappresource.ModeIntrospection {
		return r.resource + "/api/v1/introspect/sdl/demo"
	}
	return r.resource + "/api/v1/sdl/demo"
}

func (r *runner) check(cond bool, format string, args ...any) {
	if cond {
		ok(format, args...)
		return
	}
	r.failures++
	fail(format, args...)
}

func (r *runner) run(m xappclient.Method) error {
	mode := "classical"
	if r.pq {
		mode = "post-quantum"
	}
	fmt.Printf("%s%sMethod %s walkthrough (%s)%s\n", bold, cyan, m, mode, reset)

	step("Configuration")
	item("method", "%s (%s)", m, methodDescription(m))
	item("keycloak client", "%s", r.cfg.ClientID)
	item("identity key", "%s", r.cfg.KeyAlg)
	item("certificate lifetime", "%s", r.cfg.CertLifetime)
	if m == xappclient.MethodDPoP {
		item("DPoP proof key", "%s", r.cfg.DPoPAlg)
	}
	if r.pq {
		item("post-quantum identity", "%s", r.cfg.PQKeyAlg)
		if m == xappclient.MethodDPoP {
			item("post-quantum DPoP key", "%s", r.cfg.PQDPoPAlg)
		}
		item("token upgrade endpoint", "%s", r.cfg.PQShimURL)
		item("TLS key exchange", "X25519MLKEM768 required: %v", r.cfg.PQKexOnly)
	}
	item("resource xApp", "%s", r.resource)

	step("SMO onboarding and enrollment with the RIC CA")
	start := time.Now()
	client, err := r.newClient()
	if err != nil {
		return fmt.Errorf("enrollment: %w", err)
	}
	enrollMS := float64(time.Since(start).Microseconds()) / 1000
	d := client.Describe()
	item("classical certificate", "%s", d.ClassicalCert)
	if r.pq {
		item("post-quantum certificate", "%s", d.PQCert)
		r.check(strings.HasPrefix(d.PQAlg, "ML-DSA"), "identity certificate uses %s", d.PQAlg)
	}
	item("enrollment time", "%.1f ms", enrollMS)

	step("Access token")
	start = time.Now()
	tok, err := client.Token(r.ctx)
	if err != nil {
		return fmt.Errorf("token: %w", err)
	}
	tokenMS := float64(time.Since(start).Microseconds()) / 1000
	if tok.Classical != nil {
		item("Keycloak token", "alg=%s binding=cnf.%s bytes=%d", tok.Classical.Alg, tok.Classical.Binding, len(tok.Classical.Value))
		item("upgraded token", "alg=%s binding=cnf.%s bytes=%d", tok.Alg, tok.Binding, len(tok.Value))
		item("size change", "%+d bytes (%.1fx)", len(tok.Value)-len(tok.Classical.Value),
			float64(len(tok.Value))/float64(len(tok.Classical.Value)))
		r.check(strings.HasPrefix(tok.Alg, "ML-DSA"), "token is signed with %s", tok.Alg)
	} else {
		item("token", "alg=%s binding=cnf.%s bytes=%d", tok.Alg, tok.Binding, len(tok.Value))
	}
	item("cnf value", "%s", tok.Thumbprint)
	item("expires", "%s (in %s)", tok.ExpiresAt.UTC().Format(time.RFC3339), time.Until(tok.ExpiresAt).Round(time.Second))
	item("issue time", "%.1f ms", tokenMS)
	printClaims(tok)

	step("Resource request with local validation")
	status, body, state, err := r.call(client, r.path(xappresource.ModeLocal))
	if err != nil {
		return err
	}
	r.check(status == http.StatusOK, "HTTP %d %s", status, strings.TrimSpace(body))
	if state != nil {
		item("TLS key exchange", "%s", state.CurveID)
		item("TLS version", "0x%x", state.Version)
		if len(state.PeerCertificates) > 0 {
			item("server certificate", "%s", pki.KeyAlgName(state.PeerCertificates[0].PublicKey))
		}
		if r.pq {
			r.check(netx.IsPQKex(state.CurveID), "key exchange is post-quantum (%s)", state.CurveID)
		}
	}

	step("Resource request validated by introspection")
	status, body, _, err = r.call(client, r.path(xappresource.ModeIntrospection))
	if err != nil {
		return err
	}
	r.check(status == http.StatusOK, "HTTP %d %s", status, strings.TrimSpace(body))

	if err := r.methodSpecific(m, client, tok); err != nil {
		return err
	}
	return r.negative(m, client, tok)
}

func methodDescription(m xappclient.Method) string {
	switch m {
	case xappclient.MethodLongTerm:
		return "RFC 8705 certificate-bound, long-term identity key"
	case xappclient.MethodEphemeral:
		return "RFC 8705 certificate-bound, ephemeral identity key"
	case xappclient.MethodDPoP:
		return "RFC 9449 DPoP"
	}
	return string(m)
}

func printClaims(tok *xappclient.Token) {
	interesting := []string{"iss", "aud", "azp", "scope", "realm_access"}
	parts := make([]string, 0, len(interesting))
	for _, name := range interesting {
		if v, ok := tok.Claims[name]; ok {
			raw, _ := json.Marshal(v)
			parts = append(parts, fmt.Sprintf("%s=%s", name, raw))
		}
	}
	item("claims", "%s", strings.Join(parts, " "))
	if up, ok := tok.Claims["upgraded_from"].(map[string]any); ok {
		raw, _ := json.Marshal(up)
		item("provenance", "%s", raw)
	}
}

// call sends a resource request through the client and returns the TLS state.
func (r *runner) call(c xappclient.Client, url string) (int, string, *tls.ConnectionState, error) {
	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, string(body), resp.TLS, nil
}

// send crafts a request with explicit credentials, for the negative tests.
func (r *runner) send(url string, cert *tls.Certificate, headers map[string]string) (int, xappresource.RejectionBody, error) {
	conf := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: r.roots}
	if cert != nil {
		conf.Certificates = []tls.Certificate{*cert}
	}
	tr := netx.NewTransport(conf, r.overrides)
	tr.DisableKeepAlives = true
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, xappresource.RejectionBody{}, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Transport: tr, Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return 0, xappresource.RejectionBody{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var rb xappresource.RejectionBody
	if resp.StatusCode != http.StatusOK {
		_ = json.Unmarshal(raw, &rb)
	}
	return resp.StatusCode, rb, nil
}

// methodSpecific shows what makes each method different.
func (r *runner) methodSpecific(m xappclient.Method, client xappclient.Client, tok *xappclient.Token) error {
	switch m {
	case xappclient.MethodEphemeral:
		step("Key rotation (Method B)")
		before := client.Identity().Leaf().SerialNumber.Text(16)
		stats, err := client.Rotate(r.ctx)
		if err != nil {
			return fmt.Errorf("rotate: %w", err)
		}
		item("previous certificate", "serial %s", before)
		item("new certificate", "serial %s (%s, %d bytes)", stats.Serial, stats.KeyAlg, stats.CertBytes)
		item("rotation cost", "keygen %.2f ms, CA round trip %.2f ms", msOf(stats.KeyGen), msOf(stats.RoundTrip))
		// The token issued before rotation is bound to the retired certificate.
		status, rb, err := r.send(r.path(xappresource.ModeLocal), r.activeCert(client), bearer(tok))
		if err != nil {
			return err
		}
		r.check(status == http.StatusUnauthorized && rb.ReasonCode == xappresource.ReasonX5tMismatch,
			"token from before the rotation is rejected: HTTP %d %s", status, rb.ReasonCode)
		item("reason", "%s", rb.Reason)
		if _, err := client.Token(r.ctx); err != nil {
			return fmt.Errorf("token after rotation: %w", err)
		}
		status, body, _, err := r.call(client, r.path(xappresource.ModeLocal))
		if err != nil {
			return err
		}
		r.check(status == http.StatusOK, "a token bound to the new certificate is accepted: HTTP %d %s", status, strings.TrimSpace(body))

	case xappclient.MethodDPoP:
		step("DPoP proof (Method C)")
		dp := client.(xappclient.DPoP)
		signer := dp.Signer()
		if tok.PostQuantum {
			signer = dp.PQSigner()
		}
		proof, err := xappclient.BuildDPoPProof(signer, http.MethodGet, r.path(xappresource.ModeLocal), tok.Value, "", time.Now())
		if err != nil {
			return err
		}
		parsed, err := jose.ParseCompact(proof)
		if err != nil {
			return err
		}
		item("proof algorithm", "%s", parsed.Alg())
		item("proof size", "%d bytes", len(proof))
		item("proof key thumbprint", "%s", tok.Thumbprint)
		// First use is accepted, the replay of the same proof is not.
		status, _, err := r.send(r.path(xappresource.ModeLocal), r.activeCert(client), dpopHeaders(tok, proof))
		if err != nil {
			return err
		}
		r.check(status == http.StatusOK, "first use of the proof is accepted (HTTP %d)", status)
		status, rb, err := r.send(r.path(xappresource.ModeLocal), r.activeCert(client), dpopHeaders(tok, proof))
		if err != nil {
			return err
		}
		r.check(status == http.StatusUnauthorized && rb.ReasonCode == xappresource.ReasonDPoPReplayed,
			"replaying the same proof is rejected: HTTP %d %s", status, rb.ReasonCode)
		item("reason", "%s", rb.Reason)
	}
	return nil
}

// negative is the core security claim for the method: the token alone is not enough.
func (r *runner) negative(m xappclient.Method, client xappclient.Client, tok *xappclient.Token) error {
	step("Negative test: the token alone must not be enough")
	other, err := r.newClient()
	if err != nil {
		return fmt.Errorf("second client: %w", err)
	}
	fresh, err := client.Token(r.ctx)
	if err != nil {
		return err
	}
	if m == xappclient.MethodDPoP {
		// Present the DPoP-bound token with a proof signed by another key.
		dp := other.(xappclient.DPoP)
		signer := dp.Signer()
		if fresh.PostQuantum {
			signer = dp.PQSigner()
		}
		proof, err := xappclient.BuildDPoPProof(signer, http.MethodGet, r.path(xappresource.ModeLocal), fresh.Value, "", time.Now())
		if err != nil {
			return err
		}
		status, rb, err := r.send(r.path(xappresource.ModeLocal), r.activeCert(other), dpopHeaders(fresh, proof))
		if err != nil {
			return err
		}
		r.check(status == http.StatusUnauthorized && rb.ReasonCode == xappresource.ReasonDPoPJktMismatch,
			"stolen token with the attacker proof key is rejected: HTTP %d %s", status, rb.ReasonCode)
		item("reason", "%s", rb.Reason)
		return nil
	}
	// Methods A and B: present the token over another certificate, and with none.
	status, rb, err := r.send(r.path(xappresource.ModeLocal), r.activeCert(other), bearer(fresh))
	if err != nil {
		return err
	}
	r.check(status == http.StatusUnauthorized && rb.ReasonCode == xappresource.ReasonX5tMismatch,
		"stolen token over another certificate is rejected: HTTP %d %s", status, rb.ReasonCode)
	item("reason", "%s", rb.Reason)

	status, rb, err = r.send(r.path(xappresource.ModeLocal), nil, bearer(fresh))
	if err != nil {
		return err
	}
	r.check(status == http.StatusUnauthorized && rb.ReasonCode == xappresource.ReasonClientCertMissing,
		"stolen token with no certificate is rejected: HTTP %d %s", status, rb.ReasonCode)
	item("reason", "%s", rb.Reason)
	return nil
}

// activeCert is the credential a resource server expects to see.
func (r *runner) activeCert(c xappclient.Client) *tls.Certificate {
	if r.pq && c.PQIdentity() != nil {
		return c.PQIdentity().Current()
	}
	return c.Identity().Current()
}

func bearer(tok *xappclient.Token) map[string]string {
	return map[string]string{"Authorization": "Bearer " + tok.Value}
}

func dpopHeaders(tok *xappclient.Token, proof string) map[string]string {
	return map[string]string{"Authorization": "DPoP " + tok.Value, "DPoP": proof}
}

func msOf(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
```

### `scripts/_run-method.sh`

The shared driver: sources `out/host.env`, runs `methodrun`, then prints the matching log lines from the resource xApp, the shim and the CA.

```bash
#!/usr/bin/env bash
# Shared driver for scripts/run-method-{a,b,c}.sh.
#
#   _run-method.sh <A|B|C> [--pq|--classical]
#
# Runs one binding method end to end and prints, on the CLI:
#   - the configuration and algorithms in use,
#   - SMO onboarding and RIC CA enrollment (both credentials in post-quantum mode),
#   - the Keycloak token and, in post-quantum mode, its ML-DSA upgrade by the shim,
#   - the negotiated TLS key exchange group,
#   - resource calls under local validation and introspection,
#   - the method-specific behaviour (rotation for B, proof replay for C),
#   - the negative test that proves the token alone is not enough,
# followed by the matching decisions from the deployed components.
set -euo pipefail

METHOD=${1:?usage: _run-method.sh <A|B|C> [--pq]}
shift || true
MODE=classical
for arg in "$@"; do
  case "$arg" in
    --pq|-pq|pq) MODE=pq ;;
    --classical|-classical|classical) MODE=classical ;;
    *) echo "unknown option: $arg (use --pq or --classical)" >&2; exit 2 ;;
  esac
done

cd "$(dirname "$0")/.."
[[ -x out/bin/methodrun ]] || make --no-print-directory build
[[ -f out/host.env ]] || make --no-print-directory host-env
set -a; source out/host.env; set +a

if [[ "$MODE" == pq && "${PQ_MODE:-false}" != true ]]; then
  echo "note: the deployed xApps are in classical mode; run 'make pq-up' first so the"
  echo "      resource validator trusts the pq-shim issuer." >&2
fi

FLAGS=(-method "$METHOD")
BANNER="classical (ECDSA P-256 signatures, X25519 key exchange)"
if [[ "$MODE" == pq ]]; then
  FLAGS+=(-pq)
  BANNER="post-quantum (${PQ_SIGNING_ALG:-ML-DSA-65} tokens, ${PQ_IDENTITY_KEY_ALG:-ML-DSA-65} certificates, X25519MLKEM768 key exchange)"
fi

echo "==============================================================================="
echo " Method $METHOD  --  $BANNER"
echo " resource xApp: ${RESOURCE_URL}"
echo "==============================================================================="

set +e
out/bin/methodrun "${FLAGS[@]}"
rc=$?
set -e

echo
echo "--- validator decisions recorded by the resource xApp -------------------------"
kubectl -n "${XAPP_NAMESPACE:-ricxapp}" logs "deploy/${XAPP_A_NAME:-xapp-a}" --since=3m 2>/dev/null \
  | grep -E 'authz_rejected|token_binding_missing' | tail -6 | cut -c1-320 || echo "(none)"

if [[ "$MODE" == pq ]]; then
  echo
  echo "--- token upgrades recorded by the pq-shim ------------------------------------"
  kubectl -n "${RICSEC_NAMESPACE:-ricsec}" logs "deploy/${PQ_SHIM_SERVICE:-pq-shim}" --since=3m 2>/dev/null \
    | grep -E 'token_upgraded|upgrade_rejected' | tail -4 | cut -c1-400 || echo "(none)"
fi

echo
echo "--- certificates issued by the RIC CA -----------------------------------------"
kubectl -n "${RICSEC_NAMESPACE:-ricsec}" logs "deploy/${RIC_CA_SERVICE:-ric-ca}" --since=3m 2>/dev/null \
  | grep certificate_issued | tail -4 | cut -c1-320 || echo "(none)"

exit $rc
```

### `scripts/run-method-a.sh`

Method A wrapper.

```bash
#!/usr/bin/env bash
# Method A end-to-end walkthrough. Use --pq for the post-quantum run.
exec "$(dirname "$0")/_run-method.sh" A "$@"
```

### `scripts/run-method-b.sh`

Method B wrapper.

```bash
#!/usr/bin/env bash
# Method B end-to-end walkthrough. Use --pq for the post-quantum run.
exec "$(dirname "$0")/_run-method.sh" B "$@"
```

### `scripts/run-method-c.sh`

Method C wrapper.

```bash
#!/usr/bin/env bash
# Method C end-to-end walkthrough. Use --pq for the post-quantum run.
exec "$(dirname "$0")/_run-method.sh" C "$@"
```

---

## 3. The security test suite

46 cases. Positive controls for all three methods, the seven required negative tests, and extra checks (wrong `htm`/`htu`, stale proof, rotation, tampered signature, bootstrap reuse, untrusted certificate at Keycloak, DN mismatch). Every case that reaches the resource server runs twice: once with local validation, once with introspection. Each case prints the validator specific rejection reason and the results are written as CSV.

### `test/cmd/sectest/main.go`

The suite.

```go
// Command sectest is the security test suite. It runs against the deployed testbed
// (RIC CA, Keycloak, demo resource xApp) and prints, for every case, the HTTP status
// and the validator's specific rejection reason so results can be quoted directly.
// Results are also written as CSV. Exit status is non-zero if any case fails.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/config"
	"github.com/oran-ricsec/xapp-token-binding/internal/jose"
	"github.com/oran-ricsec/xapp-token-binding/internal/logx"
	"github.com/oran-ricsec/xapp-token-binding/internal/netx"
	"github.com/oran-ricsec/xapp-token-binding/internal/pki"
	"github.com/oran-ricsec/xapp-token-binding/internal/smo"
	xappclient "github.com/oran-ricsec/xapp-token-binding/xapp-client"
	xappresource "github.com/oran-ricsec/xapp-token-binding/xapp-resource"
)

type result struct {
	ID          string
	Category    string
	Description string
	Mode        string
	Expected    string
	Status      int
	ReasonCode  string
	Reason      string
	Pass        bool
}

type harness struct {
	ctx         context.Context
	log         *slog.Logger
	base        xappclient.Config
	onboarding  *smo.Onboarding
	roots       *x509.CertPool
	overrides   map[string]string
	resourceURL string
	ids         struct{ longterm, ephemeral, dpop, unbound string }
	results     []result
}

var modes = []xappresource.Mode{xappresource.ModeLocal, xappresource.ModeIntrospection}

func main() {
	out := flag.String("out", "results/security-tests.csv", "CSV output")
	expiryLifetime := flag.Duration("expiry-lifetime", 12*time.Second, "certificate lifetime used by the Method B expiry test")
	flag.Parse()

	log := logx.New("sectest")
	h, err := newHarness(log)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		os.Exit(2)
	}
	fmt.Printf("Security test suite against %s\n\n", h.resourceURL)

	steps := []struct {
		name string
		fn   func() error
	}{
		{"positive controls (A, B, C)", h.positive},
		{"N1 token over another xApp's mTLS session", h.n1WrongCertificate},
		{"N2 token without client certificate", h.n2NoCertificate},
		{"N3 DPoP proof signed by a different key", h.n3ForeignDPoPKey},
		{"N4 DPoP proof replay", h.n4Replay},
		{"N5 DPoP ath from a different token", h.n5AthOtherToken},
		{"N6 Method B token after certificate expiry", func() error { return h.n6ExpiredCertificate(*expiryLifetime) }},
		{"N7 bearer-style use", h.n7BearerStyle},
		{"X  additional proof-of-possession checks", h.extraDPoP},
		{"X  Method B rotation and token tampering", h.extraRotationAndTamper},
		{"X  enrollment and authorization-server checks", h.extraIssuance},
	}
	for _, s := range steps {
		fmt.Printf("== %s\n", s.name)
		if err := s.fn(); err != nil {
			h.add(result{ID: "ERR", Category: "harness", Description: s.name, Expected: "no harness error", Reason: err.Error()})
			fmt.Printf("  [FAIL] harness error: %v\n", err)
		}
	}

	failed := 0
	for _, r := range h.results {
		if !r.Pass {
			failed++
		}
	}
	if err := writeCSV(*out, h.results); err != nil {
		fmt.Fprintln(os.Stderr, "write results:", err)
	}
	fmt.Printf("\n%d cases, %d passed, %d failed. Results: %s\n", len(h.results), len(h.results)-failed, failed, *out)
	if failed > 0 {
		os.Exit(1)
	}
}

func newHarness(log *slog.Logger) (*harness, error) {
	e := &config.Env{}
	h := &harness{ctx: context.Background(), log: log}
	h.resourceURL = strings.TrimRight(e.Req("RESOURCE_URL"), "/")
	h.ids.longterm = e.Req("LONGTERM_CLIENT_ID")
	h.ids.ephemeral = e.Req("EPHEMERAL_CLIENT_ID")
	h.ids.dpop = e.Req("DPOP_CLIENT_ID")
	h.ids.unbound = e.Req("UNBOUND_CLIENT_ID")
	h.base = xappclient.Config{
		TokenURL:    e.Req("KEYCLOAK_TOKEN_URL"),
		Scope:       e.Str("TOKEN_SCOPE", ""),
		TrustBundle: e.List("RIC_TRUST_BUNDLE", nil),
		CAURL:       e.Req("RIC_CA_URL"),
		KeyAlg:      "EC-P256",
		DPoPAlg:     e.Str("DPOP_ALG", "ES256"),
		Rotation:    xappclient.RotateOnCertExpiry,
		HTTPTimeout: 20 * time.Second,
	}
	onbCert, onbKey, org := e.Req("SMO_ONBOARDING_CERT"), e.Req("SMO_ONBOARDING_KEY"), e.Req("ORG")
	overrides, err := netx.ParseDialOverrides(e.Str("DIAL_OVERRIDES", ""))
	if err != nil {
		e.Fail("DIAL_OVERRIDES: %v", err)
	}
	if err := e.Err(); err != nil {
		return nil, err
	}
	h.overrides, h.base.DialOverrides = overrides, overrides
	if h.roots, err = pki.LoadCertPool(h.base.TrustBundle...); err != nil {
		return nil, err
	}
	if h.onboarding, err = smo.LoadOnboarding(onbCert, onbKey, org); err != nil {
		return nil, err
	}
	return h, nil
}

// client onboards (fresh one-time bootstrap credential) and starts a client.
func (h *harness) client(m xappclient.Method, clientID string, lifetime time.Duration) (xappclient.Client, error) {
	cfg := h.base
	cfg.Method, cfg.ClientID, cfg.CertLifetime = m, clientID, lifetime
	boot, err := h.onboarding.IssueBootstrap(clientID, nil, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	cfg.Bootstrap = boot
	c, err := xappclient.New(cfg, h.log)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(h.ctx, time.Minute)
	defer cancel()
	if err := c.Start(ctx); err != nil {
		return nil, fmt.Errorf("start %s: %w", clientID, err)
	}
	return c, nil
}

func (h *harness) path(mode xappresource.Mode) string {
	if mode == xappresource.ModeIntrospection {
		return h.resourceURL + "/api/v1/introspect/sdl/sectest"
	}
	return h.resourceURL + "/api/v1/sdl/sectest"
}

// send performs a GET over a fresh TLS connection presenting cert (nil: no client certificate).
func (h *harness) send(url string, cert *tls.Certificate, headers map[string]string) (int, xappresource.RejectionBody, error) {
	conf := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: h.roots}
	if cert != nil {
		conf.Certificates = []tls.Certificate{*cert}
	}
	tr := netx.NewTransport(conf, h.overrides)
	tr.DisableKeepAlives = true
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(h.ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, xappresource.RejectionBody{}, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Transport: tr, Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return 0, xappresource.RejectionBody{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var rb xappresource.RejectionBody
	if resp.StatusCode != http.StatusOK {
		_ = json.Unmarshal(body, &rb)
	}
	return resp.StatusCode, rb, nil
}

func (h *harness) add(r result) {
	h.results = append(h.results, r)
	verdict := "PASS"
	if !r.Pass {
		verdict = "FAIL"
	}
	mode := r.Mode
	if mode == "" {
		mode = "-"
	}
	code := r.ReasonCode
	if code == "" {
		code = fmt.Sprintf("HTTP %d", r.Status)
	}
	fmt.Printf("  [%s] %-4s %-13s %-30s %s\n", verdict, r.ID, mode, code, r.Reason)
	if !r.Pass {
		fmt.Printf("         expected: %s\n", r.Expected)
	}
}

// expectAccepted records a positive case.
func (h *harness) expectAccepted(id, desc string, mode xappresource.Mode, status int, rb xappresource.RejectionBody, err error) {
	r := result{ID: id, Category: "positive", Description: desc, Mode: string(mode), Expected: "HTTP 200", Status: status}
	switch {
	case err != nil:
		r.Reason = err.Error()
	case status == http.StatusOK:
		r.Pass, r.Reason = true, "accepted"
	default:
		r.ReasonCode, r.Reason = rb.ReasonCode, rb.Reason
	}
	h.add(r)
}

// expectRejected records a negative case: HTTP 401/403 with the given reason code.
func (h *harness) expectRejected(id, desc string, mode xappresource.Mode, want string, status int, rb xappresource.RejectionBody, err error) {
	r := result{ID: id, Category: "negative", Description: desc, Mode: string(mode), Expected: "rejected with " + want, Status: status,
		ReasonCode: rb.ReasonCode, Reason: rb.Reason}
	if err != nil {
		r.Reason = err.Error()
	}
	r.Pass = err == nil && (status == http.StatusUnauthorized || status == http.StatusForbidden) && rb.ReasonCode == want
	h.add(r)
}

func bearer(tok string) map[string]string { return map[string]string{"Authorization": "Bearer " + tok} }

func dpopHeaders(tok, proof string) map[string]string {
	return map[string]string{"Authorization": "DPoP " + tok, "DPoP": proof}
}

// ---------------------------------------------------------------------------------

func (h *harness) positive() error {
	for _, spec := range []struct {
		id     string
		method xappclient.Method
		client string
		life   time.Duration
	}{
		{"P1", xappclient.MethodLongTerm, h.ids.longterm, 168 * time.Hour},
		{"P2", xappclient.MethodEphemeral, h.ids.ephemeral, 15 * time.Minute},
		{"P3", xappclient.MethodDPoP, h.ids.dpop, 168 * time.Hour},
	} {
		c, err := h.client(spec.method, spec.client, spec.life)
		if err != nil {
			return err
		}
		tok, err := c.Token(h.ctx)
		if err != nil {
			return fmt.Errorf("%s token: %w", spec.client, err)
		}
		// Milestone 2 guard, recorded explicitly: the binding Keycloak put in the token.
		h.add(result{ID: spec.id + "-cnf", Category: "positive", Description: fmt.Sprintf("Method %s token carries cnf.%s matching the client's key material", spec.method, tok.Binding),
			Expected: "cnf present and equal to certificate/JWK thumbprint", Pass: true, ReasonCode: "cnf." + tok.Binding, Reason: tok.Thumbprint})
		for _, mode := range modes {
			var status int
			var rb xappresource.RejectionBody
			if spec.method == xappclient.MethodDPoP {
				proof, perr := c.(xappclient.DPoP).Proof(http.MethodGet, h.path(mode), tok.Value)
				if perr != nil {
					return perr
				}
				status, rb, err = h.send(h.path(mode), c.Identity().Current(), dpopHeaders(tok.Value, proof))
			} else {
				status, rb, err = h.send(h.path(mode), c.Identity().Current(), bearer(tok.Value))
			}
			h.expectAccepted(spec.id, fmt.Sprintf("Method %s: token presented by its legitimate holder", spec.method), mode, status, rb, err)
		}
	}
	return nil
}

func (h *harness) n1WrongCertificate() error {
	a, err := h.client(xappclient.MethodLongTerm, h.ids.longterm, 168*time.Hour)
	if err != nil {
		return err
	}
	b, err := h.client(xappclient.MethodEphemeral, h.ids.ephemeral, 15*time.Minute)
	if err != nil {
		return err
	}
	tokA, err := a.Token(h.ctx)
	if err != nil {
		return err
	}
	for _, mode := range modes {
		status, rb, err := h.send(h.path(mode), b.Identity().Current(), bearer(tokA.Value))
		h.expectRejected("N1", "Token issued to xApp A presented over xApp B's mTLS session", mode, xappresource.ReasonX5tMismatch, status, rb, err)
	}
	return nil
}

func (h *harness) n2NoCertificate() error {
	a, err := h.client(xappclient.MethodLongTerm, h.ids.longterm, 168*time.Hour)
	if err != nil {
		return err
	}
	tokA, err := a.Token(h.ctx)
	if err != nil {
		return err
	}
	for _, mode := range modes {
		status, rb, err := h.send(h.path(mode), nil, bearer(tokA.Value))
		h.expectRejected("N2", "Token issued to xApp A presented with no client certificate", mode, xappresource.ReasonClientCertMissing, status, rb, err)
	}
	return nil
}

func (h *harness) dpopClient() (xappclient.Client, *xappclient.Token, error) {
	c, err := h.client(xappclient.MethodDPoP, h.ids.dpop, 168*time.Hour)
	if err != nil {
		return nil, nil, err
	}
	tok, err := c.Token(h.ctx)
	return c, tok, err
}

func (h *harness) n3ForeignDPoPKey() error {
	c, tok, err := h.dpopClient()
	if err != nil {
		return err
	}
	attacker, err := jose.GenerateSigner(h.base.DPoPAlg)
	if err != nil {
		return err
	}
	for _, mode := range modes {
		// Well-formed proof (correct htm, htu, ath, fresh jti) but signed by the attacker's key.
		proof, err := xappclient.BuildDPoPProof(attacker, http.MethodGet, h.path(mode), tok.Value, "", time.Now())
		if err != nil {
			return err
		}
		status, rb, err := h.send(h.path(mode), c.Identity().Current(), dpopHeaders(tok.Value, proof))
		h.expectRejected("N3", "DPoP token presented with a proof signed by a different key", mode, xappresource.ReasonDPoPJktMismatch, status, rb, err)
	}
	return nil
}

func (h *harness) n4Replay() error {
	c, tok, err := h.dpopClient()
	if err != nil {
		return err
	}
	for _, mode := range modes {
		proof, err := c.(xappclient.DPoP).Proof(http.MethodGet, h.path(mode), tok.Value)
		if err != nil {
			return err
		}
		status, rb, err := h.send(h.path(mode), c.Identity().Current(), dpopHeaders(tok.Value, proof))
		h.expectAccepted("N4-1", "DPoP proof first use (control for replay test)", mode, status, rb, err)
		status, rb, err = h.send(h.path(mode), c.Identity().Current(), dpopHeaders(tok.Value, proof))
		h.expectRejected("N4", "DPoP proof replayed (same jti)", mode, xappresource.ReasonDPoPReplayed, status, rb, err)
	}
	return nil
}

func (h *harness) n5AthOtherToken() error {
	c, tok1, err := h.dpopClient()
	if err != nil {
		return err
	}
	tok2, err := c.IssueToken(h.ctx)
	if err != nil {
		return err
	}
	for _, mode := range modes {
		proof, err := c.(xappclient.DPoP).Proof(http.MethodGet, h.path(mode), tok1.Value) // ath of token 1
		if err != nil {
			return err
		}
		status, rb, err := h.send(h.path(mode), c.Identity().Current(), dpopHeaders(tok2.Value, proof)) // presenting token 2
		h.expectRejected("N5", "DPoP proof whose ath is the hash of a different token", mode, xappresource.ReasonDPoPAthMismatch, status, rb, err)
	}
	return nil
}

func (h *harness) n6ExpiredCertificate(lifetime time.Duration) error {
	b, err := h.client(xappclient.MethodEphemeral, h.ids.ephemeral, lifetime)
	if err != nil {
		return err
	}
	tok, err := b.IssueToken(h.ctx)
	if err != nil {
		return err
	}
	cert := b.Identity().Current()
	status, rb, err := h.send(h.path(xappresource.ModeLocal), cert, bearer(tok.Value))
	h.expectAccepted("N6-1", "Method B: token accepted while its short-lived certificate is valid (control)", xappresource.ModeLocal, status, rb, err)

	wait := time.Until(cert.Leaf.NotAfter) + 2*time.Second
	fmt.Printf("  ...waiting %s for the %s certificate to expire (token still valid until %s)\n",
		wait.Round(time.Second), lifetime, tok.ExpiresAt.Format(time.TimeOnly))
	time.Sleep(wait)
	for _, mode := range modes {
		status, rb, err := h.send(h.path(mode), cert, bearer(tok.Value))
		h.expectRejected("N6", "Method B: unexpired token presented after its short-lived certificate expired", mode, xappresource.ReasonClientCertExpired, status, rb, err)
	}
	return nil
}

func (h *harness) n7BearerStyle() error {
	c, tok, err := h.dpopClient()
	if err != nil {
		return err
	}
	a, err := h.client(xappclient.MethodLongTerm, h.ids.longterm, 168*time.Hour)
	if err != nil {
		return err
	}
	tokA, err := a.Token(h.ctx)
	if err != nil {
		return err
	}
	for _, mode := range modes {
		status, rb, err := h.send(h.path(mode), nil, bearer(tokA.Value))
		h.expectRejected("N7a", "Bearer-style use of a certificate-bound token (token only, no certificate)", mode, xappresource.ReasonClientCertMissing, status, rb, err)
		status, rb, err = h.send(h.path(mode), c.Identity().Current(), bearer(tok.Value))
		h.expectRejected("N7b", "Bearer-style use of a DPoP-bound token (Bearer scheme, no proof)", mode, xappresource.ReasonDPoPAsBearer, status, rb, err)
		status, rb, err = h.send(h.path(mode), c.Identity().Current(), map[string]string{"Authorization": "DPoP " + tok.Value})
		h.expectRejected("N7c", "DPoP-bound token with DPoP scheme but no proof header", mode, xappresource.ReasonDPoPProofMissing, status, rb, err)
	}

	// A genuinely unbound token (test-only client with both binding switches off),
	// presented over a valid mTLS session: the validator must still refuse it.
	u, err := h.client(xappclient.MethodLongTerm, h.ids.unbound, time.Hour)
	if err != nil {
		return err
	}
	_, err = u.Token(h.ctx)
	if !errors.Is(err, xappclient.ErrBindingMissing) {
		return fmt.Errorf("expected the client library to refuse an unbound token, got %v", err)
	}
	h.add(result{ID: "N7d-client", Category: "negative", Description: "Client library refuses a token issued without cnf (Keycloak issues it anyway)",
		Expected: "ErrBindingMissing", Pass: true, ReasonCode: "binding_missing", Reason: err.Error()})
	raw, err := rawToken(h, u)
	if err != nil {
		return err
	}
	for _, mode := range modes {
		status, rb, err := h.send(h.path(mode), u.Identity().Current(), bearer(raw))
		h.expectRejected("N7d", "Unbound bearer token (no cnf) presented over a valid mTLS session", mode, xappresource.ReasonCnfMissing, status, rb, err)
	}
	return nil
}

// rawToken fetches a token without the client-side binding check.
func rawToken(h *harness, c xappclient.Client) (string, error) {
	resp, err := xappclient.KeycloakIssuer{}.Issue(h.ctx, xappclient.TokenRequest{
		TokenURL: h.base.TokenURL, ClientID: c.ClientID(), Scope: h.base.Scope, HTTPClient: c.HTTPClient(),
	})
	if err != nil {
		return "", err
	}
	return resp.AccessToken, nil
}

func (h *harness) extraDPoP() error {
	c, tok, err := h.dpopClient()
	if err != nil {
		return err
	}
	signer := c.(xappclient.DPoP).Signer()
	cert := c.Identity().Current()
	for _, mode := range modes {
		proof, _ := xappclient.BuildDPoPProof(signer, http.MethodPost, h.path(mode), tok.Value, "", time.Now())
		status, rb, err := h.send(h.path(mode), cert, dpopHeaders(tok.Value, proof))
		h.expectRejected("X1", "DPoP proof for a different HTTP method (htm)", mode, xappresource.ReasonDPoPHtmMismatch, status, rb, err)

		proof, _ = xappclient.BuildDPoPProof(signer, http.MethodGet, h.resourceURL+"/api/v1/sdl/other-resource", tok.Value, "", time.Now())
		status, rb, err = h.send(h.path(mode), cert, dpopHeaders(tok.Value, proof))
		h.expectRejected("X2", "DPoP proof for a different URI (htu)", mode, xappresource.ReasonDPoPHtuMismatch, status, rb, err)

		proof, _ = xappclient.BuildDPoPProof(signer, http.MethodGet, h.path(mode), tok.Value, "", time.Now().Add(-10*time.Minute))
		status, rb, err = h.send(h.path(mode), cert, dpopHeaders(tok.Value, proof))
		h.expectRejected("X3", "Stale DPoP proof (iat 10 minutes old)", mode, xappresource.ReasonDPoPIatOutOfWindow, status, rb, err)
	}
	return nil
}

func (h *harness) extraRotationAndTamper() error {
	b, err := h.client(xappclient.MethodEphemeral, h.ids.ephemeral, 15*time.Minute)
	if err != nil {
		return err
	}
	oldTok, err := b.Token(h.ctx)
	if err != nil {
		return err
	}
	if _, err := b.Rotate(h.ctx); err != nil {
		return err
	}
	for _, mode := range modes {
		status, rb, err := h.send(h.path(mode), b.Identity().Current(), bearer(oldTok.Value))
		h.expectRejected("X4", "Method B: token bound to the previous certificate, presented after key rotation", mode, xappresource.ReasonX5tMismatch, status, rb, err)
	}

	newTok, err := b.Token(h.ctx)
	if err != nil {
		return err
	}
	parts := strings.Split(newTok.Value, ".")
	sig := []byte(parts[2])
	if sig[10] == 'A' {
		sig[10] = 'B'
	} else {
		sig[10] = 'A'
	}
	tampered := parts[0] + "." + parts[1] + "." + string(sig)
	status, rb, err := h.send(h.path(xappresource.ModeLocal), b.Identity().Current(), bearer(tampered))
	h.expectRejected("X5", "Access token with a modified signature", xappresource.ModeLocal, xappresource.ReasonTokenSignatureInvalid, status, rb, err)
	status, rb, err = h.send(h.path(xappresource.ModeIntrospection), b.Identity().Current(), bearer(tampered))
	h.expectRejected("X5", "Access token with a modified signature", xappresource.ModeIntrospection, xappresource.ReasonTokenInactive, status, rb, err)
	return nil
}

func (h *harness) extraIssuance() error {
	// X6: one-time bootstrap credential.
	boot, err := h.onboarding.IssueBootstrap("sectest-onetime", nil, 10*time.Minute)
	if err != nil {
		return err
	}
	enr := &xappclient.Enroller{BaseURL: h.base.CAURL, Roots: h.roots, Overrides: h.overrides, Timeout: 20 * time.Second}
	key, _ := pki.GenerateKey("EC-P256")
	if _, err := enr.Enroll(h.ctx, boot, key, nil, time.Hour, false); err != nil {
		return fmt.Errorf("first enrollment should succeed: %w", err)
	}
	_, err = enr.Enroll(h.ctx, boot, key, nil, time.Hour, false)
	h.add(result{ID: "X6", Category: "negative", Description: "RIC CA: bootstrap credential used a second time", Expected: "HTTP 403 bootstrap_credential_reused",
		Status: statusOf(err), ReasonCode: codeOf(err, "bootstrap_credential_reused"), Reason: errString(err),
		Pass: err != nil && strings.Contains(err.Error(), "bootstrap_credential_reused")})

	// X7: Keycloak must not issue a token to a certificate outside the RIC trust anchor.
	status, detail, got := h.tokenWith(h.ids.longterm, boot)
	h.add(result{ID: "X7", Category: "negative", Description: "Keycloak: token request authenticated with a certificate not issued by the RIC CA",
		Expected: "no token", Status: status, ReasonCode: "no_token", Reason: detail, Pass: !got})

	// X8: a valid RIC certificate for another identity cannot obtain this client's token.
	b, err := h.client(xappclient.MethodEphemeral, h.ids.ephemeral, 15*time.Minute)
	if err != nil {
		return err
	}
	status, detail, got = h.tokenWith(h.ids.longterm, b.Identity().Current())
	h.add(result{ID: "X8", Category: "negative", Description: "Keycloak: client_id xapp-longterm requested with xapp-ephemeral's certificate (subject DN mismatch)",
		Expected: "no token", Status: status, ReasonCode: "no_token", Reason: detail, Pass: !got})
	return nil
}

func (h *harness) tokenWith(clientID string, cert *tls.Certificate) (int, string, bool) {
	conf := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: h.roots, Certificates: []tls.Certificate{*cert}}
	tr := netx.NewTransport(conf, h.overrides)
	tr.DisableKeepAlives = true
	defer tr.CloseIdleConnections()
	resp, err := xappclient.KeycloakIssuer{}.Issue(h.ctx, xappclient.TokenRequest{
		TokenURL: h.base.TokenURL, ClientID: clientID, Scope: h.base.Scope, HTTPClient: &http.Client{Transport: tr, Timeout: 30 * time.Second},
	})
	if err != nil {
		var ie *xappclient.IssuerError
		if errors.As(err, &ie) {
			return ie.Status, ie.Body, false
		}
		return 0, err.Error(), false
	}
	return http.StatusOK, "token issued", resp.AccessToken != ""
}

func statusOf(err error) int {
	if err == nil {
		return http.StatusOK
	}
	var code int
	if i := strings.Index(err.Error(), "HTTP "); i >= 0 {
		fmt.Sscanf(err.Error()[i:], "HTTP %d", &code)
	}
	return code
}

func codeOf(err error, want string) string {
	if err != nil && strings.Contains(err.Error(), want) {
		return want
	}
	return ""
}

func errString(err error) string {
	if err == nil {
		return "accepted"
	}
	return err.Error()
}

func writeCSV(path string, rs []result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	_ = w.Write([]string{"id", "category", "description", "validation_mode", "expected", "http_status", "reason_code", "reason", "verdict"})
	for _, r := range rs {
		verdict := "PASS"
		if !r.Pass {
			verdict = "FAIL"
		}
		_ = w.Write([]string{r.ID, r.Category, r.Description, r.Mode, r.Expected, fmt.Sprint(r.Status), r.ReasonCode, r.Reason, verdict})
	}
	w.Flush()
	return w.Error()
}
```

```bash
make test
```

```
  [PASS] N1   local         cnf_x5t_mismatch   presented certificate CN="xapp-ephemeral" ...
  [PASS] N6   local         client_certificate_expired  certificate CN="xapp-ephemeral" expired at ...
  [PASS] N7d  local         cnf_missing        access token has no cnf claim; unbound bearer tokens are not accepted

46 cases, 46 passed, 0 failed. Results: results/security-tests.csv
```

---

## 4. The measurement harness

Per method: token request latency, resource request latency and throughput under local validation versus introspection, token and proof sizes, and for Method B the rotation cost and rotations per hour at several certificate lifetimes. The CSV has a fixed schema and row order so runs are comparable; the run metadata goes to a separate file.

### `bench/cmd/bench/main.go`

The harness.

```go
// Command bench measures the three binding methods against the deployed testbed and
// writes one CSV with a fixed schema and row order (so runs are comparable), plus a
// separate CSV describing the run environment.
//
// Per method: token request latency; resource request latency and throughput with
// local validation vs introspection; token and DPoP proof sizes. Method B additionally:
// RIC CA cost per rotation and rotations/hour for a set of certificate lifetimes.
package main

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/config"
	"github.com/oran-ricsec/xapp-token-binding/internal/logx"
	"github.com/oran-ricsec/xapp-token-binding/internal/netx"
	"github.com/oran-ricsec/xapp-token-binding/internal/smo"
	xappclient "github.com/oran-ricsec/xapp-token-binding/xapp-client"
	xappresource "github.com/oran-ricsec/xapp-token-binding/xapp-resource"
)

var header = []string{"method", "metric", "variant", "unit", "samples", "p50", "p95", "p99", "mean", "min", "max", "value"}

type row struct {
	method, metric, variant, unit string
	samples                       []float64 // distribution metrics
	value                         *float64  // scalar metrics
}

func (r row) record() []string {
	f := func(v float64) string { return strconv.FormatFloat(v, 'f', 3, 64) }
	out := []string{r.method, r.metric, r.variant, r.unit}
	if r.value != nil {
		return append(out, "1", "", "", "", "", "", "", f(*r.value))
	}
	s := slices.Clone(r.samples)
	slices.Sort(s)
	if len(s) == 0 {
		return append(out, "0", "", "", "", "", "", "", "")
	}
	var sum float64
	for _, v := range s {
		sum += v
	}
	return append(out, strconv.Itoa(len(s)), f(pct(s, 50)), f(pct(s, 95)), f(pct(s, 99)), f(sum/float64(len(s))), f(s[0]), f(s[len(s)-1]), "")
}

// pct is the nearest-rank percentile of sorted samples.
func pct(sorted []float64, p float64) float64 {
	rank := int(math.Ceil(p / 100 * float64(len(sorted))))
	return sorted[max(0, min(rank-1, len(sorted)-1))]
}

func scalar(method, metric, variant, unit string, v float64) row {
	return row{method: method, metric: metric, variant: variant, unit: unit, value: &v}
}

type params struct {
	tokenN, resourceN, rotationN, warmup, concurrency int
	rpsDuration                                       time.Duration
	lifetimes                                         []time.Duration
	methods                                           []string
}

type bench struct {
	ctx         context.Context
	log         *slog.Logger
	base        xappclient.Config
	onboarding  *smo.Onboarding
	resourceURL string
	clientIDs   map[xappclient.Method]string
	lifetime    map[xappclient.Method]time.Duration
	p           params
	rows        []row
}

func main() {
	out := flag.String("out", "results/bench.csv", "results CSV")
	envOut := flag.String("env-out", "results/bench-env.csv", "run environment CSV")
	flag.Parse()

	b, err := setup()
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		os.Exit(2)
	}
	started := time.Now().UTC()
	for _, m := range b.p.methods {
		if err := b.run(xappclient.Method(m)); err != nil {
			fmt.Fprintf(os.Stderr, "method %s: %v\n", m, err)
			os.Exit(1)
		}
	}
	if err := writeCSV(*out, b.rows); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := b.writeEnv(*envOut, started); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	fmt.Printf("wrote %s (%d rows) and %s\n", *out, len(b.rows), *envOut)
}

func setup() (*bench, error) {
	e := &config.Env{}
	b := &bench{ctx: context.Background(), log: logx.New("bench")}
	b.p = params{
		tokenN:      e.Int("BENCH_TOKEN_N", 100),
		resourceN:   e.Int("BENCH_RESOURCE_N", 300),
		rotationN:   e.Int("BENCH_ROTATION_N", 30),
		warmup:      e.Int("BENCH_WARMUP", 10),
		concurrency: e.Int("BENCH_CONCURRENCY", 4),
		rpsDuration: e.Dur("BENCH_RPS_DURATION", 10*time.Second),
		methods:     e.List("BENCH_METHODS", []string{"A", "B", "C"}),
	}
	for _, l := range e.List("BENCH_ROTATION_LIFETIMES", []string{"5m", "15m", "1h", "24h"}) {
		d, err := time.ParseDuration(l)
		if err != nil {
			e.Fail("BENCH_ROTATION_LIFETIMES: %v", err)
			continue
		}
		b.p.lifetimes = append(b.p.lifetimes, d)
	}
	b.resourceURL = strings.TrimRight(e.Req("RESOURCE_URL"), "/")
	b.clientIDs = map[xappclient.Method]string{
		xappclient.MethodLongTerm:  e.Req("LONGTERM_CLIENT_ID"),
		xappclient.MethodEphemeral: e.Req("EPHEMERAL_CLIENT_ID"),
		xappclient.MethodDPoP:      e.Req("DPOP_CLIENT_ID"),
	}
	b.lifetime = map[xappclient.Method]time.Duration{
		xappclient.MethodLongTerm:  e.Dur("LONGTERM_CERT_LIFETIME", 168*time.Hour),
		xappclient.MethodEphemeral: e.Dur("EPHEMERAL_CERT_LIFETIME", 15*time.Minute),
		xappclient.MethodDPoP:      e.Dur("LONGTERM_CERT_LIFETIME", 168*time.Hour),
	}
	b.base = xappclient.Config{
		TokenURL:    e.Req("KEYCLOAK_TOKEN_URL"),
		Scope:       e.Str("TOKEN_SCOPE", ""),
		TrustBundle: e.List("RIC_TRUST_BUNDLE", nil),
		CAURL:       e.Req("RIC_CA_URL"),
		KeyAlg:      "EC-P256",
		DPoPAlg:     e.Str("DPOP_ALG", "ES256"),
		Rotation:    xappclient.RotateOnCertExpiry,
		HTTPTimeout: 30 * time.Second,
	}
	onbCert, onbKey, org := e.Req("SMO_ONBOARDING_CERT"), e.Req("SMO_ONBOARDING_KEY"), e.Req("ORG")
	overrides, err := netx.ParseDialOverrides(e.Str("DIAL_OVERRIDES", ""))
	if err != nil {
		e.Fail("DIAL_OVERRIDES: %v", err)
	}
	if err := e.Err(); err != nil {
		return nil, err
	}
	b.base.DialOverrides = overrides
	if b.onboarding, err = smo.LoadOnboarding(onbCert, onbKey, org); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *bench) newClient(m xappclient.Method) (xappclient.Client, error) {
	cfg := b.base
	cfg.Method, cfg.ClientID, cfg.CertLifetime = m, b.clientIDs[m], b.lifetime[m]
	boot, err := b.onboarding.IssueBootstrap(cfg.ClientID, nil, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	cfg.Bootstrap = boot
	c, err := xappclient.New(cfg, b.log)
	if err != nil {
		return nil, err
	}
	return c, c.Start(b.ctx)
}

func msSince(t time.Time) float64 { return float64(time.Since(t).Nanoseconds()) / 1e6 }

func (b *bench) path(mode xappresource.Mode) string {
	if mode == xappresource.ModeIntrospection {
		return b.resourceURL + "/api/v1/introspect/sdl/bench"
	}
	return b.resourceURL + "/api/v1/sdl/bench"
}

func (b *bench) call(c xappclient.Client, url string) error {
	req, err := http.NewRequestWithContext(b.ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func (b *bench) run(m xappclient.Method) error {
	ms := string(m)
	fmt.Printf("== Method %s (%s)\n", ms, b.clientIDs[m])
	c, err := b.newClient(m)
	if err != nil {
		return err
	}
	for i := 0; i < b.p.warmup; i++ {
		if _, err := c.IssueToken(b.ctx); err != nil {
			return fmt.Errorf("warmup token: %w", err)
		}
		if err := b.call(c, b.path(xappresource.ModeLocal)); err != nil {
			return fmt.Errorf("warmup resource call: %w", err)
		}
	}

	// Token request latency (issuance path only; no rotation).
	var lat []float64
	var tok *xappclient.Token
	for i := 0; i < b.p.tokenN; i++ {
		t := time.Now()
		if tok, err = c.IssueToken(b.ctx); err != nil {
			return err
		}
		lat = append(lat, msSince(t))
	}
	b.rows = append(b.rows, row{method: ms, metric: "token_request_latency", variant: "issue_only", unit: "ms", samples: lat})
	fmt.Printf("  token request p50 %.1f ms\n", pct(sorted(lat), 50))

	// Method B: key generation + CSR + RIC CA round trip per rotation, then token.
	if m == xappclient.MethodEphemeral {
		var keygen, ca, total, rotTok []float64
		for i := 0; i < b.p.rotationN; i++ {
			t := time.Now()
			st, err := c.Rotate(b.ctx)
			if err != nil {
				return err
			}
			if _, err := c.IssueToken(b.ctx); err != nil {
				return err
			}
			rotTok = append(rotTok, msSince(t))
			keygen = append(keygen, float64(st.KeyGen.Nanoseconds())/1e6)
			ca = append(ca, float64(st.RoundTrip.Nanoseconds())/1e6)
			total = append(total, float64(st.Total.Nanoseconds())/1e6)
		}
		b.rows = append(b.rows,
			row{method: ms, metric: "token_request_latency", variant: "rotate_then_issue", unit: "ms", samples: rotTok},
			row{method: ms, metric: "rotation_keygen_latency", variant: "EC-P256", unit: "ms", samples: keygen},
			row{method: ms, metric: "rotation_ca_roundtrip_latency", variant: "csr_to_certificate", unit: "ms", samples: ca},
			row{method: ms, metric: "rotation_total_latency", variant: "keygen_plus_ca", unit: "ms", samples: total},
		)
		mean := meanOf(total)
		for _, l := range b.p.lifetimes {
			renewEvery := l - l/5 // default policy renews with 20% of the lifetime remaining
			perHour := float64(time.Hour) / float64(renewEvery)
			b.rows = append(b.rows,
				scalar(ms, "rotations_per_hour", "cert_lifetime="+l.String(), "count", perHour),
				scalar(ms, "rotation_ca_cost_per_hour", "cert_lifetime="+l.String(), "ms", perHour*mean))
		}
		fmt.Printf("  rotation total p50 %.1f ms (CA round trip p50 %.1f ms)\n", pct(sorted(total), 50), pct(sorted(ca), 50))
		if tok, err = c.Token(b.ctx); err != nil {
			return err
		}
	}

	// Sizes.
	b.rows = append(b.rows, scalar(ms, "access_token_size", tok.Binding, "bytes", float64(len(tok.Value))))
	if d, ok := c.(xappclient.DPoP); ok {
		tp, err := d.Proof(http.MethodPost, b.base.TokenURL, "")
		if err != nil {
			return err
		}
		rp, err := d.Proof(http.MethodGet, b.path(xappresource.ModeLocal), tok.Value)
		if err != nil {
			return err
		}
		b.rows = append(b.rows,
			scalar(ms, "dpop_proof_size", "token_request", "bytes", float64(len(tp))),
			scalar(ms, "dpop_proof_size", "resource_request_with_ath", "bytes", float64(len(rp))))
	}

	// Resource request latency and throughput: local validation vs introspection.
	for _, mode := range []xappresource.Mode{xappresource.ModeLocal, xappresource.ModeIntrospection} {
		var rl []float64
		for i := 0; i < b.p.resourceN; i++ {
			t := time.Now()
			if err := b.call(c, b.path(mode)); err != nil {
				return fmt.Errorf("resource %s: %w", mode, err)
			}
			rl = append(rl, msSince(t))
		}
		b.rows = append(b.rows, row{method: ms, metric: "resource_request_latency", variant: string(mode), unit: "ms", samples: rl})
		rps, errs := b.throughput(c, b.path(mode))
		b.rows = append(b.rows,
			scalar(ms, "resource_throughput", string(mode), "req/s", rps),
			scalar(ms, "resource_errors_during_throughput", string(mode), "count", float64(errs)))
		fmt.Printf("  resource %-13s p50 %.1f ms, %.1f req/s (%d errors)\n", mode, pct(sorted(rl), 50), rps, errs)
	}
	return nil
}

func (b *bench) throughput(c xappclient.Client, url string) (float64, int64) {
	var ok, failed atomic.Int64
	deadline := time.Now().Add(b.p.rpsDuration)
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < b.p.concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				if err := b.call(c, url); err != nil {
					failed.Add(1)
				} else {
					ok.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	return float64(ok.Load()) / time.Since(start).Seconds(), failed.Load()
}

func sorted(v []float64) []float64 {
	s := slices.Clone(v)
	slices.Sort(s)
	return s
}

func meanOf(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	var s float64
	for _, x := range v {
		s += x
	}
	return s / float64(len(v))
}

func writeCSV(path string, rows []row) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	_ = w.Write(header)
	for _, r := range rows {
		_ = w.Write(r.record())
	}
	w.Flush()
	return w.Error()
}

func (b *bench) writeEnv(path string, started time.Time) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	host, _ := os.Hostname()
	lifetimes := make([]string, len(b.p.lifetimes))
	for i, l := range b.p.lifetimes {
		lifetimes[i] = l.String()
	}
	w := csv.NewWriter(f)
	for _, kv := range [][2]string{
		{"started_utc", started.Format(time.RFC3339)},
		{"finished_utc", time.Now().UTC().Format(time.RFC3339)},
		{"host", host},
		{"go_version", runtime.Version()},
		{"cpus", strconv.Itoa(runtime.NumCPU())},
		{"methods", strings.Join(b.p.methods, " ")},
		{"token_samples", strconv.Itoa(b.p.tokenN)},
		{"resource_samples", strconv.Itoa(b.p.resourceN)},
		{"rotation_samples", strconv.Itoa(b.p.rotationN)},
		{"warmup", strconv.Itoa(b.p.warmup)},
		{"throughput_concurrency", strconv.Itoa(b.p.concurrency)},
		{"throughput_duration", b.p.rpsDuration.String()},
		{"rotation_lifetimes", strings.Join(lifetimes, " ")},
		{"renewal_policy", "renew with 20% of certificate lifetime remaining"},
		{"token_url", b.base.TokenURL},
		{"resource_url", b.resourceURL},
		{"dpop_alg", b.base.DPoPAlg},
		{"identity_key_alg", b.base.KeyAlg},
	} {
		_ = w.Write(kv[:])
	}
	w.Flush()
	return w.Error()
}
```

```bash
make bench
```

Measured on the lab VM (4 vCPU, shared with the RIC):

| Metric | A | B | C |
|---|---|---|---|
| Token request p50 | 11.1 ms | 8.6 ms | 14.5 ms |
| Resource request p50, local | 2.0 ms | 2.2 ms | 0.6 ms |
| Resource request p50, introspection | 11.9 ms | 14.2 ms | 6.9 ms |
| Throughput, local | 1118 req/s | 1054 req/s | 2686 req/s |
| Throughput, introspection | 187 req/s | 147 req/s | 257 req/s |

Method B rotation: key generation 0.06 ms, CA round trip 9.4 ms, so even a 5 minute certificate costs about 0.15 s of CA work per hour per xApp.

