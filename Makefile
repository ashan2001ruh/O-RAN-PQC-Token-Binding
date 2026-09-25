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

# The resource validator trusts whichever service issues the token it will see, and
# the RIC CA presents an ML-DSA server certificate in PQ mode.
#
# PQ_ISSUER selects that service. Today it is the shim, because no released Keycloak
# can sign with ML-DSA. PQ_ISSUER=keycloak points every consumer straight at the
# authorization server instead, which is how the shim leaves the deployment when one
# can: no code changes, one variable.
ifeq ($(PQ_MODE),true)
RIC_CA_SERVER_CERT         := ric-ca-server-pq
ifeq ($(PQ_ISSUER),keycloak)
RESOURCE_TOKEN_ISSUER      := $(TOKEN_ISSUER)
RESOURCE_JWKS_URL          := $(TOKEN_ISSUER)/protocol/openid-connect/certs
RESOURCE_INTROSPECTION_URL := $(TOKEN_ISSUER)/protocol/openid-connect/token/introspect
else
RESOURCE_TOKEN_ISSUER      := $(PQ_SHIM_URL)
RESOURCE_JWKS_URL          := $(PQ_SHIM_URL)/v1/jwks
RESOURCE_INTROSPECTION_URL := $(PQ_SHIM_URL)/v1/introspect
endif
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
IMAGES   := ric-ca xapp pq-shim xapp-sidecar
LABEL    := part-of=xapp-token-binding
# kubectl create ... --dry-run | label | apply  (idempotent and labelled for `make down`)
APPLY    := $(KUBECTL) label --local -f - $(LABEL) -o yaml | $(KUBECTL) apply -f -
HOSTENV  := set -a; source $(OUT)/host.env; set +a;

.PHONY: help up down pki build unit images namespaces trust deploy-ca deploy-keycloak \
        import-realm deploy-shim bootstrap-xapps deploy-xapps wait host-env verify-ca verify-keycloak test bench \
        run-a run-b run-c pq-up verify-pq         kyverno demo-app-image sidecar-policy bootstrap-sidecar-xapps onboard-xapps sidecar-up sidecar-status sidecar-logs sidecar-down \
        restart-keycloak restart-xapps show-config status logs clean

help: ## list targets
	@grep -E '^[a-z-]+:.*## ' $(firstword $(MAKEFILE_LIST)) | sed 's/:.*## /\t/' | column -t -s $$'\t'

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
	  ./pqshim/cmd/pq-shim ./test/cmd/sectest ./bench/cmd/bench ./cmd/methodrun \
	  ./sidecar/cmd/xapp-sidecar

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

# --- sidecar architecture -----------------------------------------------------
# One injected sidecar per xApp carries both directions of its traffic over the
# post-quantum tunnel; Kyverno adds it, dms_cli onboards the xApps.

sidecar-up: build images demo-app-image kyverno sidecar-policy bootstrap-sidecar-xapps onboard-xapps ## Kyverno + two dms_cli-onboarded xApps with injected sidecars
	$(KUBECTL) -n $(XAPP_NAMESPACE) rollout status deploy/$(XAPP_NAMESPACE)-$(SIDECAR_C_XAPP) --timeout=300s
	$(KUBECTL) -n $(XAPP_NAMESPACE) rollout status deploy/$(XAPP_NAMESPACE)-$(SIDECAR_D_XAPP) --timeout=300s
	@echo "sidecar testbed is up: run 'make sidecar-logs'"

kyverno: ## install the Kyverno admission controller (idempotent)
	KYVERNO_CHART_VERSION=$(KYVERNO_CHART_VERSION) scripts/install-kyverno.sh

demo-app-image: ## publish the stock image the onboarded xApps run (no security code in it)
	$(SUDO) docker pull busybox:$(DEMO_APP_IMAGE_TAG)
	$(SUDO) docker tag busybox:$(DEMO_APP_IMAGE_TAG) $(LOCAL_REGISTRY)/$(DEMO_APP_IMAGE_NAME):$(DEMO_APP_IMAGE_TAG)
	$(SUDO) docker push $(LOCAL_REGISTRY)/$(DEMO_APP_IMAGE_NAME):$(DEMO_APP_IMAGE_TAG)

sidecar-policy: ## apply the Kyverno injection policy and the sidecar Services
	build/render.sh deploy/kyverno/sidecar-policy.yaml | $(KUBECTL) apply -f -
	build/render.sh deploy/kyverno/sidecar-services.yaml | $(KUBECTL) apply -f -
	$(KUBECTL) wait --for=condition=Ready clusterpolicy/xapp-token-binding-sidecar --timeout=60s

bootstrap-sidecar-xapps: ## SMO onboarding: one-time bootstrap credentials for the two sidecar xApps
	$(call bootstrap_xapp,$(SIDECAR_C_CLIENT_ID),$(SIDECAR_C_CLIENT_ID))
	$(call bootstrap_xapp,$(SIDECAR_D_CLIENT_ID),$(SIDECAR_D_CLIENT_ID))

onboard-xapps: ## onboard and install the two xApps with dms_cli
	scripts/onboard-sidecar-xapps.sh

sidecar-status: ## show the onboarded xApps and their injected sidecars
	$(KUBECTL) -n $(XAPP_NAMESPACE) get pods -l pq.oran/sidecar -o wide
	$(KUBECTL) -n $(XAPP_NAMESPACE) get svc -l part-of=xapp-token-binding

sidecar-logs: ## tail the sidecar authorization decisions
	$(KUBECTL) -n $(XAPP_NAMESPACE) logs -l pq.oran/sidecar -c pq-sidecar --tail=40 --prefix

sidecar-down: ## remove the onboarded xApps, the policy and the sidecar Services
	-dms_cli uninstall --xapp_chart_name=$(SIDECAR_C_XAPP) --namespace=$(XAPP_NAMESPACE)
	-dms_cli uninstall --xapp_chart_name=$(SIDECAR_D_XAPP) --namespace=$(XAPP_NAMESPACE)
	-$(KUBECTL) delete clusterpolicy xapp-token-binding-sidecar
	-$(KUBECTL) -n $(XAPP_NAMESPACE) delete svc $(SIDECAR_C_CLIENT_ID)-sidecar $(SIDECAR_D_CLIENT_ID)-sidecar
	-$(KUBECTL) -n $(XAPP_NAMESPACE) delete secret $(SIDECAR_C_CLIENT_ID)-bootstrap $(SIDECAR_C_CLIENT_ID)-bootstrap-pq $(SIDECAR_D_CLIENT_ID)-bootstrap $(SIDECAR_D_CLIENT_ID)-bootstrap-pq

show-config: ## print the issuer configuration the current flags resolve to
	@echo "PQ_MODE=$(PQ_MODE)  PQ_ISSUER=$(PQ_ISSUER)"
	@echo "RESOURCE_TOKEN_ISSUER      = $(RESOURCE_TOKEN_ISSUER)"
	@echo "RESOURCE_JWKS_URL          = $(RESOURCE_JWKS_URL)"
	@echo "RESOURCE_INTROSPECTION_URL = $(RESOURCE_INTROSPECTION_URL)"
	@echo "RIC_CA_SERVER_CERT         = $(RIC_CA_SERVER_CERT)"

status: ## show testbed pods
	$(KUBECTL) get pods -A -l $(LABEL) -o wide

logs: ## tail validator decisions from the demo xApps
	$(KUBECTL) -n $(XAPP_NAMESPACE) logs -l $(LABEL) --tail=50 --prefix

down: ## remove everything this project deployed (leaves the RIC untouched)
	-$(KUBECTL) -n $(XAPP_NAMESPACE) delete deploy,svc,secret,configmap -l $(LABEL)
	-$(KUBECTL) delete namespace $(RICSEC_NAMESPACE)

clean: ## remove build outputs (keeps the PKI)
	rm -rf $(BIN) $(OUT)/rendered $(OUT)/bootstrap $(OUT)/host.env
