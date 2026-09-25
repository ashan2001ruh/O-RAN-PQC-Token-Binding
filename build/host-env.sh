#!/usr/bin/env bash
# host-env.sh <out-file>
# Writes the environment used by tools run on the node (sectest, bench, verify
# scripts). Cluster Services are reached by their in-cluster DNS names through
# DIAL_OVERRIDES (name:port -> ClusterIP:port), so TLS server names and DPoP htu
# values are identical to what in-cluster xApps use.
set -euo pipefail
OUT_FILE=${1:?usage: host-env.sh <out-file>}
: "${KUBECTL:=kubectl}"

cluster_ip() { # cluster_ip <namespace> <service>
  "$KUBECTL" -n "$1" get svc "$2" -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true
}

overrides=()
add() { # add <namespace> <service> <port>
  local ip; ip=$(cluster_ip "$1" "$2")
  if [[ -n "$ip" ]]; then overrides+=("$2.$1.svc.${CLUSTER_DOMAIN}:$3=$ip:$3"); fi
}
add "$RICSEC_NAMESPACE" "$KEYCLOAK_SERVICE" "$KEYCLOAK_PORT"
add "$RICSEC_NAMESPACE" "$RIC_CA_SERVICE" "$RIC_CA_PORT"
add "$XAPP_NAMESPACE" "$XAPP_A_NAME" "$XAPP_PORT"
add "$XAPP_NAMESPACE" "$XAPP_B_NAME" "$XAPP_PORT"
add "$RICSEC_NAMESPACE" "${PQ_SHIM_SERVICE:-pq-shim}" "${PQ_SHIM_PORT:-8443}"

PKI=$(pwd)/out/pki
XAPP_A_URL="https://${XAPP_A_NAME}.${XAPP_NAMESPACE}.svc.${CLUSTER_DOMAIN}:${XAPP_PORT}"
cat > "$OUT_FILE" <<EOF
DIAL_OVERRIDES=$(IFS=,; echo "${overrides[*]}")
KEYCLOAK_TOKEN_URL=${TOKEN_ISSUER}/protocol/openid-connect/token
INTROSPECTION_URL=${TOKEN_ISSUER}/protocol/openid-connect/token/introspect
JWKS_URL=${TOKEN_ISSUER}/protocol/openid-connect/certs
TOKEN_ISSUER=${TOKEN_ISSUER}
TOKEN_AUDIENCE=${TOKEN_AUDIENCE}
TOKEN_SCOPE=${TOKEN_SCOPE}
REQUIRED_SCOPE=${TOKEN_SCOPE}
REQUIRED_ROLE=${REQUIRED_ROLE}
RIC_CA_URL=${RIC_CA_URL}
RIC_TRUST_BUNDLE=${PKI}/ric-intermediate-ca.crt,${PKI}/ric-intermediate-ca-pq.crt
SMO_ONBOARDING_CERT=${PKI}/smo-onboarding-ca.crt
SMO_ONBOARDING_KEY=${PKI}/smo-onboarding-ca.key
SMO_ONBOARDING_CERT_PQ=${PKI}/smo-onboarding-ca-pq.crt
SMO_ONBOARDING_KEY_PQ=${PKI}/smo-onboarding-ca-pq.key
SMO_ROOT_CERT=${PKI}/smo-root-ca.crt
PQ_SHIM_URL=${PQ_SHIM_URL}
PQ_JWKS_URL=${PQ_SHIM_URL}/v1/jwks
PQ_INTROSPECTION_URL=${PQ_SHIM_URL}/v1/introspect
PQ_IDENTITY_KEY_ALG=${PQ_IDENTITY_KEY_ALG}
PQ_DPOP_ALG=${PQ_DPOP_ALG}
PQ_SIGNING_ALG=${PQ_SIGNING_ALG}
PQ_KEX_ONLY=${PQ_KEX_ONLY}
PQ_MODE=${PQ_MODE}
PQ_ISSUER=${PQ_ISSUER}
ORG=${ORG}
XAPP_OU=${XAPP_OU}
RICSEC_NAMESPACE=${RICSEC_NAMESPACE}
XAPP_NAMESPACE=${XAPP_NAMESPACE}
XAPP_A_NAME=${XAPP_A_NAME}
XAPP_B_NAME=${XAPP_B_NAME}
RIC_CA_SERVICE=${RIC_CA_SERVICE}
PQ_SHIM_SERVICE=${PQ_SHIM_SERVICE}
RESOURCE_URL=${XAPP_A_URL}
LONGTERM_CLIENT_ID=${XAPP_A_CLIENT_ID}
EPHEMERAL_CLIENT_ID=${XAPP_B_CLIENT_ID}
DPOP_CLIENT_ID=xapp-dpop
UNBOUND_CLIENT_ID=xapp-unbound-probe
LONGTERM_CERT_LIFETIME=${LONGTERM_CERT_LIFETIME}
EPHEMERAL_CERT_LIFETIME=${EPHEMERAL_CERT_LIFETIME}
LOG_LEVEL=warn
EOF
echo "wrote $OUT_FILE"
