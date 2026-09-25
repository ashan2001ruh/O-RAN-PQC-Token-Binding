#!/usr/bin/env bash
# Generates the testbed PKI:
#   smo-root-ca          simulated SMO root CA (offline: its key never enters the cluster)
#   smo-onboarding-ca    simulated SMO onboarding CA, issues one-time bootstrap certificates
#   ric-intermediate-ca  RIC intermediate CA, issues xApp operational identity certificates
#   keycloak-server      TLS server certificate for Keycloak (XRF)
#   ric-ca-server        TLS server certificate for the enrollment service
# Configuration comes from config/testbed.env (exported by the Makefile).
set -euo pipefail

OUT=${1:?usage: gen-pki.sh <out-dir>}
: "${ORG:?}" "${RICSEC_NAMESPACE:?}" "${CLUSTER_DOMAIN:?}" "${KEYCLOAK_SERVICE:?}" "${RIC_CA_SERVICE:?}"
: "${ROOT_CA_DAYS:=3650}" "${INTERMEDIATE_CA_DAYS:=1825}" "${SERVER_CERT_DAYS:=365}"

HERE=$(cd "$(dirname "$0")" && pwd)
CNF="$HERE/openssl.cnf"
mkdir -p "$OUT"

generate_classical=1
if [[ -f "$OUT/ric-intermediate-ca.crt" ]]; then
  echo "classical PKI already present in $OUT (remove the directory to regenerate)"
  generate_classical=0
fi

if [[ $generate_classical == 1 ]]; then

newkey() { # newkey <file> <curve>
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:"$2" -out "$1"
  chmod 600 "$1"
}

sign() { # sign <name> <subject> <extension-section> <days> <issuer-name> <curve>
  local name=$1 subj=$2 ext=$3 days=$4 issuer=$5 curve=$6
  newkey "$OUT/$name.key" "$curve"
  openssl req -new -key "$OUT/$name.key" -subj "$subj" -config "$CNF" -out "$OUT/$name.csr"
  openssl x509 -req -in "$OUT/$name.csr" -CA "$OUT/$issuer.crt" -CAkey "$OUT/$issuer.key" \
    -set_serial "0x$(openssl rand -hex 16)" -days "$days" -sha384 \
    -extfile "$CNF" -extensions "$ext" -out "$OUT/$name.crt"
  rm -f "$OUT/$name.csr"
}

export SAN="DNS:unused"

echo "==> SMO root CA (simulated)"
newkey "$OUT/smo-root-ca.key" P-384
openssl req -x509 -new -key "$OUT/smo-root-ca.key" -sha384 -days "$ROOT_CA_DAYS" \
  -subj "/O=${ORG}/OU=SMO/CN=SMO Root CA (simulated)" \
  -config "$CNF" -extensions v3_root -out "$OUT/smo-root-ca.crt"

echo "==> SMO onboarding CA (bootstrap credentials)"
sign smo-onboarding-ca "/O=${ORG}/OU=SMO/CN=SMO Onboarding CA (simulated)" v3_intermediate "$INTERMEDIATE_CA_DAYS" smo-root-ca P-384

echo "==> RIC intermediate CA"
sign ric-intermediate-ca "/O=${ORG}/OU=Near-RT RIC/CN=RIC Intermediate CA" v3_intermediate "$INTERMEDIATE_CA_DAYS" smo-root-ca P-384

svc_sans() { # svc_sans <service> -> SAN list for an in-cluster Service
  local s=$1 ns=$RICSEC_NAMESPACE
  echo "DNS:${s}.${ns}.svc.${CLUSTER_DOMAIN},DNS:${s}.${ns}.svc,DNS:${s}.${ns},DNS:${s},DNS:localhost,IP:127.0.0.1"
}

echo "==> Keycloak server certificate"
export SAN; SAN=$(svc_sans "$KEYCLOAK_SERVICE")
sign keycloak-server "/O=${ORG}/OU=XRF/CN=${KEYCLOAK_SERVICE}.${RICSEC_NAMESPACE}.svc.${CLUSTER_DOMAIN}" v3_server "$SERVER_CERT_DAYS" ric-intermediate-ca P-256

echo "==> RIC CA enrollment service server certificate"
SAN=$(svc_sans "$RIC_CA_SERVICE")
sign ric-ca-server "/O=${ORG}/OU=RIC CA/CN=${RIC_CA_SERVICE}.${RICSEC_NAMESPACE}.svc.${CLUSTER_DOMAIN}" v3_server "$SERVER_CERT_DAYS" ric-intermediate-ca P-256

# Chains: servers present leaf+intermediate; relying parties trust the RIC intermediate.
cat "$OUT/keycloak-server.crt" "$OUT/ric-intermediate-ca.crt" > "$OUT/keycloak-server-chain.crt"
cat "$OUT/ric-ca-server.crt" "$OUT/ric-intermediate-ca.crt" > "$OUT/ric-ca-server-chain.crt"
cat "$OUT/ric-intermediate-ca.crt" "$OUT/smo-root-ca.crt" > "$OUT/ric-ca-bundle.crt"
rm -f "$OUT"/*.srl

echo "==> Verifying chains"
openssl verify -CAfile "$OUT/smo-root-ca.crt" "$OUT/ric-intermediate-ca.crt" "$OUT/smo-onboarding-ca.crt"
openssl verify -CAfile "$OUT/smo-root-ca.crt" -untrusted "$OUT/ric-intermediate-ca.crt" "$OUT/keycloak-server.crt" "$OUT/ric-ca-server.crt"
fi

# Post-quantum branch: ML-DSA root, onboarding CA, RIC intermediate CA and server
# certificates. OpenSSL 1.1.1 on this VM predates ML-DSA, so crypto/x509 does it.
echo "==> Post-quantum branch (ML-DSA, crypto/x509)"
"${PKI_GEN:-out/bin/pki-gen}" -out "$OUT" -org "$ORG" -cluster-domain "$CLUSTER_DOMAIN"   -root-alg "${PQ_ROOT_ALG:-ML-DSA-87}" -ca-alg "${PQ_CA_ALG:-ML-DSA-65}" -server-alg "${PQ_SERVER_ALG:-ML-DSA-65}"   -service "${RIC_CA_SERVICE}:${RICSEC_NAMESPACE}" -service "${PQ_SHIM_SERVICE:-pq-shim}:${RICSEC_NAMESPACE}"
