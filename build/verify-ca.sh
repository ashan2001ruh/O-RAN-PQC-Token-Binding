#!/usr/bin/env bash
# Milestone 1 check: the RIC CA issues a leaf on demand, the chain verifies with
# openssl, lifetime is a parameter, and a bootstrap credential works exactly once.
set -euo pipefail
: "${RIC_CA_URL:?run via make verify-ca}"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
PKI=out/pki
HOSTPORT=${RIC_CA_URL#https://}
RESOLVE=$(tr ',' '\n' <<<"$DIAL_OVERRIDES" | awk -F= -v hp="$HOSTPORT" '$1==hp {split($2,a,":"); print hp":"a[1]}')
[[ -n "$RESOLVE" ]] || { echo "no ClusterIP for $HOSTPORT in DIAL_OVERRIDES"; exit 1; }

enroll() { # enroll <cred-dir> <lifetime> <out-cert> -> prints HTTP status
  curl -sS --tlsv1.3 --resolve "$RESOLVE" --cacert "$RIC_TRUST_BUNDLE" \
    --cert "$1/tls.crt" --key "$1/tls.key" \
    -H 'Content-Type: application/pkcs10' --data-binary @"$WORK/req.csr" \
    -o "$3" -w '%{http_code}' "$RIC_CA_URL/v1/enroll?lifetime=$2"
}

echo "==> SMO onboarding: bootstrap credential for identity 'ca-smoke-test'"
out/bin/smo-sim -cn ca-smoke-test -validity 10m -out "$WORK/boot" -org "$ORG" \
  -ca-cert "$SMO_ONBOARDING_CERT" -ca-key "$SMO_ONBOARDING_KEY"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/leaf.key" 2>/dev/null
openssl req -new -key "$WORK/leaf.key" -subj "/CN=ignored-by-ca" -out "$WORK/req.csr"

echo "==> Enroll with bootstrap credential (lifetime=$EPHEMERAL_CERT_LIFETIME)"
code=$(enroll "$WORK/boot" "$EPHEMERAL_CERT_LIFETIME" "$WORK/leaf.pem")
[[ "$code" == 200 ]] || { echo "FAIL: enroll returned $code: $(cat "$WORK/leaf.pem")"; exit 1; }
openssl x509 -in "$WORK/leaf.pem" -noout -subject -issuer -serial -startdate -enddate -ext subjectAltName,extendedKeyUsage 2>/dev/null \
  || openssl x509 -in "$WORK/leaf.pem" -noout -subject -issuer -serial -startdate -enddate

echo "==> openssl verify (trust anchor: SMO root, untrusted intermediate: RIC CA)"
openssl verify -CAfile "$SMO_ROOT_CERT" -untrusted "$PKI/ric-intermediate-ca.crt" -purpose sslclient "$WORK/leaf.pem"

echo "==> Reusing the same bootstrap credential must be rejected"
code=$(enroll "$WORK/boot" "$EPHEMERAL_CERT_LIFETIME" "$WORK/reuse.json")
echo "HTTP $code $(cat "$WORK/reuse.json")"
[[ "$code" == 403 ]] || { echo "FAIL: bootstrap reuse was not rejected"; exit 1; }

echo "==> Long-term lifetime from the same code path via /v1/renew (authenticated by the new operational cert)"
cat "$WORK/leaf.pem" > "$WORK/op.crt"; cp "$WORK/leaf.key" "$WORK/op.key"
mkdir -p "$WORK/op" && cp "$WORK/op.crt" "$WORK/op/tls.crt" && cp "$WORK/op.key" "$WORK/op/tls.key"
code=$(curl -sS --tlsv1.3 --resolve "$RESOLVE" --cacert "$RIC_TRUST_BUNDLE" --cert "$WORK/op/tls.crt" --key "$WORK/op/tls.key" \
  -H 'Content-Type: application/pkcs10' --data-binary @"$WORK/req.csr" -o "$WORK/long.pem" -w '%{http_code}' \
  "$RIC_CA_URL/v1/renew?lifetime=$LONGTERM_CERT_LIFETIME")
[[ "$code" == 200 ]] || { echo "FAIL: renew returned $code: $(cat "$WORK/long.pem")"; exit 1; }
openssl x509 -in "$WORK/long.pem" -noout -subject -startdate -enddate
openssl verify -CAfile "$SMO_ROOT_CERT" -untrusted "$PKI/ric-intermediate-ca.crt" "$WORK/long.pem"
echo "MILESTONE 1 PASSED"
