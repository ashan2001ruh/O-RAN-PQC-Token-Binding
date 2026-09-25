#!/usr/bin/env bash
# Milestone 2 check (automated, mandatory): a token requested over mTLS by
# xapp-longterm must carry cnf.x5t#S256 equal to the SHA-256 thumbprint of the
# certificate presented. Keycloak issues a token even when the certificate never
# reaches it, so the absence of cnf is treated as a failure, not a warning.
set -euo pipefail
: "${KEYCLOAK_TOKEN_URL:?run via make verify-keycloak}"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

resolve_for() { # resolve_for <https-url> -> host:port:ip for curl --resolve
  local hp=${1#https://}; hp=${hp%%/*}
  tr ',' '\n' <<<"$DIAL_OVERRIDES" | awk -F= -v hp="$hp" '$1==hp {split($2,a,":"); print hp":"a[1]}'
}
KC_RESOLVE=$(resolve_for "$KEYCLOAK_TOKEN_URL")
CA_RESOLVE=$(resolve_for "$RIC_CA_URL")
CLIENT=${LONGTERM_CLIENT_ID}

b64url_json() { # decode JWT segment
  local s=${1//-/+}; s=${s//_//}
  while (( ${#s} % 4 )); do s+="="; done
  base64 -d <<<"$s"
}
thumbprint() { openssl x509 -in "$1" -outform der | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '='; }

echo "==> Onboard and enroll '$CLIENT' (bootstrap -> RIC CA operational certificate)"
out/bin/smo-sim -cn "$CLIENT" -validity 10m -out "$WORK/boot" -org "$ORG" -ca-cert "$SMO_ONBOARDING_CERT" -ca-key "$SMO_ONBOARDING_KEY" >/dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/op.key" 2>/dev/null
openssl req -new -key "$WORK/op.key" -subj "/CN=$CLIENT" -out "$WORK/op.csr"
code=$(curl -sS --tlsv1.3 --resolve "$CA_RESOLVE" --cacert "$RIC_TRUST_BUNDLE" --cert "$WORK/boot/tls.crt" --key "$WORK/boot/tls.key" \
  --data-binary @"$WORK/op.csr" -o "$WORK/op.crt" -w '%{http_code}' "$RIC_CA_URL/v1/enroll?lifetime=$LONGTERM_CERT_LIFETIME")
[[ "$code" == 200 ]] || { echo "FAIL: enrollment $code $(cat "$WORK/op.crt")"; exit 1; }
openssl x509 -in "$WORK/op.crt" -noout -subject

token_request() { # token_request <curl-cert-args...> -> writes $WORK/resp.json, prints status (000 = TLS failure)
  rm -f "$WORK/resp.json"
  curl -sS --tlsv1.3 --resolve "$KC_RESOLVE" --cacert "$RIC_TRUST_BUNDLE" "$@" \
    -d grant_type=client_credentials -d client_id="$CLIENT" -d scope="$TOKEN_SCOPE" \
    -o "$WORK/resp.json" -w '%{http_code}' "$KEYCLOAK_TOKEN_URL" 2>"$WORK/curl.err" || true
}

echo "==> Token request over mTLS with the operational certificate"
code=$(token_request --cert "$WORK/op.crt" --key "$WORK/op.key")
[[ "$code" == 200 ]] || { echo "FAIL: token endpoint returned $code: $(cat "$WORK/resp.json")"; exit 1; }
TOKEN=$(jq -r .access_token "$WORK/resp.json")
PAYLOAD=$(b64url_json "$(cut -d. -f2 <<<"$TOKEN")")
echo "token_type=$(jq -r .token_type "$WORK/resp.json") bytes=${#TOKEN}"
jq '{iss, aud, azp, client_id, scope, realm_access, exp, cnf}' <<<"$PAYLOAD"

CNF=$(jq -r '.cnf["x5t#S256"] // empty' <<<"$PAYLOAD")
EXPECTED=$(thumbprint "$WORK/op.crt")
if [[ -z "$CNF" ]]; then
  echo "FAIL: cnf.x5t#S256 absent - the client certificate did not reach Keycloak (token was issued anyway)"
  exit 1
fi
[[ "$CNF" == "$EXPECTED" ]] || { echo "FAIL: cnf.x5t#S256=$CNF but certificate thumbprint=$EXPECTED"; exit 1; }
echo "OK: cnf.x5t#S256 == SHA-256 thumbprint of presented certificate ($EXPECTED)"

echo "==> Token request without a client certificate must not yield a token"
code=$(token_request)
echo "HTTP $code $(cat "$WORK/resp.json" 2>/dev/null)"
[[ "$code" != 200 ]] || { echo "FAIL: token issued without client certificate"; exit 1; }

echo "==> Token request with a certificate from an untrusted CA (SMO bootstrap credential) must not yield a token"
code=$(token_request --cert "$WORK/boot/tls.crt" --key "$WORK/boot/tls.key")
echo "HTTP $code $(cat "$WORK/resp.json" 2>/dev/null) $(cat "$WORK/curl.err")"
[[ "$code" != 200 ]] || { echo "FAIL: token issued for a certificate outside the RIC trust anchor"; exit 1; }
echo "MILESTONE 2 PASSED"
