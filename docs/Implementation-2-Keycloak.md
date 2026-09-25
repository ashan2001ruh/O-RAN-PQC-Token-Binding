# Implementation Part 2: Keycloak as the Authorization Server

Keycloak plays the **AS** (authorization server) role, called the XRF in the O-RAN wording. It
authenticates the xApp over mutual TLS using the certificate subject DN, applies the realm
authorization policy, and issues the access token carrying the binding.

What Keycloak does natively, with no custom code:

* authenticates the client with the `client-x509` authenticator and an exact subject DN match,
* adds `cnf.x5t#S256` when *OAuth 2.0 Mutual TLS Certificate Bound Access Tokens* is enabled,
* adds `cnf.jkt` when *Require DPoP bound tokens* is enabled.

What it does **not** do, and this project must: enforce the binding at the resource server
(Part 3), run the certificate authority (Part 1), and sign with a post-quantum algorithm
(Part 4).

## Files in this part

| File | Lines | Purpose |
|---|---|---|
| `keycloak/k8s/keycloak.yaml` | 99 | Deployment and Service. Note `--truststore-paths` (the RIC intermediate CA is the only mTLS trust anchor), `--https-protocols=TLSv1.3`, a fixed `--hostname` so the token issuer and DPoP `htu` are stable, and `--cache=local` for a single node. |
| `keycloak/ric-realm.json` | 175 | The realm export, rendered through `envsubst` so the DNs and names come from `config/testbed.env`. |
| `build/render.sh` | 9 | Restricted `envsubst` rendering. |
| `build/host-env.sh` | 70 | Writes `out/host.env`: dial overrides, endpoints, trust bundles, onboarding CA paths, algorithms. |
| `build/import-realm.sh` | 32 | Creates the realm through the admin REST API. This is used instead of `--import-realm` because a failed startup import stops the server without reporting the error. |
| `build/verify-keycloak.sh` | 69 | Onboards an identity, enrolls it, requests a token over mTLS, decodes the token and compares `cnf.x5t#S256` with the certificate thumbprint computed by OpenSSL. |

---

## 1. The Keycloak deployment

mTLS terminates in Keycloak itself, so the client certificate reaches the X.509 authenticator directly. `--https-client-auth=request` is deliberate: with `required`, a missing or untrusted certificate fails the TLS handshake and is hard to diagnose, while with `request` it surfaces as an OAuth error. The probe timeouts are generous because the JVM stalls under load on a small node and the 1 second default makes the kubelet kill a healthy Keycloak.

### `keycloak/k8s/keycloak.yaml`

Deployment and Service. Note `--truststore-paths` (the RIC intermediate CA is the only mTLS trust anchor), `--https-protocols=TLSv1.3`, a fixed `--hostname` so the token issuer and DPoP `htu` are stable, and `--cache=local` for a single node.

```yaml
# Keycloak acting as the XRF (OAuth 2.0 authorization server), rendered from config/testbed.env.
# mTLS terminates in Keycloak itself, so the client certificate reaches the X.509
# client authenticator and the certificate-bound token logic directly.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${KEYCLOAK_SERVICE}
  namespace: ${RICSEC_NAMESPACE}
  labels: {app: ${KEYCLOAK_SERVICE}, part-of: xapp-token-binding}
spec:
  replicas: 1
  strategy: {type: Recreate}
  selector:
    matchLabels: {app: ${KEYCLOAK_SERVICE}}
  template:
    metadata:
      labels: {app: ${KEYCLOAK_SERVICE}, part-of: xapp-token-binding}
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile: {type: RuntimeDefault}
      containers:
        - name: keycloak
          image: ${KEYCLOAK_IMAGE}
          imagePullPolicy: IfNotPresent
          args:
            - start
            # The realm is loaded by build/import-realm.sh through the admin REST API
            # (idempotent, and errors are reported instead of silently stopping the server).
            # mTLS: 'request' (not 'required') during development, so a missing or
            # untrusted certificate surfaces as a diagnosable OAuth error instead of a
            # failed handshake.
            - --https-client-auth=request
            - --truststore-paths=/etc/ric-trust/ric-intermediate-ca.crt
            - --https-protocols=TLSv1.3
            - --https-certificate-file=/etc/x509/https/tls.crt
            - --https-certificate-key-file=/etc/x509/https/tls.key
            - --https-port=${KEYCLOAK_PORT}
            - --http-enabled=false
            - --hostname=${KEYCLOAK_URL}
            - --health-enabled=true
            - --db=dev-file
            - --cache=local   # single-node testbed: no JGroups cluster
          env:
            - name: KC_BOOTSTRAP_ADMIN_USERNAME
              valueFrom: {secretKeyRef: {name: keycloak-admin, key: username}}
            - name: KC_BOOTSTRAP_ADMIN_PASSWORD
              valueFrom: {secretKeyRef: {name: keycloak-admin, key: password}}
            - {name: JAVA_OPTS_KC_HEAP, value: "${KEYCLOAK_HEAP}"}
          ports:
            - {name: https, containerPort: ${KEYCLOAK_PORT}}
            - {name: management, containerPort: 9000}
          volumeMounts:
            - {name: tls, mountPath: /etc/x509/https, readOnly: true}
            - {name: trust, mountPath: /etc/ric-trust, readOnly: true}
            - {name: data, mountPath: /opt/keycloak/data/h2}
          # Generous timeouts: on a small lab VM the JVM can stall for seconds under load,
          # and the 1s default makes the kubelet kill a healthy Keycloak.
          startupProbe:
            httpGet: {path: /health/ready, port: management, scheme: HTTPS}
            periodSeconds: 10
            timeoutSeconds: 10
            failureThreshold: 90
          readinessProbe:
            httpGet: {path: /health/ready, port: management, scheme: HTTPS}
            periodSeconds: 15
            timeoutSeconds: 10
            failureThreshold: 4
          livenessProbe:
            httpGet: {path: /health/live, port: management, scheme: HTTPS}
            periodSeconds: 30
            timeoutSeconds: 15
            failureThreshold: 10
          resources:
            requests: {cpu: 250m, memory: 600Mi}
            limits: {memory: 1Gi}
          securityContext:
            allowPrivilegeEscalation: false
            capabilities: {drop: [ALL]}
      volumes:
        - name: tls
          secret: {secretName: keycloak-tls}
        - name: trust
          configMap: {name: ric-trust}
        - name: data   # survives container restarts; `make restart-keycloak` re-imports on a new pod
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: ${KEYCLOAK_SERVICE}
  namespace: ${RICSEC_NAMESPACE}
  labels: {app: ${KEYCLOAK_SERVICE}, part-of: xapp-token-binding}
spec:
  selector: {app: ${KEYCLOAK_SERVICE}}
  ports:
    - {name: https, port: ${KEYCLOAK_PORT}, targetPort: https}
```

---

## 2. The realm

Four clients. The first two are **identical** except for their subject DN, which is the point of Methods A and B: the difference lives entirely in the client-side certificate lifetime, not in the authorization server. The fourth client exists only so the test suite can prove that a token with no `cnf` is rejected.

| Client | Binding attribute |
|---|---|
| `xapp-longterm` | `tls.client.certificate.bound.access.tokens=true` |
| `xapp-ephemeral` | identical to the above |
| `xapp-dpop` | `dpop.bound.access.tokens=true` |
| `xapp-unbound-probe` | both off (test only) |

The client scope `ric-sdl-access` adds the audience `ric-xapps`, the realm role and the subject, so the token carries a real authorization decision and not just a binding.

### `keycloak/ric-realm.json`

The realm export, rendered through `envsubst` so the DNs and names come from `config/testbed.env`.

```json
{
  "realm": "${KEYCLOAK_REALM}",
  "displayName": "O-RAN Near-RT RIC xApp Authorization (XRF)",
  "enabled": true,
  "sslRequired": "all",
  "accessTokenLifespan": ${ACCESS_TOKEN_LIFESPAN},
  "roles": {
    "realm": [
      {
        "name": "${REQUIRED_ROLE}",
        "description": "Permission to call the SDL-backed resource APIs exposed by xApps"
      }
    ]
  },
  "clientScopes": [
    {
      "name": "${TOKEN_SCOPE}",
      "description": "Access to xApp SDL resources; adds the resource audience and realm roles to access tokens",
      "protocol": "openid-connect",
      "attributes": {
        "include.in.token.scope": "true",
        "display.on.consent.screen": "false"
      },
      "protocolMappers": [
        {
          "name": "audience-${TOKEN_AUDIENCE}",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-audience-mapper",
          "consentRequired": false,
          "config": {
            "included.custom.audience": "${TOKEN_AUDIENCE}",
            "access.token.claim": "true",
            "introspection.token.claim": "true",
            "id.token.claim": "false"
          }
        },
        {
          "name": "realm-roles",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-usermodel-realm-role-mapper",
          "consentRequired": false,
          "config": {
            "claim.name": "realm_access.roles",
            "jsonType.label": "String",
            "multivalued": "true",
            "access.token.claim": "true",
            "introspection.token.claim": "true",
            "id.token.claim": "false",
            "userinfo.token.claim": "false"
          }
        },
        {
          "name": "subject",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-sub-mapper",
          "consentRequired": false,
          "config": {
            "access.token.claim": "true",
            "introspection.token.claim": "true"
          }
        },
        {
          "name": "client-id",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-usersessionmodel-note-mapper",
          "consentRequired": false,
          "config": {
            "user.session.note": "client_id",
            "claim.name": "client_id",
            "jsonType.label": "String",
            "access.token.claim": "true",
            "introspection.token.claim": "true",
            "id.token.claim": "false"
          }
        }
      ]
    }
  ],
  "clients": [
    {
      "clientId": "${XAPP_A_CLIENT_ID}",
      "name": "Method A - RFC 8705 certificate-bound, long-term identity key",
      "description": "Identical configuration to ${XAPP_B_CLIENT_ID}; only the certificate lifetime differs (client side).",
      "enabled": true,
      "protocol": "openid-connect",
      "publicClient": false,
      "standardFlowEnabled": false,
      "implicitFlowEnabled": false,
      "directAccessGrantsEnabled": false,
      "serviceAccountsEnabled": true,
      "clientAuthenticatorType": "client-x509",
      "fullScopeAllowed": true,
      "defaultClientScopes": ["${TOKEN_SCOPE}"],
      "optionalClientScopes": [],
      "attributes": {
        "x509.subjectdn": "CN=${XAPP_A_CLIENT_ID},OU=${XAPP_OU},O=${ORG}",
        "x509.allow.regex.pattern.comparison": "false",
        "tls.client.certificate.bound.access.tokens": "true",
        "dpop.bound.access.tokens": "false"
      }
    },
    {
      "clientId": "${XAPP_B_CLIENT_ID}",
      "name": "Method B - RFC 8705 certificate-bound, ephemeral identity key",
      "description": "Identical configuration to ${XAPP_A_CLIENT_ID}; only the certificate lifetime differs (client side).",
      "enabled": true,
      "protocol": "openid-connect",
      "publicClient": false,
      "standardFlowEnabled": false,
      "implicitFlowEnabled": false,
      "directAccessGrantsEnabled": false,
      "serviceAccountsEnabled": true,
      "clientAuthenticatorType": "client-x509",
      "fullScopeAllowed": true,
      "defaultClientScopes": ["${TOKEN_SCOPE}"],
      "optionalClientScopes": [],
      "attributes": {
        "x509.subjectdn": "CN=${XAPP_B_CLIENT_ID},OU=${XAPP_OU},O=${ORG}",
        "x509.allow.regex.pattern.comparison": "false",
        "tls.client.certificate.bound.access.tokens": "true",
        "dpop.bound.access.tokens": "false"
      }
    },
    {
      "clientId": "xapp-dpop",
      "name": "Method C - RFC 9449 DPoP-bound",
      "description": "Client authentication over mTLS; the access token is bound to the client's DPoP JWK (cnf.jkt).",
      "enabled": true,
      "protocol": "openid-connect",
      "publicClient": false,
      "standardFlowEnabled": false,
      "implicitFlowEnabled": false,
      "directAccessGrantsEnabled": false,
      "serviceAccountsEnabled": true,
      "clientAuthenticatorType": "client-x509",
      "fullScopeAllowed": true,
      "defaultClientScopes": ["${TOKEN_SCOPE}"],
      "optionalClientScopes": [],
      "attributes": {
        "x509.subjectdn": "CN=xapp-dpop,OU=${XAPP_OU},O=${ORG}",
        "x509.allow.regex.pattern.comparison": "false",
        "tls.client.certificate.bound.access.tokens": "false",
        "dpop.bound.access.tokens": "true"
      }
    },
    {
      "clientId": "xapp-unbound-probe",
      "name": "Test only - issues plain bearer tokens (no cnf)",
      "description": "Exists solely so the test suite can prove the resource validator rejects tokens without a confirmation claim.",
      "enabled": true,
      "protocol": "openid-connect",
      "publicClient": false,
      "standardFlowEnabled": false,
      "implicitFlowEnabled": false,
      "directAccessGrantsEnabled": false,
      "serviceAccountsEnabled": true,
      "clientAuthenticatorType": "client-x509",
      "fullScopeAllowed": true,
      "defaultClientScopes": ["${TOKEN_SCOPE}"],
      "optionalClientScopes": [],
      "attributes": {
        "x509.subjectdn": "CN=xapp-unbound-probe,OU=${XAPP_OU},O=${ORG}",
        "x509.allow.regex.pattern.comparison": "false",
        "tls.client.certificate.bound.access.tokens": "false",
        "dpop.bound.access.tokens": "false"
      }
    }
  ],
  "users": [
    {"username": "service-account-${XAPP_A_CLIENT_ID}", "enabled": true, "serviceAccountClientId": "${XAPP_A_CLIENT_ID}", "realmRoles": ["${REQUIRED_ROLE}"]},
    {"username": "service-account-${XAPP_B_CLIENT_ID}", "enabled": true, "serviceAccountClientId": "${XAPP_B_CLIENT_ID}", "realmRoles": ["${REQUIRED_ROLE}"]},
    {"username": "service-account-xapp-dpop", "enabled": true, "serviceAccountClientId": "xapp-dpop", "realmRoles": ["${REQUIRED_ROLE}"]},
    {"username": "service-account-xapp-unbound-probe", "enabled": true, "serviceAccountClientId": "xapp-unbound-probe", "realmRoles": ["${REQUIRED_ROLE}"]}
  ]
}
```

---

## 3. Rendering and environment helpers

Manifests and the realm are templates. `render.sh` substitutes only the variables defined in the configuration file, leaving every other `$` untouched. `host-env.sh` writes the environment used by tools that run on the node: it maps each Service to its ClusterIP so those tools can use in-cluster DNS names, keeping TLS server names and DPoP `htu` values identical to what the in-cluster xApps use.

### `build/render.sh`

Restricted `envsubst` rendering.

```bash
#!/usr/bin/env bash
# render.sh <template>
# Substitutes only the variables defined in config/testbed.env plus the derived
# URLs exported by the Makefile, leaving every other '$' in the template untouched.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
vars=$(sed -n 's/^\([A-Z_][A-Z0-9_]*\)=.*/${\1}/p' "$ROOT/config/testbed.env" | tr '\n' ' ')
vars+=' ${KEYCLOAK_HOST} ${KEYCLOAK_URL} ${TOKEN_ISSUER} ${RIC_CA_HOST} ${RIC_CA_URL} ${PQ_SHIM_HOST} ${PQ_SHIM_URL} ${RESOURCE_TOKEN_ISSUER} ${RESOURCE_JWKS_URL} ${RESOURCE_INTROSPECTION_URL}'
envsubst "$vars" < "$1"
```

### `build/host-env.sh`

Writes `out/host.env`: dial overrides, endpoints, trust bundles, onboarding CA paths, algorithms.

```bash
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
```

### `build/import-realm.sh`

Creates the realm through the admin REST API. This is used instead of `--import-realm` because a failed startup import stops the server without reporting the error.

```bash
#!/usr/bin/env bash
# import-realm.sh <rendered-realm.json>
# Creates (or, with REPLACE=1, recreates) the realm through the Keycloak admin REST API.
set -euo pipefail
REALM_FILE=${1:?usage: import-realm.sh <realm.json>}
: "${KEYCLOAK_URL:?}" "${KEYCLOAK_REALM:?}" "${DIAL_OVERRIDES:?run after host-env}"

HP=${KEYCLOAK_URL#https://}
RESOLVE=$(tr ',' '\n' <<<"$DIAL_OVERRIDES" | awk -F= -v hp="$HP" '$1==hp {split($2,a,":"); print hp":"a[1]}')
CURL=(curl -sS --tlsv1.3 --resolve "$RESOLVE" --cacert out/pki/ric-intermediate-ca.crt)
# password@file sends the file content byte-for-byte, exactly as the Secret was created from it
TOKEN=$("${CURL[@]}" -d grant_type=password -d client_id=admin-cli -d username=admin --data-urlencode "password@out/secrets/keycloak-admin-password" \
  "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" | jq -r .access_token)
[[ -n "$TOKEN" && "$TOKEN" != null ]] || { echo "could not obtain admin token"; exit 1; }
AUTH=(-H "Authorization: Bearer $TOKEN")

exists=$("${CURL[@]}" "${AUTH[@]}" -o /dev/null -w '%{http_code}' "$KEYCLOAK_URL/admin/realms/$KEYCLOAK_REALM")
if [[ "$exists" == 200 ]]; then
  if [[ "${REPLACE:-0}" != 1 ]]; then
    echo "realm $KEYCLOAK_REALM already exists (REPLACE=1 to recreate)"
    exit 0
  fi
  "${CURL[@]}" "${AUTH[@]}" -X DELETE "$KEYCLOAK_URL/admin/realms/$KEYCLOAK_REALM"
fi

code=$("${CURL[@]}" "${AUTH[@]}" -H 'Content-Type: application/json' --data-binary @"$REALM_FILE" \
  -o /tmp/import-realm.out -w '%{http_code}' "$KEYCLOAK_URL/admin/realms")
if [[ "$code" != 201 ]]; then
  echo "realm import failed: HTTP $code $(cat /tmp/import-realm.out)"
  exit 1
fi
echo "realm $KEYCLOAK_REALM imported"
```

---

## 4. Deploy and verify

```bash
make deploy-keycloak    # deploy, wait for rollout, then import the realm
make verify-keycloak    # the milestone check below
```

This check is mandatory rather than cosmetic: **Keycloak issues a token even when the client certificate never reaches it**, simply omitting `cnf`. Three things are asserted: the token carries `cnf.x5t#S256` equal to the thumbprint of the certificate presented, a request without a certificate yields no token, and a certificate from an untrusted CA yields no token.

### `build/verify-keycloak.sh`

Onboards an identity, enrolls it, requests a token over mTLS, decodes the token and compares `cnf.x5t#S256` with the certificate thumbprint computed by OpenSSL.

```bash
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
```

Expected output:

```
==> Token request over mTLS with the operational certificate
token_type=Bearer bytes=1017
{ "iss": "...", "aud": "ric-xapps", "azp": "xapp-longterm",
  "scope": "ric-sdl-access", "cnf": { "x5t#S256": "UF7_rLNMtPcd..." } }
OK: cnf.x5t#S256 == SHA-256 thumbprint of presented certificate
==> Token request without a client certificate must not yield a token
HTTP 401 {"error":"invalid_client"}
MILESTONE 2 PASSED
```

