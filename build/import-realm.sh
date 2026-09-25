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
