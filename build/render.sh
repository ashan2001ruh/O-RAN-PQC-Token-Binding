#!/usr/bin/env bash
# render.sh <template>
# Substitutes only the variables defined in config/testbed.env plus the derived
# URLs exported by the Makefile, leaving every other '$' in the template untouched.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
vars=$(sed -n 's/^\([A-Z_][A-Z0-9_]*\)=.*/${\1}/p' "$ROOT/config/testbed.env" | tr '\n' ' ')
vars+=' ${KEYCLOAK_HOST} ${KEYCLOAK_URL} ${TOKEN_ISSUER} ${RIC_CA_HOST} ${RIC_CA_URL} ${PQ_SHIM_HOST} ${PQ_SHIM_URL} ${RESOURCE_TOKEN_ISSUER} ${RESOURCE_JWKS_URL} ${RESOURCE_INTROSPECTION_URL}'
envsubst "$vars" < "$1"
