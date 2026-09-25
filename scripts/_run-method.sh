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
