#!/usr/bin/env bash
# Onboards the two sidecar demo xApps the way an operator would: render the
# descriptors, hand them to dms_cli, then install the resulting Helm charts.
#
# Nothing here mentions the sidecar. The descriptors carry annotations; Kyverno turns
# those into a container at admission time.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

: "${XAPP_NAMESPACE:?}" "${SIDECAR_C_XAPP:?}" "${SIDECAR_D_XAPP:?}" "${CHART_REPO_URL:?}"
export CHART_REPO_URL

out=out/rendered/xapps
mkdir -p "$out"
build/render.sh xapps/schema.json > "$out/schema.json"

onboard() {
  local xapp=$1 src=$2
  build/render.sh "$src" > "$out/$xapp-config.json"
  python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$out/$xapp-config.json"
  echo "== onboarding $xapp"
  # The flag really is spelled shcema_file_path in xapp_onboarder.
  dms_cli onboard --config_file_path="$ROOT/$out/$xapp-config.json" --shcema_file_path="$ROOT/$out/schema.json"
}

install() {
  local xapp=$1
  if helm status -n "$XAPP_NAMESPACE" "$xapp" >/dev/null 2>&1; then
    echo "== removing the previous $xapp release"
    dms_cli uninstall --xapp_chart_name="$xapp" --namespace="$XAPP_NAMESPACE" || true
    # The bootstrap credential is one-time, so the old pod must be gone before the new
    # one starts; a second enrollment with the same credential is refused, by design.
    kubectl -n "$XAPP_NAMESPACE" wait --for=delete pod \
      -l "app=$XAPP_NAMESPACE-$xapp" --timeout=120s >/dev/null 2>&1 || true
  fi
  echo "== installing $xapp into $XAPP_NAMESPACE"
  dms_cli install --xapp_chart_name="$xapp" --version=1.0.0 --namespace="$XAPP_NAMESPACE"
}

onboard "$SIDECAR_C_XAPP" xapps/xappc-config.json
onboard "$SIDECAR_D_XAPP" xapps/xappd-config.json

install "$SIDECAR_C_XAPP"
install "$SIDECAR_D_XAPP"

echo
echo "onboarded xApps:"
kubectl -n "$XAPP_NAMESPACE" get pods -l 'pq.oran/sidecar' -o wide
