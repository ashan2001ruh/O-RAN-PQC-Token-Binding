#!/usr/bin/env bash
# Installs the Kyverno admission controller, which is what injects the sidecar.
#
# Only the admission controller is installed: this testbed uses one mutation rule on
# pod creation and none of the background, reports or cleanup controllers, and the
# lab node has little memory to spare.
set -euo pipefail
CHART_VERSION=${KYVERNO_CHART_VERSION:-3.3.9}

if kubectl get deploy -n kyverno kyverno-admission-controller >/dev/null 2>&1; then
  echo "kyverno already installed:"
  kubectl -n kyverno get deploy kyverno-admission-controller
  exit 0
fi

helm repo add kyverno https://kyverno.github.io/kyverno/ >/dev/null
helm repo update kyverno >/dev/null
helm install kyverno kyverno/kyverno \
  --version "$CHART_VERSION" \
  --namespace kyverno --create-namespace \
  --set admissionController.replicas=1 \
  --set admissionController.container.resources.requests.cpu=100m \
  --set admissionController.container.resources.requests.memory=128Mi \
  --set admissionController.container.resources.limits.memory=384Mi \
  --set backgroundController.enabled=false \
  --set reportsController.enabled=false \
  --set cleanupController.enabled=false \
  --set crds.migration.enabled=false \
  --timeout 10m --wait

kubectl -n kyverno get pods
