#!/usr/bin/env bash
# ==============================================================================
# Kyverno Security Lab - Automated Test Script (Bash)
# ==============================================================================
# Usage:
#   ./run-lab.sh          # Runs the full lab end-to-end (cluster, kyverno, tests)
#   ./run-lab.sh up       # Provisions the cluster and deploys Kyverno + Policies
#   ./run-lab.sh test     # Runs negative & positive tests against the cluster
#   ./run-lab.sh down     # Tears down the cluster and cleans up resources
# ==============================================================================

set -euo pipefail

CLUSTER_NAME="kyverno-lab"
LIMITS_POLICY="require-limits.yaml"
PRIV_POLICY="restrict-privilege.yaml"
ROOT_POLICY="restrict-root-user.yaml"
BAD_POD="bad-pod.yaml"
BAD_PRIV_POD="bad-pod-priv.yaml"
BAD_ROOT_POD="bad-pod-root.yaml"
GOOD_POD="good-pod.yaml"
KIND_CONFIG="kind-config.yaml"

# Styling / Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; }
header()  { echo -e "\n${BOLD}=== $* ===${NC}\n"; }

check_prerequisites() {
  header "Checking Prerequisites"
  local missing=()
  for cmd in docker kind kubectl helm; do
    if ! command -v "$cmd" &>/dev/null; then
      missing+=("$cmd")
    else
      info "Found $cmd: $(command -v "$cmd")"
    fi
  done

  if [ ${#missing[@]} -gt 0 ]; then
    error "Missing required tools: ${missing[*]}"
    echo "Please install the missing tools and try again."
    exit 1
  fi

  if ! docker info &>/dev/null; then
    error "Docker daemon is not running. Please start Docker and retry."
    exit 1
  fi
  success "All prerequisites are satisfied."
}

cluster_up() {
  header "1. Provisioning Kind Cluster (${CLUSTER_NAME})"
  if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    info "Kind cluster '${CLUSTER_NAME}' already exists. Switching context..."
    kubectl config use-context "kind-${CLUSTER_NAME}"
  else
    info "Creating Kind cluster using ${KIND_CONFIG}..."
    kind create cluster --config "${KIND_CONFIG}" --name "${CLUSTER_NAME}"
  fi
  success "Cluster '${CLUSTER_NAME}' is ready."

  header "2. Installing Kyverno via Helm"
  helm repo add kyverno https://kyverno.github.io/kyverno/ --force-update >/dev/null 2>&1 || true
  helm repo update kyverno

  info "Installing/Upgrading Kyverno Helm chart..."
  helm upgrade --install kyverno kyverno/kyverno \
    --namespace kyverno \
    --create-namespace

  info "Waiting for Kyverno controller pods to become ready (up to 180s)..."
  kubectl wait --namespace kyverno \
    --for=condition=ready pod \
    --selector=app.kubernetes.io/part-of=kyverno \
    --timeout=180s
  success "Kyverno controllers are running and ready."

  header "3. Deploying Kyverno ClusterPolicies"
  info "Applying limits policy '${LIMITS_POLICY}'..."
  kubectl apply -f "${LIMITS_POLICY}"
  info "Applying privilege restriction policy '${PRIV_POLICY}'..."
  kubectl apply -f "${PRIV_POLICY}"
  info "Applying root user restriction policy '${ROOT_POLICY}'..."
  kubectl apply -f "${ROOT_POLICY}"
  info "Waiting for policies ready state..."
  sleep 3
  kubectl get clusterpolicy
  success "Security policies applied successfully."
}

run_tests() {
  header "4. Running Policy Enforcement Tests"

  info "Ensuring context is set to kind-${CLUSTER_NAME}..."
  kubectl config use-context "kind-${CLUSTER_NAME}"

  # Negative Test 1: Missing Limits
  echo -e "\n${BOLD}--- Negative Test 1: Pod Without Limits (Should be Rejected) ---${NC}"
  info "Applying ${BAD_POD}..."
  if kubectl apply -f "${BAD_POD}" 2>&1 | tee /tmp/bad-pod-output.txt; then
    error "Test Failed! Non-compliant pod was accepted, but should have been blocked."
    exit 1
  else
    success "Negative test 1 passed! Kyverno admission webhook successfully blocked pod missing limits."
  fi

  # Negative Test 2: Privileged Container Request
  echo -e "\n${BOLD}--- Negative Test 2: Privileged Container (Should be Rejected) ---${NC}"
  info "Applying ${BAD_PRIV_POD}..."
  if kubectl apply -f "${BAD_PRIV_POD}" 2>&1 | tee /tmp/bad-pod-priv-output.txt; then
    error "Test Failed! Privileged pod was accepted, but should have been blocked."
    exit 1
  else
    success "Negative test 2 passed! Kyverno admission webhook successfully blocked privileged container."
  fi

  # Negative Test 3: Running as Root User
  echo -e "\n${BOLD}--- Negative Test 3: Root User Container (Should be Rejected) ---${NC}"
  info "Applying ${BAD_ROOT_POD}..."
  if kubectl apply -f "${BAD_ROOT_POD}" 2>&1 | tee /tmp/bad-pod-root-output.txt; then
    error "Test Failed! Pod running as root was accepted, but should have been blocked."
    exit 1
  else
    success "Negative test 3 passed! Kyverno admission webhook successfully blocked container running as root."
  fi

  # Positive Test: Compliant Pod
  echo -e "\n${BOLD}--- Positive Test: Compliant Pod (Should be Accepted) ---${NC}"
  info "Cleaning up previous good-pod if any..."
  kubectl delete pod test-pod-good --ignore-not-found >/dev/null 2>&1 || true

  info "Applying ${GOOD_POD}..."
  if kubectl apply -f "${GOOD_POD}"; then
    success "Positive test passed! Compliant pod was accepted."
    info "Waiting for test-pod-good to be Ready (up to 60s)..."
    kubectl wait --for=condition=ready pod/test-pod-good --timeout=60s || true
    echo ""
    kubectl get pod test-pod-good
    info "Container resource limits verified:"
    kubectl get pod test-pod-good -o jsonpath='{.spec.containers[*].resources}' | echo ""
  else
    error "Test Failed! Compliant pod was unexpectedly blocked."
    exit 1
  fi

  echo ""
  success "All tests completed successfully!"
}

cluster_down() {
  header "Cleaning up and Tearing Down Cluster"
  info "Deleting test pods..."
  kubectl delete pod test-pod-good test-pod-bad test-pod-hacker-priv test-pod-bad-root --ignore-not-found 2>/dev/null || true

  info "Deleting Kyverno cluster policies..."
  kubectl delete -f "${LIMITS_POLICY}" --ignore-not-found 2>/dev/null || true
  kubectl delete -f "${PRIV_POLICY}" --ignore-not-found 2>/dev/null || true
  kubectl delete -f "${ROOT_POLICY}" --ignore-not-found 2>/dev/null || true

  info "Deleting Kind cluster '${CLUSTER_NAME}'..."
  kind delete cluster --name "${CLUSTER_NAME}"
  success "Cleanup completed."
}

# Main Dispatcher
ACTION="${1:-all}"

case "$ACTION" in
  up)
    check_prerequisites
    cluster_up
    ;;
  test)
    run_tests
    ;;
  down)
    cluster_down
    ;;
  all)
    check_prerequisites
    cluster_up
    run_tests
    echo -e "\n${GREEN}${BOLD}======================================================${NC}"
    echo -e "${GREEN}${BOLD} Kyverno Security Lab Walkthrough Finished Successfully! ${NC}"
    echo -e "${GREEN}${BOLD} Run './run-lab.sh down' when you are ready to tear down. ${NC}"
    echo -e "${GREEN}${BOLD}======================================================${NC}"
    ;;
  *)
    echo "Usage: $0 {all|up|test|down}"
    exit 1
    ;;
esac
