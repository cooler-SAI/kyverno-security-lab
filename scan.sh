#!/usr/bin/env bash
# ==============================================================================
# Local DevSecOps Scanner - Kyverno CLI & Trivy IaC / Vulnerability Scans
# ==============================================================================
# Usage:
#   ./scan.sh               # Runs Kyverno unit tests, Trivy IaC and image scans
#   ./scan.sh --skip-image  # Skips container image scan
# ==============================================================================

set -euo pipefail

SKIP_IMAGE=false
if [[ "${1:-}" == "--skip-image" ]]; then
  SKIP_IMAGE=true
fi

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

header "Kyverno Security Lab - Local DevSecOps Scan"

# 1. Kyverno CLI Policy Unit Tests
header "1. Kyverno CLI Offline Policy Unit Tests"
if ! command -v kyverno &>/dev/null; then
  warn "Kyverno CLI is not installed. To install:"
  echo "  brew install kyverno # macOS / Linuxbrew"
  echo "  or visit: https://kyverno.io/docs/kyverno-cli/"
else
  info "Executing: kyverno test ."
  if kyverno test .; then
    success "All Kyverno policy unit tests passed successfully!"
  else
    error "Kyverno policy unit test failure detected."
  fi
fi

# 2. Trivy IaC Configuration Scan
header "2. Trivy IaC & Manifest Security Scan"
if ! command -v trivy &>/dev/null; then
  warn "Trivy is not installed. To install:"
  echo "  brew install trivy # macOS / Linuxbrew"
  echo "  or visit: https://aquasecurity.github.io/trivy/"
else
  info "Scanning repository manifests for security misconfigurations..."
  trivy config . --severity HIGH,CRITICAL --exit-code 0
  success "Trivy IaC scan completed."

  # 3. Trivy Container Image Scan
  if [ "$SKIP_IMAGE" = false ]; then
    header "3. Trivy Container Image Vulnerability Scan"
    TEST_IMAGE="nginxinc/nginx-unprivileged:alpine"
    info "Scanning compliant workload image: ${TEST_IMAGE}"
    trivy image --severity HIGH,CRITICAL "${TEST_IMAGE}"
    success "Trivy container image scan completed."
  fi
fi

echo -e "\n${GREEN}${BOLD}======================================================${NC}"
echo -e "${GREEN}${BOLD} Local DevSecOps Scan Completed! ${NC}"
echo -e "${GREEN}${BOLD}======================================================${NC}\n"
