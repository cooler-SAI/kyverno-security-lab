<#
.SYNOPSIS
    Kyverno Security Lab - Automated Test Script (PowerShell)

.DESCRIPTION
    Automates local cluster provisioning with Kind, Kyverno installation via Helm,
    policy deployment, and admission enforcement verification (positive & negative tests).

.PARAMETER Action
    Action to perform: 'all' (default), 'up', 'test', or 'down'.

.EXAMPLE
    .\run-lab.ps1
    .\run-lab.ps1 -Action up
    .\run-lab.ps1 -Action test
    .\run-lab.ps1 -Action down
#>

[CmdletBinding()]
param (
    [ValidateSet('all', 'up', 'test', 'down')]
    [string]$Action = 'all'
)

$ErrorActionPreference = 'Stop'

$ClusterName = "kyverno-lab"
$PolicyFile  = "require-limits.yaml"
$BadPod      = "bad-pod.yaml"
$GoodPod     = "good-pod.yaml"
$KindConfig  = "kind-config.yaml"

function Write-Info($msg) {
    Write-Host "[INFO] $msg" -ForegroundColor Cyan
}

function Write-Success($msg) {
    Write-Host "[SUCCESS] $msg" -ForegroundColor Green
}

function Write-Warning($msg) {
    Write-Host "[WARN] $msg" -ForegroundColor Yellow
}

function Write-Err($msg) {
    Write-Host "[ERROR] $msg" -ForegroundColor Red
}

function Write-Header($msg) {
    Write-Host "`n=== $msg ===`n" -ForegroundColor White -NoNewline
    Write-Host ""
}

function Assert-Prerequisites {
    Write-Header "Checking Prerequisites"
    $tools = @("docker", "kind", "kubectl", "helm")
    $missing = @()

    foreach ($tool in $tools) {
        $path = Get-Command -Name $tool -ErrorAction SilentlyContinue
        if ($null -eq $path) {
            $missing += $tool
        } else {
            Write-Info "Found $tool : $($path.Source)"
        }
    }

    if ($missing.Count -gt 0) {
        Write-Err "Missing required tools: $($missing -join ', ')"
        throw "Please install the missing tools and try again."
    }

    & docker info 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Docker engine is not running. Please start Docker and retry."
        throw "Docker engine not reachable."
    }
    Write-Success "All prerequisites are satisfied."
}

function Start-ClusterUp {
    Write-Header "1. Provisioning Kind Cluster ($ClusterName)"
    $existingClusters = & kind get clusters 2>$null
    if ($existingClusters -contains $ClusterName) {
        Write-Info "Kind cluster '$ClusterName' already exists. Switching context..."
        & kubectl config use-context "kind-$ClusterName"
    } else {
        Write-Info "Creating Kind cluster using $KindConfig..."
        & kind create cluster --config $KindConfig --name $ClusterName
        if ($LASTEXITCODE -ne 0) { throw "Failed to create Kind cluster." }
    }
    Write-Success "Cluster '$ClusterName' is ready."

    Write-Header "2. Installing Kyverno via Helm"
    & helm repo add kyverno https://kyverno.github.io/kyverno/ --force-update 2>&1 | Out-Null
    & helm repo update kyverno | Out-Null

    Write-Info "Installing/Upgrading Kyverno Helm chart..."
    & helm upgrade --install kyverno kyverno/kyverno `
        --namespace kyverno `
        --create-namespace
    if ($LASTEXITCODE -ne 0) { throw "Helm install of Kyverno failed." }

    Write-Info "Waiting for Kyverno controller pods to become ready (up to 180s)..."
    & kubectl wait --namespace kyverno `
        --for=condition=ready pod `
        --selector=app.kubernetes.io/part-of=kyverno `
        --timeout=180s
    if ($LASTEXITCODE -ne 0) { throw "Kyverno pods did not become ready in time." }
    Write-Success "Kyverno controllers are running and ready."

    Write-Header "3. Deploying Kyverno ClusterPolicy"
    & kubectl apply -f $PolicyFile
    Start-Sleep -Seconds 3
    & kubectl get clusterpolicy
    Write-Success "Security policy '$PolicyFile' applied successfully."
}

function Invoke-PolicyTests {
    Write-Header "4. Running Policy Enforcement Tests"

    Write-Info "Switching context to kind-$ClusterName..."
    & kubectl config use-context "kind-$ClusterName"

    # Negative Test
    Write-Host "`n--- Negative Test: Pod Without Limits (Should be Rejected) ---" -ForegroundColor Yellow
    Write-Info "Applying $BadPod..."
    $badOutput = & kubectl apply -f $BadPod 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Err "Test Failed! Non-compliant pod was accepted, but should have been blocked."
        throw "Negative test failed."
    } else {
        Write-Host ($badOutput | Out-String) -ForegroundColor DarkGray
        Write-Success "Negative test passed! Kyverno admission webhook successfully blocked the non-compliant pod."
    }

    # Positive Test
    Write-Host "`n--- Positive Test: Compliant Pod With Limits (Should be Accepted) ---" -ForegroundColor Yellow
    Write-Info "Cleaning up previous test-pod-good if exists..."
    & kubectl delete pod test-pod-good --ignore-not-found 2>&1 | Out-Null

    Write-Info "Applying $GoodPod..."
    $goodOutput = & kubectl apply -f $GoodPod 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Test Failed! Compliant pod was unexpectedly blocked."
        throw "Positive test failed: $goodOutput"
    } else {
        Write-Success "Positive test passed! Compliant pod was accepted."
        Write-Info "Waiting for test-pod-good to be Ready (up to 60s)..."
        & kubectl wait --for=condition=ready pod/test-pod-good --timeout=60s
        Write-Host ""
        & kubectl get pod test-pod-good
        Write-Info "Container resource limits verified:"
        & kubectl get pod test-pod-good -o jsonpath='{.spec.containers[*].resources}'
        Write-Host ""
    }

    Write-Success "All tests completed successfully!"
}

function Stop-ClusterDown {
    Write-Header "Cleaning up and Tearing Down Cluster"
    Write-Info "Deleting test pod..."
    & kubectl delete pod test-pod-good --ignore-not-found 2>&1 | Out-Null

    Write-Info "Deleting Kyverno cluster policy..."
    & kubectl delete -f $PolicyFile --ignore-not-found 2>&1 | Out-Null

    Write-Info "Deleting Kind cluster '$ClusterName'..."
    & kind delete cluster --name $ClusterName
    Write-Success "Cleanup completed."
}

# Execution Dispatcher
switch ($Action) {
    'up' {
        Assert-Prerequisites
        Start-ClusterUp
    }
    'test' {
        Invoke-PolicyTests
    }
    'down' {
        Stop-ClusterDown
    }
    'all' {
        Assert-Prerequisites
        Start-ClusterUp
        Invoke-PolicyTests
        Write-Host "`n======================================================" -ForegroundColor Green
        Write-Host " Kyverno Security Lab Walkthrough Finished Successfully! " -ForegroundColor Green
        Write-Host " Run '.\run-lab.ps1 -Action down' when ready to tear down. " -ForegroundColor Green
        Write-Host "======================================================`n" -ForegroundColor Green
    }
}
