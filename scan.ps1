<#
.SYNOPSIS
    Local DevSecOps Scanner - Kyverno CLI & Trivy IaC/Vulnerability Scans

.DESCRIPTION
    Runs shift-left security evaluations locally before committing or deploying:
    1. Kyverno CLI Policy Unit Tests (kyverno test .)
    2. Trivy Configuration / IaC Scan (trivy config .)
    3. Trivy Container Image Scan (trivy image ...)

.EXAMPLE
    .\scan.ps1
    .\scan.ps1 -SkipImageScan
#>

[CmdletBinding()]
param (
    [switch]$SkipImageScan
)

$ErrorActionPreference = 'Stop'

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

Write-Header "Kyverno Security Lab - Local DevSecOps Scan"

# 1. Kyverno CLI Policy Test
Write-Header "1. Kyverno CLI Offline Policy Unit Tests"
$kyvernoCmd = Get-Command -Name "kyverno" -ErrorAction SilentlyContinue

if ($null -eq $kyvernoCmd) {
    Write-Warning "Kyverno CLI is not installed. To install:"
    Write-Host "  winget install Kyverno.kyverno" -ForegroundColor DarkGray
    Write-Host "  or visit: https://kyverno.io/docs/kyverno-cli/`n" -ForegroundColor DarkGray
} else {
    Write-Info "Executing: kyverno test ."
    & kyverno test .
    if ($LASTEXITCODE -eq 0) {
        Write-Success "All Kyverno policy unit tests passed successfully!"
    } else {
        Write-Err "Kyverno policy unit test failure detected."
    }
}

# 2. Trivy IaC Misconfiguration Scan
Write-Header "2. Trivy IaC & Manifest Security Scan"
$trivyCmd = Get-Command -Name "trivy" -ErrorAction SilentlyContinue

if ($null -eq $trivyCmd) {
    Write-Warning "Trivy is not installed. To install:"
    Write-Host "  winget install AquaSecurity.Trivy" -ForegroundColor DarkGray
    Write-Host "  or visit: https://aquasecurity.github.io/trivy/`n" -ForegroundColor DarkGray
} else {
    Write-Info "Scanning repository manifests for security misconfigurations..."
    & trivy config . --severity HIGH,CRITICAL --exit-code 0
    Write-Success "Trivy IaC scan completed."

    # 3. Trivy Container Image Scan
    if (-not $SkipImageScan) {
        Write-Header "3. Trivy Container Image Vulnerability Scan"
        $testImage = "nginxinc/nginx-unprivileged:alpine"
        Write-Info "Scanning compliant image: $testImage"
        & trivy image --severity HIGH,CRITICAL $testImage
        Write-Success "Trivy container image scan completed."
    }
}

Write-Host "`n======================================================" -ForegroundColor Green
Write-Host " Local DevSecOps Scan Completed! " -ForegroundColor Green
Write-Host "======================================================`n" -ForegroundColor Green
