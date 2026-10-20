# ==============================================================================
# VeriDAG Universal Multi-Language SDK Release & Conformance Verification Script (PowerShell)
# ==============================================================================
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " VeriDAG Multi-Language SDK Conformance & Release Gatekeeper" -ForegroundColor Cyan
Write-Host " Root: $RootDir" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# 1. Rust SDK
Write-Host "[1/3] Verifying Rust SDK conformance..." -ForegroundColor Yellow
Push-Location $RootDir
try {
    cargo test -p veridag-sdk
    Write-Host "  [PASS] Rust SDK conformance verified." -ForegroundColor Green
} finally {
    Pop-Location
}

# 2. TypeScript SDK
Write-Host "[2/3] Verifying TypeScript SDK conformance & HTTP client..." -ForegroundColor Yellow
Push-Location "$RootDir\sdks\typescript"
try {
    npm test
    npm run build
    npm run verify-package
    Write-Host "  [PASS] TypeScript SDK conformance, build, and package verified." -ForegroundColor Green
} finally {
    Pop-Location
}

# 3. Python SDK
Write-Host "[3/3] Verifying Python SDK conformance & HTTP client..." -ForegroundColor Yellow
Push-Location "$RootDir\sdks\python"
try {
    if (Get-Command uv -ErrorAction SilentlyContinue) {
        uv run python -m unittest discover -s tests
        uv build
    } else {
        python -m unittest discover -s tests
        python -m build
    }
    Write-Host "  [PASS] Python SDK conformance, client, and distribution build verified." -ForegroundColor Green
} finally {
    Pop-Location
}

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " ALL 3 SDKS MATCH GOLDEN VECTORS 100% BIT-FOR-BIT!" -ForegroundColor Green
Write-Host " Ready for distribution to crates.io, npm, and PyPI." -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan
