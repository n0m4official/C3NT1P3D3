<#
.SYNOPSIS
    Automated ZeroLogon vulnerability testing
.DESCRIPTION
    Tests against both vulnerable and safe targets
.EXAMPLE
    .\Test-ZeroLogon.ps1 -Target 192.168.1.100
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Target
)

$harnessPath = "$PSScriptRoot\..\build\Debug\ZeroLogonTestHarness.exe"

if (-not (Test-Path $harnessPath)) {
    Write-Error "Test harness not found at $harnessPath"
    exit 1
}

Write-Host "[TEST] Starting ZeroLogon detection against $Target"

$output = & $harnessPath $Target
$output | Write-Host

# Check results
if ($output -match "\[RESULT\] Vulnerable: YES") {
    Write-Host "[WARNING] Vulnerable system detected!" -ForegroundColor Red
    exit 101
}
elseif ($output -match "\[RESULT\] Vulnerable: NO") {
    Write-Host "[INFO] System appears secure" -ForegroundColor Green
    exit 0
}
else {
    Write-Host "[ERROR] Test failed" -ForegroundColor Yellow
    exit 1
}
