# Pull the SigmaHQ community rule corpus, used only for the compile-rate report.
#
#   .\scripts\pull_sigma.ps1
#
# The corpus is vendored (gitignored) rather than committed: it is third-party
# content, it changes upstream, and we only ever measure against it.

param(
    [string]$Dest = "vendor/sigma"
)

$ErrorActionPreference = "Stop"

if (Test-Path (Join-Path $Dest ".git")) {
    Write-Host "SigmaHQ corpus already present at $Dest"
} else {
    $parent = Split-Path -Parent $Dest
    if ($parent -and -not (Test-Path $parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    git clone --depth 1 https://github.com/SigmaHQ/sigma.git $Dest
}

$awsRules = Join-Path $Dest "rules/cloud/aws"
if (-not (Test-Path $awsRules)) {
    throw "Expected AWS rules at $awsRules but the directory is missing."
}

$count = (Get-ChildItem $awsRules -Recurse -Filter *.yml | Measure-Object).Count
Write-Host "AWS CloudTrail rules available: $count"
Write-Host ""
Write-Host "Next:"
Write-Host "  python -m identity_shield.detect.pysigma_backend --db data/identity_shield.db"
