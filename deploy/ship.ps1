# ship.ps1 - commit everything, push, and let the VPS pick it up.
#
#   .\deploy\ship.ps1                      -> "deploy: 2026-10-27 21:40"
#   .\deploy\ship.ps1 "fix bounce parsing"  -> your message
#
# The VPS runs deploy/auto-deploy.sh from a two-minute systemd timer, so a push
# is all it takes: push -> timer sees a new commit -> docker compose up -d --build.
# Nothing is deployed by this script directly, so a failed push leaves the box
# untouched instead of half-updated.

param(
    [string]$Message = ""
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Push-Location $Root
try {
    if (-not (Test-Path (Join-Path $Root '.git'))) {
        throw "Not a git repository: $Root"
    }

    $status = git status --porcelain
    if (-not $status) {
        Write-Host "nothing to ship, working tree clean" -ForegroundColor Yellow
    }
    else {
        if (-not $Message) { $Message = "deploy: " + (Get-Date -Format 'yyyy-MM-dd HH:mm') }
        git add -A
        git commit -m $Message | Out-Null
        Write-Host "committed: $Message" -ForegroundColor Green
    }

    git push origin main
    if ($LASTEXITCODE -ne 0) { throw 'push failed' }

    Write-Host ""
    Write-Host "pushed. the box rebuilds within two minutes." -ForegroundColor Cyan
    Write-Host "watch it with:  ssh root@91.229.245.236 `"tail -f /var/log/dj-deploy.log`""
    Write-Host "or check:       ssh root@91.229.245.236 `"cd /opt/dropoutjeep && git log --oneline -1 && docker compose ps`""
}
finally { Pop-Location }
