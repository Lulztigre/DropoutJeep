# push-code.ps1 - ship the working tree to the DropoutJeep VPS and rebuild.
#
# Why this exists: the local folder is not a git repository and
# github.com/Lulztigre/DropoutJeep holds only a README, so there is nothing for
# the server to pull. This sends the code that actually runs.
#
# Run from anywhere:  .\deploy\push-code.ps1
# You will be asked for the root password twice (scp, then ssh).
#
# What it does NOT send: .env, instance/, *.db, venv/, __pycache__, Caddyfile,
# docker-compose*.yml. Those live on the server and hold the encryption key,
# the database and your admin IP allowlist.

$ErrorActionPreference = 'Stop'

$Root    = Split-Path -Parent $PSScriptRoot
$Server  = 'root@91.229.245.236'
$AppDir  = '/opt/dropoutjeep'
$Tarball = Join-Path $PSScriptRoot 'patch.tar.gz'

Write-Host "== building archive from $Root" -ForegroundColor Cyan
Push-Location $Root
try {
    if (Test-Path $Tarball) { Remove-Item $Tarball -Force }
    $tarArgs = @(
        '-czf', $Tarball,
        '--exclude=__pycache__', '--exclude=*.pyc',
        'dropoutjeep.py', 'dropoutjeep_lib', 'templates'
    )
    & tar.exe @tarArgs
    if ($LASTEXITCODE -ne 0) { throw "tar failed with exit code $LASTEXITCODE" }
    $size = [math]::Round((Get-Item $Tarball).Length / 1KB, 1)
    Write-Host "== archive ready: $Tarball ($size KB)" -ForegroundColor Green
}
finally { Pop-Location }

Write-Host "== copying to the server" -ForegroundColor Cyan
& scp.exe $Tarball "${Server}:/tmp/dj-patch.tar.gz"
if ($LASTEXITCODE -ne 0) { throw 'scp failed' }

Write-Host "== extracting, rebuilding, restarting" -ForegroundColor Cyan
& ssh.exe $Server "cd $AppDir && tar xzf /tmp/dj-patch.tar.gz && rm -f /tmp/dj-patch.tar.gz && docker compose up -d --build"
if ($LASTEXITCODE -ne 0) { throw 'remote build failed' }

Write-Host "== rebuilding the optional proxy stack if it is running" -ForegroundColor Cyan
& ssh.exe $Server "cd $AppDir && if [ -n \"\$(docker compose -f docker-compose.proxy.yml ps -q 2>/dev/null)\" ]; then docker compose -f docker-compose.proxy.yml up -d --build; else echo 'proxy stack not running, skipped'; fi"

Write-Host "== container state" -ForegroundColor Cyan
& ssh.exe $Server "cd $AppDir && docker compose ps"

Write-Host ""
Write-Host "Next: open the portal, sign in, and check the log for these lines:" -ForegroundColor Yellow
Write-Host "  [bounce] mailboxes=1 messages=n bounces=n      (bounce polling is alive)"
Write-Host "  journals: 'wal'                                  (SQLite concurrency fix active)"
Write-Host "  no 'Referrer-Policy' 400 on the spoof check"
