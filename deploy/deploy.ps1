<#
.SYNOPSIS
    Deploy DropoutJeep to a fresh VPS, from Windows, in one command.

.DESCRIPTION
    Two modes.

    Ssh (default)
        Uploads this folder to the server, then runs deploy/bootstrap.sh over
        SSH. Use it for providers with no cloud-init, Cloudzy included, or when
        you have local changes that are not pushed.

    CloudInit
        Renders deploy/cloud-init.rendered.yaml. Paste that into the provider's
        user data box at server creation. The server sets itself up on first
        boot, no SSH from you.

    Optionally upserts the DNS A record at Cloudflare when a token and zone are
    supplied. Never touches DNS without them.

.EXAMPLE
    .\deploy\deploy.ps1 -Domain sim.example.com -ServerIp 203.0.113.45

.EXAMPLE
    .\deploy\deploy.ps1 -Domain sim.example.com -Mode CloudInit -AdminIp 41.58.0.10

.EXAMPLE
    .\deploy\deploy.ps1 -Domain sim.example.com -ServerIp 203.0.113.45 `
        -CfToken $env:CF_TOKEN -CfZone 023e105f4ecef8ad9ca31a8372d0c353 -AdminIp 41.58.0.10
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Domain,

    [string]$ServerIp,
    [ValidateSet("Ssh", "CloudInit")]
    [string]$Mode = "Ssh",
    [string]$SshUser = "root",
    [string]$AdminUser = "admin",
    [string]$AdminIp = "",
    [string]$RepoUrl = "https://github.com/Lulztigre/DropoutJeep.git",
    [string]$Branch = "main",
    [switch]$SkipDns,
    [switch]$PrepOnly,
    [string]$CfToken,
    [string]$CfZone,
    [string]$CfRecord
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$DeployDir = $PSScriptRoot

function Write-Step { param([string]$Text) Write-Host "`n==> $Text" -ForegroundColor Cyan }
function Write-Warn { param([string]$Text) Write-Host "[!] $Text" -ForegroundColor Yellow }

function Assert-Tool {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "$Name not found on PATH. Install the Windows OpenSSH client (Settings, Optional features)."
    }
}

function Test-Value {
    param([string]$Name, [string]$Value, [string]$Pattern)
    if ($Value -ne "" -and $Value -notmatch $Pattern) {
        throw "$Name has an unexpected value: $Value"
    }
}

Test-Value -Name "Domain" -Value $Domain -Pattern '^[a-zA-Z0-9.-]+$'
Test-Value -Name "AdminIp" -Value $AdminIp -Pattern '^[0-9a-fA-F.:/,]+$'
Test-Value -Name "AdminUser" -Value $AdminUser -Pattern '^[a-zA-Z0-9._-]+$'
if ($Mode -eq "Ssh") {
    if ([string]::IsNullOrWhiteSpace($ServerIp)) { throw "-ServerIp is required in Ssh mode." }
    Test-Value -Name "ServerIp" -Value $ServerIp -Pattern '^[0-9a-fA-F.:]+$'
}

# ---------------------------------------------------------------- DNS -----
function Set-CloudflareRecord {
    param([string]$Token, [string]$ZoneId, [string]$Name, [string]$Ip)

    $headers = @{
        "Authorization" = "Bearer $Token"
        "Content-Type"  = "application/json"
    }
    $base = "https://api.cloudflare.com/client/v4/zones/$ZoneId/dns_records"

    Write-Step "DNS: upserting A record $Name -> $Ip"
    $existing = Invoke-RestMethod -Uri "$base`?type=A&name=$Name" -Headers $headers -Method Get
    $body = @{ type = "A"; name = $Name; content = $Ip; ttl = 1; proxied = $false } | ConvertTo-Json

    if ($existing.result -and $existing.result.Count -gt 0) {
        $id = $existing.result[0].id
        if ($existing.result[0].content -eq $Ip) {
            Write-Host "    record already points at $Ip"
        }
        else {
            Invoke-RestMethod -Uri "$base/$id" -Headers $headers -Method Patch -Body $body | Out-Null
            Write-Host "    updated existing record (grey cloud, DNS only)"
        }
    }
    else {
        Invoke-RestMethod -Uri $base -Headers $headers -Method Post -Body $body | Out-Null
        Write-Host "    created record (grey cloud, DNS only)"
    }

    foreach ($attempt in 1..10) {
        try {
            $resolved = Resolve-DnsName -Name $Name -Type A -ErrorAction Stop |
                Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress
            if ($resolved -contains $Ip) { Write-Host "    resolves correctly"; return }
        }
        catch { }
        Start-Sleep -Seconds 6
    }
    Write-Warn "record set but not resolving yet, DNS propagation can take a few minutes"
}

if ($CfToken -and -not $SkipDns) {
    if ([string]::IsNullOrWhiteSpace($CfZone)) { throw "-CfZone is required with -CfToken." }
    if ([string]::IsNullOrWhiteSpace($ServerIp)) { throw "DNS needs -ServerIp to point at." }
    $recordName = if ($CfRecord) { $CfRecord } else { $Domain }
    Set-CloudflareRecord -Token $CfToken -ZoneId $CfZone -Name $recordName -Ip $ServerIp
}
elseif (-not $SkipDns) {
    Write-Step "DNS: manual"
    Write-Host "    Create an A record for $Domain pointing at $ServerIp (DNS only, grey cloud)."
    Write-Host "    Pass -CfToken and -CfZone to let this script do it."
}

# ---------------------------------------------------------- CloudInit -----
if ($Mode -eq "CloudInit") {
    Write-Step "Rendering cloud-init user data"
    $template = Join-Path $DeployDir "cloud-init.yaml"
    $rendered = Join-Path $DeployDir "cloud-init.rendered.yaml"
    $text = Get-Content -Raw -Path $template
    $text = $text.Replace("__DOMAIN__", $Domain).
        Replace("__ADMIN_USER__", $AdminUser).
        Replace("__ADMIN_IP__", $AdminIp).
        Replace("__REPO_URL__", $RepoUrl).
        Replace("__BRANCH__", $Branch)
    Set-Content -Path $rendered -Value $text -Encoding UTF8

    Write-Host "    wrote $rendered"
    Write-Host @"

Next steps, exact order:

  1. Create the server at your provider and choose Ubuntu 24.04 LTS.
  2. Find the field labelled "user data", "cloud-init" or "initialisation script".
  3. Paste the contents of $rendered into it. Whole file, starting with #cloud-config.
  4. Add your SSH public key in the provider's key field as usual.
  5. Create the server, then wait 3 to 5 minutes.
  6. Check progress with:
         ssh root@SERVER_IP "tail -f /var/log/dropoutjeep-bootstrap.log"
  7. Read the generated admin password with:
         ssh root@SERVER_IP "sudo cat /opt/dropoutjeep/.env"

Cloud-init runs once, on first boot. If the domain has no DNS record yet,
Caddy retries the certificate on its own once DNS resolves.
"@
    return
}

# ---------------------------------------------------------------- Ssh -----
Assert-Tool ssh
Assert-Tool scp
Assert-Tool tar

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$work = Join-Path $env:TEMP "dropoutjeep-deploy-$stamp"
New-Item -ItemType Directory -Path $work -Force | Out-Null
$archive = Join-Path $work "dropoutjeep.tgz"
$remoteScript = Join-Path $work "remote-bootstrap.sh"
$target = "$SshUser@$ServerIp"

Write-Step "Packing $RepoRoot"
Push-Location $RepoRoot
try {
    & tar -czf $archive `
        --exclude=venv --exclude=.venv --exclude=__pycache__ `
        --exclude=.pytest_cache --exclude=logs --exclude=instance `
        --exclude=.git --exclude=.playwright-mcp --exclude=node_modules `
        --exclude="*.tgz" --exclude="*.db" .
    if ($LASTEXITCODE -ne 0) { throw "tar failed with exit code $LASTEXITCODE" }
}
finally {
    Pop-Location
}
$sizeMb = [math]::Round((Get-Item $archive).Length / 1MB, 1)
Write-Host "    $archive ($sizeMb MB)"

$remote = @"
#!/usr/bin/env bash
set -euo pipefail
DOMAIN='$Domain'
ADMIN_USER='$AdminUser'
ADMIN_IP='$AdminIp'
PREP_ONLY='$([int]$PrepOnly.IsPresent)'
export DOMAIN ADMIN_USER ADMIN_IP PREP_ONLY
mkdir -p /opt/dropoutjeep
tar xzf /tmp/dropoutjeep.tgz -C /opt/dropoutjeep
bash /opt/dropoutjeep/deploy/bootstrap.sh
"@
Set-Content -Path $remoteScript -Value $remote -Encoding ASCII -NoNewline
Write-Host "    rendered remote bootstrap with DOMAIN=$Domain ADMIN_IP=$AdminIp"

Write-Step "Uploading to $target"
$sshOpts = @("-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=20")
& scp @sshOpts $archive "${target}:/tmp/dropoutjeep.tgz"
if ($LASTEXITCODE -ne 0) { throw "scp failed with exit code $LASTEXITCODE" }
& scp @sshOpts $remoteScript "${target}:/tmp/dropoutjeep-remote.sh"
if ($LASTEXITCODE -ne 0) { throw "scp failed with exit code $LASTEXITCODE" }

Write-Step "Running bootstrap on the server"
& ssh @sshOpts $target "bash /tmp/dropoutjeep-remote.sh"
if ($LASTEXITCODE -ne 0) {
    Write-Warn "bootstrap exited $LASTEXITCODE. Full log on the server:"
    Write-Host "    ssh $target 'tail -60 /var/log/dropoutjeep-bootstrap.log'"
    throw "remote bootstrap failed"
}

Write-Step "Done"
if ($PrepOnly) {
    Write-Host @"

  Prepared, stack not started. Everything except TLS is in place.

  When the domain resolves to $ServerIp, start it:
      ssh $target "cd /opt/dropoutjeep && docker compose up -d --build"
      ssh $target "cd /opt/dropoutjeep && docker compose logs -f caddy"

  Password: ssh $target "sudo grep ADMIN_PASSWORD /opt/dropoutjeep/.env"
"@
    return
}
Write-Host @"

  URL        https://$Domain
  Login      https://$Domain/admin/login
  Password   ssh $target "sudo grep ADMIN_PASSWORD /opt/dropoutjeep/.env"

  Watch the certificate: ssh $target "cd /opt/dropoutjeep && docker compose logs -f caddy"
  Update:                ssh $target "cd /opt/dropoutjeep && git pull --ff-only && docker compose up -d --build"
"@
