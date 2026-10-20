<#
    Install-WazuhAgent.ps1
    -----------------------
    Installs and enrols the Wazuh agent on the Windows target so it reports to the
    Wazuh manager running in Docker on the Kali VM.

    Run this in an ELEVATED PowerShell (Run as Administrator) on the Windows host.

    Prerequisite:
      * wazuh-agent-4.9.2-1.msi  (this folder)
      * rootCA.pem               (this folder - the manager's Certificate Authority)

    Usage:
      .\Install-WazuhAgent.ps1
      .\Install-WazuhAgent.ps1 -ManagerIP "192.168.49.128" -AgentName "win-target"
#>

[CmdletBinding()]
param(
    # IP of the Kali VM hosting the Wazuh manager container.
    [string]$ManagerIP = "192.168.49.128",
    # Name the agent registers with in Wazuh.
    [string]$AgentName = "win-target",
    # Optional agent group (must exist on the manager, "default" always does).
    [string]$AgentGroup = "default",
    # Folder holding the MSI and rootCA.pem.
    [string]$SourceDir = $PSScriptRoot
)

$ErrorActionPreference = "Stop"

$msi = Join-Path $SourceDir "wazuh-agent-4.9.2-1.msi"
$ca  = Join-Path $SourceDir "rootCA.pem"

Write-Host "=== Wazuh agent install -> manager $ManagerIP ===" -ForegroundColor Cyan

if (-not (Test-Path $msi)) { throw "MSI not found: $msi" }
if (-not (Test-Path $ca))  { throw "CA certificate not found: $ca (copy it from the Kali VM)" }

$agentDir = "${env:ProgramFiles(x86)}\ossec-agent"

# --- 1. Trust the manager's CA -------------------------------------------------
# The Wazuh manager uses a self-signed CA, so the agent must be told to trust it.
Write-Host "[1/4] Importing manager CA into the Windows trusted root..." -ForegroundColor Yellow
Import-Certificate -FilePath $ca -CertStoreLocation Cert:\LocalMachine\Root | Out-Null

# The MSI resolves WAZUH_REGISTRATION_CA relative to the agent install folder,
# so place a copy there before installing.
if (-not (Test-Path $agentDir)) {
    # folder does not exist yet on a fresh machine; create it so the copy below works
    New-Item -ItemType Directory -Path $agentDir -Force | Out-Null
}
Copy-Item $ca (Join-Path $agentDir "rootCA.pem") -Force

# --- 2. Install + enrol --------------------------------------------------------
# The manager's authd runs with <use_password>no</use_password>, so no
# WAZUH_REGISTRATION_PASSWORD is required.
Write-Host "[2/4] Installing agent (silent)..." -ForegroundColor Yellow
$args = @(
    "/i", "`"$msi`"", "/q",
    "WAZUH_MANAGER=`"$ManagerIP`"",
    "WAZUH_REGISTRATION_SERVER=`"$ManagerIP`"",
    "WAZUH_REGISTRATION_CA=`"$agentDir\rootCA.pem`"",
    "WAZUH_AGENT_NAME=`"$AgentName`"",
    "WAZUH_AGENT_GROUP=`"$AgentGroup`"",
    "/l", "`"$SourceDir\wazuh-agent-install.log`""
)
$p = Start-Process msiexec.exe -ArgumentList $args -Wait -PassThru
if ($p.ExitCode -ne 0) {
    throw "msiexec failed with exit code $($p.ExitCode). See $SourceDir\wazuh-agent-install.log"
}
Write-Host "      msiexec exit code 0 - installed." -ForegroundColor Green

# --- 3. Start the service -----------------------------------------------------
Write-Host "[3/4] Starting WazuhSvc..." -ForegroundColor Yellow
Start-Service WazuhSvc
Set-Service WazuhSvc -StartupType Automatic
Start-Sleep -Seconds 8

# --- 4. Verify ----------------------------------------------------------------
Write-Host "[4/4] Verifying..." -ForegroundColor Yellow
$svc = Get-Service WazuhSvc
Write-Host ("      Service status : {0}" -f $svc.Status)

$keyFile = Join-Path $agentDir "client.keys"
if (Test-Path $keyFile) {
    $key = (Get-Content $keyFile | Where-Object { $_ -notmatch '^#' -and $_.Trim() -ne "" } | Select-Object -First 1)
    if ($key) {
        Write-Host "      Enrolled       : yes (agent key issued by authd)" -ForegroundColor Green
    } else {
        Write-Host "      Enrolled       : NO - agent.keys is still empty." -ForegroundColor Red
    }
} else {
    Write-Host "      Enrolled       : NO - client.keys not found." -ForegroundColor Red
}

Write-Host ""
Write-Host "Recent agent log:" -ForegroundColor Cyan
Get-Content (Join-Path $agentDir "ossec.log") -Tail 15 -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Next: check the agent appears in XSIEM -> Agents page, or:" -ForegroundColor Cyan
Write-Host "  curl -k -u wazuh-wui:$WAZUH_API_PASSWORD https://localhost:55000/agents   # credential from $env:WAZUH_API_PASSWORD"
