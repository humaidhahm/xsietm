# =====================================================================
#  XSIEM demo helper - reset the lab test account between demo runs
#  Target:  DESKTOP-GUSU8GP  (192.168.49.1)
#  Run this in an ELEVATED PowerShell BEFORE each demo run if the
#  account has been locked out by the brute-force payload.
#
#  Why this exists: the local lockout policy is threshold 10 / 10 min.
#  A burst of 8 failed logons trips the Wazuh correlation rules
#  (60204 medium, 100100 high) WITHOUT locking the account. But if the
#  payload runs more than once inside the 10-minute observation window
#  the counter keeps climbing and Windows locks the account for 10
#  minutes. Changing the password does NOT clear a lockout.
#  Toggling the account inactive then active DOES clear it immediately.
# =====================================================================

$ErrorActionPreference = 'Stop'
$acct = 'xsiem_test'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "MUST be run as Administrator (elevated PowerShell)." -ForegroundColor Red
    Write-Host "Right-click PowerShell -> Run as administrator" -ForegroundColor Yellow
    pause
    exit 1
}

Write-Host ""
Write-Host "=== XSIEM lab account reset ===" -ForegroundColor Cyan
Write-Host "Account: $acct  on $env:COMPUTERNAME"

$state = (net.exe user $acct 2>&1 | Out-String)
if ($state -match 'Account active\s+Locked') {
    Write-Host "  BEFORE: LOCKED" -ForegroundColor Red
} elseif ($state -match 'Account active\s+Yes') {
    Write-Host "  BEFORE: active" -ForegroundColor Green
} else {
    Write-Host "  BEFORE: (could not determine)" -ForegroundColor Yellow
}

# The actual unlock: disable then re-enable clears the lockout counter
net.exe user $acct /active:no  | Out-Null
Start-Sleep -Seconds 2
net.exe user $acct /active:yes | Out-Null
Start-Sleep -Seconds 2

$state2 = (net.exe user $acct 2>&1 | Out-String)
if ($state2 -match 'Account active\s+Yes') {
    Write-Host "  AFTER : active - LOCKOUT CLEARED" -ForegroundColor Green
} else {
    Write-Host "  AFTER : still locked - wait for the 10 minute lockout duration to expire" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Group memberships (should be Users only, no privileged group):" -ForegroundColor Cyan
Get-LocalGroup | ForEach-Object {
    $g = $_
    (Get-LocalGroupMember -Group $g.Name -ErrorAction SilentlyContinue).Name |
        Where-Object { $_ -match 'xsiem_test' } |
        ForEach-Object { Write-Host "   $_ in $($g.Name)" -ForegroundColor Yellow }
}

Write-Host ""
Write-Host "Agent status:" -ForegroundColor Cyan
Write-Host ("   WazuhSvc = " + (Get-Service WazuhSvc).Status)
$ck = 'C:\Program Files (x86)\ossec-agent\client.keys'
if ((Get-Item $ck -ErrorAction SilentlyContinue).Length -gt 0) {
    Write-Host "   enrolled = yes  ->  $(Get-Content $ck | Where-Object { $_ -notmatch '^#' -and $_.Trim() -ne '' })" -ForegroundColor Green
} else {
    Write-Host "   enrolled = NO - agent has no key" -ForegroundColor Red
}
Write-Host ""
