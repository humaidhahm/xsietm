# =====================================================================
#  XSIEM - check whether the Kali side has finished its work
#  Run this any time. No elevation needed. Read-only.
# =====================================================================

$api = 'http://192.168.49.128:4000'
$fs  = 'http://192.168.49.128:8080'

function Get-Json($url) {
    try {
        $r = Invoke-WebRequest -Uri $url -TimeoutSec 25 -UseBasicParsing
        $c = if ($r.Content -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($r.Content) } else { [string]$r.Content }
        return $c | ConvertFrom-Json
    } catch { return $null }
}

Write-Host ""
Write-Host "=== XSIEM Kali-side progress check ===" -ForegroundColor Cyan
Write-Host ""

# 1. manifest
Write-Host "1. Manifest published?" -ForegroundColor Cyan
$man = $false
foreach ($f in 'xsietool-manifest.json','xsietool-manifest.md','GROUND-TRUTH.md') {
    try {
        $r = Invoke-WebRequest -Uri "$fs/$f" -TimeoutSec 12 -UseBasicParsing
        Write-Host ("   {0,-26} READY  HTTP {1}  {2} bytes" -f $f, $r.StatusCode, $r.RawContentLength) -ForegroundColor Green
        if ($f -eq 'xsietool-manifest.json') { $man = $true }
    } catch {
        Write-Host ("   {0,-26} not published yet" -f $f) -ForegroundColor DarkGray
    }
}

# 2. backend filter bug
Write-Host ""
Write-Host "2. Backend severity-filter bug fixed?" -ForegroundColor Cyan
$a3 = Get-Json "$api/api/alerts?limit=3&severity=medium"
$a1k = Get-Json "$api/api/alerts?limit=1000&severity=medium"
if ($a3 -and $a1k) {
    $fixed = (@($a3.data).Count -gt 0)
    Write-Host ("   limit=3&severity=medium  -> {0} alerts" -f @($a3.data).Count)
    Write-Host ("   limit=1000&severity=medium -> {0} alerts" -f @($a1k.data).Count)
    if ($fixed) { Write-Host "   -> FIXED (small limit now returns medium alerts)" -ForegroundColor Green }
    else       { Write-Host "   -> STILL BROKEN (small limit returns 0)" -ForegroundColor Yellow }
}

# 3. severity coverage
Write-Host ""
Write-Host "3. Severity coverage" -ForegroundColor Cyan
$st = Get-Json "$api/api/stats"
if ($st) {
    Write-Host ("   total={0}  high={1}  medium={2}  low={3}" -f $st.total, $st.high, $st.medium, $st.low) -ForegroundColor Yellow
    if ($st.high -gt 0) { Write-Host "   -> HIGH severity reached" -ForegroundColor Green }
    else { Write-Host "   -> HIGH still 0 (rule 100100 fix not yet effective)" -ForegroundColor Yellow }
}
$ah = Get-Json "$api/api/alerts?limit=1000&severity=high"
if ($ah) {
    if (@($ah.data).Count -gt 0) {
        Write-Host "   HIGH alerts now present:" -ForegroundColor Green
        @($ah.data) | Select-Object -First 8 | ForEach-Object {
            Write-Host ("     {0}  rule {1}  {2}  src {3}" -f $_.timestamp, $_.rule_id, $_.desc, $_.src_ip) -ForegroundColor Green
        }
    }
}

# 4. agents
Write-Host ""
Write-Host "4. Agents reporting" -ForegroundColor Cyan
$ag = Get-Json "$api/api/agents"
if ($ag) {
    @($ag.data) | ForEach-Object {
        Write-Host ("   {0}  {1,-14} {2,-14} {3,-8} lastSeen {4}" -f $_.id, $_.name, $_.ip, $_.status, $_.lastSeen)
    }
}

# 5. target reachable
Write-Host ""
Write-Host "5. Windows endpoint reachability (from this host)" -ForegroundColor Cyan
foreach ($p in 3389, 445, 22) {
    $t = Test-NetConnection -ComputerName 192.168.49.1 -Port $p -WarningAction SilentlyContinue
    Write-Host ("   192.168.49.1:{0,-5} {1}" -f $p, $(if ($t.TcpTestSucceeded) { 'open' } else { 'closed' }))
}

Write-Host ""
if ($man -and $st -and $st.high -gt 0) {
    Write-Host "RESULT: Kali side looks COMPLETE - manifest published AND high severity reached." -ForegroundColor Green
} elseif ($man) {
    Write-Host "RESULT: manifest published, but check the severity numbers above." -ForegroundColor Yellow
} else {
    Write-Host "RESULT: Kali side has not published the manifest yet - it may still be working." -ForegroundColor DarkYellow
}
Write-Host ""
