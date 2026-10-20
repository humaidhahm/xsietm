$ErrorActionPreference = 'Continue'
$api = 'http://192.168.49.128:4000'
$fs  = 'http://192.168.49.128:8080'
$agentDir = Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
$results = @()

function Chk($name, $cond, $detail, $level) {
    # level: OK | WARN | FAIL
    $script:results += [pscustomobject]@{ Check = $name; Level = $level; Detail = $detail }
    $col = switch ($level) { 'OK' { 'Green' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } }
    Write-Host ("  [{0,-4}] {1,-46} {2}" -f $level, $name, $detail) -ForegroundColor $col
}
function J($url) {
    try {
        $r = Invoke-WebRequest -Uri $url -TimeoutSec 25 -UseBasicParsing
        $c = if ($r.Content -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($r.Content) } else { [string]$r.Content }
        return $c | ConvertFrom-Json
    } catch { return $null }
}

Write-Host ""
Write-Host "================ XSIEM DEMO PRE-FLIGHT ================" -ForegroundColor Cyan
Write-Host " Target : DESKTOP-GUSU8GP  192.168.49.1   (monitored endpoint)"
Write-Host " Server : Kali 192.168.49.128  (Wazuh + XSIEM)"
Write-Host " Time   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
Write-Host ""

Write-Host "-- WINDOWS ENDPOINT --" -ForegroundColor Cyan
foreach ($s in 'WazuhSvc','sshd','TermService') {
    $svc = Get-Service $s -ErrorAction SilentlyContinue
    if (-not $svc) { Chk "service $s" $false "NOT FOUND" 'FAIL'; continue }
    $sm = (Get-CimInstance Win32_Service -Filter "Name='$s'").StartMode
    $ok = ($svc.Status -eq 'Running' -and $sm -eq 'Auto')
    Chk "service $s" $ok "$($svc.Status) / $sm" $(if($ok){'OK'}else{'FAIL'})
}

$ck = Get-Content (Join-Path $agentDir 'client.keys') -ErrorAction SilentlyContinue |
      Where-Object { $_ -notmatch '^#' -and $_.Trim() -ne '' }
Chk "agent enrolled (client.keys)" ([bool]$ck) $(if($ck){ "id/name = " + (($ck -split '\s+')[0..1] -join '/') } else { 'EMPTY - agent has no key' }) $(if($ck){'OK'}else{'FAIL'})

$conn = Get-NetTCPConnection -RemoteAddress 192.168.49.128 -RemotePort 1514 -State Established -ErrorAction SilentlyContinue
Chk "agent session to 192.168.49.128:1514" ([bool]$conn) $(if($conn){ "Established from $($conn[0].LocalAddress):$($conn[0].LocalPort)" } else { 'NOT ESTABLISHED' }) $(if($conn){'OK'}else{'FAIL'})

$cut = (Get-Date).AddMinutes(-10)
$errs = @(Select-String -Path (Join-Path $agentDir 'ossec.log') -Pattern 'ERROR|CRITICAL' -ErrorAction SilentlyContinue |
          Where-Object { if ($_.Line -match '^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)') { try { [datetime]::ParseExact($matches[1],'yyyy/MM/dd HH:mm:ss',$null) -gt $cut } catch { $false } } else { $false } })
Chk "agent errors in the last 10 min" ($errs.Count -eq 0) $(if($errs.Count -eq 0){'clean'}else{"$($errs.Count) error lines - check if the manager was restarted"}) $(if($errs.Count -eq 0){'OK'}else{'WARN'})

$u = Get-LocalUser -Name 'xsiem_test' -ErrorAction SilentlyContinue
Chk "test account xsiem_test exists" ([bool]$u) $(if($u){ "Enabled=$($u.Enabled)" } else { 'MISSING' }) $(if($u){'OK'}else{'FAIL'})
$mem = @(Get-LocalGroup | ForEach-Object { $g=$_; (Get-LocalGroupMember -Group $g.Name -ErrorAction SilentlyContinue).Name | Where-Object { $_ -match 'xsiem_test' } | ForEach-Object { $g.Name } })
Chk "xsiem_test in Users only" (($mem -join ',') -eq 'Users') "in: $($mem -join ', ')" $(if(($mem -join ',') -eq 'Users'){'OK'}else{'FAIL'})
$locked = (net.exe user xsiem_test 2>&1 | Out-String) -match 'Account active\s+Locked'
Chk "xsiem_test not locked out" (-not $locked) $(if($locked){'LOCKED - run Reset-XsiemAccount.cmd'}else{'active'}) $(if($locked){'FAIL'}else{'OK'})

$res = @()
$res += if (Get-ScheduledTask -TaskName 'XSIEmlabProbe' -ErrorAction SilentlyContinue) { 'task XSIEmlabProbe' }
$res += if (Get-Service XSIEmlabProbe -ErrorAction SilentlyContinue) { 'service XSIEmlabProbe' }
$res += if (Test-Path 'HKLM:\SOFTWARE\XSIEMTest') { 'reg HKLM XSIEMTest' }
$res += if (Test-Path 'HKCU:\Software\XSIEMTest') { 'reg HKCU XSIEMTest' }
$res += if (Get-LocalGroup -Name 'xsiem-lab-grp' -ErrorAction SilentlyContinue) { 'group xsiem-lab-grp' }
Chk "no leftover test artefacts" ($res.Count -eq 0) $(if($res.Count -eq 0){'clean'}else{$res -join ', '}) $(if($res.Count -eq 0){'OK'}else{'WARN'})

Write-Host ""
Write-Host "-- AUDIT POLICIES --" -ForegroundColor Cyan
$expect = @('Logon','Logoff','Other Account Logon Events','Account Lockout','Security Group Management',
            'Other Account Management Events','Process Creation','Other Object Access Events','Registry',
            'Audit Policy Change','User Account Management','Security State Change','System Integrity','Special Logon')
$bad = @()
foreach ($s in $expect) {
    $o = auditpol /get "/subcategory:$s" 2>&1 | Where-Object { "$_".Trim() -and "$_" -notmatch 'System audit policy|Category/Subcategory' }
    $v = (($o | Out-String).Trim() -split "`r?`n" | Where-Object { "$_".Trim() } | Select-Object -Last 1)
    if ("$v" -match 'No Auditing') { $bad += $s }
}
Chk "all 14 audit subcategories enabled" ($bad.Count -eq 0) $(if($bad.Count -eq 0){'all enabled'}else{"OFF: $($bad -join ', ')"}) $(if($bad.Count -eq 0){'OK'}else{'FAIL'})

Write-Host ""
Write-Host "-- AGENT EVENT CHANNELS --" -ForegroundColor Cyan
$conf = [System.IO.File]::ReadAllText((Join-Path $agentDir 'ossec.conf'))
$want = @('Application','Security','System','Microsoft-Windows-PowerShell/Operational',
          'Microsoft-Windows-Windows Defender/Operational','Microsoft-Windows-TerminalServices-LocalSessionManager/Operational')
$missing = @($want | Where-Object { -not $conf.Contains($_) })
Chk "7 event channels collected" ($missing.Count -eq 0) $(if($missing.Count -eq 0){'all present'}else{"MISSING: $($missing -join ', ')"}) $(if($missing.Count -eq 0){'OK'}else{'FAIL'})

Write-Host ""
Write-Host "-- XSIEM SERVER --" -ForegroundColor Cyan
$h = J "$api/health"
Chk "FastAPI /health" ($h -and $h.wazuh -eq 'ok') $(if($h){ "backend=$($h.backend) wazuh=$($h.wazuh) auth=$($h.authenticated)" } else { 'UNREACHABLE' }) $(if($h -and $h.wazuh -eq 'ok'){'OK'}else{'FAIL'})

$ag = J "$api/api/agents"
$wt = @($ag.data | Where-Object { $_.name -eq 'win-target' })[0]
Chk "win-target registered and active" ($wt -and $wt.status -eq 'active') $(if($wt){ "$($wt.ip)  $($wt.os)  lastSeen $($wt.lastSeen)" } else { 'NOT FOUND' }) $(if($wt -and $wt.status -eq 'active'){'OK'}else{'FAIL'})

$st = J "$api/api/stats"
Chk "severity coverage: high present" ($st.high -gt 0) "high=$($st.high) medium=$($st.medium) low=$($st.low)" $(if($st.high -gt 0){'OK'}else{'WARN'})
Chk "severity coverage: medium present" ($st.medium -gt 0) "$($st.medium) medium alerts" $(if($st.medium -gt 0){'OK'}else{'WARN'})

$ah = J "$api/api/alerts?limit=1000&severity=high"
Chk "filter-before-limit fixed" ($ah -and $ah.total -eq $st.high) "stats.high=$($st.high)  filtered_total=$($ah.total)" $(if($ah -and $ah.total -eq $st.high){'OK'}else{'FAIL'})

# src_ip must be the ATTACKER (192.168.49.128) for remote events, and '-' for local ones
$srcOk = $true; $srcMsg = 'n/a'
if ($ah -and @($ah.data).Count -gt 0) {
    $remote = @($ah.data | Where-Object { $_.rule_id -eq '100100' })
    $local  = @($ah.data | Where-Object { $_.rule_id -eq '60154' })
    $badR = @($remote | Where-Object { $_.src_ip -ne '192.168.49.128' }).Count
    $badL = @($local  | Where-Object { $_.src_ip -ne '-' -and $_.src_ip -ne '' }).Count
    $srcOk = ($badR -eq 0 -and $badL -eq 0)
    $srcMsg = "remote(100100)=$(@($remote | Group-Object src_ip | ForEach-Object { $_.Name }) -join ',')  local(60154)=$(@($local | Group-Object src_ip | ForEach-Object { $_.Name }) -join ',')"
}
Chk "src_ip = attacker for remote events" $srcOk $srcMsg $(if($srcOk){'OK'}else{'FAIL'})

# the raw event body should now be mapped into the log field
$logOk = $true; $logMsg = 'n/a'
if ($ah -and @($ah.data).Count -gt 0) {
    $withLog = @($ah.data | Where-Object { $_.log -and $_.log.Trim() -ne '' }).Count
    $logOk = ($withLog -gt 0)
    $logMsg = "$withLog of $(@($ah.data).Count) HIGH alerts carry a raw event body"
}
Chk "raw event body present (log field)" $logOk $logMsg $(if($logOk){'OK'}else{'FAIL'})

# process-creation noise should be suppressed
$noise = 0
$allA = J "$api/api/alerts?limit=1000"
if ($allA) { $noise = @($allA.data | Where-Object { $_.rule_id -eq '67027' }).Count }
Chk "process-creation noise suppressed" ($noise -lt 50) "rule 67027 = $noise of the last 1000 alerts" $(if($noise -lt 50){'OK'}else{'WARN'})

$man = $false
try { $m = Invoke-WebRequest -Uri "$fs/xsietool-manifest.json" -TimeoutSec 12 -UseBasicParsing; $man = ($m.RawContentLength -gt 0) } catch {}
Chk "tool manifest published" $man $(if($man){'available'}else{'not published - tool still building'}) $(if($man){'OK'}else{'WARN'})

Write-Host ""
Write-Host "-- ENDPOINT PORTS (for the Kali attacker) --" -ForegroundColor Cyan
foreach ($p in 3389, 445, 22) {
    $l = Get-NetTCPConnection -State Listen -LocalPort $p -ErrorAction SilentlyContinue
    Chk "listening on $p" ([bool]$l) $(if($l){'listening'}else{'NOT LISTENING'}) $(if($l){'OK'}else{'FAIL'})
}

$fail = @($results | Where-Object { $_.Level -eq 'FAIL' }).Count
$warn = @($results | Where-Object { $_.Level -eq 'WARN' }).Count
Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
if ($fail -eq 0 -and $warn -eq 0) { Write-Host " RESULT: ALL GREEN - ready to demo" -ForegroundColor Green }
elseif ($fail -eq 0) { Write-Host " RESULT: READY ($warn warning(s), non-blocking)" -ForegroundColor Yellow }
else { Write-Host " RESULT: $fail FAILURE(S) - fix before demoing" -ForegroundColor Red }
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

if ($args -contains '-evidence') {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $out = "C:\Users\Humaidh-Victus\OneDrive\Desktop\xsiem-evidence-$stamp.txt"
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("XSIEM DEMO EVIDENCE REPORT")
    [void]$sb.AppendLine("Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$sb.AppendLine("Host      : $env:COMPUTERNAME  (192.168.49.1)")
    [void]$sb.AppendLine("Server    : Kali 192.168.49.128")
    [void]$sb.AppendLine("Agent key : $ck")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("CHECK RESULTS")
    foreach ($r in $results) { [void]$sb.AppendLine(("  [{0,-4}] {1,-46} {2}" -f $r.Level, $r.Check, $r.Detail)) }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("XSIEM STATS : $($st | ConvertTo-Json -Compress)")
    [void]$sb.AppendLine("AGENTS      : $($ag.data | ConvertTo-Json -Compress)")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("RECENT HIGH ALERTS")
    foreach ($x in @($ah.data | Select-Object -First 10)) {
        [void]$sb.AppendLine(("  {0}  rule {1}  {2}  sev {3}  src {4}  agent {5}" -f $x.timestamp, $x.rule_id, $x.rule, $x.severity, $x.src_ip, $x.agent))
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("AUDIT POLICIES")
    foreach ($s in $expect) {
        $o = auditpol /get "/subcategory:$s" 2>&1 | Where-Object { "$_".Trim() -and "$_" -notmatch 'System audit policy|Category/Subcategory' }
        [void]$sb.AppendLine(("  {0,-34} {1}" -f $s, (($o | Out-String).Trim() -split "`r?`n" | Where-Object { "$_".Trim() } | Select-Object -Last 1)))
    }
    Set-Content -Path $out -Value $sb.ToString()
    Write-Host " Evidence report written to: $out" -ForegroundColor Green
    Write-Host ""
}
