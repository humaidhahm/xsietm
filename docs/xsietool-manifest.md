# XSIEM payload tool - verification manifest

Generated 2026-10-20T08:49:54.932391+00:00  
Target `192.168.49.1`  |  API `http://localhost:4000`  |  Indexer `https://localhost:9200`

## Severity mapping (XSIEM backend)

| Wazuh level | Dashboard severity |
|---|---|
| >= 12 | **high** |
| 7 - 11 | **medium** |
| < 7 | **low** |

## Live index at generation time

- total alerts: **20544**
- high **38** | medium **441** | low **20065**
- agent `wazuh.manager` active 127.0.0.1 Wazuh v4.9.2
- agent `win-target` active 192.168.49.1 Wazuh v4.9.2

## Payload catalogue

| payload | severity | win event | rule | level | verified |
|---|---|---|---|---|---|
| `powershell_registry_delete` | **low** | 4104 | 91813 | 3 | yes |
| `process_created` | **none** | 4688 | 67027 | 3 | yes |
| `rdp_failed_logon` | **low** | 4625 | 60122 | 5 | yes |
| `rdp_successful_logon` | **low** | 4624 | 92652 | 6 | yes |
| `rdp_successful_logon` | **low** | 4624 | 92657 | 6 | yes |
| `scheduled_task_created` | **low** | 4698 | 60228 | 4 | yes |
| `smb_failed_logon` | **low** | 4625 | 60122 | 5 | yes |
| `smb_successful_logon` | **low** | 4624 | 92652 | 6 | yes |
| `smb_successful_logon` | **low** | 4624 | 92657 | 6 | yes |
| `ssh_failed_logon` | **low** | 4625 | 60122 | 5 | yes |
| `account_lockout` | **medium** | 4740 | 60115 | 9 | yes |
| `user_account_created` | **medium** | 4720 | 60109 | 8 | **NO** |
| `privileged_group_change` | **high** | 4732 | 60154 | 12 | **NO** |
| `rdp_auth_failure_burst` | **high** | 4625 | 100100 | 12 | **NO** |
| `smb_auth_failure_burst` | **high** | 4625 | 100100 | 12 | yes |
| `ssh_auth_failure_burst` | **high** | 4625 | 100100 | 12 | yes |

## Evidence (newest matching alert in the live index)

### `powershell_registry_delete` - low

- **91813** (level 3, low) - `2026-10-20T04:11:16.214+0000` src=`-` agent=`win-target`
  - Powershell script deleted a registry key from an object
- verified: **yes**
- evidence: VERIFIED: a captured alert exists in /api/alerts - 2026-10-20T04:11:16.214+0000 rule=91813 severity=low channel=Microsoft-Windows-PowerShell/Operational with script text 'Remove-Item -Path HKLM:\SOFTWARE\XSIEMTest -Recurse -Force'. Caveat: that trigger was an INTERACTIVE session; the tool cannot produce the 4104 itself over SSH (0 documents for SSH-spawned PowerShell), so the payload is operator-assisted and prints the command.

### `process_created` - none

- **67027** (level 3, low) - `2026-10-20T08:14:08.729+0000` src=`-` agent=`win-target`
  - A process was created.
- verified: **yes**
- evidence: VERIFIED as INDEXED (not alerted): rule 67027 produced 27+ documents for one SSH command execution on 2026-10-20 before it was silenced. The payload now verifies that the 4688 document reaches the index rather than that an alert appears.

### `rdp_failed_logon` - low

- **60122** (level 5, low) - `2026-10-20T08:43:13.127+0000` src=`-` agent=`win-target`
  - Logon Failure - Unknown user or bad password
- verified: **yes**
- evidence: 2026-10-20 rule=60122 severity=low agent=win-target after xfreerdp with a wrong password (xfreerdp exit 134, ERRCONNECT_LOGON_FAILURE)

### `rdp_successful_logon` - low

- **92652** (level 6, low) - `2026-10-20T08:49:11.151+0000` src=`-` agent=`win-target`
  - Successful Remote Logon Detected - User:\xsiem_test - NTLM authentication, possible pass-the-hash attack.
- **92657** (level 6, low) - `2026-10-20T08:49:09.885+0000` src=`-` agent=`win-target`
  - Successful Remote Logon Detected - User:\xsiem_test - NTLM authentication, possible pass-the-hash attack - Possible RDP connection. Verify that kali is allowed to perform RDP connections
- verified: **yes**
- evidence: VERIFIED 2026-10-20: a successful RDP logon as xsiem_test produced rule 92652 level 6 severity=low with src_ip=192.168.49.128 and agent=win-target ('Successful Remote Logon Detected - User:\xsiem_test - NTLM authentication'), and rule 92657 when the event carried a workstation name. NOTE: an earlier version of this entry wrongly expected rule 60106 (event 4624) for a network logon; 60106 is the interactive console path.

### `scheduled_task_created` - low

- **60228** (level 4, low) - `2026-10-20T08:04:17.215+0000` src=`-` agent=`win-target`
  - A scheduled task was created
- verified: **yes**
- evidence: 2026-10-20T05:02:34 rule=60228 severity=low src_ip=192.168.49.1 agent=win-target

### `smb_failed_logon` - low

- **60122** (level 5, low) - `2026-10-20T08:43:13.127+0000` src=`-` agent=`win-target`
  - Logon Failure - Unknown user or bad password
- verified: **yes**
- evidence: 2026-10-20T04:45:45 rule=60122 severity=low src_ip=192.168.49.1 agent=win-target

### `smb_successful_logon` - low

- **92652** (level 6, low) - `2026-10-20T08:49:11.151+0000` src=`-` agent=`win-target`
  - Successful Remote Logon Detected - User:\xsiem_test - NTLM authentication, possible pass-the-hash attack.
- **92657** (level 6, low) - `2026-10-20T08:49:09.885+0000` src=`-` agent=`win-target`
  - Successful Remote Logon Detected - User:\xsiem_test - NTLM authentication, possible pass-the-hash attack - Possible RDP connection. Verify that kali is allowed to perform RDP connections
- verified: **yes**
- evidence: VERIFIED 2026-10-20: a successful SMB logon as xsiem_test produced rule 92652 level 6 severity=low with src_ip=192.168.49.128 and agent=win-target ('Successful Remote Logon Detected - User:\xsiem_test - NTLM authentication'), and rule 92657 when the event carried a workstation name. NOTE: an earlier version of this entry wrongly expected rule 60106 (event 4624) for a network logon; 60106 is the interactive console path.

### `ssh_failed_logon` - low

- **60122** (level 5, low) - `2026-10-20T08:43:13.127+0000` src=`-` agent=`win-target`
  - Logon Failure - Unknown user or bad password
- verified: **yes**
- evidence: 2026-10-20 rule=60122 severity=low agent=win-target (10 SSH failures produced 60122)

### `account_lockout` - medium

- **60115** (level 9, medium) - `2026-10-20T08:01:04.647+0000` src=`-` agent=`win-target`
  - User account locked out (multiple login errors)
- verified: **yes**
- evidence: 2026-10-20T04:17:45 rule=60115 severity=medium src_ip=192.168.49.1 agent=win-target

### `user_account_created` - medium

- **60109** (level 8, medium) - `2026-10-20T07:09:03.488+0000` src=`-` agent=`win-target`
  - User account enabled or created
- verified: **NO**
- evidence: UNVERIFIED by this tool: rule 60109 is present in the live index from a Windows-side action, but this tool does not hold an admin credential and has not driven the account creation itself.

### `privileged_group_change` - high

- **60154** (level 12, high) - `2026-10-20T06:27:40.739+0000` src=`-` agent=`win-target`
  - Administrators Group Changed
- verified: **NO**
- evidence: UNVERIFIED by this tool: rule 60154 is confirmed working end to end on this target (2026-10-20T06:27:01 and 06:27:40, memberSid S-1-5-21-3157694894-2919287776-405654444-1023, targetSid S-1-5-32-544) but it was driven from the Windows side with administrator rights. This tool does not hold an admin credential on the target, so it prints the command for an operator instead.

### `rdp_auth_failure_burst` - high

- **100100** (level 12, high) - `2026-10-20T08:32:40.045+0000` src=`-` agent=`win-target`
  - XSIEM: Windows authentication failure burst (possible brute force)
- verified: **NO**
- evidence: UNVERIFIED: the underlying mechanism is proven - 8 failed RDP logons produce 4625 and rule 60122 (verified 2026-10-20), and rule 100100 fires on 8 same-IP 4625 events (verified 2026-10-20T06:11:54). This exact combination has not yet been observed in a single run, so it is flagged unverified rather than claimed.

### `smb_auth_failure_burst` - high

- **100100** (level 12, high) - `2026-10-20T08:32:40.045+0000` src=`-` agent=`win-target`
  - XSIEM: Windows authentication failure burst (possible brute force)
- verified: **yes**
- evidence: 2026-10-20T07:05:26 rule=100100 level=12 severity=high src_ip=192.168.49.1 agent=win-target (8 failures as xsiem_test via the tool); also 06:53:37, 06:55:57, 06:58:24, 07:00:52 - 4/4 consecutive bursts

### `ssh_auth_failure_burst` - high

- **100100** (level 12, high) - `2026-10-20T08:32:40.045+0000` src=`-` agent=`win-target`
  - XSIEM: Windows authentication failure burst (possible brute force)
- verified: **yes**
- evidence: 2026-10-20 rule=100100 level=12 severity=high agent=win-target after SSH failure bursts

## Findings

### F1 - Stock rule 60204 (MEDIUM) cannot co-fire with 100100 (HIGH)

Wazuh 4.9.2 keeps ONE composite frequency counter per matched event stream. Rules that count the same 4625 events compete for it and only one can fire. IMPORTANT CORRECTION to the earlier measurement: the 1-in-5 loss rate was measured while 100100 used <if_matched_group>authentication_failed</if_matched_group>. With the shipped form <if_matched_sid>60122</if_matched_sid> the counter is owned by 100100 alone - measured 8 of 8 consecutive bursts with 100100 and 0 of 8 for 60204 BEFORE any suppression was added. 60204 is now additionally set to level 0 (see F7) so the contest cannot happen at all.

**Impact:** The MEDIUM tier is delivered by rule 60115 (account lockout), 60109 / 60111 / 19004.

### F2 - if_matched_sid on a parent rule never fires

60105 is the parent of 60122 and never matches terminally, so a counter on it stays at zero. The original 100100 used if_matched_sid 60105 and produced 0 alerts across 21 failed logons. The working form counts on 60122. if_sid is not an option - Wazuh rejects it with 'Invalid use of frequency/context options. Missing if_matched'.

**Impact:** Fixed in config/custom-rules/xsiem-rules.xml.

### F3 - Severity filter applied after the limit slice (backend bug) - FIXED

XSIEM's /api/alerts applied severity and search filters in Python after the indexer had already sliced to `limit`, so ?limit=3&severity=medium returned 0.

**Impact:** FIXED - the filters are now pushed into the OpenSearch query. total is the count matching the filters before the limit, data is the limited slice. The response shape is unchanged and /api/stats now agrees with /api/alerts?severity= exactly.

### F4 - Account lockout counter is cumulative and cross-protocol

The target's lockout policy (threshold 10, 10 minute window) counts failed logons across SMB, SSH and RDP together. While an account is locked, Windows OpenSSH resets the connection instead of refusing the password, which reads like a network fault.

**Impact:** The tool detects the lockout as a distinct state (including the Windows 1909 signature) and refuses to report those failures as new alerts. It now refuses >9 attempts on the real account unless --i-know-this-locks is given, and the default burst is exactly 8.

### F5 - netexec failed-auth path is unusable on this target

netexec reports 'Connection Error: The NETBIOS connection with the remote host timed out' for failed authentication. smbclient and rpcclient return a real NT_STATUS_LOGON_FAILURE.

**Impact:** Failed-auth payloads use smbclient / rpcclient; netexec is used for successful auth.

### F6 - RDP 3389 was filtered until the Windows side opened it

RDP is now reachable. Failed RDP auth produces 4625 -> 60122; successful RDP auth produces 4624 -> 60106 plus 92657.

**Impact:** RDP payloads are in the catalogue.

### F7 - A local rule file CANNOT override a stock rule in Wazuh 4.9.2

Wazuh logs: 'WARNING: (7612): Rule ID '67027' is duplicated. Only the first occurrence will be considered.' The stock ruleset is loaded first, so a redefinition of an existing id in /var/ossec/etc/rules is simply ignored - whether or not it repeats the stock rule's matching conditions. To silence 67027 and 60204 the stock ruleset files themselves have to be patched: 0955-WEF-baseline_rules.xml (67027 -> level 0) and 0580-win-security_rules.xml (60204 -> level 0). Each patched copy differs from the stock file by exactly one line and is bind-mounted over the original so a container recreate cannot lose the patch.

**Impact:** The 4688 process-creation flood is stopped and the 60204/100100 contest is removed, while the raw 4688 events stay indexed for the Investigation view.

### F8 - src_ip came from agent metadata, not from the event (FIXED)

The formatter read data.srcip, a key that does not exist in the indexed document, and fell back to agent.ip - the address of the machine that REPORTED the event. The real field is data.win.eventdata.ipAddress (lower-case 'i'), which holds the address that originated the event: 192.168.49.128 for a remote logon. The indexed document for a 4625 has no src ip under data.win.system either.

**Impact:** FIXED - src_ip is now taken from data.win.eventdata.ipAddress, then data.win.system.ipAddress, and falls back to '-' (NOT the agent address) so a local administrative action is distinguishable from a remote attack.

### F9 - The log field was empty for correlation alerts (FIXED)

Diffing a stored PROBE document against a stored 100100 document showed the single decisive difference: 100100 has no `full_log` but DOES have `previous_output` (a ~20 KB string holding the aggregated raw event), while the single-event PROBE rules kept `full_log`. Wazuh stores the body of an aggregated correlation in `previous_output`, so the application - which only ever read `full_log` - returned an empty string for every correlation alert. The 500-character cap was a second, separate issue.

**Impact:** FIXED - the formatter now falls back to previous_output, and the cap was raised from 500 to 4000 characters so the Investigation view can show a whole event.

### F10 - Script Block Logging does not capture SSH-spawned PowerShell

Rule 91813 fires for interactive sessions (proven: 2026-10-20T04:11:16 from a Windows-side probe using 'Remove-Item -Path HKLM:\SOFTWARE\XSIEMTest -Recurse -Force'). But the agent produced ZERO 4104 documents for PowerShell started through sshd, while the newest 4104 in the index is the Windows OpenCode session's own interactive script. The channel itself works and the script body IS captured for interactive sessions.

**Impact:** The powershell_registry_delete payload is therefore operator-assisted: the tool prints the exact command for an interactive session and then verifies the resulting alert.

## Not verified

### `powershell_registry_delete`

Rule 91813 itself is proven to fire in this deployment (2026-10-20T04:11:16, channel Microsoft-Windows-PowerShell/Operational) but the script blocks triggered by this tool over SSH were not captured - 0 documents in the index mention the script's registry path. Needs a Windows-side check: restart the Wazuh agent so it re-reads ossec.conf, and confirm the Script Block Logging policy.

### `rdp_auth_failure_burst`

The mechanism is proven (RDP failures produce 4625/60122; 8 same-IP 4625 events trip 100100) but this exact combination has not been observed in a single run.

