# XSIEM Payload Ground Truth (Phase 1)

Empirically established on 2026-10-20 against the live lab
(Kali 192.168.49.128 → Windows 192.168.49.1, agent `win-target`, Wazuh 4.9.2).

Severity is decided by the XSIEM backend (`main.py`):

```python
level >= 12 -> high      level >= 7 -> medium      else -> low
```

Verified consistent across every alert currently in the index
(3,4,5,6 → low; 7,8,10 → medium; 12+ → high).

---

## 1. Confirmed-working payload paths

| Path | Windows event | Rule | Level | XSIEM severity | Proven |
|---|---|---|---|---|---|
| Successful logon | 4624 | 60106 | 3 | low | ✅ |
| Failed logon (bad password / unknown user) | 4625 | 60122 | 5 | low | ✅ (SMB + SSH) |
| Failed logon burst, same source IP | 4625 ×8 | 60204 | 10 | **medium** | ✅ |
| Account lockout | 4740 | 60115 | 9 | **medium** | ✅ |
| Local group created / member added / removed / deleted | 4731/4732/4733/4734 | 60143/60144/60145/60146 | 5 | low | ✅ (seen once) |
| Scheduled task created | 4698 | 60228 | 4 | low | ✅ |
| Audit policy changed | 4719 | 60112 | 8 | medium | ✅ (seen during setup) |

## 2. Rule → severity map (Windows-relevant)

### LOW (level < 7)
| Rule | Level | Description | Events |
|---|---|---|---|
| 60106 | 3 | Windows Logon Success | 4624, 4769 |
| 60118 | 3 | Windows Workstation Logon Success | 4624, 4769 |
| 60119 | 3 | First time this user logged in this system | 4624, 4769 |
| 60137 | 3 | Windows User Logoff | 4634, 4647 |
| 60105 | 5 | Windows Logon Failure | 4625 (+legacy 529-539) |
| 60122 | 5 | Logon Failure - Unknown user or bad password | 4625 |
| 60123 | 5 | Logon Failure - Account logon time restriction violated | 4625 |
| 60124 | 5 | Logon Failure - Account currently disabled | 4625 |
| 60125 | 5 | Logon Failure - Specified account expired | 4625 |
| 60127 | 5 | Logon Failure - User not granted logon type | 4625 |
| 60128 | 5 | Logon Failure - Account's password expired | 4625 |
| 60129 | 5 | Logon Failure - Internal error | 4625 |
| 60113 | 5 | Group Account Changed | 4728-4766 |
| 60138/60140 | 5 | Group Account Created / Security Enabled Global Group Created | 4727 |
| 60139/60141/60142/60143/60144/60145/60146/60147/60148 | 5 | Group created/removed/added/deleted/changed | 4728-4758 |
| 60155/60157/60158/60160/60170 | 5 | Everyone / Authenticated Users / Terminal Server Users / Domain Users / Users Group Changed | 4732 |
| 61102 | 5 | Windows System error event | severityValue=ERROR |
| 92652 | 6 | Successful Remote Logon Detected - ANONYMOUS LOGON - NTLM | 4624 |

### MEDIUM (level 7-11)
| Rule | Level | Description | Threshold |
|---|---|---|---|
| 60109 | 8 | User account enabled or created | 4720, 4722 |
| 60111 | 8 | User account disabled or deleted | 4725, 4726 |
| 60112 | 8 | Windows Audit Policy changed | 4719, 4907, 4912 |
| 60116 | 7 | Windows is shutting down | 4609 |
| 60134 / 60135 | 8 | Security enabled group created / deleted | 4728-4766 |
| 60175, 60178, 60182-60186 | 8 | Print Operators / Pre-Windows 2000 / Performance Monitor / Performance Log / WAA / TS License / DCOM Users Group Changed | 4732 |
| 60115 | 9 | User account locked out (multiple login errors) | 4740 |
| 60117 | 9 | Windows audit log was cleared | 1102 |
| 60126 | 7 | Logon Failure - User not allowed to login at this computer | **533 (legacy only — never fires on Win11)** |
| 60130 | 7 | Logon Failure - Account locked out | **539 (legacy only — never fires on Win11)** |
| 60165, 60169, 60172-60174, 60177, 60179-60181, 60190-60193 | 10 | Cert Publishers / RAS-IAS / Power Users / Account Operators / Server Operators / Replicators / RDP Users / Net Config Ops / Forest Trust Builders / Allowed RODC / Denied RODC / Event Log Readers / Cert Service DCOM Group Changed | 4732 |
| 60204 | 10 | **Multiple Windows Logon Failures** | freq 8 / 240 s, if_matched_group=authentication_failed, same_field ipAddress |
| 60203 | 10 | Multiple failed privileged operations by same user | freq 8 / 240 s, if_matched_sid=60107 |
| 60205 | 10 | Multiple Windows audit failure events | freq 8 / 240 s, if_matched_sid=60104 — **does not fire, see §5** |
| 60206 | 10 | Multiple Windows error Security events | freq 8 / 240 s, if_matched_sid=60102 |
| 60207 | 10 | Multiple Windows warning Security events | freq 8 / 120 s, if_matched_sid=60101 |
| 61110 | 10 | Multiple System error events | freq 8 / 240 s, if_matched_sid=61102 |
| 61111 | 10 | Multiple System warning events | freq 8 / 120 s, if_matched_sid=61101 |

### HIGH (level >= 12)
| Rule | Level | Description | Events | Reachable? |
|---|---|---|---|---|
| 60154 | 12 | Administrators Group Changed | 4732 + targetSid S-1-5-32-544 | **needs admin on target** |
| 60156 | 12 | Enterprise Domain Controllers Group Changed | 4732 | domain only |
| 60159 | 12 | Domain Admins Group Changed | 4728 | domain only |
| 60162 | 12 | Domain Guests Group Changed | 4728 | domain only |
| 60164 | 12 | Domain Controllers Group Changed | 4728 | domain only |
| 60166 | 12 | Schema Admins Group Changed | 4754-4757 | domain only |
| 60167 | 12 | Enterprise Admins Group Changed | 4754-4757 | domain only |
| 60171 | 12 | Guests Group Changed | 4732 | needs admin |
| 60176 | 12 | Backup Operators Group Changed | 4732 | needs admin |
| 60188 | 12 | Read-only Domain Controllers Group Changed | 4732 | domain only |
| 60189 | 12 | Cryptographic Operators Group Changed | 4732 | needs admin |
| 92650 | 12 | New Windows Service Created to start from windows root path | 7045 + imagePath %systemroot%\w+.exe | needs admin |
| 92656 | 15 | User: ... (RDP logon from localhost) | 4624 + logonType 10 + ipAddress ::1/127.0.0.1 | RDP filtered |
| 60015 | 12 | Multiple Windows critical events | freq 4 / 240 s, if_matched_sid=60012 | not deliberately triggerable |
| 61112 | 12 | Multiple System critical events | freq 8 / 120 s, if_matched_sid=61103 | not deliberately triggerable |
| 100100 | 12 | XSIEM: Windows authentication failure burst | freq 8 / 120 s, if_matched_sid=60105 | **BROKEN — see §5** |
| 100101 | 12 | XSIEM: SSH brute force attempt detected | if_sid=5712 | **unreachable on Windows** |

## 3. Target facts

| | |
|---|---|
| Hostname / IP | DESKTOP-GUSU8GP / 192.168.49.1 (Windows 11 Pro, build 26100) |
| Local users | Administrator, CodexSandboxOffline, CodexSandboxOnline, DefaultAccount, Guest, **Humaidh-Victus**, WDAGUtilityAccount, xsiem_test |
| Administrators | Administrator, **Humaidh-Victus** |
| Test account | `xsiem_test` / password in `$XSIEM_TARGET_PASSWORD` — members of Users only |
| Lockout policy | threshold **10**, duration 10 min, observation window 10 min |
| Audit policies | Logon, Logoff, Other Account Logon Events, Account Lockout, Security Group Management, Other Account Management — all enabled |
| SMB 445 | OPEN — `smbclient`/`rpcclient`/`netexec` all authenticate |
| SSH 22 | OPEN — OpenSSH for Windows 9.5, `sshpass`/`hydra` authenticate |
| RDP 3389 | **FILTERED** — no TCP response, despite the brief stating the firewall allows it |

## 4. Tooling on Kali

| Tool | Status |
|---|---|
| netexec / nxc | `/usr/bin/netexec`, `/usr/bin/nxc` — full suite |
| impacket | python module at `/home/kali/ctf-venv/.../impacket` + ~60 CLI scripts in `/usr/bin/impacket-*` |
| smbclient | 4.25.0 |
| rpcclient | present |
| smbmap | present |
| nmap | 7.991 |
| hydra | 9.7 (ssh, smb, rdp modules) |
| sshpass | present |
| ncrack | present (RDP capable) |
| crackmapexec | superseded by netexec |
| xfreerdp / rdesktop | present (RDP client — useless, port filtered) |

**netexec caveat:** failed-auth attempts against this target end in
`Connection Error: The NETBIOS connection with the remote host timed out`.
Use **smbclient** or **rpcclient** for failed-auth payloads; netexec is
reliable for *successful* auth only.

## 5. Why custom rule 100100 never fired, and how it was fixed

### 5.1 `if_matched_sid` on a PARENT rule can never fire

The original rule counted on `<if_matched_sid>60105</if_matched_sid>`. But 60105
is the **parent** of 60122: the 4625 event matches 60122, which consumes it, so
60105 is never the terminal match. A Wazuh `if_matched_sid` counter only
increments for the rule that actually matched, so the counter stayed at zero.

Empirical proof (21 failed logons, threshold 8 in 120 s):

```
4625-family alerts: 21   (all rule 60122)
rule 100100: 0 alerts
```

The stock rule **60205** (`if_matched_sid=60104`) suffers the same defect and
has also produced 0 alerts.

The fix counts on **60122**, the rule that really matches:

```xml
<rule id="100100" level="12" frequency="8" timeframe="120">
  <if_matched_sid>60122</if_matched_sid>
  <same_field>win.eventdata.ipAddress</same_field>
  ...
</rule>
```

`if_sid` is not an option: Wazuh rejects it with
`Invalid use of frequency/context options. Missing if_matched on rule '100100'`.

### 5.2 Stock rule 60204 (MEDIUM) cannot co-fire with 100100 (HIGH)

**Wazuh 4.9.2 keeps ONE composite frequency counter per matched event stream.**
Every frequency rule that counts the same 4625 events competes for that single
counter, so only one of them can fire.

Measured over 8+ bursts:

| configuration of 100100 | 100100 fired | 60204 fired |
|---|---|---|
| `if_matched_group=authentication_failed` + `same_field=ipAddress` | 7 | 1 (non-deterministic) |
| `if_matched_group=authentication_failed`, no `same_field` | 1 | 0 |
| `if_matched_sid=60122` + `same_field=ipAddress` | **4 of 4** | 0 |

So the acceptance criterion "60204 (medium) AND 100100 (high) from the same
burst" is **not satisfiable** - it is a Wazuh counter-ownership constraint, not
a configuration error. The shipped form (`if_matched_sid 60122`) makes 100100 the
deterministic owner, 4/4 consecutive bursts.

**The MEDIUM tier is therefore delivered by rule 60115 (4740 account lockout)**
rather than by stock 60204.

### 5.3 Composite-context probes (evidence)

Temporary probe rules were used to isolate the variable. All were removed
afterwards; only 100100 and 100101 remain.

| probe | mechanism | result |
|---|---|---|
| 100201 | `frequency="$MS_FREQ"` | file rejected - `Invalid frequency: $MS_FREQ. Must be integer` |
| 100202/3/4 | level 10, `ipAddress` | never fired |
| 100205 | level 12, `ipAddress` | **fired** |
| 100206 | level 10, `ipAddress`, group set | never fired |
| 100207 | level 12, `ipAddress`, no group | **fired** |
| 100208 | level 12, `same_field=targetUserName` | never fired |
| 100209 | level 10, `targetUserName` | never fired |
| 100210 | level 12, **no** `same_field` | **fired** |
| 100211 | level 10, no `same_field` | never fired |

Only `same_field=win.eventdata.ipAddress` works; `targetUserName` and
`win.system.computer` do not.

## 6. Other defects found

1. **`xsiem-rules.xml` was not valid XML** - the header comment contained
   `---------------`, and `--` is illegal inside an XML comment. Wazuh's
   tolerant parser accepted it, strict parsers rejected the file.
   **FIXED 2026-10-20** - now parses with a strict XML parser.

2. **XSIEM backend `severity`/`search` filters were applied after the indexer
   had already sliced to `limit`.** Measured on the live API:

   | query | before | after |
   |---|---|---|
   | `?limit=3&severity=medium` | 0 | total=434, data=3 |
   | `?limit=50&severity=medium` | 1 | total=434, data=50 |
   | `?limit=1000&severity=medium` | 30 | total=434, data=434 |

   **FIXED 2026-10-20** - the filters are pushed into the OpenSearch query.
   `total` is now the number of alerts matching the filters BEFORE the limit,
   `data` is the limited slice. The response shape is unchanged. `/api/stats`
   and `/api/alerts?severity=` now agree exactly.

3. **The lockout counter is cumulative across all protocols and all accounts**
   within a 10-minute window. While an account is locked, Windows OpenSSH
   **resets the connection** instead of refusing the password, which looks like
   a network fault. The tool now detects this as a distinct state.

4. `netexec -x` and SMB command execution as `xsiem_test` produce no output -
   do not rely on remote command execution for payloads.

5. **netexec's failed-auth path is unusable here** (`NETBIOS connection timed
   out`). Use `smbclient` / `rpcclient` for failed auth, `netexec` for
   successful auth.

6. **PowerShell script blocks are not being captured for this tool.** Rule
   91813 itself fires (2026-10-20T04:11:16) for the Windows session's own
   scripts, but the script blocks this tool triggers over SSH never appear in
   the index. Needs a Windows-side check: restart the Wazuh agent so it
   re-reads `ossec.conf`, and confirm the Script Block Logging policy.

## 7. Payload tool

`xsiem-payloads.sh` + `xsiem-payloads.json` in the repo root.

| payload | severity | win event | rule | verified |
|---|---|---|---|---|
| `smb_failed_logon` | low | 4625 | 60122 | yes |
| `ssh_failed_logon` | low | 4625 | 60122 | yes |
| `rdp_failed_logon` | low | 4625 | 60122 | yes |
| `smb_successful_logon` | low | 4624 | 60106 | yes |
| `rdp_successful_logon` | low | 4624 | 60106 | yes |
| `scheduled_task_created` | low | 4698 | 60228 | yes |
| `process_created` | low | 4688 | 67027 | yes |
| `powershell_registry_delete` | low | 4104 | 91813 | **NO** |
| `account_lockout` | medium | 4740 | 60115 | yes (locks xsiem_test 10 min) |
| `smb_auth_failure_burst` | **high** | 4625 | 100100 | yes |
| `ssh_auth_failure_burst` | **high** | 4625 | 100100 | yes |
| `rdp_auth_failure_burst` | **high** | 4625 | 100100 | **NO** |

Verified live (2026-10-20):
- LOW → `60122` (06:43:24), `67027` (06:43:32), `60228`, `60106`
- MEDIUM → `60115` (07:07:21)
- HIGH → `100100` (07:05:26, plus 4/4 consecutive bursts)

The MEDIUM tier comes from `60115`, not from stock `60204` - see §5.2.

## 8. Session 2 findings (2026-10-20, later)

### 8.1 A local rule file CANNOT override a stock rule
Wazuh 4.9.2 logs: `WARNING: (7612): Rule ID '67027' is duplicated. Only the first
occurrence will be considered.` The stock ruleset loads first, so a redefinition in
`/var/ossec/etc/rules` is **ignored** - even when it repeats the stock rule's
matching conditions exactly. Silencing a stock rule therefore requires patching the
ruleset file itself:

- `config/ruleset-patches/0955-WEF-baseline_rules.xml` - 67027 -> level 0
- `config/ruleset-patches/0580-win-security_rules.xml` - 60204 -> level 0

Each patched copy differs from the stock file by **exactly one line** and is
bind-mounted over the original, so a container recreate cannot lose the patch.

### 8.2 The 60204 contest is already won by 100100
The earlier "1 in 5 bursts lost" measurement was taken while 100100 used
`if_matched_group`. With the shipped `if_matched_sid 60122` form, 100100 won
**8 of 8** consecutive bursts with 0 for 60204 *before* any suppression was added.
60204 is now level 0 as well, so the contest cannot happen at all.

### 8.3 src_ip came from agent metadata (FIXED)
The formatter read `data.srcip` - a key that does not exist in the indexed
document - and fell back to `agent.ip`, the address of the machine that REPORTED
the event. The real field is `data.win.eventdata.ipAddress` (lower-case `i`),
holding the address that ORIGINATED the event: 192.168.49.128 for a remote logon.
The indexed 4625 document has no source address under `data.win.system` at all.
Local administrative actions (60154) have no address in the event, and now show
`-` instead of the agent's IP, so local and remote are distinguishable.

### 8.4 The log field was empty for correlation alerts (FIXED)
Diffing a stored PROBE document against a stored 100100 document showed the single
decisive difference: 100100 has **no `full_log`** but **does have
`previous_output`** (a ~20 KB string with the aggregated raw event), while the
single-event PROBE rules kept `full_log`. The application only ever read
`full_log`, so every correlation alert returned an empty string. The 500-char
cap was a second, separate issue - the cap is now 4000.

### 8.5 Script Block Logging does not capture SSH-spawned PowerShell
Rule 91813 fires for interactive sessions (2026-10-20T04:11:16, a Windows-side
probe using `Remove-Item -Path HKLM:\SOFTWARE\XSIEMTest -Recurse -Force`). The
agent produced **zero** 4104 documents for PowerShell started through sshd - the
newest 4104 in the index is the Windows OpenCode session's own interactive
script. The channel works; the sshd-spawned session is the problem. The
`powershell_registry_delete` payload is therefore operator-assisted.

### 8.6 A local rule file cannot override a stock rule - see 8.1
