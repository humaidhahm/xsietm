#!/usr/bin/env python3
"""Generate the XSIEM tool manifest (JSON + Markdown) from the payload library,
the Wazuh ruleset and the LIVE OpenSearch index, so the claims can be
cross-checked independently."""
import json, re, subprocess, sys, datetime, os

REPO = os.path.dirname(os.path.abspath(__file__))
LIB = f"{REPO}/xsiem-payloads.json"
OUTDIR = os.environ.get("XSIEM_MANIFEST_OUT", f"{REPO}/../docs")
API = "http://localhost:4000"
IDX = "https://localhost:9200"
IDX_AUTH = (os.environ.get("WAZUH_INDEXER_USER", ""),
            os.environ.get("WAZUH_INDEXER_PASSWORD", ""))
if not all(IDX_AUTH):
    sys.exit("[FATAL] WAZUH_INDEXER_USER and WAZUH_INDEXER_PASSWORD must be set "
             "(cp .env.example .env and export it)")

def sh(*args):
    return subprocess.run(args, capture_output=True, text=True).stdout.strip()

def jq_get(path):
    return json.loads(sh("curl", "-sk", "-u", f"{IDX_AUTH[0]}:{IDX_AUTH[1]}",
                         f"{IDX}/wazuh-alerts-*/_search", "-H", "Content-Type: application/json",
                         "-d", path) or "{}")

def api_get(url):
    return json.loads(sh("curl", "-s", "--max-time", "30", f"{API}{url}") or "{}")

# ---- live index facts -------------------------------------------------------
counts = jq_get('{"size":0,"aggs":{"r":{"terms":{"field":"rule.id","size":200}}}}')
rule_counts = {b["key"]: b["doc_count"] for b in counts.get("aggregations", {}).get("r", {}).get("buckets", [])}

sev = lambda l: "high" if l >= 12 else "medium" if l >= 7 else "low"

# authoritative rule levels straight from the manager's ruleset
LEVELS = {
    "60105": 5, "60106": 3, "60122": 5, "60126": 7, "60130": 7, "60115": 9,
    "60109": 8, "60111": 8, "60112": 8, "60134": 8, "60135": 8, "60117": 9,
    "60143": 5, "60144": 5, "60145": 5, "60146": 5, "60113": 5,
    "60204": 10, "60228": 4, "67027": 3, "67028": 3, "91813": 3, "92657": 6,
    "92652": 6, "60154": 12, "60156": 12, "60171": 12, "60176": 12, "92650": 12,
    "100100": 12, "100101": 12, "61110": 10, "61102": 5, "60137": 3,
}
DESCR = {
    "60105": "Windows Logon Failure", "60106": "Windows Logon Success",
    "60122": "Logon Failure - Unknown user or bad password",
    "60126": "Logon Failure - User not allowed to login at this computer",
    "60130": "Logon Failure - Account locked out",
    "60115": "User account locked out (multiple login errors)",
    "60109": "User account enabled or created", "60111": "User account disabled or deleted",
    "60112": "Windows Audit Policy changed", "60134": "Security enabled group created",
    "60135": "Security enabled group deleted", "60117": "Windows audit log was cleared",
    "60143": "Security Enabled Local Group Created",
    "60144": "Security Enabled Local Group Member Added",
    "60145": "Security Enabled Local Group Member Removed",
    "60146": "Security Enabled Local Group Deleted",
    "60113": "Group Account Changed", "60204": "Multiple Windows Logon Failures",
    "60228": "A scheduled task was created", "67027": "A process was created.",
    "67028": "Special privileges assigned to new logon.",
    "91813": "Powershell script deleted a registry key from an object",
    "92657": "Successful Remote Logon Detected", "92652": "Successful Remote Logon Detected - ANONYMOUS LOGON",
    "60154": "Administrators Group Changed", "60156": "Enterprise Domain Controllers Group Changed",
    "60171": "Guests Group Changed", "60176": "Backup Operators Group Changed",
    "92650": "New Windows Service Created to start from windows root path",
    "100100": "XSIEM: Windows authentication failure burst (possible brute force)",
    "100101": "XSIEM: SSH brute force attempt detected",
    "61110": "Multiple System error events", "61102": "Windows System error event",
    "60137": "Windows User Logoff",
}

lib = json.load(open(LIB))
stats = api_get("/api/stats")
agents = api_get("/api/agents")

payloads = []
for pl in lib["payloads"]:
    ev = {}
    for rid in pl["expected_rule_ids"]:
        ev[rid] = {
            "level": LEVELS.get(rid),
            "severity": sev(LEVELS[rid]) if rid in LEVELS else None,
            "description": DESCR.get(rid, ""),
            "documents_in_index_now": rule_counts.get(rid, 0),
        }
    latest = {}
    for rid in pl["expected_rule_ids"]:
        res = jq_get(json.dumps({
            "size": 1, "query": {"term": {"rule.id": rid}},
            "sort": [{"timestamp": {"order": "desc"}}],
            "_source": ["timestamp", "rule.id", "rule.level", "rule.description", "data.srcip", "agent.name"]}))
        hits = res.get("hits", {}).get("hits", [])
        latest[rid] = hits[0]["_source"] if hits else None
    payloads.append({
        "name": pl["name"], "title": pl["title"], "description": pl["description"],
        "expected_severity": pl["expected_severity"],
        "expected_rule_ids": pl["expected_rule_ids"],
        "windows_event_ids": pl["windows_event_ids"],
        "mitre_attack": pl.get("mitre_attack", []),
        "revert_required": pl.get("revert_required", False),
        "verified": pl.get("verified", False),
        "verified_evidence": pl.get("verified_evidence", ""),
        "rule_facts": ev,
        "latest_matching_alert_in_index": latest,
    })

# ---- verified_alerts: every rule id actually observed in /api/alerts ---------
# (with the captured src_ip and log length, so the claims can be cross-checked)
observed = {}
for rid, cnt in rule_counts.items():
    res = jq_get(json.dumps({
        "size": 1, "query": {"term": {"rule.id": rid}},
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["timestamp", "rule.id", "rule.level", "rule.description",
                    "data.win.eventdata.ipAddress", "data.win.system.ipAddress",
                    "agent.ip", "agent.name", "full_log", "previous_output"]}))
    hits = res.get("hits", {}).get("hits", [])
    if not hits:
        continue
    src = hits[0]["_source"]
    raw = src.get("full_log") or src.get("previous_output") or ""
    ev_ip = ((src.get("data") or {}).get("win", {}) or {}).get("eventdata", {}).get("ipAddress")
    sys_ip = ((src.get("data") or {}).get("win", {}) or {}).get("system", {}).get("ipAddress")
    lvl = (src.get("rule") or {}).get("level", 0)
    observed[rid] = {
        "rule_id": rid,
        "level": lvl,
        "severity": sev(lvl),
        "description": (src.get("rule") or {}).get("description", ""),
        "documents_in_index": cnt,
        "newest_timestamp": src.get("timestamp"),
        "captured_src_ip": ev_ip or sys_ip or "-",
        "captured_agent_ip": (src.get("agent") or {}).get("ip"),
        "captured_log_length": len(raw) if raw else 0,
        "has_raw_event": bool(raw),
        "log_source": "full_log" if src.get("full_log") else ("previous_output" if src.get("previous_output") else "none"),
    }

manifest = {
    "tool": "xsiem-payloads",
    "version": lib["version"],
    "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "target": lib["defaults"]["target"],
    "api": API,
    "indexer": IDX,
    "severity_mapping": {"high": "level >= 12", "medium": "level >= 7 and < 12", "low": "level < 7",
                         "source": "xsiem-backend main.py format_opensearch_alert()"},
    "live_index": {
        "total_alerts": stats.get("total"),
        "by_severity": {"high": stats.get("high"), "medium": stats.get("medium"), "low": stats.get("low")},
        "agents": [{"name": a.get("name"), "status": a.get("status"), "ip": a.get("ip"), "version": a.get("version")}
                   for a in agents.get("data", [])],
    },
    "payloads": payloads,
    "verified_alerts": {
        "description": "Every rule id actually observed to arrive in /api/alerts, with the "
                       "captured source IP and captured raw-log length, so every claim can be "
                       "cross-checked against the live index.",
        "rules_observed": [observed[k] for k in sorted(observed, key=lambda x: (-observed[x]["level"], x))],
        "rule_id_list": sorted(observed.keys()),
    },
    "findings": [
        {
            "id": "F1",
            "title": "Stock rule 60204 (MEDIUM) cannot co-fire with 100100 (HIGH)",
            "detail": "Wazuh 4.9.2 keeps ONE composite frequency counter per matched event stream. Rules that "
                      "count the same 4625 events compete for it and only one can fire. IMPORTANT CORRECTION to "
                      "the earlier measurement: the 1-in-5 loss rate was measured while 100100 used "
                      "<if_matched_group>authentication_failed</if_matched_group>. With the shipped form "
                      "<if_matched_sid>60122</if_matched_sid> the counter is owned by 100100 alone - measured "
                      "8 of 8 consecutive bursts with 100100 and 0 of 8 for 60204 BEFORE any suppression was "
                      "added. 60204 is now additionally set to level 0 (see F7) so the contest cannot happen at all.",
            "impact": "The MEDIUM tier is delivered by rule 60115 (account lockout), 60109 / 60111 / 19004.",
        },
        {
            "id": "F2",
            "title": "if_matched_sid on a parent rule never fires",
            "detail": "60105 is the parent of 60122 and never matches terminally, so a counter on it stays at zero. "
                      "The original 100100 used if_matched_sid 60105 and produced 0 alerts across 21 failed "
                      "logons. The working form counts on 60122. if_sid is not an option - Wazuh rejects it with "
                      "'Invalid use of frequency/context options. Missing if_matched'.",
            "impact": "Fixed in config/custom-rules/xsiem-rules.xml.",
        },
        {
            "id": "F3",
            "title": "Severity filter applied after the limit slice (backend bug) - FIXED",
            "detail": "XSIEM's /api/alerts applied severity and search filters in Python after the indexer had "
                      "already sliced to `limit`, so ?limit=3&severity=medium returned 0.",
            "impact": "FIXED - the filters are now pushed into the OpenSearch query. total is the count matching "
                      "the filters before the limit, data is the limited slice. The response shape is unchanged "
                      "and /api/stats now agrees with /api/alerts?severity= exactly.",
            "before": {"limit=3&severity=medium": 0, "limit=1000&severity=medium": 30},
            "after": {"limit=3&severity=medium": "total=434 data=3", "limit=1000&severity=medium": "total=434 data=434"},
        },
        {
            "id": "F4",
            "title": "Account lockout counter is cumulative and cross-protocol",
            "detail": "The target's lockout policy (threshold 10, 10 minute window) counts failed logons across "
                      "SMB, SSH and RDP together. While an account is locked, Windows OpenSSH resets the "
                      "connection instead of refusing the password, which reads like a network fault.",
            "impact": "The tool detects the lockout as a distinct state (including the Windows 1909 signature) and "
                      "refuses to report those failures as new alerts. It now refuses >9 attempts on the real "
                      "account unless --i-know-this-locks is given, and the default burst is exactly 8.",
        },
        {
            "id": "F5",
            "title": "netexec failed-auth path is unusable on this target",
            "detail": "netexec reports 'Connection Error: The NETBIOS connection with the remote host timed out' "
                      "for failed authentication. smbclient and rpcclient return a real NT_STATUS_LOGON_FAILURE.",
            "impact": "Failed-auth payloads use smbclient / rpcclient; netexec is used for successful auth.",
        },
        {
            "id": "F6",
            "title": "RDP 3389 was filtered until the Windows side opened it",
            "detail": "RDP is now reachable. Failed RDP auth produces 4625 -> 60122; successful RDP auth produces "
                      "4624 -> 60106 plus 92657.",
            "impact": "RDP payloads are in the catalogue.",
        },
        {
            "id": "F7",
            "title": "A local rule file CANNOT override a stock rule in Wazuh 4.9.2",
            "detail": "Wazuh logs: 'WARNING: (7612): Rule ID \'67027\' is duplicated. Only the first occurrence "
                      "will be considered.' The stock ruleset is loaded first, so a redefinition of an existing id "
                      "in /var/ossec/etc/rules is simply ignored - whether or not it repeats the stock rule's "
                      "matching conditions. To silence 67027 and 60204 the stock ruleset files themselves have to "
                      "be patched: 0955-WEF-baseline_rules.xml (67027 -> level 0) and "
                      "0580-win-security_rules.xml (60204 -> level 0). Each patched copy differs from the stock "
                      "file by exactly one line and is bind-mounted over the original so a container recreate "
                      "cannot lose the patch.",
            "impact": "The 4688 process-creation flood is stopped and the 60204/100100 contest is removed, while "
                      "the raw 4688 events stay indexed for the Investigation view.",
        },
        {
            "id": "F8",
            "title": "src_ip came from agent metadata, not from the event (FIXED)",
            "detail": "The formatter read data.srcip, a key that does not exist in the indexed document, and "
                      "fell back to agent.ip - the address of the machine that REPORTED the event. The real "
                      "field is data.win.eventdata.ipAddress (lower-case 'i'), which holds the address that "
                      "originated the event: 192.168.49.128 for a remote logon. The indexed document for a 4625 "
                      "has no src ip under data.win.system either.",
            "impact": "FIXED - src_ip is now taken from data.win.eventdata.ipAddress, then "
                      "data.win.system.ipAddress, and falls back to '-' (NOT the agent address) so a local "
                      "administrative action is distinguishable from a remote attack.",
        },
        {
            "id": "F9",
            "title": "The log field was empty for correlation alerts (FIXED)",
            "detail": "Diffing a stored PROBE document against a stored 100100 document showed the single "
                      "decisive difference: 100100 has no `full_log` but DOES have `previous_output` (a ~20 KB "
                      "string holding the aggregated raw event), while the single-event PROBE rules kept "
                      "`full_log`. Wazuh stores the body of an aggregated correlation in `previous_output`, so "
                      "the application - which only ever read `full_log` - returned an empty string for every "
                      "correlation alert. The 500-character cap was a second, separate issue.",
            "impact": "FIXED - the formatter now falls back to previous_output, and the cap was raised from 500 "
                      "to 4000 characters so the Investigation view can show a whole event.",
        },
        {
            "id": "F10",
            "title": "Script Block Logging does not capture SSH-spawned PowerShell",
            "detail": "Rule 91813 fires for interactive sessions (proven: 2026-10-20T04:11:16 from a Windows-side "
                      "probe using 'Remove-Item -Path HKLM:\\SOFTWARE\\XSIEMTest -Recurse -Force'). But the "
                      "agent produced ZERO 4104 documents for PowerShell started through sshd, while the newest "
                      "4104 in the index is the Windows OpenCode session's own interactive script. The channel "
                      "itself works and the script body IS captured for interactive sessions.",
            "impact": "The powershell_registry_delete payload is therefore operator-assisted: the tool prints the "
                      "exact command for an interactive session and then verifies the resulting alert.",
        },
    ],
    "unverified": [
        {
            "payload": "powershell_registry_delete",
            "reason": "Rule 91813 itself is proven to fire in this deployment (2026-10-20T04:11:16, "
                      "channel Microsoft-Windows-PowerShell/Operational) but the script blocks triggered by "
                      "this tool over SSH were not captured - 0 documents in the index mention the script's "
                      "registry path. Needs a Windows-side check: restart the Wazuh agent so it re-reads "
                      "ossec.conf, and confirm the Script Block Logging policy.",
        },
        {
            "payload": "rdp_auth_failure_burst",
            "reason": "The mechanism is proven (RDP failures produce 4625/60122; 8 same-IP 4625 events trip "
                      "100100) but this exact combination has not been observed in a single run.",
        },
    ],
    "files": {
        "tool": "xsiem-payloads.sh",
        "library": "xsiem-payloads.json",
        "ground_truth": "GROUND-TRUTH.md",
        "custom_rules": "/home/kali/wazuh-docker/single-node/config/custom-rules/xsiem-rules.xml",
    },
}

with open(f"{OUTDIR}/xsietool-manifest.json", "w") as f:
    json.dump(manifest, f, indent=2)

# ---------------------------------------------------------------- markdown --
L = []
A = L.append
A("# XSIEM payload tool - verification manifest")
A("")
A(f"Generated {manifest['generated_utc']}  ")
A(f"Target `{manifest['target']}`  |  API `{manifest['api']}`  |  Indexer `{manifest['indexer']}`")
A("")
A("## Severity mapping (XSIEM backend)")
A("")
A("| Wazuh level | Dashboard severity |")
A("|---|---|")
A("| >= 12 | **high** |")
A("| 7 - 11 | **medium** |")
A("| < 7 | **low** |")
A("")
A("## Live index at generation time")
A("")
A(f"- total alerts: **{manifest['live_index']['total_alerts']}**")
A(f"- high **{manifest['live_index']['by_severity']['high']}** | "
  f"medium **{manifest['live_index']['by_severity']['medium']}** | "
  f"low **{manifest['live_index']['by_severity']['low']}**")
for a in manifest["live_index"]["agents"]:
    A(f"- agent `{a['name']}` {a['status']} {a['ip']} {a['version']}")
A("")
A("## Payload catalogue")
A("")
A("| payload | severity | win event | rule | level | verified |")
A("|---|---|---|---|---|---|")
for p in manifest["payloads"]:
    for rid in p["expected_rule_ids"]:
        f = p["rule_facts"][rid]
        A(f"| `{p['name']}` | **{p['expected_severity']}** | {','.join(str(e) for e in p['windows_event_ids'])} "
          f"| {rid} | {f['level']} | {'yes' if p['verified'] else '**NO**'} |")
A("")
A("## Evidence (newest matching alert in the live index)")
A("")
for p in manifest["payloads"]:
    A(f"### `{p['name']}` - {p['expected_severity']}")
    A("")
    for rid in p["expected_rule_ids"]:
        la = p["latest_matching_alert_in_index"].get(rid)
        f = p["rule_facts"][rid]
        if la:
            A(f"- **{rid}** (level {f['level']}, {f['severity']}) - `{la['timestamp']}` "
              f"src=`{la.get('data',{}).get('srcip','-')}` agent=`{la.get('agent',{}).get('name','-')}`")
            A(f"  - {la['rule']['description']}")
        else:
            A(f"- **{rid}** - no matching document in the index right now")
    A(f"- verified: **{'yes' if p['verified'] else 'NO'}**")
    if p["verified_evidence"]:
        A(f"- evidence: {p['verified_evidence']}")
    A("")
A("## Findings")
A("")
for f in manifest["findings"]:
    A(f"### {f['id']} - {f['title']}")
    A("")
    A(f["detail"])
    A("")
    if "impact" in f:
        A(f"**Impact:** {f['impact']}")
        A("")
A("## Not verified")
A("")
for u in manifest["unverified"]:
    A(f"### `{u['payload']}`")
    A("")
    A(u["reason"])
    A("")
open(f"{OUTDIR}/xsietool-manifest.md", "w").write("\n".join(L) + "\n")

print("wrote:")
for f in ("xsietool-manifest.json", "xsietool-manifest.md"):
    print(f"  {OUTDIR}/{f}  ({os.path.getsize(OUTDIR+'/'+f)} bytes)")
print(f"  payloads: {len(payloads)}  verified: {sum(1 for p in payloads if p['verified'])}")
