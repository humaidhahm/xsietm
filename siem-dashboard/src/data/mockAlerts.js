// ─────────────────────────────────────────────────────────────
//  Mock Alert Data — Wazuh SIEM Dashboard
// ─────────────────────────────────────────────────────────────

export const MOCK_ALERTS = [
  {
    id: 1,
    timestamp: "2025-03-28 02:14:33",
    rule: "Multiple failed SSH login attempts",
    severity: "high",
    src_ip: "185.220.101.47",
    dst_ip: "10.0.0.5",
    status: "open",
    agent: "web-prod-01",
    desc: "Brute-force pattern detected: 47 failed SSH authentication attempts in 60 seconds from a Tor exit node.",
    log: `[2025-03-28 02:14:33] sshd[1248]: Failed password for root from 185.220.101.47 port 54321 ssh2
[2025-03-28 02:14:34] sshd[1249]: Failed password for admin from 185.220.101.47 port 54322 ssh2
[2025-03-28 02:14:35] PAM: 47 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=185.220.101.47`,
  },
  {
    id: 2,
    timestamp: "2025-03-28 03:41:09",
    rule: "Suspicious login from unknown IP",
    severity: "high",
    src_ip: "45.33.32.156",
    dst_ip: "10.0.0.12",
    status: "open",
    agent: "auth-server-02",
    desc: "Successful authentication from an IP never seen before, outside business hours, with elevated privileges.",
    log: `[2025-03-28 03:41:09] PAM: pam_unix(sudo:session): session opened for user root by analyst1(uid=1001)
[2025-03-28 03:41:09] sudo: analyst1 : TTY=pts/1 ; PWD=/home/analyst1 ; USER=root ; COMMAND=/bin/bash`,
  },
  {
    id: 3,
    timestamp: "2025-03-28 04:55:21",
    rule: "Port scan detected",
    severity: "medium",
    src_ip: "203.0.113.45",
    dst_ip: "10.0.0.0/24",
    status: "open",
    agent: "firewall-01",
    desc: "SYN scan across 254 hosts detected on ports 22, 80, 443, 3389. Pattern matches nmap fingerprinting.",
    log: `[2025-03-28 04:55:21] kernel: iptables DROPPED IN=eth0 SRC=203.0.113.45 DST=10.0.0.1 PROTO=TCP SPT=54891 DPT=22 SYN
[2025-03-28 04:55:21] kernel: iptables DROPPED SRC=203.0.113.45 DST=10.0.0.2 DPT=22 SYN
[2025-03-28 04:55:22] kernel: iptables DROPPED SRC=203.0.113.45 DST=10.0.0.3 DPT=443 SYN`,
  },
  {
    id: 4,
    timestamp: "2025-03-28 06:12:44",
    rule: "Malware signature matched",
    severity: "high",
    src_ip: "10.0.0.77",
    dst_ip: "91.121.55.168",
    status: "open",
    agent: "ids-sensor-01",
    desc: "Outbound C2 beacon traffic matched Cobalt Strike signature on port 443 to known malicious IP.",
    log: `[2025-03-28 06:12:44] snort[4421]: [1:2019416:5] ET MALWARE CobaltStrike Beacon Activity (POST)
[Classification: A Network Trojan was Detected] {TCP} 10.0.0.77:49152 -> 91.121.55.168:443
[Priority: 1] {TCP} 10.0.0.77:49152 -> 91.121.55.168:443`,
  },
  {
    id: 5,
    timestamp: "2025-03-28 07:30:00",
    rule: "Privilege escalation attempt",
    severity: "high",
    src_ip: "10.0.0.23",
    dst_ip: "10.0.0.5",
    status: "closed",
    agent: "dev-workstation-03",
    desc: "Sudo elevation to root detected for non-admin account outside approved change window.",
    log: `[2025-03-28 07:30:00] sudo: devuser : TTY=pts/3 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash
[2025-03-28 07:30:00] PAM: pam_unix(sudo:session): session opened for user root by devuser(uid=1005)`,
  },
  {
    id: 6,
    timestamp: "2025-03-28 08:05:17",
    rule: "Unusual outbound data transfer",
    severity: "medium",
    src_ip: "10.0.0.88",
    dst_ip: "52.86.201.33",
    status: "open",
    agent: "data-server-01",
    desc: "3.2 GB transferred to external S3-like endpoint in off-hours. Possible data exfiltration.",
    log: `[2025-03-28 08:05:17] firewall: ALLOW TCP 10.0.0.88:49200 -> 52.86.201.33:443 bytes=3421277184
[2025-03-28 08:05:17] netflow: src=10.0.0.88 dst=52.86.201.33 proto=TCP duration=3614s bytes=3421277184`,
  },
  {
    id: 7,
    timestamp: "2025-03-28 08:47:55",
    rule: "DNS tunneling detected",
    severity: "medium",
    src_ip: "10.0.0.54",
    dst_ip: "8.8.8.8",
    status: "closed",
    agent: "dns-server-01",
    desc: "Anomalous DNS query patterns consistent with iodine DNS tunneling tool detected.",
    log: `[2025-03-28 08:47:55] named[882]: client 10.0.0.54: query: a1b2c3d4e5f6.tunnel.attacker.io IN TXT
[2025-03-28 08:47:56] named[882]: client 10.0.0.54: query: b2c3d4e5f6a1.tunnel.attacker.io IN TXT`,
  },
  {
    id: 8,
    timestamp: "2025-03-28 09:21:03",
    rule: "File integrity violation",
    severity: "low",
    src_ip: "10.0.0.10",
    dst_ip: "-",
    status: "closed",
    agent: "auth-server-01",
    desc: "/etc/passwd modified outside scheduled maintenance window. Hash mismatch detected by Wazuh FIM.",
    log: `[2025-03-28 09:21:03] ossec-syscheckd: Integrity checksum changed for: /etc/passwd
Old md5sum: abc123def456789012345678901234567890abcd
New md5sum: def456abc123789012345678901234567890abcd`,
  },
  {
    id: 9,
    timestamp: "2025-03-28 10:14:29",
    rule: "Failed authentication spike",
    severity: "low",
    src_ip: "172.16.0.44",
    dst_ip: "10.0.0.1",
    status: "open",
    agent: "vpn-gateway-01",
    desc: "10 failed login attempts detected on VPN gateway. Below brute-force threshold but worth monitoring.",
    log: `[2025-03-28 10:14:29] vpnd: AUTH_FAILED user=jsmith src=172.16.0.44 reason=bad_password
[2025-03-28 10:14:31] vpnd: AUTH_FAILED user=jsmith src=172.16.0.44 reason=bad_password`,
  },
  {
    id: 10,
    timestamp: "2025-03-28 11:02:14",
    rule: "Suspicious process spawned",
    severity: "medium",
    src_ip: "10.0.0.31",
    dst_ip: "-",
    status: "open",
    agent: "win-workstation-07",
    desc: "cmd.exe spawned by Office process (WINWORD.EXE). Indicative of macro-based malware execution.",
    log: `[2025-03-28 11:02:14] sysmon: ProcessCreate RuleName=-
UtcTime: 2025-03-28 11:02:14.123
ProcessGuid: {b3c4d5e6-f7a8-b9c0-d1e2-f3a4b5c6d7e8}
Image: C:\\Windows\\System32\\cmd.exe
ParentImage: C:\\Program Files\\Microsoft Office\\WINWORD.EXE
CommandLine: cmd.exe /c powershell -enc JABz...`,
  },
];

// ─────────────────────────────────────────────────────────────
//  Chart Timeline Data
// ─────────────────────────────────────────────────────────────
export const TIMELINE_DATA = [
  { time: "01:00", high: 1, medium: 0, low: 0 },
  { time: "03:00", high: 2, medium: 1, low: 0 },
  { time: "05:00", high: 1, medium: 2, low: 1 },
  { time: "07:00", high: 3, medium: 1, low: 0 },
  { time: "09:00", high: 1, medium: 2, low: 2 },
  { time: "11:00", high: 1, medium: 1, low: 1 },
];

// ─────────────────────────────────────────────────────────────
//  Investigation Mock Data
// ─────────────────────────────────────────────────────────────
export const INVESTIGATION_DATA = {
  title: "APT-2025-03 — Coordinated Multi-Vector Intrusion",
  description:
    "A coordinated attack campaign has been detected involving SSH brute-force, suspected phishing payload execution, and potential C2 beaconing. The threat actor appears to be targeting the internal authentication infrastructure with a goal of lateral movement and data exfiltration.",
  severity: "critical",
  analyst: "SOC Tier 2 — A. Rahman",
  started: "2025-03-28 02:14",
  status: "Active",
  notes:
    "Initial entry vector appears to be the SSH brute-force at 02:14. Lateral movement detected to auth-server-02 at 03:41. C2 beacon observed at 06:12 — isolate 10.0.0.77 immediately. Recommend full forensic image of dev-workstation-03. Notify IR team and escalate to Tier 3.",
  events: [
    {
      time: "02:14",
      desc: "SSH brute-force from 185.220.101.47 (Tor exit node) on web-prod-01",
      type: "high",
    },
    {
      time: "03:41",
      desc: "Successful root login on auth-server-02 from 45.33.32.156",
      type: "high",
    },
    {
      time: "04:55",
      desc: "Network port scan across 10.0.0.0/24 subnet",
      type: "medium",
    },
    {
      time: "06:12",
      desc: "CobaltStrike C2 beacon from 10.0.0.77 → 91.121.55.168:443",
      type: "high",
    },
    {
      time: "07:30",
      desc: "Privilege escalation on dev-workstation-03 via sudo",
      type: "high",
    },
    {
      time: "08:05",
      desc: "3.2 GB outbound to 52.86.201.33 — possible exfiltration",
      type: "medium",
    },
    {
      time: "11:02",
      desc: "Macro execution detected: WINWORD.EXE → cmd.exe",
      type: "medium",
    },
  ],
};
