# XSIEM — Windows monitored endpoint

This folder is the **Windows half** of the XSIEM lab: the monitored target, its agent, and the
tooling used to prepare and demonstrate it.

The other half — the Wazuh manager, the OpenSearch indexer, the FastAPI API, the React dashboard and
the payload tool — lives on the Kali Linux VM and is in the root of this repository.

## Topology

```
Windows 11 Pro  DESKTOP-GUSU8GP  192.168.49.1     monitored endpoint
   │  Wazuh agent 4.9.2  ──TLS :1515 enrol──▶  Wazuh manager
   │                    ──AES  :1514 events──▶  (Kali Linux VM, 192.168.49.128)
   │                                                │
   │  auditpol: Logon, Logoff, Other Account Logon Events, Account Lockout,
   │             Security Group Management, Other Account Management Events,
   │             Process Creation, Other Object Access Events, Registry
   ▼
   Windows Security / System / Application / PowerShell Operational /
   Windows Defender Operational / TerminalServices-LocalSessionManager logs
                                                        │
                                    OpenSearch ◀── Wazuh manager
                                        │
                                        ▼
                              FastAPI :4000 ──▶ React dashboard :3000
```

The endpoint **only ever initiates**. Nothing connects inbound to it for telemetry; the only inbound
rules are for the authorised test traffic, scoped to `192.168.49.128` only.

## Contents

| File | What it does |
|---|---|
| `Install-WazuhAgent.ps1` | Installs and enrols the Wazuh agent. The manager's API credential is read from `$env:WAZUH_API_PASSWORD`, never hardcoded. |
| `Xsiem-DemoCheck.ps1` / `.cmd` | Pre-flight check. Verifies services, enrolment, the live session to 1514, audit policies, event channels, account state, leftover artefacts, the XSIEM API and severity coverage. Prints a green/amber/red board. Pass `-evidence` to also write a timestamped report. |
| `Reset-XsiemAccount.ps1` / `.cmd` | Clears an account lockout (`/active:no` then `/active:yes`). Self-elevates. |
| `Check-KaliProgress.ps1` / `.cmd` | Confirms the server side is healthy and the payload manifest is published. |
| `xsiem-demo-brief.html` | The demo brief — architecture, data flow, run-of-show, cloud architecture mapping, the rule table, and the troubleshooting narrative. Open it in a browser. |

## Requirements

Windows 11 with PowerShell 5.1+. The scripts need elevation; the `.cmd` wrappers request it.

## Configuration

Copy `.env.example` to `.env` at the repository root and fill it in. **`.env` is gitignored — never
commit it.** The Windows scripts read the API credential from `$env:WAZUH_API_PASSWORD`.

## Safety notes

- Windows Defender and the Windows Firewall are left enabled. Never disable them to make a detection
  work.
- The inbound rules are scoped to `192.168.49.128` only. Never widen them.
- The test account `xsiem_test` is deliberately **not** a member of any privileged group.
- The privilege-escalation detection (adding a user to Administrators, which raises a HIGH-severity
  alert) is run deliberately and reverted; it is not pre-staged.
