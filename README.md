# XSIEM — Wazuh SIEM dashboard + detection payload lab

A full-stack SOC dashboard on top of Wazuh 4.9.2, plus a menu-driven tool that
provokes **real** Windows security events on a lab endpoint and proves they
reached the dashboard by reading the XSIEM API.

> **Before anything else:**
> ```bash
> cp .env.example .env && $EDITOR .env      # fill in every credential
> set -a; . ./.env; set +a
> ```
> No credential is stored in this repository. The backend, the payload tool and
> the Compose stack all read secrets from the environment and **fail loudly**
> when one is missing.

---

## What is in here

| Path | What it is |
|---|---|
| `siem-backend/` | FastAPI backend. Reads alerts straight from the Wazuh indexer, authenticates to the manager API, and serves the dashboard's REST API. |
| `siem-dashboard/` | React 18 dashboard (Recharts, Tailwind). Dark SOC theme, alert table, agent list, investigation view. |
| `tools/` | `xsiem-payloads.sh` + `xsiem-payloads.json` — the interactive payload tool and its data-driven payload library. |
| `compose/` | Wazuh 4.9.2 single-node stack (manager + indexer + dashboard) plus the custom rules and the two patched stock ruleset files. |
| `docs/` | `GROUND-TRUTH.md` (the findings that shaped this lab) and the generated payload manifest. |
| `windows-endpoint/` | The Windows half: agent installer, pre-flight checker, lockout reset, demo brief. |

## Prerequisites

* Linux host with Docker Engine + Docker Compose v2 (`docker compose`)
* `openssl`, `curl`, `jq`, `python3` (3.11+), `node` 18+
* The Wazuh agent MSI and the `rootCA.pem` from `windows-endpoint/`
* A Windows endpoint that is allowed to talk to the SIEM

## Running the whole thing from scratch

### 1. Configure

```bash
cp .env.example .env && $EDITOR .env
set -a; . ./.env; set +a
```

### 2. Start the Wazuh stack (manager + indexer + dashboard)

```bash
cd compose
cp ../.env .env                  # the stack reads compose/.env
./deploy.sh                      # generates certs, issues the authd cert, starts the stack
```

`deploy.sh` is idempotent: re-running it will not regenerate certificates that
already exist. It also issues the manager's **authd TLS certificate** from the
freshly generated root CA — the stock Wazuh 4.9.2 image ships a self-signed
certificate that expired on 2025-11-05, which silently blocks agent enrolment
(see `docs/GROUND-TRUTH.md`).

### 3. Start the backend

```bash
cd siem-backend
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port 4000
```

The backend auto-loads `siem-backend/.env` when present; otherwise it needs the
variables exported. It refuses to start if a required credential is missing.

### 4. Build and serve the dashboard

```bash
cd siem-dashboard
npm install
npm run build
python3 -m http.server 3000 --bind 0.0.0.0 --directory build
```

A production build is served rather than `npm start` on purpose: the CRA dev
server keeps a webpack watcher resident (hundreds of MB) and the app has no
client-side router, so a plain static server needs no SPA fallback.

### 5. Open it

| | |
|---|---|
| XSIEM dashboard | http://192.168.49.128:3000 |
| XSIEM API | http://192.168.49.128:4000 — Swagger UI at `/docs` |
| Wazuh dashboard | https://localhost/ (`${WAZUH_DASHBOARD_USER}` / `.env`) |
| Wazuh API | https://localhost:55000 (`${WAZUH_API_USER}` / `.env`) |
| Indexer | https://localhost:9200 (`${WAZUH_INDEXER_USER}` / `.env`) |

## The payload tool

```bash
cd tools
./xsiem-payloads.sh                    # interactive menu
./xsiem-payloads.sh --list             # the catalogue
./xsiem-payloads.sh --payload smb_auth_failure_burst --yes
```

Full usage: [`tools/xsiem-payloads-USAGE.md`](tools/xsiem-payloads-USAGE.md).

The tool reads `XSIEM_TARGET`, `XSIEM_TARGET_USER` and `XSIEM_TARGET_PASSWORD`
from the environment. It refuses to target anything outside the lab subnet
unless `--i-have-authorization` is given, and refuses to send more than nine
failed logons at the real account unless `--i-know-this-locks` is given,
because the target's lockout threshold is 10 and a locked account breaks every
SSH/RDP payload for ten minutes.

Exit codes: `0` success · `1` usage error · `2` verification failed ·
`3` payload execution failed · `4` refused by a safety check.

## Known issues

* **Three stray `PROBE ...` alerts remain in the OpenSearch index** (rules
  100205, 100207, 100210). They were temporary diagnostic rules used to work
  out how Wazuh assigns frequency-rule counters. The rules are gone from the
  ruleset, but Wazuh alerts are immutable once indexed, so those three
  documents stay in the index until the index lifecycle removes them.
* **Rule 60204 ("Multiple Windows Logon Failures", MEDIUM) never fires** while
  the custom rule 100100 exists — Wazuh keeps one composite frequency counter
  per matched event stream, so the two rules compete for it. 60204 is set to
  level 0 so the contest cannot happen at all, and the MEDIUM tier of the demo
  is covered by rules 60115 (account lockout), 60109, 60111 and 19004.
* **PowerShell script blocks are not captured for SSH-spawned sessions.** Rule
  91813 fires for interactive sessions but the Wazuh agent produced no 4104
  document at all for PowerShell started through sshd, so that payload is
  operator-assisted.
* The payload tool talks to the target over SMB/SSH/RDP with a deliberately
  small amount of traffic. It is a lab tool, not a stress test.

## Safety notes

* The tool only ever targets `192.168.49.1` by default and refuses a public
  address outright.
* Payloads are detection-relevant only: failed logons, a scheduled task, a
  process, a registry key, a group membership change. Nothing destructive, no
  disk writes, no persistence, no mass account creation.
* Nothing disables Defender or the firewall, and nothing modifies the Wazuh
  manager, the indexer or the ruleset beyond the two documented changes
  (the custom rule file and the two patched stock rules).
