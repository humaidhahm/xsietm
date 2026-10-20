# xsiem-payloads.sh — usage

Generates real Windows security events on the lab endpoint and verifies them in
the XSIEM API. Every payload is data-driven from `xsiem-payloads.json`; adding
a payload does not require editing this script.

## Synopsis

```
xsiem-payloads.sh [options]
```

With no options it starts the interactive menu.

## Options

| Option | Meaning |
|---|---|
| `--target IP` | Target host. Default `${XSIEM_TARGET}` (192.168.49.1). Anything outside the lab subnet is refused unless `--i-have-authorization` is given. |
| `--payload NAME` | Run one payload non-interactively. |
| `--severity low\|medium\|high` | Filter (with `--list`). |
| `--set key=value` | Override a payload parameter. Repeatable. |
| `--timeout SECONDS` | Verification timeout. Default 60. |
| `--api URL` | XSIEM API base. Default `${XSIEM_API_URL}`. |
| `--yes`, `-y` | Assume yes for confirmations. |
| `--no-verify` | Execute but do not verify. |
| `--verify-only` | Only report what has arrived recently. |
| `--cleanup` | Revert every change the tool recorded. |
| `--state-check` | Confirm the target is back to its baseline. |
| `--list` | Print the payload catalogue. Add `--format json` for JSON. |
| `--dry-run` | Print exactly what would run; touch nothing. |
| `--i-have-authorization` | Required to target a host outside the lab subnet. |
| `--i-know-this-locks` | Allow more than 9 failed logons at the real account (locks it for 10 minutes). |
| `--no-tui` | Force the plain numbered menu. |
| `--no-color` | Disable colour. |

## Environment

| Variable | Used for |
|---|---|
| `XSIEM_TARGET` | default target address |
| `XSIEM_TARGET_USER` | the lab account (default `xsiem_test`) |
| `XSIEM_TARGET_PASSWORD` | the lab account password — **required** |
| `XSIEM_API_URL` | XSIEM API base URL |
| `XSIEM_ADMIN_USER` / `XSIEM_ADMIN_PASSWORD` | optional; only for the admin-assisted payloads |

A missing `XSIEM_TARGET_PASSWORD` is a hard failure (exit 4).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success — the payload ran and the expected alert was verified |
| 1 | usage error (unknown payload, bad parameter, missing secret) |
| 2 | the payload ran but the expected alert did **not** arrive within the timeout |
| 3 | the payload itself failed to execute |
| 4 | refused by a safety check (target outside the lab, too many attempts, missing secret) |

## Interactive menu

```
  1) select target
  2) select severity
  3) select payload
  4) configure payload parameters
  5) execute selected payload (with confirmation)
  6) view result / verify only
  7) list payloads
  8) reset / cleanup (revert target changes)
  9) post-run target state check
  0) quit
```

The severity filter drives the payload list, so choosing "high" shows only the
payloads that really produce a high-severity rule. Invalid input is rejected
with a message and the menu re-prompts.

## Verification

Before a payload runs the tool records the current alert ids for the target.
Afterwards it polls the XSIEM API until an alert matching the expected rule id
and severity appears, then prints:

```
  TIMESTAMP                  RULE     SEVERITY DESCRIPTION                        SOURCE IP        AGENT
  -------------------------- -------- -------- ---------------------------------- ---------------- ----------
  2026-10-20T07:05:26  100100      HIGH    XSIEM: Windows authentication fail  192.168.49.128   win-target
```

If nothing matches before the timeout it prints what was expected, what
actually arrived, and the likely reasons (threshold not reached, agent not
forwarding, wrong event, audit policy not enabled) and exits 2.

The verifier always fetches a large page (`limit=1000`) and filters locally, so
it behaves correctly even against a backend that does not push the severity
filter into its query.

## Payload catalogue

| payload | severity | win event | rule | verified | reverts itself |
|---|---|---|---|---|---|
| `smb_failed_logon` | low | 4625 | 60122 | yes | n/a |
| `ssh_failed_logon` | low | 4625 | 60122 | yes | n/a |
| `rdp_failed_logon` | low | 4625 | 60122 | yes | n/a |
| `smb_successful_logon` | low | 4624 | 92652 | yes | n/a |
| `rdp_successful_logon` | low | 4624 | 92657 | yes | n/a |
| `scheduled_task_created` | low | 4698 | 60228 | yes | yes — the task is deleted again |
| `process_created` | low | 4688 | 67027 | yes (as **indexed**) | n/a |
| `powershell_registry_delete` | low | 4104 | 91813 | yes (operator-assisted) | n/a |
| `account_lockout` | medium | 4740 | 60115 | yes | no — locks the account for 10 min |
| `user_account_created` | medium | 4720 | 60109 | no (operator-assisted) | yes — prints the delete command |
| `privileged_group_change` | high | 4732 | 60154 | no (operator-assisted) | yes — prints the removal command |
| `smb_auth_failure_burst` | high | 4625 | 100100 | yes | n/a |
| `ssh_auth_failure_burst` | high | 4625 | 100100 | yes | n/a |
| `rdp_auth_failure_burst` | high | 4625 | 100100 | no | n/a |

A successful network logon is event 4624, but the alert that appears is rule
92652 / 92657 rather than rule 60106: 92651 is a child of 60106 and a child
consumes its parent's alert, the same way 60122 consumes 60105 for a failed
logon.

`process_created` verifies that the 4688 document reached the **index** rather
than that an alert appeared: stock rule 67027 is set to level 0 on purpose so
the process-creation flood does not bury everything else.

## Non-interactive invocations

```bash
# LOW - one failed SMB logon
./xsiem-payloads.sh --payload smb_failed_logon --yes

# LOW - successful RDP logon
./xsiem-payloads.sh --payload rdp_successful_logon --yes

# LOW - create and remove a scheduled task
./xsiem-payloads.sh --payload scheduled_task_created --yes

# MEDIUM - account lockout (locks xsiem_test for 10 minutes)
./xsiem-payloads.sh --payload account_lockout --yes --i-know-this-locks

# HIGH - 8 failed SMB logons, same source IP, inside 120 s
./xsiem-payloads.sh --payload smb_auth_failure_burst --yes

# HIGH - same, over SSH, with a longer window
./xsiem-payloads.sh --payload ssh_auth_failure_burst --yes --timeout 120

# MEDIUM - account creation, operator-assisted (prints the command to run)
./xsiem-payloads.sh --payload user_account_created --yes

# HIGH - privileged group change, operator-assisted (prints the command)
./xsiem-payloads.sh --payload privileged_group_change --yes

# catalogue, filtered
./xsiem-payloads.sh --list --severity high
./xsiem-payloads.sh --list --format json

# dry run - print what would happen, send nothing
./xsiem-payloads.sh --dry-run --payload smb_auth_failure_burst --set attempts=8

# cleanup and confirm the target is back to baseline
./xsiem-payloads.sh --cleanup
./xsiem-payloads.sh --state-check

# what has arrived recently
./xsiem-payloads.sh --verify-only
```

## Parameters

Every payload accepts `attempts` (capped at 200), `delay` between attempts, the
target `account`, and where relevant the `group`, `task_name`, `command` or
`windows_command`. `windows_command` and `revert_command` accept the
placeholders `{{PASSWORD}}`, `{{ACCOUNT}}` and `{{GROUP}}`, which are
substituted from the environment at run time so no password is ever stored in
the library.

```bash
./xsiem-payloads.sh --payload smb_auth_failure_burst --yes \
    --set attempts=8 --set delay=1 --set account=xsiem_test
```

## Safety behaviour

* Only `192.168.49.1` by default. Another address inside the lab subnet needs
  `--i-have-authorization`; anything outside it needs `--i-have-authorization`
  **and** an interactive confirmation.
* More than 9 failed logons at the real account is refused unless
  `--i-know-this-locks` is given.
* If the account is already locked the tool says so before it starts, and it
  reports a lockout as its own state — never as a generic authentication
  failure and never as a detection result.
* Every run writes a timestamped log to `logs/` and prints the run id.
