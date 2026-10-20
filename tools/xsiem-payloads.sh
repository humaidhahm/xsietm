#!/usr/bin/env bash
# =============================================================================
#  xsiem-payloads.sh - interactive payload generator + verifier for the XSIEM lab
#
#  Provokes real Windows security events on the lab target and proves they
#  reached the XSIEM dashboard by reading the XSIEM API.
#
#  Usage:
#    xsiem-payloads.sh                          interactive menu
#    xsiem-payloads.sh --list [--format json]   list the payload catalogue
#    xsiem-payloads.sh --dry-run --payload NAME [options]
#    xsiem-payloads.sh --payload NAME --yes [--set k=v ...]
#
#  Exit codes:  0 success   1 usage error   2 verification failed
#               3 payload execution failed   4 refused by safety check
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="${XSIEM_PAYLOAD_LIB:-$SCRIPT_DIR/xsiem-payloads.json}"
STATE_DIR="$SCRIPT_DIR/state"
LOG_DIR="$SCRIPT_DIR/logs"
STATE_FILE="$STATE_DIR/pending-reverts.json"

# ----------------------------------------------------------------- defaults --
TARGET=""; API=""; PAYLOAD=""; TIMEOUT=""; VERIFY_LIMIT=""
SEVERITY_FILTER=""; SET_ARGS=(); ASSUME_YES=0; NO_VERIFY=0; DO_DRYRUN=0
DO_LIST=0; LIST_FORMAT="table"; VERIFY_ONLY=0; I_HAVE_AUTH=0
DO_CLEANUP=0; DO_STATE_CHECK=0; LOCKOUT_OCCURRED=0; I_KNOW_THIS_LOCKS=0
CONFIRM_REVERT=1

# ------------------------------------------------------------------ colours --
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RESET=$'\033[0m'; C_B=$'\033[1m'; C_DIM=$'\033[2m'
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
  C_BLU=$'\033[34m'; C_CYN=$'\033[36m'; C_MAG=$'\033[35m'
else
  C_RESET=""; C_B=""; C_DIM=""; C_RED=""; C_GRN=""; C_YEL=""
  C_BLU=""; C_CYN=""; C_MAG=""
fi

RUN_ID=""; LOG_FILE=""

# =============================================================================
#  Logging
# =============================================================================
init_log() {
  RUN_ID="$(date +%Y%m%d-%H%M%S)-$$"
  mkdir -p "$LOG_DIR" "$STATE_DIR"
  LOG_FILE="$LOG_DIR/xsiem-payloads-$RUN_ID.log"
  : > "$LOG_FILE"
  log "run id          : $RUN_ID"
  log "payload library : $LIB"
  log "argv            : $*"
}

log()  { printf '[%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*" >>"$LOG_FILE" 2>/dev/null || true; }
logq() { printf '%s' "$*" >>"$LOG_FILE" 2>/dev/null || true; printf '\n' >>"$LOG_FILE" 2>/dev/null || true; }

die()  { printf '%s\n' "${C_RED}[ERROR]${C_RESET} $*" >&2; exit "${2:-1}"; }
warn() { printf '%s\n' "${C_YEL}[!]${C_RESET} $*"; }
ok()   { printf '%s\n' "${C_GRN}[+]${C_RESET} $*"; }
info() { printf '%s\n' "${C_CYN}[i]${C_RESET} $*"; }
dim()  { printf '%s\n' "${C_DIM}$*${C_RESET}"; }

banner() {
  printf '\n%s\n' "${C_B}${C_CYN}================================================================${C_RESET}"
  printf '%s\n'   "${C_B}${C_CYN} $1${C_RESET}"
  printf '%s\n'   "${C_B}${C_CYN}================================================================${C_RESET}"
}

# =============================================================================
#  Small helpers
# =============================================================================
have() { command -v "$1" >/dev/null 2>&1; }

lib_get() { jq -r "$1" "$LIB"; }

payload_field() { # $1=payload name  $2=field
  jq -r --arg n "$1" --arg f "$2" '.payloads[] | select(.name==$n) | .[$f] // empty' "$LIB"
}

# Same as payload_field but emits compact JSON (for arrays / objects).
payload_field_json() { # $1=payload name  $2=field
  jq -c --arg n "$1" --arg f "$2" '.payloads[] | select(.name==$n) | .[$f] // empty' "$LIB"
}

payload_exists() { jq -e --arg n "$1" '.payloads[] | select(.name==$n)' "$LIB" >/dev/null 2>&1; }

param_default() { # payload param -> default
  jq -r --arg n "$1" --arg p "$2" \
    '.payloads[] | select(.name==$n) | .params[] | select(.name==$p) | (.default|tostring)' "$LIB"
}

param_spec() { # payload param -> json of the spec
  jq -c --arg n "$1" --arg p "$2" \
    '.payloads[] | select(.name==$n) | .params[] | select(.name==$p)' "$LIB"
}

# =============================================================================
#  Safety
# =============================================================================
ALLOWED_TARGET=""; LAB_CIDR=""
load_safety() {
  ALLOWED_TARGET="$(lib_get '.safety.allowed_default_target')"
  LAB_CIDR="$(lib_get '.safety.lab_cidr')"
}

target_is_private_lab() {
  local ip="$1"
  local net="${LAB_CIDR%/*}" prefix="${LAB_CIDR#*/}"
  [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
  local n="${prefix%%/*}"; n="${n:-24}"
  local -a ipa neta
  IFS='.' read -r -a ipa <<<"$ip"
  IFS='.' read -r -a neta <<<"$net"
  local i
  for ((i = 0; i < n / 8; i++)); do
    [[ "${ipa[i]:-}" == "${neta[i]:-}" ]] || return 1
  done
  return 0
}

safety_check_target() {
  local ip="$1"
  if [[ -z "$ip" ]]; then die "No target specified." 1; fi
  if ! [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    die "Target must be a IPv4 address, got '$ip'." 4
  fi
  if [[ "$ip" == "$ALLOWED_TARGET" ]]; then
    log "safety: target $ip is the default lab target - allowed"
    return 0
  fi
  if target_is_private_lab "$ip"; then
    if [[ "$I_HAVE_AUTH" -ne 1 ]]; then
      printf '\n%s\n' "${C_RED}[REFUSED]${C_RESET} '$ip' is inside the lab subnet ($LAB_CIDR) but is not the"
      printf '  default target %s.\n' "$ALLOWED_TARGET"
      printf '  Re-run with --i-have-authorization to target another lab host.\n\n'
      log "safety: REFUSED $ip (in lab subnet, not default, no --i-have-authorization)"
      exit 4
    fi
    warn "targeting $ip (lab subnet, authorised flag given)"
    log "safety: allowed $ip with --i-have-authorization"
    return 0
  fi
  # Not in the lab subnet at all -> refuse unless the explicit flag AND an
  # interactive confirmation are both given.
  printf '\n%s\n' "${C_RED}[REFUSED]${C_RESET} '$ip' is NOT in the lab subnet ($LAB_CIDR)."
  printf '  This tool refuses to touch hosts outside the lab by default.\n'
  if [[ "$I_HAVE_AUTH" -ne 1 ]]; then
    printf '  If you own this host and have written authorisation, re-run with:\n'
    printf '      --i-have-authorization --confirm-remote\n\n'
    log "safety: REFUSED $ip (outside lab subnet, no --i-have-authorization)"
    exit 4
  fi
  if [[ "$ASSUME_YES" -ne 1 ]]; then
    printf '  Type %sI HAVE AUTHORIZATION%s to proceed: ' "$C_B" "$C_RESET"
    local reply=""; read -r reply
    if [[ "$reply" != "I HAVE AUTHORIZATION" ]]; then
      printf '\n%s\n' "${C_YEL}Aborted.${C_RESET}"
      log "safety: aborted by user for $ip"
      exit 4
    fi
  fi
  warn "targeting $ip (outside lab subnet, explicitly authorised)"
  log "safety: allowed $ip (outside lab subnet, explicit authorisation given)"
}

# =============================================================================
#  Parameter handling
# =============================================================================
declare -A PARAMS=()

validate_param() { # name spec value -> prints error and returns 1 if invalid
  local name="$1" spec="$2" val="$3"
  local type; type="$(jq -r '.type' <<<"$spec")"
  local minv maxv
  minv="$(jq -r '.min // empty' <<<"$spec")"
  maxv="$(jq -r '.max // empty' <<<"$spec")"
  case "$type" in
    int)
      if ! [[ "$val" =~ ^-?[0-9]+$ ]]; then
        printf '  %s must be a whole number (got %q)\n' "$name" "$val"; return 1
      fi
      if [[ -n "$minv" && "$val" -lt "$minv" ]]; then
        printf '  %s must be >= %s (got %s)\n' "$name" "$minv" "$val"; return 1
      fi
      if [[ -n "$maxv" && "$val" -gt "$maxv" ]]; then
        printf '  %s must be <= %s (got %s)\n' "$name" "$maxv" "$val"; return 1
      fi
      ;;
    bool)
      case "$val" in true|false|yes|no|1|0) ;; *)
        printf '  %s must be true/false (got %q)\n' "$name" "$val"; return 1 ;;
      esac
      ;;
    string)
      if [[ ${#val} -gt 256 ]]; then
        printf '  %s is too long (>256 chars)\n' "$name"; return 1
      fi
      ;;
  esac
  return 0
}

normalise_bool() {
  case "$1" in true|yes|1) echo "true";; *) echo "false";; esac
}

load_defaults() { # payload
  local p="$1" name
  while IFS=$'\t' read -r name def; do
    [[ -z "$name" ]] && continue
    PARAMS["$name"]="$def"
  done < <(jq -r --arg n "$p" '.payloads[]|select(.name==$n)|.params[]|"\(.name)\t\(.default|tostring)"' "$LIB")
}

apply_set_args() { # payload  (applies --set key=value)
  local p="$1" kv key val spec
  for kv in "${SET_ARGS[@]}"; do
    key="${kv%%=*}"; val="${kv#*=}"
    if [[ "$kv" != *=* ]]; then die "--set expects key=value, got '$kv'" 1; fi
    spec="$(param_spec "$p" "$key")"
    if [[ -z "$spec" ]]; then
      die "Unknown parameter '$key' for payload '$p'. Known: $(jq -r --arg n "$p" '.payloads[]|select(.name==$n)|.params[].name|join(", ")' "$LIB")" 1
    fi
    if ! validate_param "$key" "$spec" "$val"; then die "Invalid value for '$key'" 1; fi
    PARAMS["$key"]="$val"
  done
}

# =============================================================================
#  Snapshot / verify
# =============================================================================
snapshot_file() { echo "$STATE_DIR/snapshot-$RUN_ID.txt"; }

snapshot_alerts() { # -> writes a JSON array of alert ids to file, prints the count
  local f; f="$(snapshot_file)"
  local body
  body="$(curl -s --max-time 30 "$API/api/alerts?limit=$VERIFY_LIMIT" 2>/dev/null)"
  if [[ -z "$body" ]]; then
    echo '[]' > "$f"
    echo 0
    return 0
  fi
  # Store as a JSON array of ids so jq --slurpfile can read it back.
  jq -c '[.data[]?.id]' <<<"$body" > "$f" 2>/dev/null || echo '[]' > "$f"
  jq -r '.total // 0' <<<"$body" 2>/dev/null || echo 0
}

verify_payload() { # payload
  local p="$1"
  local sev; sev="$(payload_field "$p" expected_severity)"
  local mode; mode="$(payload_field "$p" verify_mode)"; mode="${mode:-alert}"

  # "indexed" mode: the event is deliberately NOT alerted on (e.g. rule 67027 is
  # overridden to level 0 to stop the 4688 flood) but the raw document must
  # still have reached the index for investigation.
  if [[ "$mode" == "indexed" ]]; then
    local evs; evs="$(jq -c '.windows_event_ids' <<<"$(payload_field_json "$p" windows_event_ids)")"
    local deadline2=$(( $(date +%s) + TIMEOUT ))
    local found2=0 body2
    while [[ $(date +%s) -lt $deadline2 ]]; do
      body2="$(curl -s --max-time 30 "$API/api/alerts?limit=$VERIFY_LIMIT" 2>/dev/null)"
      found2="$(jq -r --slurpfile a "$(snapshot_file)" --argjson evs "$evs" '
        [ .data[] | select((.id as $id | ($a[0]|index($id)))==null)
               | select((.rule_id|tostring) as $r | $evs | index($r)) ] | length'         <<<"$body2" 2>/dev/null)"
      [[ -z "$found2" ]] && found2=0
      [[ "$found2" -gt 0 ]] && break
      sleep 5
    done
    if [[ "$found2" -gt 0 ]]; then
      ok "Verification succeeded - $found2 new indexed document(s) for event(s) $evs."
      warn "NOTE: this rule is deliberately silenced (level 0) so it does not create alerts."
      print_alert_table "$body2" "$(snapshot_file)" "low" '["67027"]'
      return 0
    fi
    warn "Verification FAILED - no new indexed document for event(s) $evs within ${TIMEOUT}s."
    return 2
  fi
  local rules; rules="$(jq -c 'map(tostring)' <<<"$(payload_field_json "$p" expected_rule_ids)")"
  log "verify: expecting severity=$sev rules=$rules timeout=${TIMEOUT}s"

  local snap; snap="$(snapshot_file)"
  local deadline=$(( $(date +%s) + TIMEOUT ))
  local found=0 body

  while [[ $(date +%s) -lt $deadline ]]; do
    body="$(curl -s --max-time 30 "$API/api/alerts?limit=$VERIFY_LIMIT" 2>/dev/null)"
    if [[ -n "$body" ]]; then
      # New = id not present in the pre-run snapshot.  Filter locally because the
      # XSIEM API applies severity/search AFTER slicing to `limit`.
      found="$(jq -r --slurpfile snap "$snap" '
        [ .data[]
          | select( (.id as $id | ($snap[0] | index($id))) == null )
          | select( (.rule_id as $r | $r != null) )
        ]
        | map(select( (.severity == $sev) and ((.rule_id|tostring) as $rid | $rules | index($rid)) ))
        | length' --arg sev "$sev" --argjson rules "$rules" <<<"$body" 2>/dev/null)"
      [[ -z "$found" ]] && found=0
      if [[ "$found" -gt 0 ]]; then
        break
      fi
    fi
    sleep 5
  done

  if [[ "$found" -gt 0 ]]; then
    ok "Verification succeeded - $found new $(printf '%s' "$sev") alert(s) arrived."
    print_alert_table "$body" "$snap" "$sev" "$rules"
    return 0
  fi

  # ---- failure diagnostics ----
  warn "Verification FAILED - no new $sev alert with rule ${rules} within ${TIMEOUT}s."
  echo
  printf '%s\n' "${C_B}Diagnostics${C_RESET}"
  printf '  payload ran      : %s (%s)\n' "$p" "$(payload_field "$p" title)"
  printf '  expected severity: %s\n' "$sev"
  printf '  expected rules   : %s\n' "${rules}"
  printf '  target           : %s\n' "$TARGET"
  printf '  api              : %s\n' "$API"
  printf '\n  %s\n' "${C_B}What actually arrived for this target (newest 12)${C_RESET}"
  jq -r --slurpfile snap "$snap" '
    [ .data[] | select( (.id as $id | ($snap[0]|index($id))) == null ) ]
    | sort_by(.timestamp) | reverse | .[0:12][]
    | "    [\(.severity)] L\(.level) rule=\(.rule_id) \(.rule[0:60])"' <<<"$body" 2>/dev/null
  printf '\n  %s\n' "${C_B}Most likely reasons${C_RESET}"
  printf '    - threshold not reached (check the attempts count for this payload)\n'
  printf '    - the agent did not forward the event (check /api/agents shows win-target active)\n'
    printf '    - the expected rule id changed in the ruleset\n'
  printf '    - Windows audit policy for that event is not enabled on the target\n'
  log "verify: FAILED for $p (expected $sev $rules)"
  return 2
}

print_alert_table() { # body snap sev rules
  local body="$1" snap="$2" sev="$3" rules="$4"
  echo
  printf '%s\n' "${C_B}New alerts${C_RESET}"
  printf '  %-26s %-8s %-8s %-34s %-16s %s\n' "TIMESTAMP" "RULE" "SEVERITY" "DESCRIPTION" "SOURCE IP" "AGENT"
  printf '  %-26s %-8s %-8s %-34s %-16s %s\n' "--------------------------" "--------" "--------" "----------------------------------" "----------------" "----------"
  jq -r --slurpfile snap "$snap" --arg sev "$sev" --argjson rules "$rules" '
    [ .data[]
      | select( (.id as $id | ($snap[0]|index($id))) == null )
      | select( (.severity == $sev) and ((.rule_id|tostring) as $rid | $rules | index($rid)) )
    ]
    | sort_by(.timestamp) | reverse | .[0:15][]
    | "  \(.timestamp[0:19])  \(.rule_id)      \(.severity|ascii_upcase)    \(.rule[0:34])  \(.src_ip)     \(.agent)"' <<<"$body" 2>/dev/null
}

verify_only_report() { # payload or empty
  local p="$1"
  local body; body="$(curl -s --max-time 30 "$API/api/alerts?limit=$VERIFY_LIMIT" 2>/dev/null)"
  echo
  printf '%s\n' "${C_B}Recent alerts for the target agent${C_RESET}"
  printf '  %-26s %-8s %-8s %-38s %s\n' "TIMESTAMP" "RULE" "SEVERITY" "DESCRIPTION" "AGENT"
  printf '  %-26s %-8s %-8s %-38s %s\n' "--------------------------" "--------" "--------" "--------------------------------------" "------"
  jq -r '[.data[] | select(.agent=="win-target")] | sort_by(.timestamp) | reverse | .[0:20][]
     | "  \(.timestamp[0:19])  \(.rule_id)      \(.severity|ascii_upcase)    \(.rule[0:38])  \(.agent)"' <<<"$body" 2>/dev/null
}

# =============================================================================
#  Cleanup / revert tracking
# =============================================================================
state_load() {
  # Must emit exactly ONE json document - jq would otherwise write two copies.
  if [[ -f "$STATE_FILE" ]]; then cat "$STATE_FILE"; else echo '{"pending":[]}'; fi
}

state_add() { # payload runner param value target
  local p="$1" runner="$2" param="$3" val="$4" target="$5"
  local tmp; tmp="$(mktemp)"
  state_load | jq --arg p "$p" --arg r "$runner" --arg pm "$param" --arg v "$val" --arg t "$target" \
    '.pending += [{payload:$p, runner:$r, param:$pm, value:$v, target:$t, run:"'"$RUN_ID"'"}]' > "$tmp"
  mv "$tmp" "$STATE_FILE"
  log "state: recorded pending revert ($runner $param=$val)"
}

state_clear_one() { # index
  local i="$1" tmp; tmp="$(mktemp)"
  state_load | jq --argjson i "$i" 'del(.pending[$i])' > "$tmp"
  mv "$tmp" "$STATE_FILE"
}

state_list() { state_load | jq -r '.pending | to_entries[] | "  [\(.key)] \(.value.payload) \(.value.runner) \(.value.param)=\(.value.value) on \(.value.target) (run \(.value.run))"'; }

cleanup_all() {
  local pending; pending="$(state_load | jq -c '.pending // []')"
  local n; n="$(jq -r 'length' <<<"$pending")"
  if [[ "${n:-0}" -eq 0 ]]; then
    ok "Nothing to revert - no pending state changes recorded."
    return 0
  fi
  printf '%s\n' "${C_B}Pending reverts${C_RESET}"
  jq -r 'to_entries[] | "  [\(.key)] \(.value.payload): \(.value.runner) \(.value.param)=\(.value.value) on \(.value.target)"' <<<"$pending"
  echo
  local i
  for ((i=0; i<n; i++)); do
    local item runner param val tgt
    item="$(jq -c --argjson i "$i" '.[$i]' <<<"$pending")"
    runner="$(jq -r '.runner' <<<"$item")"
    param="$(jq -r '.param' <<<"$item")"
    val="$(jq -r '.value' <<<"$item")"
    tgt="$(jq -r '.target' <<<"$item")"
    printf '  reverting [%d] %s (%s=%s on %s) ... ' "$i" "$runner" "$param" "$val" "$tgt"
    case "$runner" in
      schtasks_delete) run_schtasks_delete "$tgt" "$val" >/dev/null 2>&1 && printf '%s\n' "${C_GRN}ok${C_RESET}" || printf '%s\n' "${C_RED}failed${C_RESET}";;
      group_remove_member) run_group_remove "$tgt" "${GROUP_ACCOUNT:-xsiem_test}" "$val" >/dev/null 2>&1 && printf '%s\n' "${C_GRN}ok${C_RESET}" || printf '%s\n' "${C_RED}failed${C_RESET}";;
      operator_revert)
        printf '  run this in an elevated PowerShell on the Windows target:\n      %s\n      ' "$val"
        printf '%s\n' "${C_GRN}marked for revert${C_RESET}"
        ;;
      *) printf '%s\n' "${C_YEL}no handler${C_RESET}";;
    esac
    state_clear_one "$i"
  done
  ok "Revert pass finished."
}

# =============================================================================
#  Runners
# =============================================================================
run_smb_auth_fail() { # target account domain password attempts delay
  local target="$1" account="$2" domain="$3" pass="$4" attempts="$5" delay="$6" i user
  [[ -z "$pass" ]] && pass="XsiemDeliberatelyWrong!$$"
  user="$account"; [[ -n "$domain" ]] && user="$domain\\$account"
  for ((i=1; i<=attempts; i++)); do
    log "smb_auth_fail attempt $i/$attempts user=$user"
    local out
    out="$(smbclient -L "//$target" -U "$user%$pass" 2>&1)"
    logq "$out"
    [[ "$i" -lt "$attempts" && "$delay" -gt 0 ]] && sleep "$delay"
  done
}

run_rdp_auth_fail() { # target account password attempts delay
  local target="$1" account="$2" pass="$3" attempts="$4" delay="$5" i
  [[ -z "$pass" ]] && pass="XsiemDeliberatelyWrong!$$"
  for ((i=1; i<=attempts; i++)); do
    log "rdp_auth_fail attempt $i/$attempts user=$account"
    local out
    out="$(timeout 45 xfreerdp /v:"$target" /u:"$account" /p:"$pass" /cert:ignore \
            +auth-only 2>&1)"
    logq "$out"
    [[ "$i" -lt "$attempts" && "$delay" -gt 0 ]] && sleep "$delay"
  done
}

run_rdp_auth_success() { # target account password attempts delay
  local target="$1" account="$2" pass="$3" attempts="$4" delay="$5" i
  for ((i=1; i<=attempts; i++)); do
    log "rdp_auth_success attempt $i/$attempts user=$account"
    local out
    out="$(timeout 45 xfreerdp /v:"$target" /u:"$account" /p:"$pass" /cert:ignore \
            +auth-only 2>&1)"
    logq "$out"
    [[ "$i" -lt "$attempts" && "$delay" -gt 0 ]] && sleep "$delay"
  done
}

run_ssh_exec() { # target command attempts delay
  local target="$1" cmd="$2" attempts="$3" delay="$4" i
  for ((i=1; i<=attempts; i++)); do
    log "ssh_exec attempt $i/$attempts cmd=$cmd"
    local out
    out="$(SSHPASS="$SSH_PASSWORD" timeout 30 sshpass -e ssh -o StrictHostKeyChecking=no \
             -o UserKnownHostsFile=/dev/null "$SSH_ACCOUNT@$target" "$cmd" 2>&1)"
    logq "$out"
    [[ "$i" -lt "$attempts" && "$delay" -gt 0 ]] && sleep "$delay"
  done
}

run_admin_assisted() { # target command timeout_seconds
  local target="$1" cmd="$2" timeout_s="${3:-120}"
  printf '\n%s\n' "${C_B}${C_YEL}>>> ACTION REQUIRED ON THE WINDOWS TARGET${C_RESET}"
  printf '  This payload needs Administrator rights on %s, which the Kali side does\n' "$target"
  printf '  not hold. Run this in an elevated PowerShell on the Windows host:\n\n'
  printf '      %s\n\n' "$cmd"
  printf '  Waiting up to %s seconds for the resulting event to be forwarded...\n' "$timeout_s"
  log "admin_assisted: waiting for operator to run: $cmd"
  local waited=0
  while [[ "$waited" -lt "$timeout_s" ]]; do
    sleep 5
    waited=$((waited + 5))
    # The alert may already be in the index; the verifier confirms it.
    if [[ $((waited % 30)) -eq 0 ]]; then
      printf '.'
    fi
  done
  printf '\n'
  log "admin_assisted: waited ${waited}s for operator action"
  return 0
}

run_powershell_registry_delete() { # target registry_path attempts
  local target="$1" path="$2" attempts="$3" i
  # Build the script locally, transfer it base64-encoded (scp over Windows
  # OpenSSH needs the legacy -O mode), then execute it.
  local script
  # Rule 91812 matches the script text "Remove-Item -Path"; rule 91813 also
  # requires an "HKLM:" / "HKCU:" path. The registry operations are kept in the
  # FIRST script block because the 4104 body of an sshd-spawned session can be
  # truncated to the first block. The HKCU: operations actually succeed for a
  # non-admin account; the HKLM: line is the exact form confirmed to satisfy
  # the 91813 pattern (it may be denied without admin - the detection fires on
  # the script text either way).
  script="\$ErrorActionPreference = \"Continue\"
Remove-Item -Path 'HKLM:\\SOFTWARE\\XSIEMTest' -Recurse -Force -ErrorAction SilentlyContinue
New-Item -Path 'HKCU:\\Software\\XSIEMTest' -Force | Out-Null
Remove-Item -Path 'HKCU:\\Software\\XSIEMTest' -Recurse -Force"
  local b64; b64="$(printf '%s' "$script" | base64 -w0)"
  for ((i=1; i<=attempts; i++)); do
    log "powershell_registry_delete attempt $i/$attempts path=$path"
    SSHPASS="$SSH_PASSWORD" timeout 30 sshpass -e ssh -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null "$SSH_ACCOUNT@$target" \
      "powershell -NoProfile -Command \"[IO.File]::WriteAllBytes('C:\\Users\\xsiem_test\\xsiem-demo.ps1',[Convert]::FromBase64String('$b64'))\"" >>"$LOG_FILE" 2>&1
    SSHPASS="$SSH_PASSWORD" timeout 45 sshpass -e ssh -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null "$SSH_ACCOUNT@$target" \
      'powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Users\xsiem_test\xsiem-demo.ps1"' >>"$LOG_FILE" 2>&1
  done
}

run_ssh_auth_fail() { # target account password attempts delay
  local target="$1" account="$2" pass="$3" attempts="$4" delay="$5" i
  [[ -z "$pass" ]] && pass="XsiemDeliberatelyWrong!$$"
  for ((i=1; i<=attempts; i++)); do
    log "ssh_auth_fail attempt $i/$attempts user=$account"
    local out
    out="$(SSHPASS="$pass" timeout 15 sshpass -e ssh -o StrictHostKeyChecking=no \
             -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password \
             -o PubkeyAuthentication=no "$account@$target" 'echo x' 2>&1)"
    logq "$out"
    [[ "$i" -lt "$attempts" && "$delay" -gt 0 ]] && sleep "$delay"
  done
}

run_smb_auth_success() { # target account domain password attempts delay
  local target="$1" account="$2" domain="$3" pass="$4" attempts="$5" delay="$6" i user
  user="$account"; [[ -n "$domain" ]] && user="$domain\\$account"
  for ((i=1; i<=attempts; i++)); do
    log "smb_auth_success attempt $i/$attempts user=$user"
    local out
    out="$(netexec smb "$target" -u "$user" -p "$pass" 2>&1)"
    logq "$out"
    [[ "$i" -lt "$attempts" && "$delay" -gt 0 ]] && sleep "$delay"
  done
}

run_schtasks_create() { # target task_name command time
  local target="$1" task="$2" cmd="$3" tm="$4"
  log "schtasks_create task=$task cmd=$cmd time=$tm"
  # Make it idempotent: remove a leftover task with the same name first,
  # otherwise /create fails and no new 4698 event is produced.
  run_schtasks_delete "$target" "$task" >/dev/null 2>&1
  local out
  out="$(SSHPASS="$SSH_PASSWORD" timeout 30 sshpass -e ssh -o StrictHostKeyChecking=no \
           -o UserKnownHostsFile=/dev/null "$SSH_ACCOUNT@$target" \
           "schtasks /create /tn \"$task\" /tr \"$cmd\" /sc once /st $tm /f" 2>&1)"
  logq "$out"
  [[ "$out" == *"SUCCESS"* ]]
}

run_schtasks_delete() { # target task
  local target="$1" task="$2"
  log "schtasks_delete task=$task"
  local out
  out="$(SSHPASS="$SSH_PASSWORD" timeout 30 sshpass -e ssh -o StrictHostKeyChecking=no \
           -o UserKnownHostsFile=/dev/null "$SSH_ACCOUNT@$target" \
           "schtasks /delete /tn \"$task\" /f" 2>&1)"
  logq "$out"
  [[ "$out" == *"SUCCESS"* ]]
}

run_group_add() { # target account group comment
  local target="$1" account="$2" group="$3" comment="$4"
  log "group_add account=$account group=$group"
  local out
  out="$(netexec smb "$target" -u "$ADMIN_USER" -p "$ADMIN_PASS" \
         -x "net localgroup \"$group\" $account /add" 2>&1)"
  logq "$out"
  [[ "$out" == *"The command completed successfully"* || "$out" == *"added to the local group"* ]]
}

run_group_remove() { # target account group
  local target="$1" account="$2" group="$3"
  log "group_remove account=$account group=$group"
  local out
  out="$(netexec smb "$target" -u "$ADMIN_USER" -p "$ADMIN_PASS" \
         -x "net localgroup \"$group\" $account /delete" 2>&1)"
  logq "$out"
  [[ "$out" == *"The command completed successfully"* || "$out" == *"removed from the local group"* ]]
}

# Credentials come from the environment only. There is no default and no
# fallback: a missing secret is a hard failure (see require_env below).
SSH_ACCOUNT="${XSIEM_TARGET_USER:-xsiem_test}"
SSH_PASSWORD="${XSIEM_TARGET_PASSWORD:-}"
ADMIN_USER="${XSIEM_ADMIN_USER:-}"
ADMIN_PASS="${XSIEM_ADMIN_PASSWORD:-}"

require_env() { # name -> value on stdout, or exit 4
  local name="$1" val="${!1:-}"
  if [[ -z "$val" ]]; then
    printf '%s\n' "${C_RED}${C_B}[FATAL]${C_RESET} Required environment variable $name is not set." >&2
    printf '        cp .env.example .env, fill it in, then:  set -a; . ./.env; set +a\n' >&2
    exit 4
  fi
  printf '%s' "$val"
}

# =============================================================================
#  Payload execution
# =============================================================================
run_payload() { # payload -> exit code
  local p="$1"
  local runner; runner="$(payload_field "$p" runner)"
  local account="${PARAMS[account]:-$SSH_ACCOUNT}"
  local domain="${PARAMS[domain]:-}"
  local pass="${PARAMS[password]:-}"
  # An empty password parameter means "take it from the environment" for the
  # successful-authentication payloads; the failed-auth payloads deliberately
  # use a wrong password instead.
  if [[ -z "$pass" && "$runner" != "smb_auth_fail" && "$runner" != "ssh_auth_fail" && "$runner" != "rdp_auth_fail" ]]; then
    pass="$SSH_PASSWORD"
  fi
  local attempts="${PARAMS[attempts]:-1}"
  local delay="${PARAMS[delay]:-0}"

  case "$runner" in
    smb_auth_fail)    run_smb_auth_fail    "$TARGET" "$account" "$domain" "$pass" "$attempts" "$delay" ;;
    ssh_auth_fail)    run_ssh_auth_fail    "$TARGET" "$account" "$pass" "$attempts" "$delay" ;;
    rdp_auth_fail)    run_rdp_auth_fail    "$TARGET" "$account" "$pass" "$attempts" "$delay" ;;
    rdp_auth_success) run_rdp_auth_success "$TARGET" "$account" "$pass" "$attempts" "$delay" ;;
    ssh_exec)         run_ssh_exec         "$TARGET" "${PARAMS[command]}" "${PARAMS[attempts]:-1}" "${PARAMS[delay]:-1}" ;;
    powershell_registry_delete) run_powershell_registry_delete "$TARGET" "${PARAMS[registry_path]}" "${PARAMS[attempts]:-1}" ;;
    admin_assisted)
      local cmd="${PARAMS[windows_command]}"
      cmd="${cmd//'{{PASSWORD}}'/$SSH_PASSWORD}"
      cmd="${cmd//'{{ACCOUNT}}'/${PARAMS[account]:-$SSH_ACCOUNT}}"
      cmd="${cmd//'{{GROUP}}'/${PARAMS[group]:-Administrators}}"
      if [[ "${PARAMS[revert_command]:-}" == *"{{PASSWORD}}"* || "${PARAMS[revert_command]:-}" == *"{{ACCOUNT}}"* || "${PARAMS[revert_command]:-}" == *"{{GROUP}}"* ]]; then
        PARAMS[revert_command]="${PARAMS[revert_command]//'{{PASSWORD}}'/$SSH_PASSWORD}"
        PARAMS[revert_command]="${PARAMS[revert_command]//'{{ACCOUNT}}'/${PARAMS[account]:-$SSH_ACCOUNT}}"
        PARAMS[revert_command]="${PARAMS[revert_command]//'{{GROUP}}'/${PARAMS[group]:-Administrators}}"
      fi
      if [[ -n "$ADMIN_USER" && -n "$ADMIN_PASS" ]]; then
        log "admin_assisted: running with admin credential $ADMIN_USER"
        netexec smb "$TARGET" -u "$ADMIN_USER" -p "$ADMIN_PASS" -x "$cmd" >>"$LOG_FILE" 2>&1
      else
        run_admin_assisted "$TARGET" "$cmd" "${PARAMS[wait_seconds]:-120}"
      fi
      if [[ -n "${PARAMS[revert_command]:-}" ]]; then
        state_add "$p" "operator_revert" "revert_command" "${PARAMS[revert_command]}" "$TARGET"
        info "revert recorded: ${PARAMS[revert_command]}"
      fi
      return 0
      ;;
    smb_auth_success) run_smb_auth_success "$TARGET" "$account" "$domain" "$pass" "$attempts" "$delay" ;;
    schtasks_create)
      if run_schtasks_create "$TARGET" "${PARAMS[task_name]}" "${PARAMS[task_command]}" "${PARAMS[task_time]}"; then
        if [[ "$(normalise_bool "${PARAMS[keep]:-false}")" == "false" ]]; then
          state_add "$p" "schtasks_delete" "task_name" "${PARAMS[task_name]}" "$TARGET"
          info "revert recorded: schtasks delete ${PARAMS[task_name]}"
        fi
        return 0
      fi
      return 3 ;;
    group_add_member)
      if [[ -z "$ADMIN_USER" ]]; then warn "no admin credential configured - cannot change group membership"; return 3; fi
      if run_group_add "$TARGET" "$account" "${PARAMS[group]}" "${PARAMS[comment]}"; then
        state_add "$p" "group_remove_member" "group" "${PARAMS[group]}" "$TARGET"
        GROUP_ACCOUNT="$account"
        info "revert recorded: remove $account from ${PARAMS[group]}"
        return 0
      fi
      return 3 ;;
    *) warn "unknown runner '$runner'"; return 3 ;;
  esac
  return 0
}

# =============================================================================
#  Presentation
# =============================================================================
show_payload_summary() { # payload
  local p="$1"
  printf '%s\n' "${C_B}Payload${C_RESET}  $p  -  $(payload_field "$p" title)"
  printf '%s\n' "${C_DIM}  $(payload_field "$p" description)${C_RESET}"
  printf '  %-14s %s\n' "severity"  "$(payload_field "$p" expected_severity)"
  printf '  %-14s %s\n' "win events" "$(jq -c 'join(", ")' <<<"$(payload_field_json "$p" windows_event_ids)")"
  printf '  %-14s %s\n' "rule ids"   "$(jq -c 'join(", ")' <<<"$(payload_field_json "$p" expected_rule_ids)")"
  printf '  %-14s %s\n' "mitre"      "$(jq -c 'join(", ")' <<<"$(payload_field "$p" mitre_attack)")"
  printf '  %-14s %s\n' "target"     "$TARGET"
  printf '  %-14s %s\n' "api"        "$API"
  printf '%s\n' "${C_DIM}  parameters (effective)${C_RESET}"
  local n v
  while IFS= read -r n; do
    [[ -z "$n" ]] && continue
    v="${PARAMS[$n]:-}"
    if [[ -z "$v" && "$n" == "password" ]]; then
      v="(from \$XSIEM_TARGET_PASSWORD)"
    fi
    printf '    %-16s = %s\n' "$n" "$v"
  done < <(jq -r --arg n "$p" '.payloads[]|select(.name==$n)|.params[].name' "$LIB")
}

list_payloads() { # severity-filter  format
  local sev="${1:-}" fmt="${2:-table}"
  if [[ "$fmt" == "json" ]]; then
    if [[ -n "$sev" ]]; then
      jq --arg s "$sev" '.payloads |= map(select(.expected_severity==$s))' "$LIB"
    else
      cat "$LIB"
    fi
    return
  fi
  printf '%s\n' "${C_B}Payload catalogue${C_RESET} (target $TARGET)"
  printf '  %-26s %-8s %-12s %-10s %-4s %s\n' "NAME" "SEVERITY" "WIN EVENT" "RULE" "OK" "DESCRIPTION"
  printf '  %-26s %-8s %-12s %-10s %-4s %s\n' "--------------------------" "--------" "------------" "----------" "----" "---------------------------------"
  local line
  while IFS=$'\t' read -r line; do
    [[ -z "$line" ]] && continue
    IFS=$'\t' read -r nm sv ev rl okv ds <<<"$line"
    printf '  %-26s %-8s %-12s %-10s %-4s %s\n' "$nm" "$sv" "$ev" "$rl" "$okv" "$ds"
  done < <(jq -r --arg s "$sev" '
    (.payloads | map(select($s=="" or $s=="all" or .expected_severity==$s)))
    | .[] | [ .name, .expected_severity,
              (.windows_event_ids|map(tostring)|join(",")),
              (.expected_rule_ids|map(tostring)|join(",")),
              (if .verified then "yes" else "NO" end),
              .description ] | @tsv' "$LIB")
}

# =============================================================================
#  Interactive menu
# =============================================================================
MENU_TUI=""
detect_tui() {
  if have whiptail && [[ -t 0 ]] && [[ -z "${NO_TUI:-}" ]]; then MENU_TUI="whiptail"; fi
}

prompt() { # prompt var
  local __var="$1"; shift
  local reply=""
  printf '%s' "$1"
  read -r reply
  printf -v "$__var" '%s' "$reply"
}

# Menu selections are returned via globals, NOT via command substitution:
# a $(...) would swallow the menu text into the selected value.
MENU_SEVERITY=""; MENU_PAYLOAD=""

menu_select_severity() {
  local choice
  printf '\n%s\n' "${C_B}Select severity${C_RESET}"
  printf '  1) all      - every payload\n'
  printf '  2) low      - Wazuh level < 7\n'
  printf '  3) medium   - Wazuh level 7-11\n'
  printf '  4) high     - Wazuh level >= 12\n'
  prompt choice "  choice [1]: "
  case "$choice" in
    2|low)    MENU_SEVERITY="low";;
    3|medium) MENU_SEVERITY="medium";;
    4|high)   MENU_SEVERITY="high";;
    *)        MENU_SEVERITY="all";;
  esac
}

menu_select_payload() { # severity -> sets MENU_PAYLOAD
  local sev="$1" p sel
  local names; names="$(jq -r --arg s "$sev" '.payloads|map(select($s=="" or $s=="all" or .expected_severity==$s))|map(.name)|join("\n")' "$LIB")"
  local count; count="$(grep -c . <<<"$names")"
  if [[ -z "$names" || "$count" -eq 0 ]]; then
    warn "no payloads registered for severity '$sev'"
    return 1
  fi
  printf '\n%s\n' "${C_B}Select payload${C_RESET}"
  local i=1
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    printf '  %2d) %-26s %-8s %s\n' "$i" "$p" "$(payload_field "$p" expected_severity)" "$(payload_field "$p" title)"
    i=$((i+1))
  done <<<"$names"
  printf '  0) back\n'
  while true; do
    prompt sel "  choice [1]: "
    [[ "$sel" == "0" ]] && return 1
    if [[ -z "$sel" ]]; then sel=1; fi
    if [[ ! "$sel" =~ ^[0-9]+$ ]] || [[ "$sel" -gt "$count" ]]; then
      warn "invalid choice '$sel' - pick 1-$count, or 0 to go back"
      continue
    fi
    MENU_PAYLOAD="$(sed -n "${sel}p" <<<"$names")"
    if [[ -n "$MENU_PAYLOAD" ]]; then return 0; fi
    warn "invalid choice '$sel' - pick 1-$count, or 0 to go back"
  done
}

menu_configure_params() { # payload
  local p="$1" n spec type def val
  while IFS= read -r n; do
    [[ -z "$n" ]] && continue
    spec="$(param_spec "$p" "$n")"
    type="$(jq -r '.type' <<<"$spec")"
    def="$(jq -r '.default|tostring' <<<"$spec")"
    desc="$(jq -r '.description' <<<"$spec")"
    case "$type" in
      bool)
        printf '    %-16s (%s) [y/n] default=%s : ' "$n" "$desc" "$def"
        local r; read -r r
        case "$r" in
          y|Y|yes|true|1) PARAMS["$n"]="true";;
          n|N|no|false|0) PARAMS["$n"]="false";;
          "") PARAMS["$n"]="$def";;
          *) warn "not a boolean, keeping default $def"; PARAMS["$n"]="$def";;
        esac
        ;;
      *)
        printf '    %-16s (%s) [%s] : ' "$n" "$desc" "$def"
        read -r val
        [[ -z "$val" ]] && val="$def"
        if validate_param "$n" "$spec" "$val"; then
          PARAMS["$n"]="$val"
        else
          warn "invalid value - keeping default $def"
          PARAMS["$n"]="$def"
        fi
        ;;
    esac
  done < <(jq -r --arg n "$p" '.payloads[]|select(.name==$n)|.params[].name' "$LIB")
}

menu_confirm() { # question
  if [[ "$ASSUME_YES" -eq 1 ]]; then return 0; fi
  local r
  printf '%s [y/N]: ' "$1"
  read -r r
  [[ "$r" =~ ^[Yy]$ ]]
}

interactive_menu() {
  detect_tui
  local sev p
  banner "XSIEM payload generator - interactive menu"
  info "target : $TARGET"
  info "api    : $API"
  info "run id : $RUN_ID"
  info "log    : $LOG_FILE"
  while true; do
    printf '\n%s\n' "${C_B}${C_CYN}Main menu${C_RESET}"
    printf '  1) select target\n'
    printf '  2) select severity\n'
    printf '  3) select payload\n'
    printf '  4) configure payload parameters\n'
    printf '  5) execute selected payload (with confirmation)\n'
    printf '  6) view result / verify only\n'
    printf '  7) list payloads\n'
    printf '  8) reset / cleanup (revert target changes)\n'
    printf '  9) post-run target state check\n'
    printf '  0) quit\n'
    local c
    prompt c "  choice [0]: "
    case "$c" in
      1)
        local t
        prompt t "  target ip [$TARGET]: "
        [[ -z "$t" ]] || { safety_check_target "$t" && TARGET="$t"; }
        ;;
      2) menu_select_severity; sev="$MENU_SEVERITY"; info "severity filter = $sev";;
      3) if menu_select_payload "${sev:-all}"; then PAYLOAD="$MENU_PAYLOAD"; load_defaults "$PAYLOAD"; ok "payload = $PAYLOAD"; fi;;
      4)
        [[ -n "$PAYLOAD" ]] || { warn "select a payload first (option 3)"; continue; }
        load_defaults "$PAYLOAD"; menu_configure_params "$PAYLOAD"; ok "parameters updated";;
      5)
        [[ -n "$PAYLOAD" ]] || { warn "select a payload first (option 3)"; continue; }
        show_payload_summary "$PAYLOAD"
        echo
        menu_confirm "Execute this payload?" || { warn "aborted"; continue; }
        execute_payload "$PAYLOAD";;
      6)
        if [[ -n "$PAYLOAD" ]]; then verify_payload "$PAYLOAD"; else verify_only_report ""; fi;;
      7) list_payloads "${sev:-all}" table;;
      8) cleanup_all;;
      9) post_run_state_check;;
      0|q|Q) banner "done - log: $LOG_FILE"; break;;
      *) warn "unknown choice";;
    esac
  done
}

post_run_state_check() {
  banner "post-run target state check"
  info "target: $TARGET"
  local out
  out="$(SSHPASS="$SSH_PASSWORD" timeout 30 sshpass -e ssh -o StrictHostKeyChecking=no \
           -o UserKnownHostsFile=/dev/null "$SSH_ACCOUNT@$TARGET" \
           'net localgroup Users' 2>&1)"
  printf '%s\n' "${C_DIM}$out${C_RESET}" | head -20
  if grep -qi "xsiem_test" <<<"$out"; then
    ok "xsiem_test is in Users (expected baseline)"
  else
    warn "xsiem_test NOT found in Users - inspect the target"
  fi
  out="$(SSHPASS="$SSH_PASSWORD" timeout 30 sshpass -e ssh -o StrictHostKeyChecking=no \
           -o UserKnownHostsFile=/dev/null "$SSH_ACCOUNT@$TARGET" \
           'schtasks /query /fo LIST' 2>&1)"
  if grep -qi "XsiemDemoTask" <<<"$out"; then
    warn "a scheduled task named XsiemDemoTask still exists - run reset/cleanup"
  else
    ok "no leftover XsiemDemoTask scheduled task (expected baseline)"
  fi
}

# Probe the target account state. Because we know the correct password, a
# FAILED success-auth means the account is locked out (or the password changed).
# A locked account must be reported as its own state, never as a generic
# failure and never as "new alerts".
probe_account_state() { # -> prints OK | LOCKED | UNKNOWN
  local out
  out="$(netexec smb "$TARGET" -u "$SSH_ACCOUNT" -p "$SSH_PASSWORD" 2>&1)"
  if grep -q "xsiem_test:$SSH_PASSWORD" <<<"$out"; then
    echo "OK"; return 0
  fi
  if grep -qi "NETBIOS connection\|ACCESS_DENIED\|LOCKED" <<<"$out"; then
    echo "LOCKED"; return 1
  fi
  echo "UNKNOWN"; return 2
}

preflight_lockout_check() { # -> warns if the real lab account is locked out
  local state; state="$(probe_account_state)"
  if [[ "$state" == "LOCKED" ]]; then
    warn "The lab account '$SSH_ACCOUNT' is LOCKED OUT on the target."
    warn "  Windows OpenSSH resets the connection while an account is locked, so"
    warn "  SSH payloads will fail with 'Connection reset' until the lockout expires."
    warn "  The target's policy is: threshold 10, duration 10 minutes."
    warn "  It can be cleared immediately from a Windows admin shell with:"
    warn "      net user $SSH_ACCOUNT /active:no ; net user $SSH_ACCOUNT /active:yes"
    log "preflight: account $SSH_ACCOUNT is LOCKED OUT"
    return 1
  fi
  log "preflight: account $SSH_ACCOUNT state=$state"
  return 0
}

lockout_warning() { # payload
  local attempts="${PARAMS[attempts]:-0}"
  local account="${PARAMS[account]:-}"
  if [[ "$attempts" =~ ^[0-9]+$ ]] && [[ "$attempts" -ge 10 ]] && [[ "$account" == "$SSH_ACCOUNT" ]]; then
    printf '\n%s\n' "${C_RED}${C_B}*** WARNING: THIS WILL LOCK THE ACCOUNT OUT ***${C_RESET}"
    printf '  %s failed logons for %s exceeds the target lockout threshold of 10.\n' "$attempts" "$account"
    printf '  The account will be locked for 10 minutes. While it is locked, Windows\n'
    printf '  OpenSSH resets the connection, so every SSH/RDP payload will fail with\n'
    printf '  "Connection reset" and will NOT produce new alerts.\n'
    printf '  Clear it from a Windows admin shell with:\n'
    printf '      net user %s /active:no ; net user %s /active:yes\n\n' "$account" "$account"
    log "lockout warning: attempts=$attempts account=$account"
    return 0
  fi
  return 0
}

# Hard safety gate. The target's lockout threshold is 10, so anything above 9
# can lock the lab account for 10 minutes and stall a live demo. Refusing by
# default; the operator can still opt in explicitly.
enforce_attempt_cap() { # payload -> 0 ok, 1 refused
  local attempts="${PARAMS[attempts]:-0}"
  local account="${PARAMS[account]:-}"
  [[ "$attempts" =~ ^[0-9]+$ ]] || return 0
  [[ "$attempts" -le 9 ]] && return 0
  [[ "$account" == "$SSH_ACCOUNT" ]] || return 0
  if [[ "$I_KNOW_THIS_LOCKS" -eq 1 ]]; then
    warn "attempts=$attempts exceeds the safe maximum of 9 - proceeding because --i-know-this-locks was given."
    warn "  $SSH_ACCOUNT may be locked out on the target for 10 minutes."
    log "attempt cap: allowed attempts=$attempts via --i-know-this-locks"
    return 0
  fi
  printf '\n%s\n%s attempts for %s can lock the account out.\n' \
    "${C_RED}${C_B}[REFUSED]${C_RESET}" "$attempts" "$account"
  printf '  The target lockout threshold is 10 (10 minute duration) and a locked\n'
  printf '  account breaks every SSH/RDP payload for the rest of that window.\n'
  printf '  The safe default is 8. If you really want the lockout, re-run with:\n'
  printf '      --i-know-this-locks\n\n'
  log "attempt cap: REFUSED attempts=$attempts account=$account (no --i-know-this-locks)"
  return 1
}

# Look for the Windows lockout error in what the runner just produced.
# ERROR_ACCOUNT_LOCKED_OUT is Windows error 1909.
detect_lockout_error() { # -> 0 if a lockout signature was seen
  local chunk; chunk="$(tail -c 200000 "$LOG_FILE" 2>/dev/null)"
  if grep -qiE "ACCOUNT_LOCKED_OUT|ERR_ACCOUNT_LOCKED|1909" <<<"$chunk"; then
    return 0
  fi
  return 1
}

execute_payload() { # payload
  local p="$1"
  banner "executing payload: $p"
  local before; before="$(snapshot_alerts)"
  info "alerts before: $before"
  preflight_lockout_check || warn "continuing, but SSH-based payloads may fail while the account is locked."
  lockout_warning "$p"
  # Hard safety gate: >9 attempts on the real account can lock it for 10 minutes.
  if ! enforce_attempt_cap "$p"; then
    return 4
  fi
  log "execute: payload=$p target=$TARGET params=$(jq -c . <<<"$(declare -p PARAMS | sed 's/^declare -A PARAMS=//')" 2>/dev/null || echo '{}')"
  local rc=0
  run_payload "$p" || rc=$?
  if [[ "$rc" -ne 0 ]]; then
    warn "payload execution reported failure (rc=$rc)"
    log "execute: runner returned $rc"
    return 3
  fi
  ok "payload executed"
  # Distinct lockout state: the account was locked by this run. This is NOT a
  # verification failure and must not be reported as "no new alerts".
  local state; state="$(probe_account_state)"
  if detect_lockout_error; then
    printf '\n%s\n' "${C_YEL}${C_B}TARGET STATE: ACCOUNT LOCKED OUT (Windows error 1909)${C_RESET}"
    printf '  The target reported ERROR_ACCOUNT_LOCKED_OUT during this run.\n'
    printf '  Those authentication failures are NOT detection results - no alert\n'
    printf '  was produced by them. The account unlocks itself after 10 minutes,\n'
    printf '  or a Windows admin can clear it immediately with:\n'
    printf '      net user %s /active:no ; net user %s /active:yes\n\n' "$SSH_ACCOUNT" "$SSH_ACCOUNT"
    log "execute: runner reported ERROR_ACCOUNT_LOCKED_OUT (1909)"
    LOCKOUT_OCCURRED=1
  elif [[ "$state" == "LOCKED" ]]; then
    printf '\n%s\n' "${C_YEL}${C_B}TARGET STATE: ACCOUNT LOCKED OUT${C_RESET}"
    printf '  The target locked %s during this run (threshold 10, duration 10 min).\n' "$SSH_ACCOUNT"
    printf '  While it is locked, Windows OpenSSH resets the connection, so further\n'
    printf '  SSH/RDP payloads will fail and produce NO new alerts.\n'
    printf '  Clear it from a Windows admin shell with:\n'
    printf '      net user %s /active:no ; net user %s /active:yes\n\n' "$SSH_ACCOUNT" "$SSH_ACCOUNT"
    log "execute: target account is LOCKED OUT after this run"
    LOCKOUT_OCCURRED=1
  else
    LOCKOUT_OCCURRED=0
  fi
  if [[ "$NO_VERIFY" -eq 1 ]]; then
    warn "verification skipped (--no-verify)"
    return 0
  fi
  verify_payload "$p"
}

# =============================================================================
#  Non-interactive argument parsing
# =============================================================================
usage() {
  cat <<EOF
${C_B}xsiem-payloads.sh${C_RESET} - generate real Windows security events for the XSIEM lab

  (no arguments)                 interactive menu
  --list [--format json]         print the payload catalogue
  --dry-run                      print what would run, touch nothing
  --payload NAME                 run one payload non-interactively
  --target IP                    target host (default $ALLOWED_TARGET)
  --severity low|medium|high     filter (with --list)
  --set key=value                override a payload parameter (repeatable)
  --timeout SECONDS              verification timeout (default 45)
  --api URL                      XSIEM API base (default http://localhost:4000)
  --yes                          assume yes for confirmations
  --no-verify                    execute but do not verify
  --verify-only                  only report what has arrived recently
  --cleanup                      revert every change this tool recorded
  --state-check                  confirm the target is back to baseline
  --i-have-authorization         required to target anything outside the lab
  --i-know-this-locks            allow >9 attempts on the real account (locks it for 10 min)
  --no-tui                       force the plain numbered menu
  --list-payloads                (alias of --list)

exit codes: 0 ok  1 usage  2 verification failed  3 execution failed  4 refused
EOF
}

main() {
  local positional=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --target)   TARGET="$2"; shift 2;;
      --api)      API="$2"; shift 2;;
      --payload)  PAYLOAD="$2"; shift 2;;
      --severity) SEVERITY_FILTER="$2"; shift 2;;
      --timeout)  TIMEOUT="$2"; shift 2;;
      --set)      SET_ARGS+=("$2"); shift 2;;
      --list|--list-payloads) DO_LIST=1; shift;;
      --format)   LIST_FORMAT="$2"; shift 2;;
      --dry-run)  DO_DRYRUN=1; shift;;
      --yes|-y)   ASSUME_YES=1; shift;;
      --no-verify) NO_VERIFY=1; shift;;
      --verify-only) VERIFY_ONLY=1; shift;;
      --cleanup)     DO_CLEANUP=1; shift;;
      --state-check) DO_STATE_CHECK=1; shift;;
      --i-have-authorization) I_HAVE_AUTH=1; shift;;
      --i-know-this-locks) I_KNOW_THIS_LOCKS=1; shift;;
      --no-tui)   export NO_TUI=1; shift;;
      --no-color) export NO_COLOR=1; shift;;
      -h|--help)  load_safety; usage; exit 0;;
      *) positional+=("$1"); shift;;
    esac
  done

  [[ -f "$LIB" ]] || { printf 'payload library not found: %s\n' "$LIB" >&2; exit 1; }
  load_safety
  [[ -z "$API" ]] && API="$(lib_get '.defaults.api')"
  [[ -z "$TIMEOUT" ]] && TIMEOUT="$(lib_get '.defaults.timeout')"
  VERIFY_LIMIT="$(lib_get '.defaults.verify_limit')"
  [[ -z "$TARGET" ]] && TARGET="$(lib_get '.defaults.target')"

  init_log "$@"

  if [[ "$DO_LIST" -eq 1 ]]; then
    list_payloads "$SEVERITY_FILTER" "$LIST_FORMAT"
    exit 0
  fi

  if [[ "$DO_CLEANUP" -eq 1 ]]; then
    safety_check_target "$TARGET"
    banner "cleanup - reverting target changes"
    cleanup_all
    exit 0
  fi

  if [[ "$DO_STATE_CHECK" -eq 1 ]]; then
    safety_check_target "$TARGET"
    banner "post-run target state check"
    post_run_state_check
    exit 0
  fi

  if [[ "$VERIFY_ONLY" -eq 1 ]]; then
    safety_check_target "$TARGET"
    banner "verify-only report"
    verify_only_report "$PAYLOAD"
    exit 0
  fi

  safety_check_target "$TARGET"
  # The target account password is required for the payloads that authenticate
  # (SMB success, SSH, scheduled task, process execution). require_env exits
  # the whole script, so it must NOT be used inside a command substitution.
  require_env XSIEM_TARGET_PASSWORD >/dev/null
  SSH_PASSWORD="${XSIEM_TARGET_PASSWORD}"

  if [[ -n "$PAYLOAD" ]]; then
    if ! payload_exists "$PAYLOAD"; then
      die "Unknown payload '$PAYLOAD'. Use --list to see the catalogue." 1
    fi
    load_defaults "$PAYLOAD"
    apply_set_args "$PAYLOAD"
    if [[ "$DO_DRYRUN" -eq 1 ]]; then
      banner "dry run - nothing was executed"
      show_payload_summary "$PAYLOAD"
      printf '\n%s\n' "${C_YEL}dry run: no packets sent, target untouched${C_RESET}"
      exit 0
    fi
    show_payload_summary "$PAYLOAD"
    echo
    if [[ "$ASSUME_YES" -ne 1 ]]; then
      menu_confirm "Execute this payload?" || { printf '%s\n' "${C_YEL}aborted${C_RESET}"; exit 0; }
    fi
    execute_payload "$PAYLOAD"
    rc=$?
    banner "run complete - log: $LOG_FILE"
    exit "$rc"
  fi

  if [[ "$DO_DRYRUN" -eq 1 ]]; then
    die "--dry-run needs --payload NAME" 1
  fi

  interactive_menu
  exit 0
}

main "$@"
