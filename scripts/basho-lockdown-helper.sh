#!/usr/bin/env bash
set -euo pipefail

umask 077

# CRITICAL SECURITY INVARIANT:
# When running as real root (UID 0, e.g. via sudo), NEVER read or honor any
# BASHO_LOCKDOWN_* environment overrides. Paths and binaries are hardcoded.
# When running unprivileged (UID != 0), refuse execution unless invoked from a
# non-installed temp copy with BASHO_LOCKDOWN_TEST_UID=0 for hermetic tests.
REAL_UID="$(/usr/bin/id -u)"
SCRIPT_SELF="$(/usr/bin/readlink -f -- "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"

if [ "$REAL_UID" -eq 0 ]; then
  PATH="/usr/sbin:/usr/bin:/sbin:/bin"
  export PATH
  EFFECTIVE_UID="0"
  UFW_BIN="/usr/bin/ufw"
  SYSTEMCTL_BIN="/usr/bin/systemctl"
  SYSTEMD_RUN_BIN="/usr/bin/systemd-run"
  POLICY_DIR="/etc/basho-lockdown"
  STATE_DIR="/var/lib/basho-lockdown"
  HELPER_SELF="/usr/local/libexec/basho-lockdown-helper"
  TEST_MODE="0"
else
  if [ "$SCRIPT_SELF" = "/usr/local/libexec/basho-lockdown-helper" ] || [ "${BASHO_LOCKDOWN_TEST_UID:-}" != "0" ]; then
    printf 'basho-lockdown-helper: root privileges required\n' >&2
    exit 77
  fi
  EFFECTIVE_UID="0"
  UFW_BIN="${BASHO_LOCKDOWN_UFW:-/usr/bin/ufw}"
  SYSTEMCTL_BIN="${BASHO_LOCKDOWN_SYSTEMCTL:-/usr/bin/systemctl}"
  SYSTEMD_RUN_BIN="${BASHO_LOCKDOWN_SYSTEMD_RUN:-/usr/bin/systemd-run}"
  POLICY_DIR="${BASHO_LOCKDOWN_POLICY_DIR:-/etc/basho-lockdown}"
  STATE_DIR="${BASHO_LOCKDOWN_STATE_DIR:-/var/lib/basho-lockdown}"
  HELPER_SELF="$SCRIPT_SELF"
  TEST_MODE="1"
fi

die() {
  printf 'basho-lockdown-helper: %s\n' "$1" >&2
  exit "${2:-1}"
}

validate_op_id() {
  local id="$1"
  if [[ ! "$id" =~ ^[A-Za-z0-9._:-]{1,64}$ ]] || [[ "$id" == -* ]] || [[ "$id" == *..* ]]; then
    die "invalid operation id" 64
  fi
}

validate_ttl() {
  local ttl="$1"
  if [[ ! "$ttl" =~ ^[0-9]+$ ]]; then
    die "invalid ttl" 64
  fi
  if [ "$((10#$ttl))" -lt 30 ] || [ "$((10#$ttl))" -gt 1800 ]; then
    die "ttl must be between 30 and 1800 seconds" 64
  fi
}

is_protected_ipv4() {
  local o1="$1" o2="$2" o3="$3" o4="$4"
  # 0.0.0.0/8 unspecified
  if [ "$o1" -eq 0 ]; then return 0; fi
  # 127.0.0.0/8 loopback
  if [ "$o1" -eq 127 ]; then return 0; fi
  # 100.64.0.0/10 Tailscale CGNAT
  if [ "$o1" -eq 100 ] && [ "$o2" -ge 64 ] && [ "$o2" -le 127 ]; then return 0; fi
  # 224.0.0.0/4 multicast
  if [ "$o1" -ge 224 ] && [ "$o1" -le 239 ]; then return 0; fi
  # 255.255.255.255 broadcast
  if [ "$o1" -eq 255 ] && [ "$o2" -eq 255 ] && [ "$o3" -eq 255 ] && [ "$o4" -eq 255 ]; then return 0; fi
  return 1
}

parse_strict_ipv4() {
  local raw="$1"
  if [[ ! "$raw" =~ ^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$ ]]; then
    return 1
  fi
  local o1="${BASH_REMATCH[1]}" o2="${BASH_REMATCH[2]}" o3="${BASH_REMATCH[3]}" o4="${BASH_REMATCH[4]}"
  if [ "$o1" -gt 255 ] || [ "$o2" -gt 255 ] || [ "$o3" -gt 255 ] || [ "$o4" -gt 255 ]; then
    return 1
  fi
  PARSED_O1="$o1"
  PARSED_O2="$o2"
  PARSED_O3="$o3"
  PARSED_O4="$o4"
  return 0
}

format_canonical_ipv6() {
  local -a g=("$@")
  local best_start=-1 best_len=0 cur_start=-1 cur_len=0 i
  for ((i = 0; i < 8; i++)); do
    if [ "${g[i]}" -eq 0 ]; then
      if [ "$cur_start" -eq -1 ]; then
        cur_start="$i"
        cur_len=1
      else
        cur_len=$((cur_len + 1))
      fi
      if [ "$cur_len" -gt "$best_len" ]; then
        best_start="$cur_start"
        best_len="$cur_len"
      fi
    else
      cur_start=-1
      cur_len=0
    fi
  done

  local out=""
  if [ "$best_len" -lt 2 ]; then
    for ((i = 0; i < 8; i++)); do
      [ "$i" -gt 0 ] && out+=":"
      out+="$(printf '%x' "${g[i]}")"
    done
    printf '%s' "$out"
    return 0
  fi

  local left="" right=""
  for ((i = 0; i < best_start; i++)); do
    [ -n "$left" ] && left+=":"
    left+="$(printf '%x' "${g[i]}")"
  done
  for ((i = best_start + best_len; i < 8; i++)); do
    [ -n "$right" ] && right+=":"
    right+="$(printf '%x' "${g[i]}")"
  done
  printf '%s::%s' "$left" "$right"
}

canonicalize_and_validate_ip() {
  local raw="$1"
  CANONICAL_IP=""

  if [ -z "$raw" ] || [[ "$raw" =~ [[:space:]/%] ]] || [[ "$raw" == -* ]]; then
    return 1
  fi

  if parse_strict_ipv4 "$raw"; then
    if is_protected_ipv4 "$PARSED_O1" "$PARSED_O2" "$PARSED_O3" "$PARSED_O4"; then
      return 1
    fi
    CANONICAL_IP="${PARSED_O1}.${PARSED_O2}.${PARSED_O3}.${PARSED_O4}"
    return 0
  fi

  if [[ "$raw" != *:* ]] || [[ ! "$raw" =~ ^[0-9a-fA-F:.]+$ ]] || [[ "$raw" == *:::* ]]; then
    return 1
  fi

  local working="$raw"
  local has_v4=0 v4_hi=0 v4_lo=0
  local tail="${working##*:}"
  if [[ "$tail" == *.* ]]; then
    if ! parse_strict_ipv4 "$tail"; then
      return 1
    fi
    has_v4=1
    v4_hi=$(( (PARSED_O1 << 8) | PARSED_O2 ))
    v4_lo=$(( (PARSED_O3 << 8) | PARSED_O4 ))
    local prefix="${working%:"$tail"}"
    if [ -z "$prefix" ]; then
      return 1
    fi
    if [[ "$prefix" == *: ]]; then
      working="${prefix}:"
    else
      working="$prefix"
    fi
  fi

  local expected_hex=8
  if [ "$has_v4" -eq 1 ]; then
    expected_hex=6
  fi

  local -a groups=()
  if [[ "$working" == *::* ]]; then
    local left_str="${working%%::*}"
    local right_str="${working#*::}"
    if [[ "$right_str" == *::* ]]; then
      return 1
    fi
    if [[ "$left_str" == :* ]] || [[ "$left_str" == *: ]] || [[ "$right_str" == :* ]] || [[ "$right_str" == *: ]]; then
      return 1
    fi

    local -a left_parts=() right_parts=()
    if [ -n "$left_str" ]; then
      IFS=':' read -r -a left_parts <<< "$left_str"
    fi
    if [ -n "$right_str" ]; then
      IFS=':' read -r -a right_parts <<< "$right_str"
    fi

    local missing=$(( expected_hex - ${#left_parts[@]} - ${#right_parts[@]} ))
    if [ "$missing" -lt 1 ]; then
      return 1
    fi

    local part i
    for part in "${left_parts[@]}"; do
      [[ "$part" =~ ^[0-9a-fA-F]{1,4}$ ]] || return 1
      groups+=("$((16#$part))")
    done
    for ((i = 0; i < missing; i++)); do
      groups+=(0)
    done
    for part in "${right_parts[@]}"; do
      [[ "$part" =~ ^[0-9a-fA-F]{1,4}$ ]] || return 1
      groups+=("$((16#$part))")
    done
  else
    if [[ "$working" == :* ]] || [[ "$working" == *: ]]; then
      return 1
    fi
    local -a parts=()
    IFS=':' read -r -a parts <<< "$working"
    if [ "${#parts[@]}" -ne "$expected_hex" ]; then
      return 1
    fi
    local part
    for part in "${parts[@]}"; do
      [[ "$part" =~ ^[0-9a-fA-F]{1,4}$ ]] || return 1
      groups+=("$((16#$part))")
    done
  fi

  if [ "$has_v4" -eq 1 ]; then
    groups+=("$v4_hi" "$v4_lo")
  fi
  if [ "${#groups[@]}" -ne 8 ]; then
    return 1
  fi

  # Unwrap IPv4-mapped IPv6 (::ffff:0:0/96)
  if [ "${groups[0]}" -eq 0 ] && [ "${groups[1]}" -eq 0 ] && [ "${groups[2]}" -eq 0 ] && \
     [ "${groups[3]}" -eq 0 ] && [ "${groups[4]}" -eq 0 ] && [ "${groups[5]}" -eq 65535 ]; then
    local o1=$(( (groups[6] >> 8) & 255 ))
    local o2=$(( groups[6] & 255 ))
    local o3=$(( (groups[7] >> 8) & 255 ))
    local o4=$(( groups[7] & 255 ))
    if is_protected_ipv4 "$o1" "$o2" "$o3" "$o4"; then
      return 1
    fi
    CANONICAL_IP="${o1}.${o2}.${o3}.${o4}"
    return 0
  fi

  # :: unspecified
  if [ "${groups[0]}" -eq 0 ] && [ "${groups[1]}" -eq 0 ] && [ "${groups[2]}" -eq 0 ] && \
     [ "${groups[3]}" -eq 0 ] && [ "${groups[4]}" -eq 0 ] && [ "${groups[5]}" -eq 0 ] && \
     [ "${groups[6]}" -eq 0 ] && [ "${groups[7]}" -eq 0 ]; then
    return 1
  fi

  # ::1 loopback
  if [ "${groups[0]}" -eq 0 ] && [ "${groups[1]}" -eq 0 ] && [ "${groups[2]}" -eq 0 ] && \
     [ "${groups[3]}" -eq 0 ] && [ "${groups[4]}" -eq 0 ] && [ "${groups[5]}" -eq 0 ] && \
     [ "${groups[6]}" -eq 0 ] && [ "${groups[7]}" -eq 1 ]; then
    return 1
  fi

  # fd7a:115c:a1e0::/48 Tailscale IPv6 ULA
  if [ "${groups[0]}" -eq $((16#fd7a)) ] && [ "${groups[1]}" -eq $((16#115c)) ] && [ "${groups[2]}" -eq $((16#a1e0)) ]; then
    return 1
  fi

  # ff00::/8 multicast
  if [ "$(( groups[0] & 16#ff00 ))" -eq "$((16#ff00))" ]; then
    return 1
  fi

  CANONICAL_IP="$(format_canonical_ipv6 "${groups[@]}")"
  return 0
}

ensure_state_dir() {
  if [ -L "$STATE_DIR" ]; then
    die "state directory must not be a symlink" 1
  fi
  if [ ! -d "$STATE_DIR" ]; then
    /usr/bin/mkdir -p -m 0700 "$STATE_DIR" || die "failed to create state dir" 1
  fi
}

timer_unit_for_id() {
  local id="$1"
  local sanitized="${id//[^A-Za-z0-9_.-]/_}"
  printf 'basho-rollback-%s' "$sanitized"
}

find_lan_policy_file() {
  if [ -e "${POLICY_DIR}/lan-policy.conf" ]; then
    printf '%s' "${POLICY_DIR}/lan-policy.conf"
    return 0
  fi
  if [ -e "${POLICY_DIR}/lan-policy" ]; then
    printf '%s' "${POLICY_DIR}/lan-policy"
    return 0
  fi
  return 1
}

verify_helper_install() {
  if [ "$TEST_MODE" != "0" ]; then
    return 0
  fi
  if [ "$SCRIPT_SELF" != "$HELPER_SELF" ]; then
    return 1
  fi
  if [ -L "$HELPER_SELF" ] || [ ! -f "$HELPER_SELF" ]; then
    return 1
  fi
  local owner mode
  owner="$(/usr/bin/stat -c '%u' "$HELPER_SELF" 2>/dev/null || printf 'invalid')"
  mode="$(/usr/bin/stat -c '%a' "$HELPER_SELF" 2>/dev/null || printf '777')"
  if [ "$owner" != "0" ] || [[ ! "$mode" =~ ^[0-7]{3,4}$ ]]; then
    return 1
  fi
  if [ $(( 8#$mode & 8#022 )) -ne 0 ]; then
    return 1
  fi
  return 0
}

verify_ufw_active() {
  UFW_STATUS_OUT=""
  local ufw_status_out
  if ! ufw_status_out="$("$UFW_BIN" status 2>/dev/null)"; then
    return 1
  fi
  if [ -z "$ufw_status_out" ]; then
    return 1
  fi
  if printf '%s\n' "$ufw_status_out" | /usr/bin/grep -Eqi '(^|[[:space:]])Status:[[:space:]]*inactive([[:space:]]|$)'; then
    return 1
  fi
  if [ "$TEST_MODE" = "0" ]; then
    if ! printf '%s\n' "$ufw_status_out" | /usr/bin/grep -Eqi '^Status:[[:space:]]*active([[:space:]]|$)'; then
      return 1
    fi
  else
    if printf '%s\n' "$ufw_status_out" | /usr/bin/grep -Eqi '(^|[[:space:]])Status:' && \
       ! printf '%s\n' "$ufw_status_out" | /usr/bin/grep -Eqi '(^|[[:space:]])Status:[[:space:]]*active([[:space:]]|$)'; then
      return 1
    fi
  fi
  UFW_STATUS_OUT="$ufw_status_out"
  return 0
}

has_preserved_tailscale_allow() {
  local ufw_out="$1"
  printf '%s\n' "$ufw_out" | /usr/bin/awk '
    {
      line = $0
      sub(/#.*/, "", line)
      sub(/^\[[[:space:]]*[0-9]+\][[:space:]]*/, "", line)
      has_tailscale = (line ~ /(^|[[:space:]])(on[[:space:]]+)?tailscale0([[:space:]]|$)/) ||
                      (line ~ /(^|[[:space:]])41641(\/udp)?([[:space:]]|$)/)
      if (!has_tailscale) next
      has_allow = (line ~ /(^|[[:space:]])ALLOW([[:space:]]+IN)?([[:space:]]|$)/) &&
                  !(line ~ /(^|[[:space:]])ALLOW[[:space:]]+(OUT|FWD)([[:space:]]|$)/) &&
                  !(line ~ /(^|[[:space:]])(DENY|REJECT)([[:space:]]|$)/)
      has_deny = (line ~ /(^|[[:space:]])(DENY|REJECT)([[:space:]]+IN)?([[:space:]]|$)/) &&
                 !(line ~ /(^|[[:space:]])(DENY|REJECT)[[:space:]]+(OUT|FWD)([[:space:]]|$)/)
      if (has_deny) blocked = 1
      if (has_allow) found = 1
    }
    END { exit((found && !blocked) ? 0 : 1) }
  '
}

load_and_verify_lan_policy() {
  LAN_INTERFACE=""
  LAN_PORTS_LIST=()

  if [ -L "$POLICY_DIR" ] || [ ! -d "$POLICY_DIR" ]; then
    return 1
  fi

  local policy_file
  if ! policy_file="$(find_lan_policy_file)"; then
    return 1
  fi
  if [ -L "$policy_file" ] || [ ! -f "$policy_file" ]; then
    return 1
  fi

  local owner mode
  owner="$(/usr/bin/stat -c '%u' "$policy_file" 2>/dev/null || printf 'invalid')"
  mode="$(/usr/bin/stat -c '%a' "$policy_file" 2>/dev/null || printf '777')"
  if [ "$TEST_MODE" = "0" ]; then
    if [ "$owner" != "0" ]; then
      return 1
    fi
    if [ $(( 8#$mode & 8#022 )) -ne 0 ]; then
      return 1
    fi
  else
    if [ "$owner" != "$REAL_UID" ] && [ "$owner" != "0" ]; then
      return 1
    fi
    if [ $(( 8#$mode & 8#002 )) -ne 0 ]; then
      return 1
    fi
  fi

  local line key val ports_raw=""
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%%$'\r'}"
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    if [[ "$line" =~ ^([A-Z_]+)=(.*)$ ]]; then
      key="${BASH_REMATCH[1]}"
      val="${BASH_REMATCH[2]}"
      case "$key" in
        LAN_INTERFACE) LAN_INTERFACE="$val" ;;
        LAN_PORTS) ports_raw="$val" ;;
        *) return 1 ;;
      esac
    else
      return 1
    fi
  done < "$policy_file"

  if [[ ! "$LAN_INTERFACE" =~ ^[A-Za-z0-9._:-]{1,32}$ ]] || \
     [ "$LAN_INTERFACE" = "lo" ] || [[ "$LAN_INTERFACE" == tailscale* ]]; then
    return 1
  fi

  if [ -z "$ports_raw" ]; then
    return 1
  fi

  local -a raw_ports=()
  IFS=',' read -r -a raw_ports <<< "$ports_raw"
  local port
  for port in "${raw_ports[@]}"; do
    if [[ ! "$port" =~ ^[0-9]+$ ]]; then
      return 1
    fi
    local pnum=$((10#$port))
    if [ "$pnum" -lt 1 ] || [ "$pnum" -gt 65535 ] || [ "$pnum" -eq 41641 ]; then
      return 1
    fi
    LAN_PORTS_LIST+=("$pnum")
  done

  [ "${#LAN_PORTS_LIST[@]}" -gt 0 ] || return 1

  # Verify UFW is active and preserved Tailscale paths are explicitly allowed before any mutation.
  if ! verify_ufw_active; then
    return 1
  fi
  if ! has_preserved_tailscale_allow "$UFW_STATUS_OUT"; then
    return 1
  fi

  return 0
}

find_tagged_rule_numbers_desc() {
  local ufw_numbered="$1"
  local tag="basho-$2"
  printf '%s\n' "$ufw_numbered" | /usr/bin/awk -v tag="$tag" '
    match($0, /^\[[[:space:]]*[0-9]+\]/) {
      num = substr($0, RSTART + 1, RLENGTH - 2)
      gsub(/[[:space:]]+/, "", num)
      idx = index($0, "# " tag)
      if (idx > 0) {
        rest = substr($0, idx + length("# " tag))
        if (rest == "" || substr(rest, 1, 1) ~ /[[:space:]]/) {
          print num
        }
      }
    }
  ' | /usr/bin/sort -rn
}

cmd_status() {
  [ $# -eq 0 ] || die "status takes no arguments" 64
  verify_helper_install || die "helper path or ownership verification failed" 1
  [ -x "$UFW_BIN" ] || die "ufw binary unavailable" 1
  [ -x "$SYSTEMD_RUN_BIN" ] || die "systemd-run binary unavailable" 1
  ensure_state_dir
  verify_ufw_active || die "ufw is not active" 1

  local lan_state="missing"
  if load_and_verify_lan_policy; then
    lan_state="ready"
  fi
  printf 'status=ready\neffective_uid=%s\nlan_policy=%s\n' "$EFFECTIVE_UID" "$lan_state"
}

cmd_deny_ip() {
  [ $# -eq 3 ] || die "usage: deny-ip <ip> <ttl> <id>" 64
  local raw_ip="$1" ttl="$2" op_id="$3"

  verify_helper_install || die "helper path or ownership verification failed" 1
  validate_ttl "$ttl"
  validate_op_id "$op_id"
  if ! canonicalize_and_validate_ip "$raw_ip"; then
    die "refused protected or malformed IP address" 1
  fi
  [ -x "$UFW_BIN" ] || die "ufw binary unavailable" 1
  [ -x "$SYSTEMD_RUN_BIN" ] || die "systemd-run binary unavailable" 1
  verify_ufw_active || die "ufw is not active" 1

  ensure_state_dir
  local lock_file="${STATE_DIR}/lock"
  local lease_file="${STATE_DIR}/lease-${op_id}.meta"
  local lease_tmp="${STATE_DIR}/.lease-${op_id}.$$.tmp"
  local timer_unit
  timer_unit="$(timer_unit_for_id "$op_id")"

  exec 9>"$lock_file"
  /usr/bin/flock -x 9

  printf 'verb=deny-ip\nip=%s\nttl=%s\nid=%s\ntimer=%s\n' \
    "$CANONICAL_IP" "$ttl" "$op_id" "$timer_unit" >"$lease_tmp"
  /usr/bin/mv -f "$lease_tmp" "$lease_file"

  # Arm independent lease rollback timer BEFORE mutating the firewall.
  if ! "$SYSTEMD_RUN_BIN" \
    --unit="$timer_unit" \
    --on-active="${ttl}s" \
    --timer-property=AccuracySec=1s \
    -- "$HELPER_SELF" rollback "$op_id" >/dev/null; then
    /usr/bin/rm -f "$lease_file"
    die "failed to arm rollback timer" 1
  fi

  if ! "$UFW_BIN" prepend deny from "$CANONICAL_IP" to any comment "basho-${op_id}" >/dev/null; then
    "$SYSTEMCTL_BIN" stop "${timer_unit}.timer" >/dev/null 2>&1 || true
    /usr/bin/rm -f "$lease_file"
    die "failed to prepend ufw deny rule" 1
  fi

  printf 'active %s\n' "$op_id"
}

cmd_isolate_lan() {
  [ $# -eq 2 ] || die "usage: isolate-lan <ttl> <id>" 64
  local ttl="$1" op_id="$2"

  verify_helper_install || die "helper path or ownership verification failed" 1
  validate_ttl "$ttl"
  validate_op_id "$op_id"

  if ! load_and_verify_lan_policy; then
    die "LAN policy missing or preserved paths could not be verified" 1
  fi

  ensure_state_dir
  local lock_file="${STATE_DIR}/lock"
  local lease_file="${STATE_DIR}/lease-${op_id}.meta"
  local lease_tmp="${STATE_DIR}/.lease-${op_id}.$$.tmp"
  local timer_unit
  timer_unit="$(timer_unit_for_id "$op_id")"

  exec 9>"$lock_file"
  /usr/bin/flock -x 9

  printf 'verb=isolate-lan\ninterface=%s\nttl=%s\nid=%s\ntimer=%s\n' \
    "$LAN_INTERFACE" "$ttl" "$op_id" "$timer_unit" >"$lease_tmp"
  /usr/bin/mv -f "$lease_tmp" "$lease_file"

  # Arm independent lease rollback timer BEFORE mutating the firewall.
  if ! "$SYSTEMD_RUN_BIN" \
    --unit="$timer_unit" \
    --on-active="${ttl}s" \
    --timer-property=AccuracySec=1s \
    -- "$HELPER_SELF" rollback "$op_id" >/dev/null; then
    /usr/bin/rm -f "$lease_file"
    die "failed to arm rollback timer" 1
  fi

  local port
  for port in "${LAN_PORTS_LIST[@]}"; do
    if ! "$UFW_BIN" prepend deny in on "$LAN_INTERFACE" to any port "$port" comment "basho-${op_id}" >/dev/null; then
      # Best-effort cleanup of partially inserted tagged rules, re-reading rule numbers each step.
      local partial_out next_num cleanup_iter=0
      while [ "$cleanup_iter" -lt 128 ]; do
        partial_out="$("$UFW_BIN" status numbered 2>/dev/null)" || break
        next_num="$(find_tagged_rule_numbers_desc "$partial_out" "$op_id" | /usr/bin/head -n 1)"
        [ -n "$next_num" ] || break
        "$UFW_BIN" --force delete "$next_num" >/dev/null 2>&1 || break
        cleanup_iter=$((cleanup_iter + 1))
      done
      die "failed to prepend LAN isolation rule for port $port" 1
    fi
  done

  printf 'active %s\n' "$op_id"
}

cmd_inspect() {
  [ $# -eq 1 ] || die "usage: inspect <id>" 64
  local op_id="$1"
  validate_op_id "$op_id"

  ensure_state_dir
  local lock_file="${STATE_DIR}/lock"
  exec 9>>"$lock_file"
  /usr/bin/flock -s 9

  local ufw_out
  if ! ufw_out="$("$UFW_BIN" status numbered)"; then
    die "ufw status failed" 1
  fi

  local matches
  matches="$(find_tagged_rule_numbers_desc "$ufw_out" "$op_id")"
  if [ -n "$matches" ]; then
    printf 'active\n'
  else
    printf 'absent\n'
  fi
}

cmd_rollback() {
  [ $# -eq 1 ] || die "usage: rollback <id>" 64
  local op_id="$1"
  validate_op_id "$op_id"

  ensure_state_dir
  local lock_file="${STATE_DIR}/lock"
  local lease_file="${STATE_DIR}/lease-${op_id}.meta"
  local timer_unit
  timer_unit="$(timer_unit_for_id "$op_id")"

  exec 9>"$lock_file"
  /usr/bin/flock -x 9

  # Re-read `ufw status numbered` before every single delete so concurrent operator
  # edits cannot cause stale rule numbers to delete the wrong rule.
  local max_iterations=128
  local iter=0
  local ufw_out next_num
  while [ "$iter" -lt "$max_iterations" ]; do
    if ! ufw_out="$("$UFW_BIN" status numbered)"; then
      die "ufw status failed during rollback" 1
    fi
    next_num="$(find_tagged_rule_numbers_desc "$ufw_out" "$op_id" | /usr/bin/head -n 1)"
    if [ -z "$next_num" ]; then
      break
    fi
    if ! "$UFW_BIN" --force delete "$next_num" >/dev/null; then
      die "failed to delete tagged rule $next_num" 1
    fi
    iter=$((iter + 1))
  done

  # Confirm no rules carrying this tag remain before clearing lease state.
  local verify_out remaining
  if ! verify_out="$("$UFW_BIN" status numbered)"; then
    die "ufw verification failed after rollback" 1
  fi
  remaining="$(find_tagged_rule_numbers_desc "$verify_out" "$op_id")"
  if [ -n "$remaining" ]; then
    die "tagged rules still present after rollback" 1
  fi

  /usr/bin/rm -f "$lease_file"
  "$SYSTEMCTL_BIN" stop "${timer_unit}.timer" >/dev/null 2>&1 || true
  printf 'absent\n'
}

VERB="${1:-}"
[ -n "$VERB" ] || die "missing verb" 64
shift

case "$VERB" in
  status) cmd_status "$@" ;;
  deny-ip) cmd_deny_ip "$@" ;;
  isolate-lan) cmd_isolate_lan "$@" ;;
  inspect) cmd_inspect "$@" ;;
  rollback) cmd_rollback "$@" ;;
  *) die "unknown verb: $VERB" 64 ;;
esac
