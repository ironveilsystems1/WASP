#!/bin/sh
# =============================================================================
# wasp-appsec.sh — CrowdSec AppSec (WAF) body inspection, light ruleset, opt-in
# =============================================================================
#   wasp-appsec.sh status                 what is on, memory, recent blocks
#   wasp-appsec.sh on [--key-file F] [--fail-closed] [--max-body BYTES] [--yes]
#   wasp-appsec.sh off
#   wasp-appsec.sh test                   prove a request is inspected and blocked
#   wasp-appsec.sh watchdog               cron: restart CrowdSec before it hits its cap
#
# WHAT IT ADDS. Without it, CrowdSec on WASP reads LOGS: it bans an address
# after the requests are made. With it, every PHP request is shown to the
# AppSec component first, body included, and refused (403) if a rule matches:
# virtual patches for known WordPress plugin CVEs and a few generic rules. That
# is the difference between banning the scanner after the exploit attempt and
# refusing the exploit attempt.
#
# WHAT "LIGHT" MEANS. In-band virtual patching and generic rules only. No
# OWASP Core Rule Set, in band or out of band. See
# payload/crowdsec/appsec/wasp-appsec-light.yaml for why.
#
# THE COST, stated before anything is switched on:
#   memory  CrowdSec 1.8.x has an open report of AppSec memory growing without
#           bound under load (issue #4797: coraza transformation cache; RSS to
#           ~2.5 GB with CRS out of band; fix milestoned for 1.8.3). The light
#           ruleset evaluates far fewer transformations, but the same code is
#           in the path. WASP caps the CrowdSec container at 512 MB, and the
#           watchdog restarts it at 448 MB rather than waiting for the kernel
#           to kill it. While it restarts (~15 s) requests pass uninspected
#           (fail-open), and log detection pauses.
#   CPU     one extra local HTTP round trip per PHP request, usually 1-5 ms,
#           bounded by a 200 ms timeout. 2 vCPU recommended.
#   reach   PHP requests only. Bodies over 128 KiB are forwarded without the
#           body. Files inside multipart uploads are not forwarded.
# =============================================================================
set -u

if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then exec doas "$0" "$@"; fi
  echo "Run as root (or via doas)" >&2; exit 1
fi

ETC=${WASP_ETC:-/etc/wp-install}
[ -r "$ETC/vars.sh" ] && . "$ETC/vars.sh"
PAYLOAD=${WASP_PAYLOAD:-/etc/wp-install/payload}
CS_CONF=${CS_CONF_DIR:-/opt/crowdsec/config}
SECRETS=${WP_SECRETS_DIR:-/home/wpuser/wp/secrets}
PHPCONF=${WP_PHPCONF_DIR:-/home/wpuser/wp/php-conf}
STATE=${APPSEC_STATE:-/var/lib/wasp-appsec}
RUN_EXTRA=${WP_RUN_EXTRA:-$ETC/wp-run-extra.env}
LISTEN_PORT=${APPSEC_PORT:-7422}
FW_RULE=${FW_RULE:-/usr/local/bin/wasp-fw-rule.sh}
SITE_URL=${APPSEC_SITE_URL:-http://127.0.0.1}
GW=10.89.10.1
WP_IP=10.89.10.3
MEM_RESTART_MB=${APPSEC_MEM_RESTART_MB:-448}
BOUNCER_NAME=wasp-appsec
TEST_URI=/crowdsec-test-NtktlJHV4TfBSK3wvlhiOBnl
PREPEND_IN_CTR=/usr/local/lib/wasp/wasp-appsec.php
MOUNTS="-v ${PHPCONF}/wasp-appsec.php:${PREPEND_IN_CTR}:ro -v ${PHPCONF}/wasp-appsec.ini:/usr/local/etc/php/conf.d/zz-wasp-appsec.ini:ro"

_ok()  { printf '  \033[32m✔\033[0m  %s\n' "$1"; }
_bad() { printf '  \033[31m✗\033[0m  %s\n' "$1"; }
_warn(){ printf '  \033[33m!\033[0m  %s\n' "$1"; }
_note(){ printf '     %s\n' "$1"; }

_src() {   # the payload copy of a file, falling back to the installed tool's own release tree
  for _d in "$PAYLOAD" /usr/local/share/wasp; do
    [ -r "$_d/$1" ] && { printf '%s' "$_d/$1"; return 0; }
  done
  return 1
}

_enabled() { [ -r "$SECRETS/appsec.ini" ] && grep -q '^enabled = 1' "$SECRETS/appsec.ini"; }
_cs_up()   { podman inspect -f '{{.State.Running}}' crowdsec 2>/dev/null | grep -q true; }
_upstream(){ grep -q '^enforcement=upstream' "$ETC/crowdsec-topology" 2>/dev/null; }

# HTTP status from the listener for a request with the given key (or none).
_probe() {   # _probe <key|-> <uri> [ip]
  if [ "$1" = - ]; then
    curl -s --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${LISTEN_PORT}/" 2>/dev/null
  else
    curl -s --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 5 \
      -H "X-Crowdsec-Appsec-Api-Key: $1" -H "X-Crowdsec-Appsec-Ip: ${3:-$GW}" \
      -H "X-Crowdsec-Appsec-Uri: $2" -H "X-Crowdsec-Appsec-Host: wasp-appsec.test" \
      -H "X-Crowdsec-Appsec-Verb: GET" -H "X-Crowdsec-Appsec-User-Agent: wasp-appsec-selftest" \
      -H "X-Crowdsec-Appsec-Http-Version: 11" "http://127.0.0.1:${LISTEN_PORT}/" 2>/dev/null
  fi
}

# CrowdSec container memory in MiB: podman stats, falling back to the main
# process's resident set.
_cs_mem_mb() {
  _mu=$(podman stats --no-stream --format '{{.MemUsage}}' crowdsec 2>/dev/null | head -1 | cut -d/ -f1 | tr -d ' ')
  _mb=$(printf '%s' "$_mu" | awk '
    match($0, /^[0-9.]+/) { n = substr($0, 1, RLENGTH); u = substr($0, RLENGTH + 1)
      if (u == "B") n /= 1048576; else if (u == "kB" || u == "KB") n /= 1024; else if (u == "KiB") n /= 1024
      else if (u == "MB") n = n * 1000000 / 1048576; else if (u == "GB") n = n * 1000000000 / 1048576
      else if (u == "GiB") n *= 1024; else if (u != "MiB") { print ""; exit }
      printf "%d\n", n }')
  if [ -z "$_mb" ]; then
    _pid=$(podman inspect -f '{{.State.Pid}}' crowdsec 2>/dev/null)
    [ -n "$_pid" ] && _mb=$(awk '/^VmRSS:/ {printf "%d\n", $2/1024}' "/proc/$_pid/status" 2>/dev/null)
  fi
  printf '%s' "${_mb:-0}"
}

_restart_cs() {
  podman restart crowdsec >/dev/null 2>&1 || return 1
  for _i in 1 2 3 4 5 6 7 8 9 10 11 12; do
    _c=$(_probe -); [ -n "$_c" ] && [ "$_c" != 000 ] && return 0
    sleep 5
  done
  return 1
}

_wp_mounts_present() { grep -qF "zz-wasp-appsec.ini" "$RUN_EXTRA" 2>/dev/null; }

# Adds the two mounts to the record every WordPress-container rebuild path
# reads (stage 06, the OpenRC service, update.sh, wp-geoip-setup.sh), then
# recreates the container through the OpenRC service so the mounts exist.
# Installs from 10.13 on have them from the start.
_wp_mounts_ensure() {
  _wp_mounts_present && return 0
  [ -r "$RUN_EXTRA" ] || { _bad "No ${RUN_EXTRA} — cannot add the forwarder mounts"; return 1; }
  _cur=$(sed -n "s/^WP_EXTRA_VOLS='\(.*\)'$/\1/p" "$RUN_EXTRA")
  _new="${_cur:+$_cur }${MOUNTS}"
  _q=$(printf '%s' "$_new" | sed "s/'/'\\\\''/g")
  if grep -q '^WP_EXTRA_VOLS=' "$RUN_EXTRA"; then
    sed -i "s|^WP_EXTRA_VOLS=.*|WP_EXTRA_VOLS='${_q}'|" "$RUN_EXTRA"
  else
    printf "WP_EXTRA_VOLS='%s'\n" "$_q" >> "$RUN_EXTRA"
  fi
  _note "Recreating the WordPress container with the forwarder mounts (a few seconds of downtime)…"
  podman rm -f wordpress >/dev/null 2>&1
  rc-service wp-container restart >/dev/null 2>&1 || rc-service wp-container start >/dev/null 2>&1
  sleep 3
  podman inspect wordpress >/dev/null 2>&1 || { _bad "WordPress did not come back — rc-service wp-container start"; return 1; }
}

_install_php_files() {
  install -d -m 0755 "$PHPCONF"
  _p=$(_src php-conf/wasp-appsec.php) || { _bad "wasp-appsec.php not found in the payload"; return 1; }
  install -m 0644 "$_p" "$PHPCONF/wasp-appsec.php"
  [ -f "$PHPCONF/wasp-appsec.ini" ] || printf '; WASP AppSec forwarder: OFF.\n' > "$PHPCONF/wasp-appsec.ini"
  chmod 0644 "$PHPCONF/wasp-appsec.ini"
}

# Written in place (truncate, not replace): a bind-mounted file that is
# replaced by rename keeps showing the container the old inode.
_set_ini() {
  if [ "$1" = on ]; then
    printf '; WASP AppSec forwarder: ON (wasp-appsec.sh).\nauto_prepend_file = %s\n' "$PREPEND_IN_CTR" > "$PHPCONF/wasp-appsec.ini"
  else
    printf '; WASP AppSec forwarder: OFF.\n' > "$PHPCONF/wasp-appsec.ini"
  fi
}

_warning_block() {
  _mem_total=$(awk '/^MemTotal:/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null)
  _cpus=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)
  echo ""
  echo "  CrowdSec AppSec — light ruleset (virtual patching + generic rules, no CRS)"
  echo "  ─────────────────────────────────────────────────────────────────────────"
  echo "  Memory: CrowdSec 1.8.x has an OPEN report of AppSec memory growing"
  echo "    without bound under load (crowdsecurity/crowdsec#4797, the coraza"
  echo "    transformation cache; ~2.5 GB with CRS; fix planned for 1.8.3)."
  echo "    The light ruleset runs far fewer transformations, but the same code."
  echo "    CrowdSec stays capped at 512 MB, and a watchdog restarts it at"
  echo "    ${MEM_RESTART_MB} MB. During a restart (~15 s) requests pass UNINSPECTED"
  echo "    and log detection pauses. Every restart is logged and reported."
  echo "  CPU: one local round trip per PHP request, usually 1-5 ms, never more"
  echo "    than 200 ms. Under a flood, that is CPU the site does not get."
  echo "  Reach: PHP requests only; bodies over $(( ${MAX_BODY:-131072} / 1024 )) KiB are forwarded without"
  echo "    the body; files in uploads are not forwarded."
  echo ""
  printf '  This VM: %s MB RAM, %s vCPU.' "${_mem_total:-?}" "${_cpus:-?}"
  if [ "${_mem_total:-0}" -lt 1800 ] || [ "${_cpus:-0}" -lt 2 ]; then
    echo "  BELOW the 2 GB / 2 vCPU recommended for AppSec."
  else
    echo "  Meets the 2 GB / 2 vCPU recommendation."
  fi
  echo ""
}

# ── Commands ────────────────────────────────────────────────────────────────
cmd_status() {
  echo ""
  echo "CrowdSec AppSec (WAF body inspection)"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  if _enabled; then _ok "ON — light ruleset, PHP requests inspected before WordPress runs"
  else _note "OFF. CrowdSec reads logs only. To inspect requests: wasp-appsec.sh on"; fi
  _c=$(_probe -)
  case "$_c" in
    ''|000) if _enabled; then _bad "Listener 127.0.0.1:${LISTEN_PORT} not answering — requests pass UNINSPECTED"; fi ;;
    *) _ok "Listener answering on :${LISTEN_PORT}" ;;
  esac
  if _cs_up; then
    _m=$(_cs_mem_mb)
    if [ "$_m" -ge "$MEM_RESTART_MB" ]; then _warn "CrowdSec memory ${_m} MB (watchdog restarts at ${MEM_RESTART_MB}, cap 512)"
    else _ok "CrowdSec memory ${_m} MB (watchdog restarts at ${MEM_RESTART_MB}, cap 512)"; fi
  else
    _bad "CrowdSec container not running"
  fi
  _r=$(_restarts_24h)
  [ "$_r" -gt 0 ] && _warn "Watchdog restarts in the last 24 h: ${_r}" || _ok "No watchdog restarts in the last 24 h"
  if _enabled; then
    grep -q '^failure_action = ban' "$SECRETS/appsec.ini" && _note "If AppSec is unreachable: requests REFUSED (fail-closed)" \
      || _note "If AppSec is unreachable: requests pass uninspected (fail-open)"
    if grep -qs 'auto_prepend_file' /home/wpuser/wp/html/.htaccess /home/wpuser/wp/html/.user.ini 2>/dev/null; then
      _warn "The site sets its own auto_prepend_file (.htaccess/.user.ini — e.g. a plugin firewall)."
      _note "That replaces this forwarder for the site's requests. Remove one of the two."
    fi
  fi
  echo ""
}

_restarts_24h() {
  _since=$(( $(date +%s) - 86400 ))
  awk -v s="$_since" '$1 >= s' "$STATE/restarts" 2>/dev/null | grep -c . || true
}

cmd_on() {
  _key_file=""; _fail=passthrough; MAX_BODY=131072; _yes=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --key-file) _key_file="${2:-}"; shift 2 ;;
      --fail-closed) _fail=ban; shift ;;
      --max-body) MAX_BODY="${2:-}"; shift 2 ;;
      --yes|-y) _yes=1; shift ;;
      *) echo "Unknown option: $1" >&2; return 2 ;;
    esac
  done
  case "$MAX_BODY" in ''|*[!0-9]*) echo "--max-body takes a number of bytes" >&2; return 2 ;; esac
  [ "$MAX_BODY" -le 1048576 ] || { echo "--max-body is capped at 1 MiB on a WASP VM" >&2; return 2; }

  _warning_block
  if [ "$_yes" != 1 ]; then
    printf '  Switch AppSec on? [y/N] : '; read -r _a
    case "$_a" in y|Y|yes) : ;; *) echo "  Nothing changed."; return 0 ;; esac
  fi
  _cs_up || { _bad "CrowdSec is not running. Fix that first: wp-hardening.sh cs-doctor"; return 1; }

  # The API key the forwarder presents. AppSec checks it against the LAPI.
  if [ -n "$_key_file" ]; then
    [ -r "$_key_file" ] || { _bad "Cannot read ${_key_file}"; return 1; }
    _key=$(tr -d ' \r\n' < "$_key_file")
  elif _upstream; then
    _bad "This VM reports to a central LAPI, so the key must be made there:"
    _note "  on the LAPI host:  cscli bouncers add $(hostname)-appsec"
    _note "  then here:         echo '<key>' > /root/appsec.key; chmod 600 /root/appsec.key"
    _note "                     doas wasp-appsec.sh on --key-file /root/appsec.key"
    return 2
  else
    podman exec crowdsec cscli bouncers delete "$BOUNCER_NAME" >/dev/null 2>&1
    _key=$(podman exec crowdsec cscli bouncers add "$BOUNCER_NAME" -o raw 2>/dev/null | tail -1 | tr -d ' \r\n')
  fi
  case "$_key" in ''|*[!A-Za-z0-9_+/=-]*) _bad "No usable API key"; return 1 ;; esac

  echo "  Installing the AppSec rule collections…"
  podman exec crowdsec cscli collections install crowdsecurity/appsec-virtual-patching \
      crowdsecurity/appsec-generic-rules >/dev/null 2>&1 \
    || { _bad "Could not install the AppSec collections (hub reachable from this VM?)"; return 1; }

  _a=$(_src crowdsec/appsec/wasp-appsec.yaml) && _c=$(_src crowdsec/appsec/wasp-appsec-light.yaml) \
    || { _bad "AppSec configuration files not found in the payload"; return 1; }
  install -d "$CS_CONF/acquis.d" "$CS_CONF/appsec-configs"
  install -m 0644 "$_c" "$CS_CONF/appsec-configs/wasp-appsec-light.yaml"
  install -m 0644 "$_a" "$CS_CONF/acquis.d/wasp-appsec.yaml"
  # The acquisition directory must be read. Default configs carry it; an
  # older config.yaml may not.
  if [ -f "$CS_CONF/config.yaml" ] && ! grep -q 'acquisition_dir:' "$CS_CONF/config.yaml"; then
    sed -i 's|^\([[:space:]]*\)acquisition_path:.*|&\n\1acquisition_dir: /etc/crowdsec/acquis.d|' "$CS_CONF/config.yaml"
  fi

  if ! _restart_cs || [ "$(_probe -)" = 000 ]; then
    _bad "CrowdSec did not come back with the AppSec listener. Rolling back."
    podman logs --tail 15 crowdsec 2>&1 | sed 's/^/       /'
    _rollback_cs
    return 1
  fi
  _c=$(_probe "$_key" /)
  if [ "$_c" != 200 ]; then
    _bad "The listener refused the API key (HTTP ${_c}). Rolling back."
    _upstream && _note "The key must be a bouncer on the central LAPI this VM reports to."
    _rollback_cs
    return 1
  fi
  _ok "AppSec listener up, API key accepted"

  "$FW_RULE" add appsec input ip saddr "$WP_IP" ip daddr "$GW" tcp dport "$LISTEN_PORT" accept >/dev/null \
    || { _bad "Could not add the firewall rule for the container. Rolling back."; _rollback_cs; return 1; }

  _install_php_files || { _rollback_cs; return 1; }
  ( umask 027
    { printf 'enabled = 1\n'
      printf 'url = http://%s:%s/\n' "$GW" "$LISTEN_PORT"
      printf 'key = %s\n' "$_key"
      printf 'timeout_ms = 200\nmax_body = %s\nfailure_action = %s\n' "$MAX_BODY" "$_fail"
    } > "$SECRETS/appsec.ini" )
  chown root:33 "$SECRETS/appsec.ini" 2>/dev/null; chmod 0440 "$SECRETS/appsec.ini"
  _set_ini on
  if _wp_mounts_present; then
    podman restart wordpress >/dev/null 2>&1
  else
    _wp_mounts_ensure || { cmd_off >/dev/null 2>&1; return 1; }
  fi
  mkdir -p "$STATE"
  logger -t wasp-appsec "AppSec light ruleset ON (failure_action=${_fail}, max_body=${MAX_BODY})" 2>/dev/null
  _ok "AppSec ON. PHP requests are inspected before WordPress runs."
  echo ""
  cmd_test
}

_rollback_cs() {
  rm -f "$CS_CONF/acquis.d/wasp-appsec.yaml" "$CS_CONF/appsec-configs/wasp-appsec-light.yaml"
  _restart_cs >/dev/null 2>&1
  if _cs_up; then _note "CrowdSec restored without AppSec."
  else _bad "CrowdSec is not running after the rollback: podman logs crowdsec"; fi
}

cmd_off() {
  [ -f "$SECRETS/appsec.ini" ] && printf 'enabled = 0\n' > "$SECRETS/appsec.ini"
  [ -f "$PHPCONF/wasp-appsec.ini" ] && _set_ini off
  podman restart wordpress >/dev/null 2>&1
  rm -f "$CS_CONF/acquis.d/wasp-appsec.yaml" "$CS_CONF/appsec-configs/wasp-appsec-light.yaml"
  _restart_cs >/dev/null 2>&1
  "$FW_RULE" del appsec >/dev/null 2>&1
  _upstream || podman exec crowdsec cscli bouncers delete "$BOUNCER_NAME" >/dev/null 2>&1
  logger -t wasp-appsec "AppSec OFF" 2>/dev/null
  _ok "AppSec OFF. CrowdSec reads logs only, as before."
}

cmd_test() {
  _enabled || { _bad "AppSec is off."; return 1; }
  _key=$(sed -n 's/^key = //p' "$SECRETS/appsec.ini")
  _rc=0
  _c=$(_probe "$_key" /)
  [ "$_c" = 200 ] && _ok "A clean request is allowed by the engine (200)" || { _bad "A clean request got ${_c}, expected 200"; _rc=1; }
  _c=$(_probe "$_key" "$TEST_URI")
  [ "$_c" = 403 ] && _ok "The CrowdSec test request is blocked by the engine (403)" \
    || { _bad "The CrowdSec test request got ${_c}, expected 403 (rules not loaded?)"; _rc=1; }
  # Through Apache and PHP, from this host: the full path a visitor's request
  # takes. The source is a private address, so no ban follows.
  _c=$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 10 \
         -H "Host: ${WP_DOMAIN:-localhost}" "${SITE_URL}${TEST_URI}" 2>/dev/null)
  [ "$_c" = 403 ] && _ok "Through the site itself, the test request is refused (403)" \
    || { _bad "Through the site, the test request got ${_c}, expected 403 — the forwarder is not in the path"; _rc=1; }
  return $_rc
}

# Every 5 minutes from cron. Silent unless something needs saying.
cmd_watchdog() {
  _enabled || return 0
  mkdir -p "$STATE"
  if ! _cs_up; then
    logger -t wasp-appsec "CrowdSec not running: requests pass UNINSPECTED" 2>/dev/null
    return 1
  fi
  _m=$(_cs_mem_mb)
  printf '%s %s\n' "$(date +%s)" "$_m" > "$STATE/last-mem"
  if [ "$_m" -ge "$MEM_RESTART_MB" ]; then
    logger -t wasp-appsec "CrowdSec at ${_m} MB (restart threshold ${MEM_RESTART_MB}, cap 512): restarting before the cap is hit — known AppSec memory growth, crowdsecurity/crowdsec#4797" 2>/dev/null
    date +%s >> "$STATE/restarts"
    tail -200 "$STATE/restarts" > "$STATE/restarts.tmp" && mv -f "$STATE/restarts.tmp" "$STATE/restarts"
    _restart_cs || logger -t wasp-appsec "CrowdSec did not come back after the watchdog restart" 2>/dev/null
  fi
  return 0
}

case "${1:-status}" in
  status) cmd_status ;;
  on) shift; cmd_on "$@" ;;
  off) cmd_off ;;
  test) cmd_test ;;
  watchdog) cmd_watchdog ;;
  *) sed -n '4,8p' "$0"; exit 2 ;;
esac
