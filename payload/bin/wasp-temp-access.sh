#!/bin/sh
# =============================================================================
# wasp-temp-access.sh — time-boxed admin access for an outside contractor
# =============================================================================
# WHY THIS EXISTS
#
# "Let the web developer in for a couple of days" is a routine request and a
# routinely permanent outcome. The IP gets added by hand, the work finishes,
# and the entry stays — because removing it is a separate task nobody is
# assigned and nobody is reminded of. Allowlists accrete, and every stale
# entry is a route into wp-admin that no longer has an owner.
#
# So the grant and the revocation are created together, or not at all. The
# expiry is scheduled at the same moment the access is opened, by the same
# command, and it does not depend on anyone remembering.
#
# WHAT IT TOUCHES
#
# Admin access on this VM is enforced by TWO independent layers, and a
# contractor outside the permitted country needs an exemption in both:
#
#   wp-security.conf  <DirectoryMatch wp-admin> / <Files wp-login.php>
#                     -- the IP allowlist
#   geoip.conf        <Location /> -- the country test, which applies to
#                     every URL on the site
#
# Since AuthMerging And, both must pass. Granting in only one place produces
# a 403 that looks like the grant failed. This writes both.
#
# Every inserted line carries a marker comment naming the label and the
# expiry, so revocation is an exact string match rather than a guess about
# which lines were added by hand.
#
#   wasp-temp-access.sh grant <label> <days> <ip> [ip...]
#   wasp-temp-access.sh revoke <label>
#   wasp-temp-access.sh list
#
# =============================================================================
set -u

CONF_DIR=/home/wpuser/wp/apache-conf
SEC_CONF="${CONF_DIR}/wp-security.conf"
GEO_CONF="${CONF_DIR}/geoip.conf"
LOG=/var/log/wasp-temp-access.log
CRONTAB=/etc/crontabs/root
MARKER="WASP-TEMP-ACCESS"
SELF=/usr/local/bin/wasp-temp-access.sh

_ok()   { printf '  \033[32m✔\033[0m  %s\n' "$1"; }
_bad()  { printf '  \033[31m✗\033[0m  %s\n' "$1" >&2; }
_warn() { printf '  \033[33m⚠\033[0m  %s\n' "$1" >&2; }
_log()  { printf '%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$LOG" 2>/dev/null || true; }

# A bind-mounted single file keeps its INODE. sed -i writes a new file and
# renames over it, which leaves the container reading the ORIGINAL inode --
# the edit appears to work on the host and has no effect inside. Truncate and
# rewrite in place instead. This cost a live debugging session once already.
_write_inplace() {  # $1 = target, stdin = new content
  _tmp=$(mktemp 2>/dev/null || echo "/tmp/wta.$$")
  cat > "$_tmp" || return 1
  [ -s "$_tmp" ] || { _bad "refusing to write an empty $1"; rm -f "$_tmp"; return 1; }
  cat "$_tmp" > "$1" || { rm -f "$_tmp"; return 1; }
  rm -f "$_tmp"
}

_reload() {
  if ! podman exec wordpress apache2ctl configtest 2>&1 | grep -q 'Syntax OK'; then
    _bad "Apache rejected the configuration — NOT reloading."
    podman exec wordpress apache2ctl configtest 2>&1 | sed 's/^/     /' >&2
    return 1
  fi
  podman exec wordpress apache2ctl -k graceful >/dev/null 2>&1
  sleep 2
  # The public site must still answer. <Location /> matches every URL, so a
  # mistake here takes the whole site down, not just admin.
  _code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1/ 2>/dev/null)
  case "$_code" in
    200|301|302) _ok "Apache reloaded; public site answering (${_code})" ; return 0 ;;
    *) _bad "Public site returned ${_code} after reload — check immediately." ; return 1 ;;
  esac
}

_valid_ip() {
  printf '%s' "$1" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$' || return 1
  # Reject the obviously-too-broad. A /0 or /8 here is not a contractor.
  case "$1" in */[0-9]|*/1[0-5]) return 1 ;; esac
  return 0
}

case "${1:-}" in

# ── grant ───────────────────────────────────────────────────────────────────
grant)
  _label="${2:-}"; _days="${3:-}"; shift 3 2>/dev/null || true
  [ -n "$_label" ] && [ -n "$_days" ] && [ $# -gt 0 ] || {
    echo "Usage: wasp-temp-access.sh grant <label> <days> <ip> [ip...]" >&2
    echo "   eg: wasp-temp-access.sh grant webdev 2 139.135.49.52 124.29.239.165" >&2
    exit 1; }
  printf '%s' "$_label" | grep -qE '^[A-Za-z0-9_-]+$' || { _bad "label must be letters, digits, dash, underscore"; exit 1; }
  case "$_days" in ''|*[!0-9]*) _bad "days must be a number"; exit 1 ;; esac
  [ "$_days" -ge 1 ] && [ "$_days" -le 30 ] || { _bad "days must be 1-30. Longer than that is not temporary."; exit 1; }

  for _ip in "$@"; do
    _valid_ip "$_ip" || { _bad "'${_ip}' is not a plausible single address or narrow CIDR"; exit 1; }
  done

  grep -q "${MARKER} ${_label} " "$SEC_CONF" 2>/dev/null && {
    _bad "label '${_label}' is already granted. Revoke it first:  wasp-temp-access.sh revoke ${_label}"; exit 1; }

  _exp_epoch=$(( $(date +%s) + _days * 86400 ))
  _exp_human=$(date -u -d "@${_exp_epoch}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
               || date -u -r "${_exp_epoch}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)
  _exp_min=$(date -u -d "@${_exp_epoch}" +%M 2>/dev/null || date -u -r "${_exp_epoch}" +%M)
  _exp_hr=$(date  -u -d "@${_exp_epoch}" +%H 2>/dev/null || date -u -r "${_exp_epoch}" +%H)
  _exp_day=$(date -u -d "@${_exp_epoch}" +%d 2>/dev/null || date -u -r "${_exp_epoch}" +%d)
  _exp_mon=$(date -u -d "@${_exp_epoch}" +%m 2>/dev/null || date -u -r "${_exp_epoch}" +%m)

  cp "$SEC_CONF" "${SEC_CONF}.bak-$(date -u +%s)" 2>/dev/null
  cp "$GEO_CONF" "${GEO_CONF}.bak-$(date -u +%s)" 2>/dev/null

  # Build the lines once, used in both files. Inserting immediately after
  # <RequireAny> is structurally valid in every block we target and avoids
  # depending on which install-specific Require lines are already present.
  _ins=""
  for _ip in "$@"; do
    _ins="${_ins}            Require ip ${_ip}  # ${MARKER} ${_label} expires=${_exp_human}
"
  done

  for _f in "$SEC_CONF" "$GEO_CONF"; do
    [ -f "$_f" ] || { _bad "missing ${_f}"; exit 1; }
    awk -v ins="$_ins" '
      /<RequireAny>/ { print; printf "%s", ins; next }
      { print }
    ' "$_f" | _write_inplace "$_f" || { _bad "could not write ${_f}"; exit 1; }
  done
  _ok "Granted in wp-security.conf (admin allowlist) and geoip.conf (country test)"

  # Schedule the revocation NOW. An expiry that depends on someone
  # remembering is not an expiry.
  mkdir -p "$(dirname "$CRONTAB")" 2>/dev/null
  touch "$CRONTAB" 2>/dev/null
  grep -v "${MARKER} ${_label}\$" "$CRONTAB" 2>/dev/null > "${CRONTAB}.tmp" || true
  printf '%s %s %s %s * %s revoke %s  # %s %s\n' \
    "$_exp_min" "$_exp_hr" "$_exp_day" "$_exp_mon" "$SELF" "$_label" "$MARKER" "$_label" \
    >> "${CRONTAB}.tmp"
  cat "${CRONTAB}.tmp" > "$CRONTAB"; rm -f "${CRONTAB}.tmp"
  rc-service crond restart >/dev/null 2>&1 || /etc/init.d/crond restart >/dev/null 2>&1 || true
  _ok "Revocation scheduled for ${_exp_human} (cron, as root)"

  if ! _reload; then
    _warn "Rolling the grant back because the reload did not come up clean."
    "$SELF" revoke "$_label" >/dev/null 2>&1
    exit 1
  fi

  _log "GRANT label=${_label} ips=$* expires=${_exp_human}"
  echo ""
  echo "  Access opens NOW and closes automatically at ${_exp_human} (UTC)."
  echo "  Revoke sooner with:  wasp-temp-access.sh revoke ${_label}"
  echo ""
  _warn "They still need a WordPress account, and MFA enforcement applies to it."
  _warn "An IP exemption is not a login."
  ;;

# ── revoke ──────────────────────────────────────────────────────────────────
revoke)
  _label="${2:-}"
  [ -n "$_label" ] || { echo "Usage: wasp-temp-access.sh revoke <label>" >&2; exit 1; }

  _found=0
  for _f in "$SEC_CONF" "$GEO_CONF"; do
    [ -f "$_f" ] || continue
    grep -q "${MARKER} ${_label} " "$_f" 2>/dev/null && _found=1
    grep -v "${MARKER} ${_label} " "$_f" | _write_inplace "$_f" \
      || { _bad "could not rewrite ${_f}"; exit 1; }
  done

  if [ -f "$CRONTAB" ]; then
    grep -v "${MARKER} ${_label}\$" "$CRONTAB" > "${CRONTAB}.tmp" 2>/dev/null || true
    cat "${CRONTAB}.tmp" > "$CRONTAB"; rm -f "${CRONTAB}.tmp"
    rc-service crond restart >/dev/null 2>&1 || /etc/init.d/crond restart >/dev/null 2>&1 || true
  fi

  if [ "$_found" = "1" ]; then
    _ok "Revoked '${_label}' from both layers and removed its scheduled expiry"
    _log "REVOKE label=${_label}"
  else
    _warn "No active grant named '${_label}' — nothing to remove."
  fi
  _reload || exit 1
  ;;

# ── list ────────────────────────────────────────────────────────────────────
list|status)
  echo ""
  echo "Temporary admin access grants"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  if ! grep -h "$MARKER" "$SEC_CONF" 2>/dev/null | grep -q .; then
    echo "  (none)"
  else
    # Deduplicate: wp-security.conf carries two RequireAny blocks
    # (<DirectoryMatch wp-admin> and <Files wp-login.php>), so every grant
    # legitimately appears twice. Listing it twice reads like a mistake.
    grep -h "$MARKER" "$SEC_CONF" 2>/dev/null | sort -u | while IFS= read -r _l; do
      _ip=$(printf '%s' "$_l" | awk '{print $3}')
      _lb=$(printf '%s' "$_l" | sed "s/.*${MARKER} //;s/ expires=.*//")
      _ex=$(printf '%s' "$_l" | sed 's/.*expires=//')
      printf '  %-18s %-22s expires %s\n' "$_lb" "$_ip" "$_ex"
    done
  fi
  echo ""
  echo "Scheduled revocations:"
  grep "$MARKER" "$CRONTAB" 2>/dev/null | sed 's/^/  /' || echo "  (none)"
  echo ""
  ;;

*)
  sed -n '38,42p' "$0"
  exit 1 ;;
esac
