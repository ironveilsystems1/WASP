#!/bin/sh
# =============================================================================
# wasp-alerts.sh — what the site emails you about, and the watches behind it
# =============================================================================
#   wasp-alerts.sh status                 what is emailed, to whom
#   wasp-alerts.sh setup [email,...]      write the settings (installer runs it)
#   wasp-alerts.sh to <email[,email]>     change who receives them
#   wasp-alerts.sh on|off <event|all>     turn one event (or every one) on or off
#   wasp-alerts.sh login-mode new_ip|all  admin sign-ins: new addresses only, or every one
#   wasp-alerts.sh test                   send a real alert through WordPress
#
#   wasp-alerts.sh watch-site             cron: site down for 10 min, and recovered
#   wasp-alerts.sh watch-admins           cron: the administrator list in the DATABASE changed
#   wasp-alerts.sh watch-integrity        cron: plugin files or WASP's own tools modified
#
# TWO HALVES
#
# Inside WordPress, the 07-wasp-alerts.php mu-plugin emails the operator when
# an administrator is added or removed, signs in from a new address, changes
# a password or email, when an application password is created, two-factor
# is turned off, code changes, or the site address, admin email, registration
# or default role change. Those are actions taken THROUGH WordPress by someone
# with a session -- invisible to every file and log scan WASP runs.
#
# On the host, three watches cover what WordPress cannot report about itself:
#   site       WordPress stopped serving (it cannot email about its own outage)
#   admins     an administrator that appeared in the database without passing
#              through WordPress -- SQL injection, a stolen database login --
#              so no hook fired
#   integrity  plugin files that no longer match wordpress.org, or WASP's own
#              tools modified (both weekly checks only logged, until now)
#   content    spam links typed or pasted into the pages (wp-links.sh spam,
#              weekly) -- content, so no file scan ever sees it
#
# ONE SETTINGS FILE
#
# /home/wpuser/wp/secrets/alerts.ini, mounted read-only into WordPress at
# /var/www/private/alerts.ini. Read-only and outside wp-admin on purpose: an
# intruder with an administrator session cannot switch alerts off or send
# them elsewhere. Every event defaults to ON.
# =============================================================================
set -u
if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then exec doas "$0" "$@"; fi
  echo "Run as root (or via doas)" >&2; exit 1
fi
[ -r /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh

SECRETS_DIR="${WASP_SECRETS_DIR:-/home/wpuser/wp/secrets}"
ALERTS_FILE="${SECRETS_DIR}/alerts.ini"
STATE="${WASP_ALERTS_STATE:-/var/lib/wasp-alerts}"
NOTIFY="${WASP_NOTIFY:-/usr/local/bin/wp-notify.sh}"
HEALTH="${WASP_HEALTH_CHECK:-/usr/local/bin/wp-health-check.sh}"
PLUGINS="${WASP_PLUGINS_TOOL:-/usr/local/bin/wp-plugins.sh}"
VERIFY="${WASP_VERIFY_TOOL:-/usr/local/bin/wasp-verify-integrity.sh}"
UPDATE_LOCK="${WASP_UPDATE_LOCK:-/run/lock/wordpress-update.lock}"
SITE_FAILS_TO_ALERT="${SITE_FAILS_TO_ALERT:-2}"
SITE_REMIND_HOURS="${SITE_REMIND_HOURS:-6}"
mkdir -p "$STATE" 2>/dev/null && chmod 700 "$STATE" 2>/dev/null

# key|label. The WordPress events must match wasp_alerts_events() in
# 07-wasp-alerts.php -- test/test-alerts.sh holds the two lists together.
_EVENTS="admin_role|Administrator added, promoted, demoted or deleted
admin_login|Administrator sign-in from a new address
admin_credentials|Administrator password or email changed, or a reset requested
app_password|Application password created (API access without the login page or 2FA)
mfa_change|Two-factor turned off or changed for an administrator
code_change|Plugins and themes installed, updated, activated, deactivated, deleted, switched; core updated
settings_change|Site address, admin email, open registration or default role changed
content_spam|Spam links saved into a page, widget or menu (as saved; the weekly scan too)
site_down|Host watch: the site stops serving, and when it recovers
admin_db|Host watch: an administrator appears in or leaves the database
integrity|Host watch: plugin files or WASP's own tools modified (weekly)"
_keys() { printf '%s\n' "$_EVENTS" | cut -d'|' -f1; }
_is_key() { _keys | grep -qx "$1"; }

_ok()   { printf '  \033[32m✔\033[0m  %s\n' "$1"; }
_bad()  { printf '  \033[31m✗\033[0m  %s\n' "$1" >&2; }
_warn() { printf '  \033[33m⚠\033[0m  %s\n' "$1"; }
_note() { printf '     %s\n' "$1"; }

_get() { [ -r "$ALERTS_FILE" ] && sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$ALERTS_FILE" | head -1; }
_enabled() {
  [ -r "$ALERTS_FILE" ] || return 1
  case "$(_get "$1" | tr 'A-Z' 'a-z')" in off|0|no|false) return 1 ;; esac
  return 0
}
_valid_list() { # comma list of addresses, every one plausible
  [ -n "$1" ] || return 1
  # Trailing newline: `read` drops a final line without one, and the last (or
  # only) address would then never be checked at all.
  printf '%s\n' "$1" | tr ',' '\n' | while IFS= read -r _a; do
    _a=$(printf '%s' "$_a" | tr -d ' ')
    case "$_a" in
      *[!A-Za-z0-9._%+@-]*|*@*@*|@*|*@|'') exit 1 ;;
      *@*.*) : ;;
      *) exit 1 ;;
    esac
  done
}
_norm_list() { printf '%s' "$1" | tr -d ' '; }
_default_to() {
  if [ -n "${NOTIFY_EMAIL:-}" ]; then printf '%s' "$NOTIFY_EMAIL"; return; fi
  if [ -n "${WP_ADMIN_EMAIL:-}" ]; then printf '%s' "$WP_ADMIN_EMAIL"; return; fi
  sed -n 's/^[[:space:]]*user[[:space:]]*=[[:space:]]*//p' "${SECRETS_DIR}/smtp.ini" 2>/dev/null | head -1
}

# Rewrite one key, in place (the directory is bind-mounted into WordPress).
_set() {
  _k="$1"; _v="$2"; _t=$(mktemp) || return 1
  if grep -qE "^[[:space:]]*${_k}[[:space:]]*=" "$ALERTS_FILE"; then
    awk -v k="$_k" -v v="$_v" '
      $0 ~ "^[[:space:]]*" k "[[:space:]]*=" { if (!d) { print k " = " v; d = 1 }; next }
      { print }' "$ALERTS_FILE" > "$_t"
  else
    cat "$ALERTS_FILE" > "$_t"; printf '%s = %s\n' "$_k" "$_v" >> "$_t"
  fi
  cat "$_t" > "$ALERTS_FILE"; rm -f "$_t"
  _perms
}
_perms() {
  chmod 0440 "$ALERTS_FILE" 2>/dev/null
  chown root:33 "$ALERTS_FILE" 2>/dev/null || true
}

_write_new() { # recipient
  mkdir -p "$SECRETS_DIR"
  chown root:33 "$SECRETS_DIR" 2>/dev/null || true
  chmod 0750 "$SECRETS_DIR" 2>/dev/null || true
  {
    printf '; WASP security alerts. Data, not code. Read by 07-wasp-alerts.php\n'
    printf '; (mounted read-only) and by wasp-alerts.sh. Change it with wasp-alerts.sh.\n'
    printf 'to = %s\n' "$1"
    _keys | while IFS= read -r _k; do printf '%s = on\n' "$_k"; done
    printf '; new_ip: email a sign-in from an address not seen for that account in\n'
    printf ';         login_ip_days. all: email every administrator sign-in.\n'
    printf 'admin_login_mode = new_ip\n'
    printf 'login_ip_days = 90\n'
    printf '; Ceiling on WordPress alert emails per hour (one notice when reached).\n'
    printf 'max_per_hour = 20\n'
  } > "$ALERTS_FILE"
  _perms
}

# wp-cli in its own container, with the private directory mounted so the
# mu-plugin sees its settings and the SMTP relay -- as in wp-mail.sh.
_wpcli_image() {
  _wi=$(sed -n 's/^WPCLI_IMAGE=//p' /etc/wp-install/pinned.env 2>/dev/null | tr -d '"' | head -1)
  [ -n "$_wi" ] || _wi="docker.io/library/wordpress:cli"
  printf '%s' "$_wi"
}
_wp() {
  _env=/etc/wordpress/wp.env; [ -r "$_env" ] || _env=/etc/wordpress/env
  podman run --rm --network "container:wordpress" --user 33:33 \
    --env-file "$_env" -e WORDPRESS_DB_HOST=mariadb:3306 \
    -v "${SECRETS_DIR}:/var/www/private:ro" \
    -v /home/wpuser/wp/html:/var/www/html \
    "$(_wpcli_image)" wp --path=/var/www/html "$@"
}

# Host-side alerts go through wp-notify.sh, to the same recipients.
_send() { # tag subject bodyfile
  [ -x "$NOTIFY" ] || { logger -t wasp-alerts "wp-notify.sh missing; not emailed: $2"; return 1; }
  NOTIFY_EMAIL="$(_get to)" NOTIFY_COOLDOWN_HOURS=0 "$NOTIFY" "$1" "$2" "$3" >/dev/null 2>&1
}

_hn() { printf '%s' "${HOSTNAME:-$(hostname 2>/dev/null || echo wordpress-vm)}"; }

case "${1:-status}" in

status)
  echo ""
  echo "Security alerts"
  echo "━━━━━━━━━━━━━━━"
  if [ ! -r "$ALERTS_FILE" ]; then
    _warn "Not set up — nothing is emailed. Set it up:"
    _note "doas wasp-alerts.sh setup you@example.com"
    exit 1
  fi
  _to=$(_get to)
  if [ -n "$_to" ]; then _ok "Recipient(s): ${_to}"; else _bad "No recipient — nothing is emailed:  wasp-alerts.sh to you@example.com"; fi
  [ -r "${SECRETS_DIR}/smtp.ini" ] || _warn "No SMTP relay configured, so nothing can be sent:  wp-mail.sh setup"
  echo ""
  printf '%s\n' "$_EVENTS" | while IFS='|' read -r _k _l; do
    if _enabled "$_k"; then printf '    \033[32mON \033[0m %-18s %s\n' "$_k" "$_l"
    else printf '    \033[2moff\033[0m %-18s %s\n' "$_k" "$_l"; fi
  done
  echo ""
  _note "Administrator sign-ins: $( [ "$(_get admin_login_mode)" = all ] && echo 'every one' || echo "from an address new to that account in $(_get login_ip_days) days")"
  _note "WordPress alert ceiling: $(_get max_per_hour) emails/hour"
  [ -f "$STATE/site.alerted" ] && _warn "The site is currently reported DOWN (since $(cat "$STATE/site.down_since" 2>/dev/null))"
  echo ""
  _note "Change:  wasp-alerts.sh on|off <event>     Test:  wasp-alerts.sh test"
  ;;

setup)
  _arg="${2:-}"; _quiet=0
  [ "$_arg" = "--quiet" ] && { _quiet=1; _arg="${3:-}"; }
  [ "${3:-}" = "--quiet" ] && _quiet=1
  if [ -r "$ALERTS_FILE" ] && [ -z "$_arg" ]; then
    [ "$_quiet" = 1 ] || { echo "  Already set up. Current settings:"; "$0" status; }
    exit 0
  fi
  _to="${_arg:-$(_default_to)}"
  _to=$(_norm_list "$_to")
  if ! _valid_list "$_to"; then
    if [ "$_quiet" = 1 ]; then
      logger -t wasp-alerts "not set up: no operator email address given at install"
      exit 0
    fi
    _bad "Give the address(es) to send alerts to:  wasp-alerts.sh setup you@example.com"
    exit 1
  fi
  if [ -r "$ALERTS_FILE" ]; then _set to "$_to"; else _write_new "$_to"; fi
  [ "$_quiet" = 1 ] || { _ok "Alerts go to ${_to}; every event is on."; _note "Test it:  wasp-alerts.sh test"; }
  ;;

to)
  _to=$(_norm_list "${2:-}")
  _valid_list "$_to" || { _bad "Not an address list: '${2:-}'"; exit 1; }
  [ -r "$ALERTS_FILE" ] || _write_new "$_to"
  _set to "$_to"
  _ok "Alerts now go to ${_to}"
  logger -t wasp-alerts "recipient changed to ${_to}"
  ;;

on|off)
  _k="${2:-}"
  [ -r "$ALERTS_FILE" ] || { _bad "Not set up yet:  wasp-alerts.sh setup you@example.com"; exit 1; }
  if [ "$_k" = "all" ]; then
    for _e in $(_keys); do _set "$_e" "$1"; done
    _ok "Every event turned $1"
  elif _is_key "$_k"; then
    _set "$_k" "$1"
    _ok "${_k} turned $1"
  else
    _bad "Unknown event '${_k}'. One of:"
    _keys | sed 's/^/       /' >&2
    exit 1
  fi
  logger -t wasp-alerts "${_k} turned $1"
  ;;

login-mode)
  case "${2:-}" in
    new_ip|all) [ -r "$ALERTS_FILE" ] || { _bad "Not set up yet"; exit 1; }
                _set admin_login_mode "$2"; _ok "Administrator sign-ins: ${2}" ;;
    *) _bad "login-mode new_ip|all"; exit 1 ;;
  esac
  ;;

test)
  [ -r "$ALERTS_FILE" ] || { _bad "Not set up yet:  wasp-alerts.sh setup you@example.com"; exit 1; }
  echo "Sending a test alert to $(_get to) through WordPress…"
  _out=$(_wp eval 'if (!function_exists("wasp_alerts_send_test")) { echo "NOPLUGIN"; } elseif (!wasp_alerts_config()) { echo "NOCONFIG"; } else { echo wasp_alerts_send_test() ? "SENT" : "FAILED"; }' 2>&1) || true
  case "$_out" in
    *SENT*)     _ok "Sent — check $(_get to), including spam." ;;
    *NOPLUGIN*) _bad "The 07-wasp-alerts.php mu-plugin is not installed in wp-content/mu-plugins."; exit 1 ;;
    *NOCONFIG*) _bad "WordPress cannot read ${ALERTS_FILE} at /var/www/private, or it names no valid recipient."; exit 1 ;;
    *)          _bad "Send failed:"; printf '%s\n' "$_out" | sed 's/^/       /' >&2
                _note "Mail itself:  wp-mail.sh doctor"; exit 1 ;;
  esac
  ;;

watch-site)
  # Two consecutive failures (ten minutes at the cron interval) before an
  # alert: a restart during an update or a podman auto-update is a minute,
  # not an outage. Recovery is reported too, with how long it lasted, so the
  # operator is not left wondering whether to drive in.
  _enabled site_down || exit 0
  [ -d "$UPDATE_LOCK" ] && { logger -t wasp-alerts "watch-site skipped: update.sh holds the lock"; exit 0; }
  _now=$(date +%s)
  if "$HEALTH" > "$STATE/site.last" 2>&1; then
    if [ -f "$STATE/site.alerted" ]; then
      _since=$(cat "$STATE/site.down_since" 2>/dev/null || echo "$_now")
      _mins=$(( (_now - _since) / 60 ))
      _b=$(mktemp)
      { echo "WordPress on $(_hn) is serving again."
        echo ""
        echo "Down for about ${_mins} minute(s), from $(date -u -d "@${_since}" '+%Y-%m-%d %H:%M' 2>/dev/null || echo "$_since") UTC."
        echo ""
        echo "Worth knowing why:  doas podman logs --tail 100 wordpress"
        echo "                    doas validate-wordpress.sh"; } > "$_b"
      _send wasp-site "Site RECOVERED after ${_mins} min" "$_b"; rm -f "$_b"
      logger -t wasp-alerts "site recovered after ${_mins} min"
    fi
    rm -f "$STATE/site.fails" "$STATE/site.alerted" "$STATE/site.down_since" "$STATE/site.reminded"
    exit 0
  fi
  _f=$(( $(cat "$STATE/site.fails" 2>/dev/null || echo 0) + 1 ))
  printf '%s\n' "$_f" > "$STATE/site.fails"
  [ -f "$STATE/site.down_since" ] || printf '%s\n' "$_now" > "$STATE/site.down_since"
  _since=$(cat "$STATE/site.down_since")
  if [ ! -f "$STATE/site.alerted" ] && [ "$_f" -ge "$SITE_FAILS_TO_ALERT" ]; then
    _b=$(mktemp)
    { echo "WordPress on $(_hn) has failed its health check ${_f} times in a row."
      echo "Visitors are probably seeing an error, or nothing."
      echo ""
      echo "Health check output:"
      sed 's/^/  /' "$STATE/site.last"
      echo ""
      echo "First steps:"
      echo "  doas rc-service wp-container status"
      echo "  doas podman ps -a"
      echo "  doas podman logs --tail 100 wordpress"
      echo "  doas validate-wordpress.sh"
      echo ""
      echo "You will get one more email when it recovers."; } > "$_b"
    _send wasp-site "Site DOWN — health check failing" "$_b" && : > "$STATE/site.alerted"
    printf '%s\n' "$_now" > "$STATE/site.reminded"
    rm -f "$_b"
    logger -t wasp-alerts "site DOWN after ${_f} failed checks"
  elif [ -f "$STATE/site.alerted" ]; then
    _r=$(cat "$STATE/site.reminded" 2>/dev/null || echo "$_now")
    if [ $(( _now - _r )) -ge $(( SITE_REMIND_HOURS * 3600 )) ]; then
      _b=$(mktemp)
      { echo "WordPress on $(_hn) has now been down for about $(( (_now - _since) / 3600 )) hour(s)."
        echo ""; sed 's/^/  /' "$STATE/site.last"; } > "$_b"
      _send wasp-site "Site STILL DOWN" "$_b"; rm -f "$_b"
      printf '%s\n' "$_now" > "$STATE/site.reminded"
    fi
  fi
  exit 1
  ;;

watch-admins)
  # The database's own answer, so an administrator inserted with SQL -- no
  # WordPress hook fires for that -- is still reported. The first run records
  # the list without emailing it.
  _enabled admin_db || exit 0
  _pfx=$(podman exec mariadb sh -c 'printf %s "${WORDPRESS_TABLE_PREFIX:-wp_}"' 2>/dev/null) || exit 1
  case "$_pfx" in *[!A-Za-z0-9_]*|'') logger -t wasp-alerts "watch-admins: unexpected table prefix"; exit 1 ;; esac
  _now_list=$(podman exec mariadb sh -c \
    'exec mariadb -u root -p"$MARIADB_ROOT_PASSWORD" -N -B "${WORDPRESS_DB_NAME:-wordpress}" -e "$1"' _ \
    "SELECT u.ID, u.user_login, u.user_email, u.user_registered
       FROM ${_pfx}users u JOIN ${_pfx}usermeta m ON u.ID = m.user_id
      WHERE m.meta_key = '${_pfx}capabilities' AND m.meta_value LIKE '%\"administrator\"%'
      ORDER BY u.ID;" 2>/dev/null) || { logger -t wasp-alerts "watch-admins: database query failed"; exit 1; }
  _cur="$STATE/admins.list"; _new=$(mktemp)
  printf '%s\n' "$_now_list" | sed '/^$/d' | tr '\t' '|' > "$_new"
  if [ ! -f "$_cur" ]; then
    mv "$_new" "$_cur"; chmod 600 "$_cur"
    logger -t wasp-alerts "watch-admins: baseline of $(grep -c . "$_cur") administrator(s) recorded"
    exit 0
  fi
  _added=$(grep -vxF -f "$_cur" "$_new" || true)
  _gone=$(grep -vxF -f "$_new" "$_cur" || true)
  if [ -z "$_added" ] && [ -z "$_gone" ]; then rm -f "$_new"; exit 0; fi
  _b=$(mktemp)
  { echo "The administrator accounts in the WordPress database on $(_hn) changed."
    echo "This check reads the database directly, so it also sees accounts that"
    echo "were inserted without going through WordPress at all."
    if [ -n "$_added" ]; then echo ""; echo "Now an administrator (id | login | email | registered):"
      printf '%s\n' "$_added" | sed 's/^/  + /'; fi
    if [ -n "$_gone" ]; then echo ""; echo "No longer an administrator:"
      printf '%s\n' "$_gone" | sed 's/^/  - /'; fi
    echo ""
    echo "Expected after an import or after you changed a role. If not:"
    echo "  doas wp-forensics.sh admins"
    echo "  doas wp-plugins.sh lock-user <id> \"not ours\"     (keeps the evidence)"
    echo "  doas wp-forensics.sh timeline"; } > "$_b"
  _send wasp-admins "Administrator accounts changed in the database" "$_b"
  rm -f "$_b"
  mv "$_new" "$_cur"; chmod 600 "$_cur"
  logger -t wasp-alerts "watch-admins: administrator list changed"
  ;;

watch-integrity)
  # Weekly. Both checks already ran (or could) -- and reported to syslog,
  # where a modified plugin file waited for someone to look.
  _enabled integrity || exit 0
  _rc=0; _b=$(mktemp)
  if [ -x "$PLUGINS" ]; then
    if ! "$PLUGINS" verify > "$STATE/plugins.out" 2>&1; then
      _rc=1
      { echo "Plugin files that do not match their published wordpress.org copy:"
        echo ""; sed 's/^/  /' "$STATE/plugins.out"; echo ""
        echo "A changed plugin file is how most WordPress backdoors persist."
        echo "  doas wp-malware-scan.sh remediate            (shows the plan first)"
        echo ""; } >> "$_b"
    fi
  fi
  if [ -x "$VERIFY" ]; then
    if ! "$VERIFY" > "$STATE/tooling.out" 2>&1; then
      _rc=1
      { echo "WASP's own tools differ from the signed release they came from:"
        echo ""; sed 's/^/  /' "$STATE/tooling.out"; echo ""
        echo "These run as root on a schedule. Do not overwrite them before you know"
        echo "how they changed: the change is the evidence."; } >> "$_b"
    fi
  fi
  [ "$_rc" = 0 ] || NOTIFY_EMAIL="$(_get to)" "$NOTIFY" wasp-integrity "Modified files: plugins or WASP tooling" "$_b" >/dev/null 2>&1
  rm -f "$_b"
  exit "$_rc"
  ;;

*)
  sed -n '4,15p' "$0"
  exit 1 ;;
esac
