#!/usr/bin/env bash
# =============================================================================
# test-alerts.sh — security alerts: the settings tool and the host watches
# =============================================================================
#
#   - the WordPress half (07-wasp-alerts.php) is driven by test-alerts.php
#   - the event names wasp-alerts.sh offers are exactly the mu-plugin's
#   - setup writes alerts.ini from the operator email, root:33 0440, every
#     event on; with no address it writes nothing rather than guessing
#   - to / on / off / login-mode change one key and nothing else, in place
#   - watch-site: one failure is silence, two is one DOWN email, recovery is
#     one email with the duration, a long outage gets a reminder; nothing
#     while update.sh holds its lock
#   - watch-admins: the first run records without emailing; an administrator
#     added or removed in the database is emailed once
#   - watch-integrity: modified plugins or tooling are emailed; clean is silent
#   - an event turned off silences its watch too
#
# Host-side mail is captured by a stand-in wp-notify.sh. Run under the host
# shell and BusyBox (BUSYBOX=/path/to/busybox, required).
# =============================================================================
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
_p() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
_f() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n         %s\n' "$1" "${2:-}"; }
TOOL="$REPO/payload/bin/wasp-alerts.sh"
PLUGIN="$REPO/payload/mu-plugins/07-wasp-alerts.php"

echo ""
echo "Security alerts: settings and host watches"
[ "$(id -u)" -eq 0 ] || { _f "must run as root" "the tool re-executes through doas otherwise"; exit 1; }
BB="${BUSYBOX:-$(command -v busybox 2>/dev/null || true)}"

# ── the two event lists agree ───────────────────────────────────────────────
_php_keys=$(sed -n "/function wasp_alerts_events/,/^}/p" "$PLUGIN" | sed -n "s/^[[:space:]]*'\([a-z_]*\)'[[:space:]]*=>.*/\1/p" | sort)
_sh_keys=$(sed -n '/^_EVENTS="/,/"$/p' "$TOOL" | sed 's/^_EVENTS="//' | cut -d'|' -f1 \
           | grep -vE '^(site_down|admin_db|integrity)$' | sort)
[ -n "$_php_keys" ] && [ "$_php_keys" = "$_sh_keys" ] \
  && _p "wasp-alerts.sh offers exactly the mu-plugin's WordPress events" \
  || _f "event lists differ" "php: $(echo $_php_keys) | sh: $(echo $_sh_keys)"

# ── the WordPress half ──────────────────────────────────────────────────────
if command -v php >/dev/null 2>&1; then
  _o=$(php "$REPO/test/test-alerts.php" 2>&1); _rc=$?
  [ "$_rc" = 0 ] && _p "mu-plugin: $(printf '%s' "$_o" | sed -n 's/.*alerts (php): //p')" \
    || _f "mu-plugin scenarios failed" "$(printf '%s' "$_o" | grep -A3 FAIL | head -20)"
else
  _f "php is required for the mu-plugin scenarios" "apt install php-cli"
fi

_suite() { # label shell pathprefix
  L="$1"; SH="$2"; PP="$3"; W="$T/$L"
  mkdir -p "$W/bin" "$W/secrets" "$W/state" "$W/mail"
  # Stand-ins. wp-notify records tag, subject, recipient and body.
  cat > "$W/bin/wp-notify.sh" <<EOF
#!$SH
n=\$(ls "$W/mail" | wc -l); n=\$((n+1))
{ echo "TAG=\$1"; echo "SUBJECT=\$2"; echo "TO=\${NOTIFY_EMAIL:-}"; cat "\$3" 2>/dev/null; } > "$W/mail/\$n"
EOF
  printf '#!%s\n[ -f "%s/health.fail" ] && { echo "  ✗  HTTP 502"; exit 1; }\necho "  ✔  ok"\n' "$SH" "$W" > "$W/bin/health"
  printf '#!%s\ncat "%s/plugins.out"; [ -f "%s/plugins.bad" ] && exit 1; exit 0\n' "$SH" "$W" "$W" > "$W/bin/plugins"
  printf '#!%s\necho "  Nothing has been modified."; [ -f "%s/tool.bad" ] && exit 1; exit 0\n' "$SH" "$W" > "$W/bin/verify"
  cat > "$W/bin/podman" <<EOF
#!$SH
case "\$*" in
  *WORDPRESS_TABLE_PREFIX*) printf 'wp7x_' ;;
  *SELECT*) cat "$W/admins.db" ;;
esac
EOF
  printf '#!%s\nexit 0\n' "$SH" > "$W/bin/logger"
  printf 'Success: Verified 4 of 4 plugins.\n' > "$W/plugins.out"
  chmod +x "$W/bin/"*
  _a() { env PATH="$W/bin:$PP" WASP_SECRETS_DIR="$W/secrets" WASP_ALERTS_STATE="$W/state" \
           WASP_NOTIFY="$W/bin/wp-notify.sh" WASP_HEALTH_CHECK="$W/bin/health" \
           WASP_PLUGINS_TOOL="$W/bin/plugins" WASP_VERIFY_TOOL="$W/bin/verify" \
           WASP_UPDATE_LOCK="$W/update.lock" WP_ADMIN_EMAIL="${ADM-ops@example.com}" \
           "$SH" "$TOOL" "$@" 2>&1; }
  _mails() { ls "$W/mail" | wc -l | tr -d ' '; }
  _last() { cat "$W/mail/$(_mails)" 2>/dev/null; }
  INI="$W/secrets/alerts.ini"

  echo ""
  echo "  ── under ${L}"
  out=$(ADM= _a setup --quiet); rc=$?
  [ "$rc" = 0 ] && [ ! -e "$INI" ] && _p "$L: no operator email at install: nothing written, nothing guessed" \
    || _f "$L: setup without an address" "rc=$rc $(cat "$INI" 2>/dev/null)"
  _a setup --quiet >/dev/null
  { grep -qx 'to = ops@example.com' "$INI" && [ "$(grep -c ' = on$' "$INI")" = 11 ] \
    && [ "$(stat -c %a "$INI")" = 440 ]; } \
    && _p "$L: setup writes the operator email, every event on, mode 0440" \
    || _f "$L: setup" "$(cat "$INI"; stat -c %a "$INI")"
  ino=$(ls -i "$INI" | awk '{print $1}'); cp "$INI" "$W/before"
  _a off code_change >/dev/null
  # Lines that differ, counted without diff: BusyBox diff prints unified format
  # by default, so counting GNU diff's "<"/">" lines found nothing there.
  { grep -qx 'code_change = off' "$INI" \
    && [ "$(wc -l < "$W/before")" = "$(wc -l < "$INI")" ] \
    && [ "$(awk 'NR == FNR { a[FNR] = $0; next } a[FNR] != $0' "$W/before" "$INI" | wc -l | tr -d ' ')" = 1 ] \
    && [ "$(ls -i "$INI" | awk '{print $1}')" = "$ino" ]; } \
    && _p "$L: off changes that one key, in place" || _f "$L: off" "$(diff "$W/before" "$INI")"
  _a on code_change >/dev/null; grep -qx 'code_change = on' "$INI" && _p "$L: on turns it back" || _f "$L: on" ""
  out=$(_a off made_up); [ $? = 1 ] && printf '%s' "$out" | grep -q 'admin_role' \
    && _p "$L: an unknown event is refused, listing the real ones" || _f "$L: unknown event" "$out"
  _a to 'a@example.com, b@example.org' >/dev/null
  grep -qx 'to = a@example.com,b@example.org' "$INI" && _p "$L: to sets a recipient list" || _f "$L: to" "$(grep '^to' "$INI")"
  out=$(_a to 'not-an-address'); [ $? = 1 ] && grep -qx 'to = a@example.com,b@example.org' "$INI" \
    && _p "$L: an invalid recipient is refused and nothing changes" || _f "$L: bad to" "$out"
  _a login-mode all >/dev/null; grep -qx 'admin_login_mode = all' "$INI" && _p "$L: login-mode" || _f "$L: login-mode" ""
  out=$(_a status); printf '%s' "$out" | grep -q 'a@example.com' && printf '%s' "$out" | grep -q 'every one' \
    && _p "$L: status shows recipients, events and sign-in mode" || _f "$L: status" "$out"

  # ── watch-site ──
  rm -f "$W/mail"/*
  : > "$W/health.fail"
  _a watch-site >/dev/null
  [ "$(_mails)" = 0 ] && _p "$L: one failed health check is not an alert" || _f "$L: alerted on one failure" "$(_last)"
  _a watch-site >/dev/null
  { [ "$(_mails)" = 1 ] && _last | grep -q 'SUBJECT=Site DOWN' && _last | grep -q 'HTTP 502' \
    && _last | grep -q 'TO=a@example.com,b@example.org'; } \
    && _p "$L: two in a row: one DOWN email, with the check output, to the alert recipients" || _f "$L: down" "$(_last)"
  _a watch-site >/dev/null
  [ "$(_mails)" = 1 ] && _p "$L: still down: no repeat inside the reminder interval" || _f "$L: repeated" ""
  echo $(( $(date +%s) - 7 * 3600 )) > "$W/state/site.reminded"
  _a watch-site >/dev/null
  { [ "$(_mails)" = 2 ] && _last | grep -q 'SUBJECT=Site STILL DOWN'; } \
    && _p "$L: a long outage gets a reminder" || _f "$L: reminder" "$(_last)"
  rm -f "$W/health.fail"; echo $(( $(date +%s) - 1500 )) > "$W/state/site.down_since"
  _a watch-site >/dev/null
  { [ "$(_mails)" = 3 ] && _last | grep -q 'SUBJECT=Site RECOVERED after 25 min'; } \
    && _p "$L: recovery is one email, with how long it lasted" || _f "$L: recovered" "$(_last)"
  _a watch-site >/dev/null; [ "$(_mails)" = 3 ] && _p "$L: healthy afterwards: silence" || _f "$L: noise" ""
  : > "$W/health.fail"; mkdir -p "$W/update.lock"
  _a watch-site >/dev/null; _a watch-site >/dev/null
  { [ "$(_mails)" = 3 ] && [ ! -f "$W/state/site.fails" ]; } \
    && _p "$L: nothing while update.sh holds its lock" || _f "$L: alerted during an update" ""
  rmdir "$W/update.lock"; rm -f "$W/health.fail"
  _a off site_down >/dev/null; : > "$W/health.fail"
  _a watch-site >/dev/null; _a watch-site >/dev/null
  [ "$(_mails)" = 3 ] && _p "$L: site_down off silences the watch" || _f "$L: off ignored" ""
  rm -f "$W/health.fail"; _a on site_down >/dev/null

  # ── watch-admins ──
  rm -f "$W/mail"/*
  printf '1\towner\towner@example.com\t2025-01-01 00:00:00\n' > "$W/admins.db"
  _a watch-admins >/dev/null
  [ "$(_mails)" = 0 ] && [ -f "$W/state/admins.list" ] && _p "$L: first run records the administrators, emails nothing" \
    || _f "$L: baseline" "$(_last)"
  _a watch-admins >/dev/null; [ "$(_mails)" = 0 ] && _p "$L: unchanged: silence" || _f "$L: noise" ""
  printf '1\towner\towner@example.com\t2025-01-01 00:00:00\n42\twp_svc\tx@evil.example\t2026-11-13 03:00:00\n' > "$W/admins.db"
  _a watch-admins >/dev/null
  { [ "$(_mails)" = 1 ] && _last | grep -q '+ 42|wp_svc|x@evil.example' && _last | grep -q 'lock-user'; } \
    && _p "$L: an administrator added in the database is emailed, with what to do" || _f "$L: added" "$(_last)"
  _a watch-admins >/dev/null; [ "$(_mails)" = 1 ] && _p "$L: ...once" || _f "$L: repeated" ""
  printf '42\twp_svc\tx@evil.example\t2026-11-13 03:00:00\n' > "$W/admins.db"
  _a watch-admins >/dev/null
  { [ "$(_mails)" = 2 ] && _last | grep -q -- '- 1|owner'; } \
    && _p "$L: an administrator removed is emailed too" || _f "$L: removed" "$(_last)"

  # ── watch-integrity ──
  rm -f "$W/mail"/*
  _a watch-integrity >/dev/null; [ "$(_mails)" = 0 ] && _p "$L: integrity clean: silence" || _f "$L: noise" "$(_last)"
  printf "Warning: File doesn't verify against checksum: wp-file-manager/lib/php/connector.minimal.php\n" > "$W/plugins.out"
  : > "$W/plugins.bad"
  _a watch-integrity >/dev/null
  { [ "$(_mails)" = 1 ] && _last | grep -q 'TAG=wasp-integrity' && _last | grep -q 'connector.minimal.php'; } \
    && _p "$L: a modified plugin file is emailed, naming the file" || _f "$L: plugin" "$(_last)"
  rm -f "$W/plugins.bad"; : > "$W/tool.bad"; rm -f "$W/mail"/*
  _a watch-integrity >/dev/null
  { [ "$(_mails)" = 1 ] && _last | grep -q "WASP's own tools differ"; } \
    && _p "$L: modified WASP tooling is emailed" || _f "$L: tooling" "$(_last)"
  rm -f "$W/tool.bad"
}

_suite host /bin/sh "/usr/local/bin:/usr/bin:/bin"
if [ -n "$BB" ] && "$BB" --list >/dev/null 2>&1; then
  mkdir -p "$T/bb"; for _a in $("$BB" --list); do ln -sf "$BB" "$T/bb/$_a"; done
  _suite busybox "$T/bb/sh" "$T/bb"
else
  _f "BusyBox not found: the Alpine-shell pass did not run" "set BUSYBOX=/path/to/busybox"
fi

echo ""
echo "  alerts: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" = 0 ]
