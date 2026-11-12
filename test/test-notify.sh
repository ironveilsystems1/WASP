#!/usr/bin/env bash
# =============================================================================
# test-notify.sh — does an alert actually leave the VM?
# =============================================================================
#
# Every scheduled scan reports through wp-notify.sh. Before 10.11 it handed
# msmtp a password command written for the old smtp.php format while the relay
# settings lived in smtp.ini, so msmtp authenticated with an empty password and
# every alert failed -- quietly, because the cron jobs exit 0 either way.
#
# msmtp is stubbed here to do what msmtp does with --passwordeval: run the
# command through a shell and use its output. So this checks the password the
# relay would actually receive, from a real smtp.ini written the way the
# installer and wp-mail.sh write it.
# =============================================================================
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
_p() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
_f() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n         %s\n' "$1" "${2:-}"; }

mkdir -p "$T/bin" "$T/secrets" "$T/state" "$T/etc"
printf 'NOTIFY_EMAIL=ops@example.com\n' > "$T/etc/vars.sh"
PW='p@ss w0rd;"quote'\''s=and\more'
{ printf 'host = smtp.example.com\nport = 587\nuser = relay@example.com\n'
  printf 'pass_b64 = %s\n' "$(printf '%s' "$PW" | base64 | tr -d '\n')"
  printf 'from = alerts@example.com\nfrom_name = WASP\nencryption = tls\ntimeout = 10\n'; } > "$T/secrets/smtp.ini"

cat > "$T/bin/msmtp" <<STUB
#!/usr/bin/env bash
pe=""; for a in "\$@"; do case "\$a" in --passwordeval=*) pe="\${a#--passwordeval=}" ;; esac; done
printf '%s' "\$(sh -c "\$pe")" > "$T/password"
printf '%s\n' "\$@" > "$T/args"
cat > "$T/message"
echo x >> "$T/sends"
STUB
printf '#!/bin/sh\nexit 0\n' > "$T/bin/logger"
printf '#!/bin/sh\necho wp-test-07\n' > "$T/bin/hostname"
chmod +x "$T/bin/"*

sed -e '/^if \[ "\$(id -u)" -ne 0 \]; then$/,/^fi$/d' \
    -e "s#/etc/wp-install/vars.sh#$T/etc/vars.sh#g" \
    "$REPO/payload/bin/wp-notify.sh" > "$T/notify.sh"
_n() { env -u HOSTNAME SECRETS_DIR="$T/secrets" STATE="$T/state" \
       PATH="$T/bin:${WASP_TEST_TOOLS:+$WASP_TEST_TOOLS:}$PATH" ${WASP_TEST_SH:-sh} "$T/notify.sh" "$@" 2>&1; }

echo ""
echo "Alert delivery"
echo ""
printf 'Vulnerable plugin found.\n' > "$T/body"
_n wp-vulns "1 critical finding" "$T/body" >/dev/null
[ -s "$T/sends" ] && _p "an alert is handed to msmtp" || _f "send" "nothing sent"
[ "$(cat "$T/password" 2>/dev/null)" = "$PW" ] && _p "with the real password from smtp.ini (quotes, spaces, = and \\ intact)" \
  || _f "password" "relay would get: '$(cat "$T/password" 2>/dev/null)'"
grep -q 'ops@example.com' "$T/args" && _p "to NOTIFY_EMAIL" || _f "recipient" "$(cat "$T/args")"
_hn=$(env -u HOSTNAME PATH="$T/bin:${WASP_TEST_TOOLS:+$WASP_TEST_TOOLS:}$PATH" ${WASP_TEST_SH:-sh} -c 'printf %s "${HOSTNAME:-$(hostname)}"')
grep -qF "Subject: [${_hn}] 1 critical finding" "$T/message" && [ -n "$_hn" ] && [ "$_hn" != wordpress-vm ] \
  && _p "headed with the VM's own name ($_hn), whatever the shell" || _f "subject" "$(grep Subject "$T/message")"
grep -q 'Vulnerable plugin found.' "$T/message" && _p "carrying the body" || _f "body" ""
grep -q -- '--passwordeval' "$T/args" && ! grep -qF "$PW" "$T/args" \
  && _p "and the password never appears in msmtp's arguments" || _f "argv" "password on the command line"

: > "$T/sends"; _n wp-vulns "1 critical finding" "$T/body" >/dev/null
[ ! -s "$T/sends" ] && _p "an identical alert inside the cooldown is not repeated" || _f "dedupe" "sent twice"
: > "$T/sends"; NOTIFY_COOLDOWN_HOURS=0 _n wp-report "Weekly report" "$T/body" >/dev/null
NOTIFY_COOLDOWN_HOURS=0 _n wp-report "Weekly report" "$T/body" >/dev/null
[ "$(grep -c . "$T/sends")" = 2 ] && _p "with a cooldown of 0 (the weekly report) it always sends" || _f "cooldown 0" "$(grep -c . "$T/sends")"

# A VM still on the old smtp.php keeps working.
rm -f "$T/secrets/smtp.ini" "$T/state"/sent-*
printf "<?php return array(\n  'host' => 'smtp.example.com',\n  'port' => 587,\n  'user' => 'relay@example.com',\n  'pass' => 'legacy-secret',\n  'from' => 'alerts@example.com',\n);\n" > "$T/secrets/smtp.php"
: > "$T/password"; _n wp-vulns "legacy" "$T/body" >/dev/null
[ "$(cat "$T/password")" = "legacy-secret" ] && _p "a VM still on smtp.php gets its password too" || _f "legacy" "'$(cat "$T/password")'"

echo ""
printf '  passed %d   failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
