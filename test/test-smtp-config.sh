#!/usr/bin/env bash
# =============================================================================
# test-smtp-config.sh — the SMTP password really changes, and the mail doctor
# tells the truth
# =============================================================================
#
# From one live VM (10.16):
#
#   - `wp-rotate-secrets.sh smtp <new>` printed ✔ and changed nothing. It
#     edited `password=` / `AuthPass=` lines; smtp.ini holds `pass_b64 =`.
#     The site kept the old password, the relay's brute-force guard banned the
#     whole premises, and every site behind that address lost mail.
#   - `wp-mail.sh doctor` printed "mu-plugin : MISSING" on every VM, working or
#     not: MU_PLUGIN was never defined.
#   - An imported FluentSMTP sent every message to the old host while the
#     error named WASP's relay. Doctor now names such plugins.
#
# 10.27: the client's own mail server (wp-mail.sh client): Microsoft 365 or
# SMTP written as data with the secret encoded, root:33 0440, port 25 refused,
# egress or the firewall pin updated; the relay's setup now records the new
# host and re-pins the firewall to it; status, test and off.
#
# The real tools run against temp files, with podman and wp-cli stood in.
# Run under the host shell and BusyBox (BUSYBOX=/path/to/busybox, required).
# =============================================================================
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
_p() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
_f() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n         %s\n' "$1" "${2:-}"; }

echo ""
echo "SMTP password rotation and mail doctor"
[ "$(id -u)" -eq 0 ] || { _f "must run as root" "the tools re-execute through doas otherwise"; exit 1; }
BB="${BUSYBOX:-$(command -v busybox 2>/dev/null || true)}"

_ini() { # host user b64
  printf '; WASP SMTP relay settings. Data, not code -- never include() this.\n'
  printf 'host = mail.example.net\nport = 587\nuser = alerts@example.net\n'
  printf 'pass_b64 = %s\n' "$(printf '%s' "$1" | base64 | tr -d '\n')"
  printf 'from = alerts@example.net\nfrom_name = Example\nencryption = tls\ntimeout = 10\n'
}
_dec() { sed -n 's/^[[:space:]]*pass_b64[[:space:]]*=[[:space:]]*//p' "$1" | head -1 | base64 -d; }

_suite() { # label shell pathprefix
  L="$1"; SH="$2"; PP="$3"; W="$T/$L"
  mkdir -p "$W/bin" "$W/secrets" "$W/bak" "$W/mu"
  cat > "$W/bin/podman" <<EOF
#!$SH
case "\$*" in
  *"X-WASP-Mail: client"*) cat "$W/client-out" 2>/dev/null ;;
  *"plugin list"*) printf '%s\n' \$(cat "$W/active" 2>/dev/null) ;;
  *inspect*)       echo '/var/www/private=false' ;;
  *fsockopen*)     printf reachable ;;
  *)               exit 0 ;;
esac
EOF
  printf '#!%s\nexit 0\n' "$SH" > "$W/bin/logger"
  for _tool in wasp-egress.sh wp-hardening.sh; do
    printf '#!%s\necho "%s $*" >> "%s/calls"\n' "$SH" "$_tool" "$W" > "$W/bin/$_tool"
  done
  chmod +x "$W/bin/"*
  _rot() { env PATH="$W/bin:$PP" WASP_SECRETS_DIR="$W/secrets" WASP_ROTATE_BACKUP_DIR="$W/bak" \
             "$SH" "$REPO/payload/bin/wp-rotate-secrets.sh" smtp "$@" 2>&1; }
  sed -e "s#^SECRETS_DIR=.*#SECRETS_DIR=$W/secrets#" \
      -e "s#/etc/wp-install/pinned.env#$W/none#g" -e "s#/etc/wp-install/vars.sh#$W/vars.sh#g" \
      -e "s#^WP_LOG_DIR=.*#WP_LOG_DIR=$W/logs#" "$REPO/payload/bin/wp-mail.sh" > "$W/wp-mail.sh"
  mkdir -p "$W/logs"; printf "SMTP_HOST='mail.example.net'\nOTHER='kept'\n" > "$W/vars.sh"
  _mail() { env PATH="$W/bin:$PP" WASP_MU_PLUGIN="$W/mu/01-wpvm-smtp.php" "$SH" "$W/wp-mail.sh" "$@" 2>&1; }

  echo ""
  echo "  ── under ${L}"
  _ini 'old-Pa55' > "$W/secrets/smtp.ini"; cp "$W/secrets/smtp.ini" "$W/orig.ini"
  ino=$(ls -i "$W/secrets/smtp.ini" | awk '{print $1}')
  NEW='n3w&p#ss'"'"'"$x =;\ end'
  out=$(_rot "$NEW" </dev/null); rc=$?
  [ "$rc" = 0 ] && [ "$(_dec "$W/secrets/smtp.ini")" = "$NEW" ] \
    && _p "$L: the stored password is the new one (& # quotes \$ = ; \\ space all survive)" \
    || _f "$L: rotation did not store the password" "rc=$rc decoded=[$(_dec "$W/secrets/smtp.ini")] $out"
  diff <(grep -v pass_b64 "$W/orig.ini") <(grep -v pass_b64 "$W/secrets/smtp.ini") >/dev/null \
    && [ "$(grep -c pass_b64 "$W/secrets/smtp.ini")" = 1 ] \
    && _p "$L: every other setting is untouched, one pass_b64 line" || _f "$L: other lines changed" "$(cat "$W/secrets/smtp.ini")"
  [ "$(ls -i "$W/secrets/smtp.ini" | awk '{print $1}')" = "$ino" ] \
    && _p "$L: rewritten in place (it is read through a bind mount)" || _f "$L: inode changed" ""
  ls "$W/bak"/smtp.ini.* >/dev/null 2>&1 && _p "$L: the previous file is kept as a snapshot" || _f "$L: no snapshot" "$(ls "$W/bak")"
  printf '%s' "$out" | grep -q 'stored and read back' && _p "$L: success is claimed only after reading it back" || _f "$L: message" "$out"

  cp "$W/secrets/smtp.ini" "$W/before.ini"
  out=$(_rot </dev/null); rc=$?
  [ "$rc" = 1 ] && cmp -s "$W/before.ini" "$W/secrets/smtp.ini" \
    && _p "$L: no password and no terminal: refused, nothing changed" || _f "$L: changed without a password" "rc=$rc"

  grep -v pass_b64 "$W/orig.ini" > "$W/secrets/smtp.ini"; cp "$W/secrets/smtp.ini" "$W/nopass.ini"
  out=$(_rot 'x' </dev/null); rc=$?
  [ "$rc" = 1 ] && cmp -s "$W/nopass.ini" "$W/secrets/smtp.ini" && printf '%s' "$out" | grep -q 'wp-mail.sh setup' \
    && _p "$L: a file with no pass_b64 is refused and points at setup" || _f "$L: no pass_b64" "rc=$rc $out"
  rm -f "$W/secrets/smtp.ini"
  out=$(_rot 'x' </dev/null); rc=$?
  [ "$rc" = 1 ] && printf '%s' "$out" | grep -q 'wp-mail.sh setup' \
    && _p "$L: no smtp.ini at all: refused, points at setup" || _f "$L: missing ini" "rc=$rc $out"

  # ── doctor ──
  _ini 'pw' > "$W/secrets/smtp.ini"
  printf '<?php\n' > "$W/mu/01-wpvm-smtp.php"; : > "$W/active"
  out=$(_mail doctor)
  printf '%s' "$out" | grep -q 'mu-plugin   : present' \
    && _p "$L: doctor sees the SMTP mu-plugin that is there" || _f "$L: doctor mu-plugin" "$out"
  printf '%s' "$out" | grep -q 'overrides   : none' \
    && _p "$L: doctor reports no mail-override plugin when there is none" || _f "$L: overrides none" "$out"
  rm -f "$W/mu/01-wpvm-smtp.php"
  _mail doctor | grep -q 'mu-plugin   : MISSING' \
    && _p "$L: ...and MISSING only when it is missing" || _f "$L: missing not reported" ""
  printf 'akismet fluent-smtp elementor\n' > "$W/active"
  out=$(_mail doctor)
  printf '%s' "$out" | grep -q 'overrides   : fluent-smtp' && printf '%s' "$out" | grep -q 'Deactivate' \
    && _p "$L: an active FluentSMTP is named, with what to do" || _f "$L: override not named" "$out"
  : > "$W/active"

  # ── the relay's setup records the new host and re-pins (10.27) ──
  : > "$W/calls"
  out=$(printf 'relay.example.org\n587\nalerts@example.org\nrelay-pw\n\nSite\n' | _mail setup)
  grep -qx "SMTP_HOST='relay.example.org'" "$W/vars.sh" && grep -qx "OTHER='kept'" "$W/vars.sh" \
    && _p "$L: relay setup records the new host for the firewall, nothing else changed" || _f "$L: vars" "$(cat "$W/vars.sh") $out"
  grep -qx 'wp-hardening.sh smtp-repin' "$W/calls" && _p "$L: ...and re-pins the firewall to it" || _f "$L: repin" "$(cat "$W/calls")"
  out=$(printf 'bad host;rm\n' | _mail setup); rc=$?
  [ "$rc" != 0 ] && grep -qx "SMTP_HOST='relay.example.org'" "$W/vars.sh" && _p "$L: a hostname with odd characters is refused" || _f "$L: bad host" "rc=$rc"

  # ── the client's own server ──
  out=$(_mail client)
  printf '%s' "$out" | grep -q 'Through the operator relay (relay.example.org)' && _p "$L: client status with none: the site's mail uses the relay" || _f "$L: client none" "$out"
  : > "$W/calls"
  SEC='s3cr~et.with=odd;chars"'
  out=$(printf '1\ncontoso.example\n3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90\n%s\n2027-11-01\nforms@client.example\nClient Website\n' "$SEC" | _mail client setup)
  CF="$W/secrets/client-mail.ini"
  { grep -qx 'transport = m365' "$CF" && grep -qx 'tenant = contoso.example' "$CF" && grep -qx 'from = forms@client.example' "$CF" \
    && grep -qx 'secret_expires = 2027-11-01' "$CF" \
    && [ "$(sed -n 's/^secret_b64 = //p' "$CF" | base64 -d)" = "$SEC" ]; } \
    && _p "$L: Microsoft 365: tenant, app, mailbox and expiry stored; the secret exact, encoded" || _f "$L: m365 file" "$(cat "$CF" 2>/dev/null) $out"
  grep -q "$SEC" "$CF" && _f "$L: secret" "stored in the clear" || _p "$L: ...never in the clear"
  [ "$(stat -c '%a %u:%g' "$CF")" = "440 0:33" ] && _p "$L: ...root:33, mode 440" || _f "$L: mode" "$(stat -c '%a %u:%g' "$CF")"
  grep -qx 'wasp-egress.sh reconcile' "$W/calls" && _p "$L: ...and the egress it needs is added (reconcile)" || _f "$L: egress" "$(cat "$W/calls")"
  out=$(_mail client)
  printf '%s' "$out" | grep -q 'Microsoft 365 through Graph' && printf '%s' "$out" | grep -q 'Secret expires: *2027-11-01' \
    && ! printf '%s' "$out" | grep -q "$SEC" && _p "$L: client status: transport, expiry, the secret redacted" || _f "$L: status m365" "$out"
  _soon=$(date -u -d "@$(( $(date +%s) + 10*86400 ))" +%Y-%m-%d)
  chmod 600 "$CF"; sed -i "s/^secret_expires = .*/secret_expires = ${_soon}/" "$CF"; chmod 440 "$CF"
  _mail client | grep -q 'within 30 days' && _p "$L: a secret expiring within 30 days is flagged" || _f "$L: expiry soon" "$(_mail client)"
  out=$(printf '1\ncontoso.example\nnot-a-guid\n' | _mail client setup); rc=$?
  [ "$rc" != 0 ] && grep -qx 'transport = m365' "$CF" && _p "$L: a malformed application ID is refused, the old settings kept" || _f "$L: bad guid" "rc=$rc"

  : > "$W/calls"
  out=$(printf '2\nsmtp.gmail.com\n25\n' | _mail client setup); rc=$?
  [ "$rc" != 0 ] && printf '%s' "$out" | grep -q 'Port 25 is server-to-server' && _p "$L: SMTP on port 25 is refused" || _f "$L: port 25" "rc=$rc $out"
  out=$(printf '2\nsmtp.gmail.com\n587\nforms@client.example\napp pw 16 chars\n\n\n' | _mail client setup)
  { grep -qx 'transport = smtp' "$CF" && grep -qx 'host = smtp.gmail.com' "$CF" && grep -qx 'encryption = tls' "$CF" \
    && grep -qx 'from = forms@client.example' "$CF" && [ "$(sed -n 's/^pass_b64 = //p' "$CF" | base64 -d)" = 'app pw 16 chars' ]; } \
    && _p "$L: SMTP (an app password on 587): STARTTLS, From the mailbox" || _f "$L: smtp file" "$(cat "$CF") $out"
  grep -qx 'wp-hardening.sh smtp-repin' "$W/calls" && _p "$L: ...and the firewall is re-pinned to include it" || _f "$L: smtp repin" "$(cat "$W/calls")"

  printf 'SENT\n' > "$W/client-out"
  out=$(_mail client test office@client.example); rc=$?
  [ "$rc" = 0 ] && printf '%s' "$out" | grep -q "Sent by the client's server" && _p "$L: client test: success said plainly" || _f "$L: client test ok" "rc=$rc $out"
  printf '[wpvm-smtp] client mail failed (SMTP Error: Could not authenticate.); sent through the operator relay instead\nFELLBACK\n' > "$W/client-out"
  out=$(_mail client test office@client.example); rc=$?
  [ "$rc" = 1 ] && printf '%s' "$out" | grep -q 'did NOT take it' && printf '%s' "$out" | grep -q 'Why: SMTP Error: Could not authenticate.' \
    && _p "$L: client test: a fallback is a failure, with the reason" || _f "$L: client test fallback" "rc=$rc $out"
  printf '[x] [wpvm-smtp] client mail failed (Microsoft sign-in refused (HTTP 401): bad secret); sent through the operator relay instead\n' > "$W/logs/error.log"
  _mail client | grep -q 'Recent messages the client' && _p "$L: client status lists recent fallbacks from the log" || _f "$L: status fallbacks" "$(_mail client)"
  _mail log | grep -q 'client mail failed' && _p "$L: wp-mail.sh log reads the real log folder (said 'not found' before)" || _f "$L: log" "$(_mail log)"

  # ── the firewall pin covers the relay and the client's SMTP server ──
  printf '#!%s\ncase "$2" in relay.example.org) echo "198.51.100.7 STREAM relay.example.org" ;; smtp.gmail.com) printf "192.0.2.10 STREAM x\\n192.0.2.11 STREAM x\\n" ;; esac\n' "$SH" > "$W/bin/getent"
  printf '#!%s\nexit 0\n' "$SH" > "$W/bin/nft"; chmod +x "$W/bin/getent" "$W/bin/nft"
  printf 'table inet filter {\n  chain output {\n    ip daddr { 203.0.113.1 } tcp dport { 465, 587 } accept\n  }\n}\n' > "$W/nft.nft"
  out=$(env PATH="$W/bin:$PP" WASP_VARS="$W/vars.sh" WASP_CLIENT_MAIL="$CF" WASP_NFT_FILE="$W/nft.nft" "$SH" "$REPO/payload/bin/wp-hardening.sh" smtp-repin 2>&1)
  grep -q 'ip daddr { 192.0.2.10,192.0.2.11,198.51.100.7 } tcp dport' "$W/nft.nft" \
    && _p "$L: smtp-repin pins both the relay and the client's SMTP server" || _f "$L: repin both" "$(cat "$W/nft.nft") $out"
  printf 'table inet filter {\n  chain output {\n    tcp dport { 465, 587 } accept\n  }\n}\n' > "$W/nft2.nft"
  out=$(env PATH="$W/bin:$PP" WASP_VARS="$W/vars.sh" WASP_CLIENT_MAIL="$CF" WASP_NFT_FILE="$W/nft2.nft" "$SH" "$REPO/payload/bin/wp-hardening.sh" smtp-repin 2>&1); rc=$?
  [ "$rc" = 1 ] && printf '%s' "$out" | grep -q 'no SMTP destination rule' && _p "$L: ...and says so when there is no pinned rule, instead of claiming success" || _f "$L: no rule" "rc=$rc $out"

  out=$(printf 'no\n' | _mail client off)
  [ -r "$CF" ] && _p "$L: client off without OFF changes nothing" || _f "$L: off unconfirmed" "$out"
  out=$(printf ' OFF \n' | _mail client off)
  [ ! -e "$CF" ] && ls "$W/secrets"/client-mail.ini.off-* >/dev/null 2>&1 && _p "$L: client off: back to the relay, old settings kept beside it" || _f "$L: off" "$out"
}

_suite host /bin/sh "/usr/local/bin:/usr/bin:/bin"
if [ -n "$BB" ] && "$BB" --list >/dev/null 2>&1; then
  mkdir -p "$T/bb"; for _a in $("$BB" --list); do ln -sf "$BB" "$T/bb/$_a"; done
  # base64 is BusyBox's too; nothing from the build host leaks in.
  _suite busybox "$T/bb/sh" "$T/bb"
else
  _f "BusyBox not found: the Alpine-shell pass did not run" "set BUSYBOX=/path/to/busybox"
fi

echo ""
echo "  smtp-config: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" = 0 ]
