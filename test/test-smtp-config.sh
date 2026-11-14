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
  *"plugin list"*) printf '%s\n' \$(cat "$W/active" 2>/dev/null) ;;
  *inspect*)       echo '/var/www/private=false' ;;
  *fsockopen*)     printf reachable ;;
  *)               exit 0 ;;
esac
EOF
  printf '#!%s\nexit 0\n' "$SH" > "$W/bin/logger"
  chmod +x "$W/bin/"*
  _rot() { env PATH="$W/bin:$PP" WASP_SECRETS_DIR="$W/secrets" WASP_ROTATE_BACKUP_DIR="$W/bak" \
             "$SH" "$REPO/payload/bin/wp-rotate-secrets.sh" smtp "$@" 2>&1; }
  sed -e "s#^SECRETS_DIR=.*#SECRETS_DIR=$W/secrets#" \
      -e "s#/etc/wp-install/pinned.env#$W/none#g" "$REPO/payload/bin/wp-mail.sh" > "$W/wp-mail.sh"
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
