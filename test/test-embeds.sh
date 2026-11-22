#!/usr/bin/env bash
# =============================================================================
# test-embeds.sh — security-header exceptions as a setting (10.28)
# =============================================================================
#
# Two field VMs had wp-security.conf edited by hand so Google Maps, reCAPTCHA
# and Google Fonts would load, and the edit did not apply until the container
# was restarted. `wp-hardening.sh embeds` makes it a setting. This drives the
# real tool against WASP's own header file, with podman stood in, and checks:
#
#   - each service adds exactly its origins, to both the site's line and the
#     wp-admin line (which keeps 'unsafe-eval' and sends no reports)
#   - a hand-edited VM keeps what it had: the first run records it
#   - written in place (the container reads the file by inode), Apache asked
#     first, the old file put back if Apache refuses, WordPress restarted and
#     the live header read back
#   - report-only mode, custom origins (validated), --no-restart, a file that
#     does not have WASP's two lines
#   - the report: what browsers said was blocked, grouped, with the command
#
# Run under the host shell and BusyBox (BUSYBOX=/path/to/busybox).
# =============================================================================
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
_p() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
_f() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n         %s\n' "$1" "${2:-}"; }
echo ""
echo "Security-header exceptions (embeds)"
[ "$(id -u)" -eq 0 ] || { _f "must run as root" "the tool re-executes through doas otherwise"; exit 1; }
BB="${BUSYBOX:-$(command -v busybox 2>/dev/null || true)}"

_suite() {  # label shell pathprefix
  L="$1"; SH="$2"; PP="$3"; W="$T/$L"
  mkdir -p "$W/bin" "$W/logs" "$W/state"
  CONF="$W/wp-security.conf"; ST="$W/state/embeds"
  # podman: apache2ctl -t, restart, and the live header = the file's line for
  # the site (outside the wp-admin LocationMatch), as Apache would serve it.
  cat > "$W/bin/podman" <<EOF
#!$SH
case "\$*" in
  *"apache2ctl -t"*) [ -f "$W/apache-fail" ] && exit 1; exit 0 ;;
  *"restart wordpress"*) echo restart >> "$W/calls"; exit 0 ;;
  *"php -r"*)
    [ -f "$W/live-override" ] && { cat "$W/live-override"; exit 0; }
    awk '/<LocationMatch/{a=1} /<\/LocationMatch>/{a=0} !a && /Header always set Content-Security-Policy/ {
      sub(/^[[:space:]]*Header always set /, ""); n = index(\$0, " "); h = substr(\$0, 1, n-1); v = substr(\$0, n+2); sub(/"\$/, "", v); print h ": " v }' "$CONF" ;;
esac
exit 0
EOF
  printf '#!%s\necho "wasp-egress.sh $*" >> "%s/calls"\n' "$SH" "$W" > "$W/bin/wasp-egress.sh"
  chmod +x "$W/bin/"*
  _e() { env PATH="$W/bin:$PP" WASP_APACHE_CONF="$CONF" WASP_EMBEDS_STATE="$ST" WP_LOG_DIR="$W/logs" \
           "$SH" "$REPO/payload/bin/wp-hardening.sh" embeds "$@" 2>&1; }
  _pub() { awk '/<LocationMatch/{a=1} /<\/LocationMatch>/{a=0} !a && /Content-Security-Policy/' "$CONF"; }
  _adm() { awk '/<LocationMatch[^>]*wp-admin/{a=1} a && /Content-Security-Policy/ {print} /<\/LocationMatch>/{a=0}' "$CONF"; }
  _ino() { ls -i "$CONF" | awk '{print $1}'; }

  echo ""
  echo "  ── under ${L}"
  cp "$REPO/payload/apache-conf/wp-security-fallback.conf" "$CONF"; : > "$W/calls"
  orig=$(cat "$CONF")
  out=$(_e status)
  [ -f "$ST" ] && grep -qx 'mode=enforce' "$ST" && ! grep -q '^allow ' "$ST" && _p "$L: first use records the settings: enforce, nothing extra" || _f "$L: state" "$(cat "$ST" 2>/dev/null)"
  [ "$(cat "$CONF")" = "$orig" ] && _p "$L: status changes nothing" || _f "$L: status wrote" ""
  printf '%s' "$out" | grep -q 'The site serves something else' && printf '%s' "$out" | grep -q 'embeds apply' \
    && _p "$L: a header that differs from the settings is said, with the fix" || _f "$L: status mismatch" "$out"

  i0=$(_ino); : > "$W/calls"
  out=$(_e allow google-maps recaptcha); rc=$?
  p=$(_pub); a=$(_adm)
  [ "$rc" = 0 ] && printf '%s' "$p" | grep -q "frame-src 'self' https://www.google.com https://maps.google.com;" \
    && printf '%s' "$p" | grep -q "script-src 'self' 'unsafe-inline' https://www.google.com https://www.gstatic.com;" \
    && _p "$L: maps and reCAPTCHA: exactly their origins on the site's line" || _f "$L: allow pub" "rc=$rc $p $out"
  printf '%s' "$p" | grep -q "report-uri /?wasp_csp_report=1" && ! printf '%s' "$p" | grep -q "unsafe-eval" \
    && _p "$L: ...with the report address, and still no 'unsafe-eval'" || _f "$L: pub report" "$p"
  printf '%s' "$a" | grep -q "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://www.google.com https://www.gstatic.com;" \
    && printf '%s' "$a" | grep -q "frame-src 'self' https://www.google.com https://maps.google.com;" && ! printf '%s' "$a" | grep -q report-uri \
    && _p "$L: the wp-admin line gets them too, keeps 'unsafe-eval', sends no reports" || _f "$L: allow adm" "$a"
  printf '%s' "$p" | grep -q "img-src 'self' data: https:; font-src 'self' data:;" && printf '%s' "$p" | grep -q "frame-ancestors 'self'" \
    && _p "$L: everything else as WASP has always sent it" || _f "$L: rest" "$p"
  [ "$(_ino)" = "$i0" ] && _p "$L: written in place (the container reads it by inode)" || _f "$L: inode" ""
  grep -qx restart "$W/calls" && printf '%s' "$out" | grep -q 'The site now serves it' && _p "$L: WordPress restarted and the live header read back" || _f "$L: restart" "$(cat "$W/calls") $out"
  grep -qx 'wasp-egress.sh allow www.google.com --permanent' "$W/calls" || [ ! -f /opt/squid/config/allowlist-runtime.txt ] \
    && _p "$L: reCAPTCHA's server check gets its egress (where egress filtering is on)" || _f "$L: egress" "$(cat "$W/calls")"
  ls "$CONF".bak-embeds-* >/dev/null 2>&1 && _p "$L: the previous file is kept" || _f "$L: backup" ""
  [ "$(grep -c '^allow ' "$ST")" = 2 ] && _p "$L: the settings say what was allowed" || _f "$L: state allows" "$(cat "$ST")"

  : > "$W/calls"; cp "$CONF" "$W/before"
  out=$(_e allow google-maps)
  cmp -s "$W/before" "$CONF" && printf '%s' "$out" | grep -q 'already matches' && _p "$L: allowing it again changes nothing" || _f "$L: idempotent" "$out"
  out=$(_e deny recaptcha)
  p=$(_pub)
  ! printf '%s' "$p" | grep -q gstatic && printf '%s' "$p" | grep -q "frame-src 'self' https://www.google.com https://maps.google.com;" \
    && _p "$L: deny takes out only that service's origins" || _f "$L: deny" "$p"
  out=$(_e add frame-src https://apps.example.net)
  _pub | grep -q "frame-src 'self' https://www.google.com https://maps.google.com https://apps.example.net;" && _p "$L: a custom origin joins its directive" || _f "$L: add" "$(_pub) $out"
  out=$(_e add connect-src https://api.example.net)
  _pub | grep -q "connect-src 'self' https://api.example.net;" && _p "$L: ...and a new directive is written when first needed" || _f "$L: connect" "$(_pub)"
  cp "$CONF" "$W/before"
  for bad in "frame-src http://apps.example.net" "frame-src https://apps.example.net/path" "frame-src https://evil.example.net;script-src" \
             "form-action https://apps.example.net" "frame-src https://*.example.net" "img-src https://x.example.net"; do
    out=$(_e add $bad); rc=$?
    [ "$rc" != 0 ] && cmp -s "$W/before" "$CONF" || { _f "$L: refused $bad" "rc=$rc $out"; continue; }
  done
  cmp -s "$W/before" "$CONF" && _p "$L: refused: http, a path, a ';', form-action, a wildcard, img-src" || :
  out=$(_e remove connect-src https://api.example.net)
  ! _pub | grep -q connect-src && _p "$L: remove takes a custom origin out" || _f "$L: remove" "$(_pub)"

  out=$(_e mode report)
  _pub | grep -q '^Header always set Content-Security-Policy-Report-Only "' && _adm | grep -q 'Header always set Content-Security-Policy "' \
    && grep -q '^report_since=' "$ST" && _p "$L: report mode: the site's header reports instead of blocking; wp-admin still enforced" || _f "$L: report mode" "$(_pub) $(_adm)"
  _e status | grep -q 'REPORT ONLY' && _p "$L: ...and status says so" || _f "$L: report status" ""
  out=$(_e mode enforce)
  _pub | grep -q '^Header always set Content-Security-Policy "' && ! grep -q '^report_since=' "$ST" && _p "$L: back to enforce" || _f "$L: enforce" "$(_pub)"

  : > "$W/calls"; cp "$CONF" "$W/before"; touch "$W/apache-fail"
  out=$(_e allow youtube); rc=$?
  rm -f "$W/apache-fail"
  [ "$rc" != 0 ] && cmp -s "$W/before" "$CONF" && ! grep -qx restart "$W/calls" && printf '%s' "$out" | grep -q 'refused the new header' \
    && _p "$L: Apache refusing: the previous file back, no restart" || _f "$L: apache fail" "rc=$rc $out"
  : > "$W/calls"
  out=$(_e allow youtube --no-restart)
  _pub | grep -q 'youtube-nocookie' && ! grep -qx restart "$W/calls" && printf '%s' "$out" | grep -q 'Not restarted' \
    && _p "$L: --no-restart writes it and says when it applies" || _f "$L: no-restart" "$out"
  printf 'Content-Security-Policy: default-src *\n' > "$W/live-override"
  out=$(_e apply); rc=$?
  rm -f "$W/live-override"
  [ "$rc" != 0 ] && printf '%s' "$out" | grep -q 'serves a different header' && printf '%s' "$out" | grep -q '.htaccess' \
    && _p "$L: a live header that differs after the restart is reported, with where to look" || _f "$L: live differs" "rc=$rc $out"

  out=$(_e apply)
  out=$(_e check); rc=$?
  [ "$rc" = 0 ] && printf '%s' "$out" | grep -q '^allows: google-maps youtube https://apps.example.net$' && _p "$L: check: 0 and what it allows, when the site serves the settings" || _f "$L: check ok" "rc=$rc $out"
  out=$(_e mode report); out=$(_e check); rc=$?
  [ "$rc" = 2 ] && printf '%s' "$out" | grep -q '^report-only since 20' && _p "$L: check: 2 in report-only mode, with since when" || _f "$L: check report" "rc=$rc $out"
  out=$(_e mode enforce)
  printf 'Content-Security-Policy: default-src *\n' > "$W/live-override"; out=$(_e check); rc=$?; rm -f "$W/live-override"
  [ "$rc" = 1 ] && _p "$L: check: 1 when the live header differs" || _f "$L: check differs" "rc=$rc $out"

  # A VM edited by hand before 10.28 keeps what it had.
  rm -f "$ST"
  sed -e "s#script-src 'self' 'unsafe-inline';#script-src 'self' 'unsafe-inline' https://www.google.com https://www.gstatic.com;#" \
      -e "s#style-src 'self' 'unsafe-inline';#style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;#" \
      -e "s#frame-ancestors 'self'\"#frame-src 'self' https://www.google.com https://maps.google.com; frame-ancestors 'self'\"#" \
      "$REPO/payload/apache-conf/wp-security-fallback.conf" > "$CONF"
  out=$(_e apply)
  grep -qx 'allow recaptcha' "$ST" && grep -qx 'allow google-maps' "$ST" && grep -qx 'allow google-fonts' "$ST" && ! grep -q youtube "$ST" \
    && _pub | grep -q 'fonts.googleapis.com' && _pub | grep -q 'maps.google.com' \
    && _p "$L: a hand-edited VM: maps, reCAPTCHA and fonts recorded and kept" || _f "$L: adopt" "$(cat "$ST") $(_pub)"

  printf 'ServerTokens Prod\n' > "$CONF"; cp "$CONF" "$W/before"
  out=$(_e allow youtube); rc=$?
  [ "$rc" != 0 ] && cmp -s "$W/before" "$CONF" && printf '%s' "$out" | grep -q 'does not have the two header lines' \
    && _p "$L: a file without WASP's two lines is left alone, with why" || _f "$L: foreign file" "rc=$rc $out"

  # ── what browsers reported (a fresh VM: nothing allowed yet) ──
  rm -f "$ST"; cp "$REPO/payload/apache-conf/wp-security-fallback.conf" "$CONF"
  cat > "$W/logs/error.log" <<'LOG'
[Sat Nov 21 10:00:01 2026] [php:notice] [wasp-csp] font-src blocked https://fonts.gstatic.com on /
[Sat Nov 21 10:00:02 2026] [php:notice] [wasp-csp] style-src blocked https://fonts.googleapis.com on /about/
[Sat Nov 21 10:00:03 2026] [php:notice] [wasp-csp] font-src blocked https://fonts.gstatic.com on /contact/
[Sat Nov 21 10:00:04 2026] [php:notice] [wasp-csp] frame-src blocked https://forms.example.org on /contact/
[Sat Nov 21 10:00:05 2026] [php:notice] [wasp-csp] script-src blocked inline on /
LOG
  out=$(_e report)
  printf '%s' "$out" | grep -qE '^ +2  font-src https://fonts.gstatic.com  \(first seen on /\)' && _p "$L: report groups what was blocked, with counts and a page" || _f "$L: report counts" "$out"
  printf '%s' "$out" | grep -q 'google-fonts: fonts loaded from Google.*embeds allow google-fonts' && _p "$L: ...names the service and the command" || _f "$L: report service" "$out"
  printf '%s' "$out" | grep -q 'embeds add frame-src https://forms.example.org' && _p "$L: ...and an unknown origin, with the command to add it" || _f "$L: report custom" "$out"
  printf '%s' "$out" | grep -q 'embeds add script-src inline' && _f "$L: inline" "suggested allowing inline" || _p "$L: ...but never suggests allowing inline code"
  : > "$W/logs/error.log"
  _e report | grep -q 'Nothing reported' && _p "$L: an empty report says what that means" || _f "$L: empty report" ""
}

_suite host /bin/sh "/usr/local/bin:/usr/bin:/bin"
if [ -n "$BB" ] && "$BB" --list >/dev/null 2>&1; then
  mkdir -p "$T/bb"; for _a in $("$BB" --list); do ln -sf "$BB" "$T/bb/$_a"; done
  _suite busybox "$T/bb/sh" "$T/bb"
else
  _f "BusyBox not found: the Alpine-shell pass did not run" "set BUSYBOX=/path/to/busybox"
fi

echo ""
printf '  passed %d   failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
