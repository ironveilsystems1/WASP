#!/usr/bin/env bash
# =============================================================================
# test-headers.sh — opener isolation and hotlink protection (10.29)
# =============================================================================
#
# `wp-hardening.sh headers` owns one block of wp-security.conf, written from
# /etc/wp-install/headers: Cross-Origin-Opener-Policy (on by default) and, on
# /wp-content/uploads/ only, Cross-Origin-Resource-Policy (hotlink protection,
# off by default). This drives the real tool and the 10.29 upgrade step
# against WASP's own header file, with podman stood in, and checks:
#
#   - an older file gets the block after Permissions-Policy, in place, with a
#     copy kept, Apache asked first, WordPress restarted, the live headers read
#   - each setting adds and removes exactly its lines; CORP never on pages
#   - a refused configtest or a damaged block changes nothing
#   - the CSP lines (wp-hardening.sh embeds) and this block leave each other alone
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
echo "Cross-origin headers"
[ "$(id -u)" -eq 0 ] || { _f "must run as root" "the tool re-executes through doas otherwise"; exit 1; }
BB="${BUSYBOX:-$(command -v busybox 2>/dev/null || true)}"

_suite() {  # label shell pathprefix
  L="$1"; SH="$2"; PP="$3"; W="$T/$L"; R="$W/root"
  mkdir -p "$W/bin" "$R/home/wpuser/wp/apache-conf" "$R/etc/wp-install" "$R/usr/local/bin" "$W/logs"
  CONF="$R/home/wpuser/wp/apache-conf/wp-security.conf"; ST="$R/etc/wp-install/headers"
  printf 'WP_DOMAIN="www.site.example"\n' > "$W/vars.sh"
  # podman: configtest, restart, and the live headers as Apache would serve
  # them from the file: site-wide lines outside any LocationMatch, the uploads
  # LocationMatch's lines on /wp-content/uploads/ only.
  cat > "$W/bin/podman" <<STUB
#!$SH
case "\$*" in
  *"apache2ctl -t"*) [ -f "$W/apache-fail" ] && exit 1; exit 0 ;;
  *"restart wordpress"*) echo restart >> "$W/calls"; exit 0 ;;
  *"Content-Security-Policy"*)
    awk '/<LocationMatch/{a=1} /<\/LocationMatch>/{a=0} !a && /Header always set Content-Security-Policy/ {
      sub(/^[[:space:]]*Header always set /, ""); n = index(\$0, " "); h = substr(\$0, 1, n-1); v = substr(\$0, n+2); sub(/"\$/, "", v); print h ": " v }' "$CONF" ;;
  *"php -r"*)
    [ -f "$W/live-override" ] && { cat "$W/live-override"; exit 0; }
    for a in "\$@"; do p="\$a"; done
    echo "HTTP/1.1 200 OK"
    awk -v p="\$p" '
      /<LocationMatch/ { loc = \$0; inl = 1; next }
      /<\/LocationMatch>/ { inl = 0; next }
      /Header always set Cross-Origin-/ {
        if (inl && !(loc ~ /wp-content\/uploads/ && p ~ /^\/wp-content\/uploads\//)) next
        sub(/^[[:space:]]*Header always set /, ""); n = index(\$0, " "); h = substr(\$0, 1, n-1); v = substr(\$0, n+2); gsub(/"/, "", v); print h ": " v }' "$CONF" ;;
esac
exit 0
STUB
  printf '#!%s\nexit 0\n' "$SH" > "$W/bin/wasp-egress.sh"
  chmod +x "$W/bin/"*
  cp "$REPO/payload/bin/wp-hardening.sh" "$R/usr/local/bin/wp-hardening.sh"; chmod +x "$R/usr/local/bin/wp-hardening.sh"
  _h() { env PATH="$W/bin:$PP" WASP_APACHE_CONF="$CONF" WASP_HEADERS_STATE="$ST" WASP_EMBEDS_STATE="$W/embeds" \
           WASP_VARS="$W/vars.sh" WP_LOG_DIR="$W/logs" "$SH" "$REPO/payload/bin/wp-hardening.sh" "$@" 2>&1; }
  _hook() { env PATH="$W/bin:$PP" WASP_ROOT="$R" WASP_VARS="$W/vars.sh" "$SH" "$REPO/payload/upgrade/hooks/10.29.sh" 2>&1; }
  _ino() { ls -i "$CONF" | awk '{print $1}'; }
  _blk() { awk '/^# BEGIN WASP managed headers/{b=1} b {print} /^# END WASP managed headers/{b=0}' "$CONF"; }

  echo ""
  echo "  ── under ${L}"
  # A file from before 10.29: the fallback without the block.
  awk '/^# BEGIN WASP managed headers/{s=1} !s {print} /^# END WASP managed headers/{s=0}' \
    "$REPO/payload/apache-conf/wp-security-fallback.conf" > "$CONF"
  grep -q 'managed headers' "$CONF" && _f "$L: fixture" "still has the block"
  cp "$CONF" "$W/orig"; : > "$W/calls"
  out=$(_h headers status)
  printf '%s' "$out" | grep -q 'predates them' && printf '%s' "$out" | grep -q 'headers apply' \
    && _p "$L: status on an older file: says it predates the headers, with the fix" || _f "$L: status old" "$out"
  cmp -s "$CONF" "$W/orig" && _p "$L: status changes nothing" || _f "$L: status wrote" ""
  out=$(_h headers check); rc=$?
  [ "$rc" = 1 ] && _p "$L: check: differs (exit 1)" || _f "$L: check old" "rc=$rc $out"

  i0=$(_ino)
  out=$(_hook); rc=$?
  [ "$rc" = 0 ] && _p "$L: the 10.29 upgrade step applies them" || _f "$L: hook" "rc=$rc $out"
  awk '/Permissions-Policy/ {p=NR} /^# BEGIN WASP managed headers/ {b=NR} END {exit !(p && b == p + 1)}' "$CONF" \
    && _p "$L: the block goes right after Permissions-Policy" || _f "$L: placement" "$(cat "$CONF")"
  _blk | grep -qx 'Header always set Cross-Origin-Opener-Policy "same-origin-allow-popups"' && ! _blk | grep -q Resource-Policy \
    && _p "$L: by default: COOP same-origin-allow-popups, no hotlink protection" || _f "$L: default block" "$(_blk)"
  [ "$(_ino)" = "$i0" ] && _p "$L: written in place (the container reads the file by inode)" || _f "$L: inode" ""
  ls "$CONF".bak-headers-* >/dev/null 2>&1 && _p "$L: the previous file is kept" || _f "$L: backup" ""
  grep -q restart "$W/calls" && _p "$L: WordPress restarted so Apache applies it" || _f "$L: restart" "$(cat "$W/calls")"
  [ "$(grep -c 'Content-Security-Policy' "$CONF")" = "$(grep -c 'Content-Security-Policy' "$W/orig")" ] \
    && diff <(grep 'Content-Security-Policy' "$W/orig") <(grep 'Content-Security-Policy' "$CONF") >/dev/null \
    && _p "$L: the CSP lines are untouched" || _f "$L: csp" ""
  out=$(_h headers check); rc=$?
  [ "$rc" = 0 ] && printf '%s' "$out" | grep -q 'COOP on, hotlink protection off' && _p "$L: check: matches (exit 0)" || _f "$L: check" "rc=$rc $out"
  cp "$CONF" "$W/once"; : > "$W/calls"
  out=$(_hook)
  cmp -s "$CONF" "$W/once" && [ ! -s "$W/calls" ] && printf '%s' "$out" | grep -q 'nothing to do' \
    && _p "$L: the step again: nothing changes, no restart" || _f "$L: hook again" "$out"

  out=$(_h headers hotlink on); rc=$?
  _blk | grep -q '<LocationMatch "^/wp-content/uploads/">' && _blk | grep -q 'Cross-Origin-Resource-Policy "same-site"' && [ "$rc" = 0 ] \
    && _p "$L: hotlink on: CORP same-site, on uploads only" || _f "$L: hotlink on" "rc=$rc $out $(_blk)"
  printf '%s' "$out" | grep -q 'outside$' && printf '%s' "$out" | grep -q 'site.example and its subdomains' \
    && _p "$L: and says what it breaks, naming the domain without www" || _f "$L: hotlink warning" "$out"
  grep -qx 'hotlink=on' "$ST" && _p "$L: recorded as a setting" || _f "$L: state" "$(cat "$ST")"
  live=$(env PATH="$W/bin:$PP" podman exec x php -r x /wp-content/uploads/2026/11/a.jpg)
  printf '%s' "$live" | grep -q '^Cross-Origin-Resource-Policy: same-site' && _p "$L: (the stand-in serves CORP on an upload)" || _f "$L: stub" "$live"
  out=$(_h headers check); [ $? = 0 ] && _p "$L: check matches with hotlink on (CORP on uploads, not on pages)" || _f "$L: check hotlink" "$out"
  out=$(_h headers hotlink off)
  ! _blk | grep -q Resource-Policy && ! grep -q 'wp-content/uploads/">' "$CONF" && _p "$L: hotlink off: removed" || _f "$L: hotlink off" "$(_blk)"
  out=$(_h headers coop off)
  ! _blk | grep -q Opener && [ "$(_blk | wc -l)" = 2 ] && _p "$L: coop off: the block keeps only its markers" || _f "$L: coop off" "$(_blk)"
  out=$(_h headers check); [ $? = 0 ] && _p "$L: and check agrees (no COOP served)" || _f "$L: check off" "$out"
  _h headers coop on >/dev/null

  : > "$W/calls"
  _h headers hotlink on --no-restart >/dev/null
  [ ! -s "$W/calls" ] && _p "$L: --no-restart writes without restarting" || _f "$L: no-restart" "$(cat "$W/calls")"
  _h headers hotlink off >/dev/null
  cp "$CONF" "$W/good"; touch "$W/apache-fail"
  out=$(_h headers hotlink on); rc=$?
  rm -f "$W/apache-fail"
  [ "$rc" = 1 ] && cmp -s "$CONF" "$W/good" && printf '%s' "$out" | grep -q 'Apache refused' \
    && _p "$L: Apache refusing it puts the previous file back" || _f "$L: refused" "rc=$rc $out"
  _h headers hotlink off >/dev/null 2>&1
  printf '%s\n' "$(cat "$CONF")" "# BEGIN WASP managed headers -- stray" > "$W/damaged"; cat "$W/damaged" > "$CONF"
  out=$(_h headers apply); rc=$?
  [ "$rc" = 1 ] && cmp -s "$CONF" "$W/damaged" && printf '%s' "$out" | grep -q 'damaged managed-headers block' \
    && _p "$L: a damaged block: refused, nothing changed" || _f "$L: damaged" "rc=$rc $out"
  cat "$W/good" > "$CONF"

  # The two commands leave each other's lines alone.
  _h embeds allow google-maps >/dev/null
  _blk | grep -q 'Cross-Origin-Opener-Policy' && grep -q "frame-src 'self' https://www.google.com" "$CONF" \
    && _p "$L: embeds keeps this block" || _f "$L: embeds" "$(cat "$CONF")"
  _h headers hotlink on >/dev/null
  grep -q "frame-src 'self' https://www.google.com" "$CONF" && _blk | grep -q Resource-Policy \
    && _p "$L: and headers keeps embeds' lines" || _f "$L: headers vs embeds" "$(cat "$CONF")"
  printf 'HTTP/1.1 200 OK\nCross-Origin-Opener-Policy: same-origin\n' > "$W/live-override"
  out=$(_h headers status); rc=0; _h headers check >/dev/null || rc=$?
  rm -f "$W/live-override"
  printf '%s' "$out" | grep -q 'serves something else' && [ "$rc" = 1 ] \
    && _p "$L: another file setting them: status says so, check exits 1" || _f "$L: override" "rc=$rc $out"
}

_suite host "$(command -v bash)" "$PATH"
if [ -n "$BB" ] && [ -x "$BB" ]; then
  mkdir -p "$T/bb"
  for a in $("$BB" --list); do ln -sf "$BB" "$T/bb/$a"; done
  _suite busybox "$T/bb/sh" "$T/bb:$PATH"
else
  echo "  (BusyBox not found: host shell only)"
fi

echo ""
echo "── new builds"
awk '/Permissions-Policy "camera/ {p=NR} /^# BEGIN WASP managed headers/ {b=NR} /^Header always set Cross-Origin-Opener-Policy "same-origin-allow-popups"$/ {c=NR} END {exit !(p && b == p + 1 && c == b + 1)}' \
  "$REPO/lib/03-dynamic-configs.sh" && _p "the installer writes the block, with COOP, after Permissions-Policy" || _f "lib/03" ""
grep -q '^Header always set Cross-Origin-Opener-Policy "same-origin-allow-popups"$' "$REPO/payload/apache-conf/wp-security-fallback.conf" \
  && _p "and so does the fallback file" || _f "fallback" ""

echo ""
printf '  passed %d   failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
