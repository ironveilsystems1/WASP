#!/usr/bin/env bash
# =============================================================================
# test-egress-temporary.sh — nothing temporary outlives an hour
# =============================================================================
#
# The permanent allowlist should hold the theme and builder vendors a site
# updates from. Everything else -- a one-off allow, a file-sharing service, a
# maintenance window, an import download -- is a temporary entry that closes
# by itself within 60 minutes, whether or not anyone runs wasp-egress again.
#
# This drives the real wasp-egress.sh and wp-import.sh with podman, curl and
# logger stubbed, and checks the files Squid reads. Whether Squid honours them
# is a live-VM question (`wasp-egress test`).
# =============================================================================
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
_p() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
_f() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n         %s\n' "$1" "${2:-}"; }

mkdir -p "$T/bin" "$T/inbox" "$T/staging" "$T/etc" "$T/sq/config" "$T/sq/logs"
: > "$T/etc/vars.sh"
printf 'wasp-placeholder.invalid\n' > "$T/sq/config/allowlist-maintenance.txt"
printf 'api.wordpress.org\n' > "$T/sq/config/allowlist-runtime.txt"
M="$T/sq/config/allowlist-maintenance.txt"; R="$T/sq/config/allowlist-runtime.txt"
L="$T/sq/config/.temporary"

sed -e '/^if \[ "\$(id -u)" -ne 0 \]; then$/,/^fi$/d' \
    -e "s#/etc/wp-install/vars.sh#$T/etc/vars.sh#g" \
    -e "s#^IMPORT_SOURCES=.*#IMPORT_SOURCES=$T/etc/import-sources.txt#" \
    -e "s#^SQ=.*#SQ=$T/sq#" \
    "$REPO/payload/bin/wasp-egress.sh" > "$T/wasp-egress.sh"
sed -e '/^if \[ "\$(id -u)" -ne 0 \]; then$/,/^fi$/d' \
    -e "s#/etc/wp-install/vars.sh#$T/etc/vars.sh#g" \
    -e "s#^INBOX=.*#INBOX=$T/inbox#" \
    -e "s#^STAGING=.*#STAGING=$T/staging#" \
    -e "s#/usr/local/bin/wasp-egress.sh#$T/wasp-egress.sh#g" \
    "$REPO/payload/bin/wp-import.sh" > "$T/wp-import.sh"
chmod +x "$T/wasp-egress.sh"

# podman: `squid -k parse` fails when PARSE_FAIL=1; every reconfigure is counted.
cat > "$T/bin/podman" <<STUB
#!/usr/bin/env bash
case "\$*" in
  *'container exists squid'*) exit 0 ;;
  *'squid -k parse'*) [ "\${PARSE_FAIL:-0}" = 1 ] && exit 1; exit 0 ;;
  *'squid -k reconfigure'*) echo x >> "$T/reconfigures"; exit 0 ;;
  *'grep -qxF'*) exit 1 ;;
esac
exit 0
STUB
cat > "$T/bin/curl" <<STUB
#!/usr/bin/env bash
out=""; while [ \$# -gt 0 ]; do case "\$1" in -o) out="\$2"; shift ;; esac; shift; done
cp "$M" "$T/during"
printf 'PK\003\004 archive' > "\$out"
STUB
printf '#!/bin/sh\nexit 0\n' > "$T/bin/logger"; cp "$T/bin/logger" "$T/bin/sleep"
chmod +x "$T/bin/"*

_eg()  { PATH="$T/bin:${WASP_TEST_TOOLS:+$WASP_TEST_TOOLS:}$PATH" ${WASP_TEST_SH:-sh} "$T/wasp-egress.sh" "$@" 2>&1; }
_imp() { PATH="$T/bin:${WASP_TEST_TOOLS:+$WASP_TEST_TOOLS:}$PATH" ${WASP_TEST_SH:-sh} "$T/wp-import.sh" fetch url "$1" 2>&1; }
_in()  { grep -qxF "$1" "$M"; }
_age() { # make every ledger entry for $1 already expired
  awk -v d="$1" '$3==d {$1=1} {print}' "$L" > "$L.x"; cat "$L.x" > "$L"; rm -f "$L.x"; }

echo ""
echo "Temporary egress"
echo ""
echo "── allow is temporary unless told otherwise"
_eg allow files.example.net >/dev/null
_in files.example.net && _p "allow opens the host" || _f "allow" "$(cat "$M")"
grep -q files "$R" && _f "allow" "went onto the permanent list" || _p "and leaves the permanent list alone"
_left=$(awk '$3=="files.example.net" {print $1}' "$L")
_d=$(( _left - $(date -u +%s) ))
[ "$_d" -gt 3500 ] && [ "$_d" -le 3600 ] && _p "default is 60 minutes" || _f "default" "$_d s"
_eg allow long.example.net --for 600 >/dev/null
_d=$(( $(awk '$3=="long.example.net" {print $1}' "$L") - $(date -u +%s) ))
[ "$_d" -le 3600 ] && _p "--for 600 is capped at 60 minutes" || _f "cap" "$_d s"
_eg allow short.example.net --for 5 >/dev/null
_d=$(( $(awk '$3=="short.example.net" {print $1}' "$L") - $(date -u +%s) ))
[ "$_d" -le 300 ] && [ "$_d" -gt 240 ] && _p "--for 5 is 5 minutes" || _f "--for 5" "$_d s"
for bad in .com nodots 'http://x.example.net' 'a b.example.net' '*.example.net'; do
  _eg allow "$bad" >/dev/null; [ $? = 1 ] && _p "refuses '$bad'" || _f "accepted" "$bad"
done
_eg allow --for 0 zero.example.net >/dev/null; [ $? = 1 ] && _p "refuses --for 0" || _f "--for 0" "accepted"
_eg allow .vendor.example.com --permanent >/dev/null
grep -qxF .vendor.example.com "$R" && _p "--permanent goes on the permanent list" || _f "--permanent" "$(cat "$R")"
_in .vendor.example.com && _f "--permanent" "also in the temporary list" || _p "and not on the temporary one"

echo ""
echo "── expiry needs nobody"
_ino=$(stat -c %i "$M" 2>/dev/null || ls -i "$M" | awk '{print $1}')
_age files.example.net
_eg expire >/dev/null
_in files.example.net && _f "expire" "still open" || _p "an expired entry is closed by \`expire\` (cron, every minute)"
_in long.example.net && _p "and the others stay open" || _f "expire" "closed the wrong entry"
_ino2=$(stat -c %i "$M" 2>/dev/null || ls -i "$M" | awk '{print $1}')
[ "$_ino" = "$_ino2" ] && _p "Squid's file is rewritten in place (same inode)" || _f "inode" "$_ino -> $_ino2"
: > "$T/reconfigures"; _eg expire >/dev/null
[ ! -s "$T/reconfigures" ] && _p "an expire with nothing due does not touch Squid" || _f "idle expire" "reconfigured"
grep -q '/usr/local/bin/wasp-egress.sh expire' "$REPO/payload/cron/wordpress-vm.cron" \
  && grep '/usr/local/bin/wasp-egress.sh expire' "$REPO/payload/cron/wordpress-vm.cron" | grep -q '^\* \* \* \* \*' \
  && _p "cron runs expire every minute" || _f "cron" "no per-minute expire"

echo ""
echo "── file-sharing services"
_eg fileshare open dropbox >/dev/null
_in .dropbox.com && _in .dropboxusercontent.com && _p "dropbox opens with the host its downloads redirect to" || _f "dropbox" "$(cat "$M")"
_eg fileshare open gdrive onedrive >/dev/null
_in .drive.google.com && _in .usercontent.google.com && _in onedrive.live.com && _p "several at once" || _f "gdrive onedrive" "$(cat "$M")"
_eg fileshare open syncedtool >/dev/null
_in activeit.syncedtool.com && _p "SyncedTool is a service here, not an installer question" || _f "syncedtool" ""
_eg fileshare open mega >/dev/null; [ $? = 1 ] && _p "an unknown service is refused" || _f "unknown" "accepted"
for _m in "www.dropbox.com dropbox" "uc12ab.dl.dropboxusercontent.com dropbox" "drive.usercontent.google.com gdrive" \
          "acme-my.sharepoint.com onedrive" "we.tl wetransfer" "dl.boxcloud.com box" "activeit.syncedtool.com syncedtool"; do
  set -- $_m
  [ "$(_eg fileshare match "$1")" = "$2" ] && _p "match: $1 → $2" || _f "match $1" "$(_eg fileshare match "$1")"
done
for _h in evil-dropbox.com dropbox.com.evil.net other.syncedtool.com; do
  _eg fileshare match "$_h" >/dev/null && _f "match $_h" "matched" || _p "no match: $_h"
done
_eg allow www.dropbox.com >/dev/null
_in www.dropbox.com && _f "overlap" "www.dropbox.com listed beside .dropbox.com" \
  || _p "a host already covered by .dropbox.com is not listed twice (Squid warns on that)"
_eg fileshare close >/dev/null
_in .dropbox.com && _f "fileshare close" "still open" || _p "fileshare close closes the services"
grep -q 'www.dropbox.com' "$L" && _p "but not a separate allow of one of their hosts" || _f "fileshare close" "took the allow"
_in www.dropbox.com && _p "which is now listed on its own" || _f "re-listed" "$(cat "$M")"

echo ""
echo "── a rejected list opens nothing"
cp "$L" "$T/ledger-before"
PARSE_FAIL=1 _eg fileshare open box >/dev/null; rc=$?
[ "$rc" = 1 ] && _p "Squid refusing the list fails the command" || _f "parse fail rc" "$rc"
cmp -s "$L" "$T/ledger-before" && ! _in .box.com && _p "and the ledger and Squid's file are put back" || _f "rollback" "$(cat "$M")"

echo ""
echo "── an import opens its service, and closes only what it opened"
_eg close --all >/dev/null
_eg allow .dropboxusercontent.com --for 30 >/dev/null
: > "$T/during"
_imp 'https://www.dropbox.com/scl/fi/abc/backup.zip?dl=1' >/dev/null; rc=$?
[ "$rc" = 0 ] && _p "a Dropbox link downloads" || _f "fetch" "exit $rc"
grep -qx .dropbox.com "$T/during" && _p "Dropbox was open during the transfer" || _f "during" "$(cat "$T/during")"
_in .dropbox.com && _f "after" "Dropbox left open" || _p "and closed after it"
_in .dropboxusercontent.com && _p "an operator's own entry for a Dropbox host survives the import" || _f "clobbered" "$(cat "$M")"
: > "$T/during"
_imp 'https://unknown.example.org/backup.zip' >/dev/null
grep -q unknown "$T/during" && _f "unlisted" "opened" || _p "a host that is neither a service nor an import source opens nothing"

echo ""
echo "── maintenance is a temporary allow with a reason"
_eg maintenance enable --duration 240 --reason "plugin vendor licence check" --host updates.example.org >/dev/null
_d=$(( $(awk '$3=="updates.example.org" {print $1}' "$L") - $(date -u +%s) ))
_in updates.example.org && [ "$_d" -le 3600 ] && _p "a window opens, capped at 60 minutes (was 120)" || _f "maintenance" "$_d s"
_eg maintenance enable --duration 10 --reason short --host x.example.org >/dev/null; [ $? = 1 ] && _p "a reason is still required" || _f "reason" "accepted"
_eg maintenance disable >/dev/null
_in updates.example.org && _f "disable" "still open" || _p "disable closes it"
# A 10.10 window carried over on upgrade, with an expiry two hours out.
printf 'reason=old window\nuntil=%s\nhosts=legacy.example.org\n' "$(( $(date -u +%s) + 7200 ))" > "$T/sq/config/.maintenance"
_eg temporary >/dev/null
_d=$(( $(awk '$3=="legacy.example.org" {print $1}' "$L") - $(date -u +%s) ))
[ ! -e "$T/sq/config/.maintenance" ] && [ "$_d" -le 3600 ] && _p "a 10.10 window is migrated, and capped" || _f "migrate" "$_d s"

echo ""
echo "── deny means now, permanent and temporary"
_eg allow .vendor2.example.com --permanent >/dev/null
_eg allow .vendor2.example.com --for 20 >/dev/null
_eg deny .vendor2.example.com >/dev/null
if grep -qxF .vendor2.example.com "$R"; then _f "deny" "the permanent entry stayed"
elif _in .vendor2.example.com; then _f "deny" "the temporary entry stayed"
else _p "deny removes both"; fi

echo ""
echo "── nothing in the installer names a file host"
grep -q 'syncedtool' "$REPO/lib/01-interactive-setup.sh" && _f "installer" "still asks about SyncedTool" \
  || _p "the installer no longer asks about activeit.syncedtool.com"

echo ""
printf '  passed %d   failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
