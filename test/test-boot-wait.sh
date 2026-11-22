#!/usr/bin/env bash
# =============================================================================
# test-boot-wait.sh — at boot, WordPress starts when it could connect
# =============================================================================
#
# 10.28: wp-container's wait before starting WordPress was a root ping, which
# answers before InnoDB is ready and before WordPress's own user can log in.
# `mariadb-health-check.sh --wait` waits for WordPress's own connection (its
# user, its database, a query InnoDB answers). The service written by stage 07
# runs it; the 10.28 upgrade step adds it to a service written before.
# =============================================================================
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
_p() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
_f() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n         %s\n' "$1" "${2:-}"; }
echo ""
echo "Boot: WordPress waits for its own database connection"
mkdir -p "$T/bin" "$T/root/etc/init.d"
printf 'MARIADB_PASSWORD=pw\n' > "$T/env"
cat > "$T/bin/podman" <<STUB
#!/bin/sh
cat >/dev/null
n=\$(cat "$T/calls" 2>/dev/null || echo 0); n=\$((n + 1)); echo "\$n" > "$T/calls"
[ -f "$T/ready-at" ] && [ "\$n" -ge "\$(cat "$T/ready-at")" ] && { echo 12; exit 0; }
exit 1
STUB
chmod +x "$T/bin/podman"
_w() { env PATH="$T/bin:${WASP_TEST_TOOLS:+$WASP_TEST_TOOLS:}$PATH" WASP_DB_ENV="$T/env" ${WASP_TEST_SH:-sh} "$REPO/payload/bin/mariadb-health-check.sh" --wait "$@" 2>&1; }

echo 3 > "$T/ready-at"; rm -f "$T/calls"
out=$(_w 10); rc=$?
[ "$rc" = 0 ] && printf '%s' "$out" | grep -q 'ready for WordPress after 4s' && _p "ready on the third try: exit 0, after 4s" || _f "ready" "rc=$rc $out"
rm -f "$T/ready-at" "$T/calls"
out=$(_w 4); rc=$?
[ "$rc" = 1 ] && printf '%s' "$out" | grep -q 'not ready for WordPress after 4s' && _p "never ready: exit 1 at the limit, said" || _f "timeout" "rc=$rc $out"
grep -q 'MARIADB_USER.*MARIADB_DATABASE.*information_schema\|information_schema.*DATABASE()' "$REPO/payload/bin/mariadb-health-check.sh" \
  && _p "the query is WordPress's own user and database, through InnoDB" || _f "query" ""

echo ""
echo "── the service, new and upgraded"
_render() {  # stage-07 text -> the wp-container service it writes
  sed -n '/^cat > \/etc\/init.d\/wp-container << ORCSVC_WP$/,/^ORCSVC_WP$/p' \
    | sed '1s|.*|cat <<ORCSVC_WP|' > "$T/r.sh"
  WP_IMAGE=img SVC_HEADERS_VOL= SVC_REMOTEIP_VOLS= bash "$T/r.sh"
}
_render < "$REPO/payload/stages/07-openrc-services.sh" > "$T/new"
sh -n "$T/new" && _p "the service stage 07 writes parses" || _f "new parse" ""
awk '/mariadb-health-check.sh --wait/ {w=NR} /^  _wait=0$/ {l=NR} /podman start wordpress/ {s=NR} END {exit !(w && l && s && w < l && l < s)}' "$T/new" \
  && _p "it waits for WordPress's connection first, then the old ping, then starts WordPress" || _f "order" "$(grep -n 'wait\|podman start' "$T/new")"
grep -q '"${WASP_DB_WAIT:-120}"' "$T/new" && _p "for up to 120s (WASP_DB_WAIT)" || _f "120" "$(grep -n WASP_DB_WAIT "$T/new")"

# A service as written before 10.28: the same, without the new wait.
awk '/^  # 10.28: ready means/ {skip = 1} !skip {print} skip && /^  fi$/ {skip = 0}' \
  "$T/new" > "$T/root/etc/init.d/wp-container"
grep -q 'mariadb-health-check.sh --wait "' "$T/root/etc/init.d/wp-container" && _f "fixture" "the older service still has the wait"
cp "$T/root/etc/init.d/wp-container" "$T/old"
out=$(WASP_ROOT="$T/root" ${WASP_TEST_SH:-sh} "$REPO/payload/upgrade/hooks/10.28.sh" 2>&1); rc=$?
S="$T/root/etc/init.d/wp-container"
[ "$rc" = 0 ] && grep -q '/usr/local/bin/mariadb-health-check.sh --wait "' "$S" && sh -n "$S" && _p "the 10.28 upgrade step adds the wait to an older service, which still parses" || _f "hook" "rc=$rc $out"
awk '/mariadb-health-check.sh --wait/ {w=NR} /^  _wait=0$/ {l=NR} END {exit !(w && l && w < l)}' "$S" && _p "ahead of the old loop" || _f "hook order" ""
cmp -s "$T/old" "$S.bak-10.28" && _p "the previous file is kept beside it" || _f "backup" "$(ls "$T/root/etc/init.d")"
cp "$S" "$T/once"
out=$(WASP_ROOT="$T/root" ${WASP_TEST_SH:-sh} "$REPO/payload/upgrade/hooks/10.28.sh" 2>&1)
cmp -s "$T/once" "$S" && printf '%s' "$out" | grep -q 'nothing to do' && _p "run again: nothing changes" || _f "repeat" "$out"
printf '#!/sbin/openrc-run\nstart() { podman start wordpress; }\n' > "$S"; cp "$S" "$T/odd"
out=$(WASP_ROOT="$T/root" ${WASP_TEST_SH:-sh} "$REPO/payload/upgrade/hooks/10.28.sh" 2>&1); rc=$?
[ "$rc" = 0 ] && cmp -s "$T/odd" "$S" && printf '%s' "$out" | grep -q 'left alone' && _p "a service edited out of shape is left alone, said" || _f "odd" "rc=$rc $out"
rm -f "$S"
out=$(WASP_ROOT="$T/root" ${WASP_TEST_SH:-sh} "$REPO/payload/upgrade/hooks/10.28.sh" 2>&1); rc=$?
[ "$rc" = 0 ] && printf '%s' "$out" | grep -q 'skipped' && _p "no wp-container service: skipped" || _f "none" "rc=$rc $out"

echo ""
printf '  passed %d   failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
