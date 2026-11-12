#!/usr/bin/env bash
# =============================================================================
# test-vuln-scan.sh — does a vulnerability scan say when it could not scan?
# =============================================================================
#
# The dangerous output of a scanner is "nothing found" from a run that looked at
# nothing. So most of this feeds failure in and asserts the scan says so, and
# that the daily job raises it. The real wp-plugins.sh and wp-vuln-cron.sh run
# with curl and podman stubbed.
#
# The WPVulnerability fixtures follow the maintainer's client code and test
# fixture. The applicability rules were re-checked in 10.11 against that client
# (wpvulnerability_is_vulnerability_applicable and _get_vulnerabilities): no
# live response was reachable from the build environment, so the response shape
# is still a reading of that code, and `wp-plugins.sh vulns` on a VM confirms it.
# =============================================================================
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
command -v jq >/dev/null 2>&1 || { echo "  SKIPPED — jq not installed"; exit 0; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
_p() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
_f() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n         %s\n' "$1" "${2:-}"; }
_has()  { case "$2" in *"$3"*) _p "$1" ;; *) _f "$1" "missing: $3 :: $(printf '%s' "$2" | tail -4)" ;; esac; }
_hasnt(){ case "$2" in *"$3"*) _f "$1" "found: $3" ;; *) _p "$1" ;; esac; }

mkdir -p "$T/bin" "$T/cache" "$T/etc" "$T/api" "$T/usr"
: > "$T/etc/vars.sh"; : > "$T/etc/pinned.env"; : > "$T/requests"; : > "$T/notify"

cat > "$T/bin/curl" <<STUB
#!/usr/bin/env bash
url=""; out=/dev/null; hdr=/dev/null
while [ \$# -gt 0 ]; do
  case "\$1" in -o) out="\$2"; shift ;; -D) hdr="\$2"; shift ;; -w|-H|--max-time) shift ;; http*) url="\$1" ;; esac
  shift
done
echo "\$url" >> "$T/requests"
case "\$url" in
  *wordfence.com*)
    [ -f "$T/wf.json" ] || { printf 000; exit 7; }
    cp "$T/wf.json" "\$out"; printf 200; exit 0 ;;
esac
key=\$(printf '%s' "\$url" | sed 's|.*wpvulnerability.net/||; s|/\$||; s|/|-|')
# A sequence of answers, one per attempt: lets a test say "429, then 200".
if [ -s "$T/api/\$key.seq" ]; then
  c=\$(head -1 "$T/api/\$key.seq"); sed -i '1d' "$T/api/\$key.seq"
  [ -f "$T/api/\$key.hdr" ] && cp "$T/api/\$key.hdr" "\$hdr"
  if [ "\$c" = 200 ]; then cp "$T/api/\$key.json" "\$out"; fi
  printf '%s' "\$c"; exit 0
fi
if [ -f "$T/api/\$key.code" ]; then printf '%s' "\$(cat "$T/api/\$key.code")"; exit 0; fi
if [ -f "$T/api/\$key.json" ]; then cp "$T/api/\$key.json" "\$out"; printf 200; exit 0; fi
printf 404
STUB
cat > "$T/bin/podman" <<STUB
#!/usr/bin/env bash
case "\$*" in
  ps\ *) echo wordpress ;;
  *'plugin list'*) cat "$T/plugins.csv" ;;
  *'theme list'*)  printf 'name,version,status\nastra,4.0.0,active\n' ;;
  *'core version'*) echo 7.1.4 ;;
  *PHP_VERSION*)    printf 8.4.27 ;;
  *'mariadb --version'*) echo 'mariadb from 11.4.8-MariaDB' ;;
esac
exit 0
STUB
cat > "$T/bin/sleep" <<STUB
#!/usr/bin/env bash
echo "\$1" >> "$T/sleeps"
STUB
cat > "$T/bin/logger" <<STUB
#!/usr/bin/env bash
echo "\$*" >> "$T/syslog"
STUB
chmod +x "$T/bin/"*
printf 'name,version,status\nelementor,3.0.0,active\ncontact-form,2.5,active\nmy-bespoke,1.0,active\n' > "$T/plugins.csv"

sed -e '/^if \[ "\$(id -u)" -ne 0 \]; then$/,/^fi$/d' \
    -e "s#/etc/wp-install/vars.sh#$T/etc/vars.sh#g" \
    -e "s#/etc/wp-install/pinned.env#$T/etc/pinned.env#g" \
    -e "s#^VULN_CONF=.*#VULN_CONF=\"$T/etc/vuln-sources.conf\"#" \
    -e "s#^VULN_CACHE=.*#VULN_CACHE=\"$T/cache\"#" \
    "$REPO/payload/bin/wp-plugins.sh" > "$T/wp-plugins.sh"
sed -e "s#/usr/local/bin/wp-plugins.sh#$T/wp-plugins.sh#g" \
    -e "s#/usr/local/bin/wp-notify.sh#$T/notify.sh#g" \
    "$REPO/payload/bin/wp-vuln-cron.sh" > "$T/cron.sh"
printf '#!/bin/sh\necho "$2" >> %s/notify\ncat "$3" >> %s/notify\n' "$T" "$T" > "$T/notify.sh"
chmod +x "$T/notify.sh" "$T/wp-plugins.sh"

_scan() { PATH="$T/bin:${WASP_TEST_TOOLS:+$WASP_TEST_TOOLS:}$PATH" ${WASP_TEST_SH:-sh} "$T/wp-plugins.sh" vulns "$@" 2>&1; }
_cron() { PATH="$T/bin:${WASP_TEST_TOOLS:+$WASP_TEST_TOOLS:}$PATH" ${WASP_TEST_SH:-sh} "$T/cron.sh" 2>&1; }
_reset() { rm -rf "$T/cache"/* "$T/cache"/.[a-z]* "$T/wf.json" "$T/api"/*; : > "$T/requests"; : > "$T/notify"; : > "$T/sleeps"; rm -f "$T/syslog" "$T/etc/vuln-sources.conf"; }
_conf() { printf '%s\n' "$@" > "$T/etc/vuln-sources.conf"; }
wf() { printf '%s' "$1" > "$T/wf.json"; }

WF_NOCVE='{"a":{"title":"RCE with no CVE yet","cve":null,"cvss":{"score":9.8},"software":[{"slug":"elementor","affected_versions":{"x":{"from_version":"*","from_inclusive":true,"to_version":"3.5.0","to_inclusive":true}}}]}}'
vuln() { printf '{"name":"%s","operator":{"min_operator":"%s","min_version":"%s","max_operator":"%s","max_version":"%s","unfixed":%s,"closed":0},"source":[{"id":"%s","name":"x"}],"impact":{"cvss":{"score":"%s","severity":"%s"}}}' "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9"; }
api() { printf '{"error":0,"message":null,"data":{"name":"x","closed":%s,"vulnerability":[%s]}}' "$2" "$3" > "$T/api/$1.json"; }

echo ""
echo "Vulnerability scan"
echo ""
echo "── A scan that cannot run says so"
_reset; _conf 'WPVULNERABILITY=0'
o=$(_scan); rc=$?
[ "$rc" = 3 ] && _p "no source at all exits 3, not 0" || _f "no source" "exit $rc"
_has "and says INCOMPLETE" "$o" "INCOMPLETE:"
_hasnt "and does not call the site clean" "$o" "No installed component matched"

_cron >/dev/null
grep -q 'did not complete' "$T/syslog" 2>/dev/null && _p "the daily job logs it" || _f "cron log" ""
grep -q 'incomplete' "$T/notify" && _p "the daily job emails it" || _f "cron notify" ""

_reset; _conf 'WORDFENCE_API_KEY=t' 'WPVULNERABILITY=0'
o=$(_scan); rc=$?
[ "$rc" = 3 ] && _p "a failed feed download with no cache is incomplete" || _f "failed feed" "exit $rc"

_reset; _conf 'WORDFENCE_API_KEY=t' 'WPVULNERABILITY=0'; wf '{}'; _scan >/dev/null
touch -d '5 days ago' "$T/cache/wordfence-scanner.json"; rm -f "$T/wf.json"
o=$(_scan); rc=$?
[ "$rc" = 3 ] && _p "a stale feed that cannot refresh is incomplete" || _f "stale" "exit $rc"

_reset; _conf 'WORDFENCE_API_KEY=t' 'WPVULNERABILITY=0'; printf 'not json' > "$T/cache/wordfence-scanner.json"
o=$(_scan); rc=$?
[ "$rc" = 3 ] && _p "an unreadable feed is incomplete" || _f "bad feed" "exit $rc: $o"

_reset; _conf 'WORDFENCE_API_KEY=t' 'WPVULNERABILITY=0'; wf '{}'
o=$(_scan); rc=$?
[ "$rc" = 0 ] && _p "a working source exits 0" || _f "clean" "exit $rc: $o"
_has "and says nothing matched" "$o" "No installed component matched"
_cron >/dev/null; [ -s "$T/notify" ] && _f "clean run" "emailed" || _p "a clean day stays silent"
grep -q 'result=complete' "$T/cache/.last-scan" && _p "the outcome is recorded for the validator" || _f "state" ""

echo ""
echo "── Sources are only what was queried"
_reset; _conf 'WORDFENCE_API_KEY=t' 'WPVULNERABILITY=0' 'PATCHSTACK_API_KEY=k' 'WPSCAN_API_TOKEN=k'; wf '{}'
o=$(_scan)
_hasnt "a stored Patchstack key does not claim coverage" "$o" "Patchstack"
_hasnt "a stored WPScan key does not claim coverage" "$o" "WPScan"
o=$(PATH="$T/bin:${WASP_TEST_TOOLS:+$WASP_TEST_TOOLS:}$PATH" ${WASP_TEST_SH:-sh} "$T/wp-plugins.sh" set-key patchstack k 2>&1); rc=$?
[ "$rc" = 1 ] && _p "set-key refuses a source that does nothing" || _f "set-key" "exit $rc"

echo ""
echo "── Wordfence severity"
_reset; _conf 'WORDFENCE_API_KEY=t' 'WPVULNERABILITY=0'; wf "$WF_NOCVE"
o=$(_scan)
_has "a 9.8 with no CVE is CRITICAL (empty fields hold their place)" "$o" "[CRITICAL] elementor 3.0.0"

echo ""
echo "── WPVulnerability, on by default"
_reset
o=$(_scan); rc=$?
grep -q wpvulnerability "$T/requests" && _p "on when nothing is configured" || _f "default" "not queried"
[ "$rc" = 0 ] && _p "so a VM with no Wordfence token is still scanned" || _f "no token" "exit $rc: $o"
_has "and Sources names it" "$o" "WPVulnerability"

_reset; _conf 'WORDFENCE_API_KEY=t'; wf '{}'
_scan >/dev/null
grep -q wpvulnerability "$T/requests" && _p "and alongside a Wordfence token" || _f "with token" "not queried"

_reset; PATH="$T/bin:${WASP_TEST_TOOLS:+$WASP_TEST_TOOLS:}$PATH" ${WASP_TEST_SH:-sh} "$T/wp-plugins.sh" vuln-source wpvulnerability off >/dev/null 2>&1
grep -qx 'WPVULNERABILITY=0' "$T/etc/vuln-sources.conf" && _p "off is written down" || _f "off" "not stored"
: > "$T/requests"; wf '{}'; _scan >/dev/null
grep -q wpvulnerability "$T/requests" && _f "off" "still queried" || _p "and off sends nothing"
PATH="$T/bin:${WASP_TEST_TOOLS:+$WASP_TEST_TOOLS:}$PATH" ${WASP_TEST_SH:-sh} "$T/wp-plugins.sh" vuln-source wpvulnerability on >/dev/null 2>&1
[ "$(grep -c '^WPVULNERABILITY=' "$T/etc/vuln-sources.conf")" = 1 ] && _p "switching does not stack lines" || _f "stack" ""

_reset; _conf 'WPVULNERABILITY=1'
api plugin-elementor 0 "$(vuln 'Stored XSS' ge 1.0.0 lt 3.5.0 0 CVE-2026-1111 7.5 h)"
api plugin-contact-form 0 "$(vuln 'Past bug' '>=' 1.0 '<=' 2.4 0 CVE-2026-2222 9.8 c)"
api theme-astra 1 "$(vuln 'No fix' '' '' le 4.0.0 1 CVE-2026-3333 6.1 m)"
api core-7.1.4 0 ""; api php-8.4.27 0 "$(vuln 'PHP bug' ge 8.4.0 lt 8.4.99 0 CVE-2026-4444 9.1 c)"; api mariadb-11.4.8 0 ""
o=$(_scan); rc=$?
_has   "a version inside the range matches"            "$o" "[HIGH] elementor 3.0.0"
_hasnt "a version past the range does not"             "$o" "contact-form 2.5"
_has   "an unfixed issue says no fix exists"           "$o" "NO FIX PUBLISHED"
_has   "a closed plugin is noticed"                    "$o" "[NOTICE] astra"
_has   "PHP is checked"                                "$o" "[CRITICAL] PHP 8.4.27"
grep -q 'core/7.1.4/' "$T/requests" && _p "core is checked" || _f "core" ""
grep -q 'mariadb/11.4.8/' "$T/requests" && _p "MariaDB is checked" || _f "mariadb" ""
_has   "a bespoke plugin with no record is not a failure" "$o" "no WPVulnerability record"
_hasnt "and does not make the scan incomplete"         "$o" "INCOMPLETE:"
[ "$rc" = 0 ] && _p "this source alone is a complete scan" || _f "wpv alone" "exit $rc: $o"

: > "$T/requests"; _scan >/dev/null
grep -q 'plugin/elementor' "$T/requests" && _f "cache" "re-queried inside 12 hours" || _p "answers are cached, one request a day per component"

_reset; _conf 'WPVULNERABILITY=1' 'WPV_SKIP="my-bespoke"'
_scan >/dev/null
grep -q 'my-bespoke' "$T/requests" && _f "WPV_SKIP" "slug left the VM" || _p "WPV_SKIP keeps a slug on the VM"

_reset; _conf 'WPVULNERABILITY=1'; printf 500 > "$T/api/plugin-elementor.code"
o=$(_scan); rc=$?
{ [ "$rc" = 3 ] && case "$o" in *'did not answer for 1 component'*) true ;; *) false ;; esac; } \
  && _p "a server error is incomplete, not clean" || _f "500" "exit $rc: $o"

_reset; _conf 'WPVULNERABILITY=1'; printf 'nonsense' > "$T/api/plugin-elementor.json"
o=$(_scan); [ $? = 3 ] && _p "a non-JSON reply is incomplete" || _f "bad json" "$o"

_reset; _conf 'WPVULNERABILITY=1'; printf '{"error":0,"data":{"vulnerability":"surprise"}}' > "$T/api/plugin-elementor.json"
o=$(_scan); [ $? = 3 ] && _p "an unexpected response shape is incomplete" || _f "shape" "$o"

_reset; _conf 'WPVULNERABILITY=1'; printf 429 > "$T/api/plugin-elementor.code"
o=$(_scan); rc=$?
[ "$(grep -c 'plugin/elementor' "$T/requests")" = 3 ] && _p "a 429 is retried, three tries in all" || _f "429 tries" "$(cat "$T/requests")"
[ "$(grep -c wpvulnerability "$T/requests")" = 3 ] && _p "and a 429 that survives them stops further requests" || _f "429 stop" "$(cat "$T/requests")"
[ "$rc" = 3 ] && _p "which is reported INCOMPLETE, not clean" || _f "429 rc" "exit $rc"
[ "$(tr '\n' ' ' < "$T/sleeps")" = "5 15 " ] && _p "backing off 5s, then 15s" || _f "backoff" "$(cat "$T/sleeps")"

# The field-test fault: one refusal on an unattended run made the whole scan
# INCOMPLETE. A momentary limit now clears on retry.
_reset; _conf 'WPVULNERABILITY=1'
api plugin-elementor 0 "$(vuln 'After a retry' ge 1.0.0 lt 3.5.0 0 CVE-2026-7777 8.1 h)"
printf '429\n200\n' > "$T/api/plugin-elementor.seq"
printf 'HTTP/2 429\r\nretry-after: 7\r\n\r\n' > "$T/api/plugin-elementor.hdr"
o=$(_scan); rc=$?
_has "a 429 then a 200 is an answer" "$o" "CVE-2026-7777"
[ "$rc" = 0 ] && _p "and the scan is complete" || _f "retry rc" "exit $rc: $o"
[ "$(head -1 "$T/sleeps")" = 7 ] && _p "a lower-case retry-after header is honoured" || _f "retry-after" "$(cat "$T/sleeps")"
grep -q 'plugin/contact-form' "$T/requests" && _p "and later components are still asked" || _f "after retry" "$(cat "$T/requests")"

_reset; _conf 'WPVULNERABILITY=1'
api plugin-elementor 0 ""
printf '503\n200\n' > "$T/api/plugin-elementor.seq"
o=$(_scan); [ $? = 0 ] && _p "a 503 then a 200 is an answer too" || _f "503 retry" "$o"
_reset; _conf 'WPVULNERABILITY=1'
printf '429\n' > "$T/api/plugin-elementor.seq"
printf 'HTTP/2 429\r\nretry-after: 3600\r\n\r\n' > "$T/api/plugin-elementor.hdr"
_scan >/dev/null
[ "$(head -1 "$T/sleeps")" = 60 ] && _p "a Retry-After of an hour is capped at 60s" || _f "cap" "$(cat "$T/sleeps")"

echo ""
echo "── Version ranges, as the provider's client reads them"
_reset; _conf 'WPVULNERABILITY=1'
api plugin-elementor 0 "$(vuln 'No range given' '' '' '' '' 0 CVE-2026-8001 9.0 c)"
api plugin-contact-form 0 "$(vuln 'Only a minimum' ge 2.0 '' '' 0 CVE-2026-8002 7.0 h)"
api core-7.1.4 0 "$(vuln 'Core, per version' '' '' '' '' 0 CVE-2026-8003 7.2 h)"
api php-8.4.27 0 "$(vuln 'PHP, no range' '' '' '' '' 0 CVE-2026-8004 9.0 c)"
o=$(_scan)
_hasnt "a plugin entry with no range does not apply (not every version)" "$o" "CVE-2026-8001"
_has   "a minimum alone is honoured"                                    "$o" "CVE-2026-8002"
_has   "every entry on core's per-version endpoint applies"             "$o" "CVE-2026-8003"
_hasnt "a PHP entry with no range does not apply"                       "$o" "CVE-2026-8004"

_reset; _conf 'WORDFENCE_API_KEY=t' 'WPVULNERABILITY=1'
wf '{"a":{"title":"Same bug","cve":"CVE-2026-1111","cvss":{"score":7.5},"software":[{"slug":"elementor","affected_versions":{"x":{"from_version":"*","from_inclusive":true,"to_version":"3.5.0","to_inclusive":true}}}]}}'
api plugin-elementor 0 "$(vuln 'Same bug' '' '' lt 3.5.0 0 CVE-2026-1111 7.5 h)"
o=$(_scan)
[ "$(printf '%s' "$o" | grep -c 'CVE-2026-1111')" = 1 ] && _p "one CVE from both sources prints once" || _f "dedupe" "$o"

echo ""
echo "── Staged inventory"
_reset; _conf 'WPVULNERABILITY=1'
api plugin-elementor 0 "$(vuln 'Staged bug' '' '' lt 3.5.0 0 CVE-2026-5555 8.8 h)"
printf 'plugin,elementor,3.0.0\nplugin,../../etc,1\nplugin,bad;slug,1\n' > "$T/inv.csv"
o=$(_scan --inventory "$T/inv.csv")
_has "a staged plugin is matched" "$o" "[HIGH] elementor 3.0.0"
grep -qE '\.\./|bad;' "$T/requests" && _f "hostile slug" "reached a URL" || _p "a hostile slug never reaches a URL"
grep -q 'core/' "$T/requests" && _f "staged core" "live versions queried" || _p "staged scans do not query the live site's versions"
[ -f "$T/cache/.last-scan" ] && _f "state" "staged scan recorded as the daily scan" || _p "a staged scan is not recorded as the daily scan"

echo ""
echo "── The weekly report is sent whatever it says"
_dig() { VULN_STATE="$T/cache/.last-scan" MALWARE_STATE="$T/mal" \
         PATH="$T/bin:${WASP_TEST_TOOLS:+$WASP_TEST_TOOLS:}$PATH" ${WASP_TEST_SH:-sh} "$T/cron.sh" --digest "$@" 2>&1; }
mkdir -p "$T/mal"
_reset; _conf 'WPVULNERABILITY=1'
api core-7.1.4 0 ""; api php-8.4.27 0 ""; api mariadb-11.4.8 0 ""
date -u +%Y-%m-%dT%H:%M:%SZ > "$T/mal/last-scan-time"; : > "$T/mal/last-scan.tsv"
_scan >/dev/null; : > "$T/notify"
o=$(_dig)
head -1 "$T/notify" | grep -q '^Weekly security report: all scans ran, nothing found$' \
  && _p "a clean week is still reported, and says so" || _f "clean digest" "$(head -3 "$T/notify")"
grep -q 'WPVulnerability' "$T/notify" && grep -q 'Last run : .*complete' "$T/notify" \
  && _p "it names the sources and when the daily scan last completed" || _f "digest body" "$(cat "$T/notify")"
grep -q 'MALWARE AND INTEGRITY' "$T/notify" && grep -q '0 critical, 0 high' "$T/notify" \
  && _p "and the malware scan's last result" || _f "malware section" "$(cat "$T/notify")"
: > "$T/notify"; _dig --print >/dev/null
[ ! -s "$T/notify" ] && _p "--print sends nothing" || _f "--print" "sent"

printf 'at=%s\nresult=complete\nreason=\n' "$(( $(date +%s) - 72*3600 ))" > "$T/cache/.last-scan"
: > "$T/notify"; _dig >/dev/null
head -1 "$T/notify" | grep -q 'ATTENTION.*vulnerability scan has not run for 7[0-9]h' \
  && _p "a daily scan that stopped running is called out in the subject" || _f "stale" "$(head -1 "$T/notify")"

_reset; _conf 'WPVULNERABILITY=1'
api plugin-elementor 0 "$(vuln 'Weekly bug' ge 1.0.0 lt 3.5.0 0 CVE-2026-9001 9.8 c)"
api core-7.1.4 0 ""; api php-8.4.27 0 ""; api mariadb-11.4.8 0 ""
printf 'CRITICAL\tObfuscated PHP: /x/y.php\tdetail\n' > "$T/mal/last-scan.tsv"
_scan >/dev/null; : > "$T/notify"
_dig >/dev/null
grep -q 'CVE-2026-9001' "$T/notify" && _p "findings are listed in the report" || _f "findings" "$(cat "$T/notify")"
head -1 "$T/notify" | grep -q 'ATTENTION.*1 CRITICAL malware finding' && _p "a CRITICAL malware finding puts it in the subject" || _f "malware subject" "$(head -1 "$T/notify")"
grep -q 'Obfuscated PHP: /x/y.php' "$T/notify" && _p "and the finding is in the body" || _f "malware body" ""
rm -f "$T/cache/.last-scan"; : > "$T/notify"; _dig >/dev/null
head -1 "$T/notify" | grep -q 'no daily vulnerability scan has been recorded' \
  && _p "the report's own scan does not stand in for a daily run that never happened" || _f "own scan" "$(head -1 "$T/notify")"
rm -rf "$T/mal"; : > "$T/notify"; _dig >/dev/null
head -1 "$T/notify" | grep -q 'no malware scan has been recorded' && _p "no malware scan ever recorded is called out" || _f "no malware" "$(head -1 "$T/notify")"

grep -q '^15 7 \* \* 1 /usr/local/bin/wp-vuln-cron.sh --digest' "$REPO/payload/cron/wordpress-vm.cron" \
  && _p "the report is scheduled weekly (Monday 07:15 UTC)" || _f "digest cron" ""
grep -q '^30 6 \* \* \* /usr/local/bin/wp-vuln-cron.sh$' "$REPO/payload/cron/wordpress-vm.cron" \
  && _p "the vulnerability scan is scheduled daily (06:30 UTC)" || _f "daily cron" ""
grep -q '^30 3 \* \* \* /usr/local/bin/wp-malware-scan.sh quick' "$REPO/payload/cron/wordpress-vm.cron" \
  && grep -q '^45 3 \* \* 0 /usr/local/bin/wp-malware-scan.sh yara' "$REPO/payload/cron/wordpress-vm.cron" \
  && _p "the malware scans are scheduled daily and weekly" || _f "malware cron" ""

echo ""
printf '  passed %d   failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
