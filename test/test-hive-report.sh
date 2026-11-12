#!/usr/bin/env bash
# =============================================================================
# test-hive-report.sh — does a WASP VM's report reach a WASP Hive, and only
# that Hive?
# =============================================================================
#
# Runs the real wasp-hive-report.sh against a real hive_server.py on
# localhost, with a freshly generated key, enrolled with the line the real
# hive-admin prints. podman, rc-service and logger are stubbed; curl, jq,
# openssl and python3 are real. Checks:
#
#   - the report is built from what the scheduled jobs recorded (vulnerability
#     report, malware state, integrity, CrowdSec, backups, egress, controls)
#   - enrollment delivers the first report, and the Hive stores it
#   - a different key on the Hive (re-keyed, or someone in the middle) means
#     the report is WITHHELD, and that is logged as a pin mismatch
#   - a rotated token is refused; a report cannot name another node
#   - the token never appears on a command line
# =============================================================================
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
T=$(mktemp -d); SRV=""
trap '[ -n "$SRV" ] && kill "$SRV" 2>/dev/null; rm -rf "$T"' EXIT
PASS=0; FAIL=0
_p() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
_f() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n         %s\n' "$1" "${2:-}"; }

for _c in python3 openssl curl jq; do
  command -v "$_c" >/dev/null 2>&1 || { echo "  $_c is required for this test"; exit 1; }
done
[ "$(id -u)" = 0 ] || { echo "  run as root (the reporter refuses otherwise)"; exit 1; }

echo ""
echo "WASP Hive reporting"

# ── A VM's recorded state ────────────────────────────────────────────────────
mkdir -p "$T/etc" "$T/bin" "$T/stub" "$T/state" "$T/vulns" "$T/malware" "$T/backups" "$T/hive/data"
NOW=$(date +%s)
cat > "$T/etc/vars.sh" <<'EOF'
WASP_RELEASE='10.12'
WP_DOMAIN='www.example.com'
MFA_ENFORCE='1'
EGRESS_PROXY='1'
RESTRICT_EGRESS='1'
DEPLOYMENT_PROFILE='production'
WP_ADMIN_SLUG='door-7c2e'
ADMIN_CIDR='192.0.2.0/24'
EOF
printf 'enforcement=local\n' > "$T/etc/crowdsec-topology"
printf 'WORDFENCE_API_KEY=not-a-real-key\n' > "$T/etc/vuln-sources.conf"
echo "$((NOW - 7200))" > "$T/etc/offsite-last-ok"
: > "$T/etc/offsite.conf"
printf 'host = smtp.example.com\n' > "$T/smtp.ini"
printf 'at=%s\nresult=complete\n' "$((NOW - 3600))" > "$T/vulns/.last-scan"
printf 'at=%s\nresult=fail\nmodified=2\n' "$((NOW - 86400))" > "$T/vulns/.last-verify"
cat > "$T/vulns/last-report.txt" <<'EOF'
WordPress vulnerability scan
  Sources: Wordfence + WPVulnerability
  [HIGH] contact-form-x 5.2.1
        Unauthenticated stored XSS
        CVE-2026-10001   cvss 7.2
        fix: 5.2.2
  [MEDIUM] gallery-lite 2.0.4
        Missing authorization on settings export
        fix: 2.0.5
EOF
date -u -d "@$((NOW - 1800))" +%Y-%m-%dT%H:%M:%SZ > "$T/malware/last-scan-time"
printf 'CRITICAL\tobfuscated-php\twp-content/uploads/x.php\nSUSPICIOUS\tunusual-mu\tloader.php\n' > "$T/malware/last-scan.tsv"
: > "$T/backups/wp-db-2026.sql.gz"
printf '%s fileshare .dropbox.com ops share\n' "$((NOW + 1800))" > "$T/ledger"

printf '#!/bin/sh\necho "OK wordpress up, db up"\nexit 0\n' > "$T/bin/validate-wordpress.sh"
printf '#!/bin/sh\necho "all files match"\nexit 0\n' > "$T/bin/wasp-verify-integrity.sh"
cat > "$T/stub/podman" <<'EOF'
#!/bin/sh
case "$*" in
  *wp_version*)            echo 6.8.3 ;;
  *PHP_VERSION*)           echo 8.3.27 ;;
  *"mariadb --version"*)   echo "mariadb from 11.4.8-MariaDB, client 15.2" ;;
  *"lapi status"*)         exit 0 ;;
  *"decisions list"*)      echo '[{"id":1},{"id":2}]' ;;
  *"alerts list"*)         echo '[{"scenario":"crowdsecurity/http-probing"},{"scenario":"crowdsecurity/http-probing"},{"scenario":"crowdsecurity/http-bad-user-agent"}]' ;;
  *) exit 1 ;;
esac
EOF
printf '#!/bin/sh\nexit 0\n' > "$T/stub/rc-service"
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "%s/log"\n' "$T" > "$T/stub/logger"
printf '#!/bin/sh\necho wp-test-hive\n' > "$T/stub/hostname"
# Records every curl command line, then runs the real curl.
_realcurl=$(command -v curl)
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "%s/curl-argv"\nexec %s "$@"\n' "$T" "$_realcurl" > "$T/stub/curl"
chmod +x "$T/bin/"* "$T/stub/"*

_rep() {
  env WASP_ETC="$T/etc" WASP_BIN="$T/bin" HIVE_STATE="$T/state" \
      VULN_REPORT="$T/vulns/last-report.txt" VULN_STATE="$T/vulns/.last-scan" VERIFY_STATE="$T/vulns/.last-verify" \
      MALWARE_STATE="$T/malware" EGRESS_LEDGER="$T/ledger" BACKUP_DIR="$T/backups" SMTP_INI="$T/smtp.ini" \
      PATH="$T/stub:${WASP_TEST_TOOLS:+$WASP_TEST_TOOLS:}$PATH" \
      ${WASP_TEST_SH:-sh} "$REPO/payload/bin/wasp-hive-report.sh" "$@" 2>&1
}

# ── The report ───────────────────────────────────────────────────────────────
J=$(_rep show)
if ! printf '%s' "$J" | jq -e . >/dev/null 2>&1; then
  _f "show prints valid JSON" "$(printf '%s' "$J" | head -5)"
else
  _p "show prints valid JSON"
  _q() { printf '%s' "$J" | jq -r "$1"; }
  [ "$(_q '.schema') $(_q '.wasp_release') $(_q '.domain')" = "1 10.12 www.example.com" ] \
    && _p "release and domain come from vars.sh" || _f "identity" "$(_q '[.schema,.wasp_release,.domain]|@csv')"
  [ "$(_q '.health.check_rc') $(_q '.health.check')" = "0 OK wordpress up, db up" ] \
    && _p "health is validate-wordpress.sh --check's line and exit code" || _f "health" "$(_q .health)"
  [ "$(_q '.versions.wordpress') $(_q '.versions.php') $(_q '.versions.mariadb')" = "6.8.3 8.3.27 11.4.8" ] \
    && _p "WordPress, PHP and MariaDB versions" || _f "versions" "$(_q .versions)"
  [ "$(_q '.vulns.findings | length') $(_q '.vulns.findings[0].severity') $(_q '.vulns.findings[0].cve') $(_q '.vulns.findings[1].cve')" = "2 HIGH CVE-2026-10001 " ] \
    && _p "vulnerabilities parsed from the daily scan's report (with and without a CVE)" || _f "vulns" "$(_q .vulns.findings)"
  [ "$(_q '.vulns.result') $(_q '.vulns.sources')" = "complete Wordfence + WPVulnerability" ] \
    && _p "scan result and sources" || _f "vuln meta" "$(_q .vulns)"
  [ "$(_q '[.malware.findings[].severity] | join(",")')" = "CRITICAL,SUSPICIOUS" ] && [ "$(_q '.malware.at')" -gt $((NOW - 1900)) ] \
    && _p "malware findings and scan time" || _f "malware" "$(_q .malware)"
  [ "$(_q '.integrity.tooling') $(_q '.integrity.checksums') $(_q '.integrity.checksums_modified')" = "pass fail 2" ] \
    && _p "tooling integrity and the last checksum verification" || _f "integrity" "$(_q .integrity)"
  [ "$(_q '.crowdsec.lapi_ok') $(_q '.crowdsec.decisions') $(_q '.crowdsec.alerts_24h') $(_q '.crowdsec.top_scenarios[0].count') $(_q '.crowdsec.bouncer')" = "true 2 3 2 active" ] \
    && _p "CrowdSec: LAPI, bans, alerts and top scenario" || _f "crowdsec" "$(_q .crowdsec)"
  [ "$(_q '.backups.offsite_configured') $(_q '.backups.local_at > 0') $(_q '.backups.offsite_at')" = "true true $((NOW - 7200))" ] \
    && _p "backup markers" || _f "backups" "$(_q .backups)"
  [ "$(_q '.egress.temporary[0].domain') $(_q '.egress.temporary[0].tag')" = ".dropbox.com fileshare" ] \
    && _p "temporary egress from the ledger" || _f "egress" "$(_q .egress)"
  [ "$(_q '[.controls.mfa_enforce,.controls.login_slug,.controls.admin_ip_restricted,.controls.wordfence_feed,.controls.smtp_alerts,.controls.release_signature] | @csv')" = 'true,true,true,true,true,"verified"' ] \
    && _p "controls switched on are reported as on" || _f "controls" "$(_q .controls)"
  # Every field the compliance map reads must exist in what this script sends;
  # one that does not is a control stuck at "unknown" on every VM.
  _missing=""
  for _fld in $(jq -r '.checks[] | (.field // empty), (.checks[]?.field)' "$REPO/hive/compliance.json" | grep -v '^_hive\.' | sort -u); do
    printf '%s' "$J" | jq -e --arg f "$_fld" 'getpath($f | split(".")) != null' >/dev/null || _missing="$_missing $_fld"
  done
  [ -z "$_missing" ] && _p "every field the compliance map reads is in the report" || _f "fields not reported" "$_missing"
fi

# A degraded VM: validate's exit code, not the last command's, is reported.
printf '#!/bin/sh\necho "WARN wp-cron overdue"\necho "second line"\nexit 1\n' > "$T/bin/validate-wordpress.sh"
printf '#!/bin/sh\necho "MODIFIED since install: /usr/local/bin/x"\nexit 1\n' > "$T/bin/wasp-verify-integrity.sh"
_J2=$(_rep show)
[ "$(printf '%s' "$_J2" | jq -r '"\(.health.check_rc) \(.health.check) \(.integrity.tooling) \(.integrity.tooling_modified)"')" = "1 WARN wp-cron overdue fail 1" ] \
  && _p "a WARN health line and modified tooling are reported as such" \
  || _f "degraded state" "$(printf '%s' "$_J2" | jq -c '[.health, .integrity]')"
printf '#!/bin/sh\necho "OK wordpress up, db up"\nexit 0\n' > "$T/bin/validate-wordpress.sh"
printf '#!/bin/sh\necho "all files match"\nexit 0\n' > "$T/bin/wasp-verify-integrity.sh"

# ── A real Hive ──────────────────────────────────────────────────────────────
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -keyout "$T/hive/key" -out "$T/hive/crt" \
  -subj /CN=hive.test >/dev/null 2>&1
cat > "$T/hive/conf" <<EOF
LISTEN_ADDR=127.0.0.1
LISTEN_PORT=$PORT
DATA_DIR=$T/hive/data
CERT=$T/hive/crt
KEY=$T/hive/key
EOF
python3 "$REPO/hive/hive_server.py" --config "$T/hive/conf" 2>"$T/hive/log" &
SRV=$!
for _i in 1 2 3 4 5 6 7 8 9 10; do
  curl -sk "https://127.0.0.1:$PORT/api/v1/ping" 2>/dev/null | grep -q wasp-hive && break; sleep 0.3
done
_admin() { HIVE_CONF="$T/hive/conf" HIVE_PUBLIC_URL="https://127.0.0.1:$PORT" python3 "$REPO/hive/hive_admin.py" "$@"; }
LINE=$(_admin enroll wp-test-hive --client "Example Client" | grep 'wasp-hive-report.sh enroll')
set -- $LINE; shift 2      # drop "doas wasp-hive-report.sh"
[ "$1" = enroll ] && [ "$#" = 5 ] && _p "hive-admin enroll prints the line to run on the VM" || _f "enroll line" "$LINE"
TOKEN=$4; PIN=$5

_o=$(_rep "$@"); _rc=$?
_db() { python3 -c "import sqlite3,sys; c=sqlite3.connect('$T/hive/data/hive.db'); print(c.execute(sys.argv[1]).fetchone()[0])" "$1"; }
[ "$_rc" = 0 ] && [ "$(_db "SELECT COUNT(*) FROM reports WHERE node='wp-test-hive'")" = 1 ] \
  && _p "enrollment delivers the first report, and the Hive stores it" || _f "enroll" "rc=$_rc $_o $(tail -3 "$T/hive/log")"
[ "$(stat -c %a "$T/etc/hive.token")" = 600 ] && _p "the token is stored 0600" || _f "token mode" "$(stat -c %a "$T/etc/hive.token")"
if grep -qF "$TOKEN" "$T/curl-argv" 2>/dev/null; then _f "the token appeared on curl's command line" "$(head -1 "$T/curl-argv")"
else _p "the token never appears on a command line (ps would show it)"; fi
[ ! -e "$T/state/auth.hdr" ] && _p "the header file holding the token is removed after use" || _f "auth.hdr left behind" ""

_o=$(_rep send); _rc=$?
[ "$_rc" = 0 ] && [ "$(_db "SELECT COUNT(*) FROM reports")" = 2 ] && _p "send (the cron job) delivers again" || _f "send" "rc=$_rc"

# The Hive's key changes: a re-keyed Hive, or a machine in the middle.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -keyout "$T/hive/key" -out "$T/hive/crt" \
  -subj /CN=hive.test >/dev/null 2>&1
kill "$SRV"; wait "$SRV" 2>/dev/null
python3 "$REPO/hive/hive_server.py" --config "$T/hive/conf" 2>>"$T/hive/log" & SRV=$!
for _i in 1 2 3 4 5 6 7 8 9 10; do
  curl -sk "https://127.0.0.1:$PORT/api/v1/ping" 2>/dev/null | grep -q wasp-hive && break; sleep 0.3
done
: > "$T/log"
_o=$(_rep send); _rc=$?
{ [ "$_rc" != 0 ] && [ "$(_db "SELECT COUNT(*) FROM reports")" = 2 ]; } \
  && _p "a Hive with a different key gets nothing (report withheld)" || _f "pin not enforced" "rc=$_rc"
grep -q 'does NOT match the pinned key' "$T/log" && _p "and that is logged as a pin mismatch, not a network error" \
  || _f "pin mismatch not named" "$(cat "$T/log")"
NEWPIN=$(_admin pin | sed 's#.*sha256//##')
sed -i "s#^pin=.*#pin=$NEWPIN#" "$T/etc/hive.conf"

# A rotated token: the old one stops working.
_admin rotate wp-test-hive >/dev/null
: > "$T/log"
_o=$(_rep send); _rc=$?
{ [ "$_rc" != 0 ] && grep -q 'HTTP 401' "$T/log"; } && _p "after hive-admin rotate, the old token is refused" || _f "rotate" "rc=$_rc $(cat "$T/log")"

# A VM cannot write another VM's report, or assert the Hive's own facts.
LINE=$(_admin rotate wp-test-hive | grep 'wasp-hive-report.sh enroll'); set -- $LINE; TOKEN=$6
_admin enroll wp-other >/dev/null
printf '%s' "$J" | jq '.node="wp-other" | ._hive={wazuh_active:true}' > "$T/forged.json"
printf 'Authorization: Bearer %s\nX-Hive-Node: wp-other\n' "$TOKEN" > "$T/h"
_c=$(curl -sk -o /dev/null -w '%{http_code}' -H @"$T/h" -H 'Content-Type: application/json' --data-binary @"$T/forged.json" "https://127.0.0.1:$PORT/api/v1/report")
[ "$_c" = 401 ] && _p "one node's token cannot report as another node" || _f "cross-node" "HTTP $_c"
printf 'Authorization: Bearer %s\nX-Hive-Node: wp-test-hive\n' "$TOKEN" > "$T/h"
_c=$(curl -sk -o /dev/null -w '%{http_code}' -H @"$T/h" -H 'Content-Type: application/json' --data-binary @"$T/forged.json" "https://127.0.0.1:$PORT/api/v1/report")
_stored=$(python3 -c "import sqlite3,json; c=sqlite3.connect('$T/hive/data/hive.db'); b=json.loads(c.execute(\"SELECT body FROM reports ORDER BY rowid DESC LIMIT 1\").fetchone()[0]); print(b['node'], '_hive' in b)")
[ "$_c" = 204 ] && [ "$_stored" = "wp-test-hive False" ] \
  && _p "the token, not the body, decides the node; a VM cannot claim Hive-side evidence" || _f "body trusted" "HTTP $_c $_stored"

# ── The path to the Hive: wasp-egress.sh hive ───────────────────────────────
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "%s/fw.log"\n' "$T" > "$T/stub/fwrule"
printf '#!/bin/sh\n[ "$2" = hive.test ] && echo "127.0.0.1       hive.test"\n' > "$T/stub/getent"
chmod +x "$T/stub/fwrule" "$T/stub/getent"
_eg() { env WASP_TEST_LOOPBACK_HIVE="${WASP_TEST_LOOPBACK_HIVE:-0}" RESTRICT_EGRESS="${RE:-1}" HIVE_EGRESS="$T/etc/hive-egress" HIVE_CONF_FILE="$T/etc/hive.conf" FW_RULE="$T/stub/fwrule" \
        PATH="$T/stub:${WASP_TEST_TOOLS:+$WASP_TEST_TOOLS:}$PATH" ${WASP_TEST_SH:-sh} "$REPO/payload/bin/wasp-egress.sh" hive "$@" 2>&1; }
: > "$T/fw.log"
_o=$(_eg set "https://192.0.2.5:8443")
grep -qx 'add hive output ip daddr 192.0.2.5 tcp dport 8443 accept' "$T/fw.log" \
  && _p "egress: a Hive on 8443 under restricted egress gets one rule, to that address and port" || _f "hive rule" "$(cat "$T/fw.log") $_o"
: > "$T/fw.log"; _o=$(_eg set 192.0.2.5)
{ grep -qx 'del hive' "$T/fw.log" && ! grep -q '^add' "$T/fw.log"; } \
  && _p "egress: a Hive on 443 needs no rule (and any old one is removed)" || _f "443" "$(cat "$T/fw.log")"
: > "$T/fw.log"; _o=$(RE=0 _eg set 192.0.2.5:8443)
! grep -q '^add' "$T/fw.log" && _p "egress: with outbound unrestricted, nothing is opened" || _f "unrestricted" "$(cat "$T/fw.log")"
_o=$(_eg set 10.89.10.3); _rc=$?
[ "$_rc" != 0 ] && _p "egress: a container address is refused as a Hive" || _f "container address" "$_o"
# The name is resolved once and pinned; the report then goes to that address
# even though "hive.test" resolves nowhere else.
: > "$T/fw.log"
_o=$(WASP_TEST_LOOPBACK_HIVE=1 _eg set "https://hive.test:$PORT")
grep -q '^ip=127.0.0.1$' "$T/etc/hive-egress" && _p "egress: a name is resolved once and the address recorded" || _f "resolve" "$(cat "$T/etc/hive-egress") $_o"
printf '%s' "$_o" | grep -q 'WASP Hive answers' && _p "egress: hive test reaches the Hive" || _f "hive test" "$_o"
printf '%s' "$_o" | grep -q "matches the pin this VM enrolled with" && _p "egress: the key the Hive presents is compared with the enrolled pin" \
  || _f "pin compare" "$(printf '%s' "$_o" | tail -3)"
sed -i "s#^url=.*#url=https://hive.test:$PORT#" "$T/etc/hive.conf"
printf '%s\n' "$TOKEN" > "$T/etc/hive.token"
: > "$T/curl-argv"
_o=$(_rep send); _rc=$?
{ [ "$_rc" = 0 ] && grep -q -- "--resolve hive.test:$PORT:127.0.0.1" "$T/curl-argv" && grep -q -- "--noproxy" "$T/curl-argv"; } \
  && _p "the report goes to the recorded address (--resolve), never through a proxy" || _f "--resolve" "rc=$_rc $(tail -1 "$T/curl-argv")"

_o=$(_rep leave)
[ ! -e "$T/etc/hive.conf" ] && [ ! -e "$T/etc/hive.token" ] && _p "leave forgets the Hive and the token" || _f "leave" "$_o"

echo ""
printf '  passed %d   failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
