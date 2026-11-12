#!/bin/sh
# =============================================================================
# wasp-hive-report.sh — report this VM's state to a WASP Hive
# =============================================================================
#   wasp-hive-report.sh enroll <https://hive-host> <node-name> <token> <pin>
#                        the line `hive-admin enroll` prints, pasted here
#   wasp-hive-report.sh send          collect and push (cron, every 15 minutes)
#   wasp-hive-report.sh show          print the report, send nothing
#   wasp-hive-report.sh status        where it reports, and when it last did
#   wasp-hive-report.sh leave         stop reporting and forget the Hive
#
# PUSH, NOT PULL. The Hive never logs in to this VM and holds nothing that
# could. This VM holds one token that can do one thing: replace this VM's own
# row on the Hive. A Hive that is broken into can be made to show wrong
# numbers; it cannot be used to reach, change or read anything on the fleet.
# That is the line docs/FLEET.md draws -- "monitor with tools that observe,
# not tools that control" -- and it is why nothing here accepts a command.
#
# PINNED, NOT TRUSTED. The Hive uses its own self-signed certificate. The
# public key's hash is pinned at enrollment (curl --pinnedpubkey), so a
# machine-in-the-middle on the VLAN cannot read the report or the token, and
# no certificate authority is involved at all.
#
# CHEAP. Nothing here runs a scan. It reads what the scheduled jobs already
# recorded -- the daily vulnerability report, the last malware scan, the
# integrity check, backup markers -- so a report every 15 minutes costs a few
# file reads and three podman execs.
# =============================================================================
set -u

if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then exec doas "$0" "$@"; fi
  echo "Run as root (or via doas)" >&2; exit 1
fi
# Every path can be overridden from the environment, for test/test-hive-report.sh.
ETC=${WASP_ETC:-/etc/wp-install}
BIN=${WASP_BIN:-/usr/local/bin}
[ -r "$ETC/vars.sh" ] && . "$ETC/vars.sh"

CONF=$ETC/hive.conf                     # url, node, pin (not secret)
TOKEN_FILE=$ETC/hive.token              # 0600: the one secret
STATE=${HIVE_STATE:-/var/lib/wasp-hive}
VULN_REPORT=${VULN_REPORT:-/var/cache/wp-vulns/last-report.txt}
VULN_STATE=${VULN_STATE:-/var/cache/wp-vulns/.last-scan}
VERIFY_STATE=${VERIFY_STATE:-/var/cache/wp-vulns/.last-verify}
MALWARE=${MALWARE_STATE:-/var/lib/wp-malware-scan}
LEDGER=${EGRESS_LEDGER:-/opt/squid/config/.temporary}
BACKUP_DIR=${BACKUP_DIR:-/root/wp-db-backups}
SMTP_INI=${SMTP_INI:-/home/wpuser/wp/secrets/smtp.ini}
HIVE_EGRESS=${HIVE_EGRESS:-$ETC/hive-egress}
APPSEC_STATE=${APPSEC_STATE:-/var/lib/wasp-appsec}
APPSEC_INI=${APPSEC_INI:-/home/wpuser/wp/secrets/appsec.ini}

_ok()  { printf '  \033[32m✔\033[0m  %s\n' "$1"; }
_bad() { printf '  \033[31m✗\033[0m  %s\n' "$1"; }
_note(){ printf '     %s\n' "$1"; }

# Parsed, never sourced: three keys, assigned by case.
_load_conf() {
  HIVE_URL=""; HIVE_NODE=""; HIVE_PIN=""
  [ -r "$CONF" ] || return 1
  while IFS= read -r _l || [ -n "$_l" ]; do
    case "$_l" in
      url=*)  HIVE_URL=${_l#url=} ;;
      node=*) HIVE_NODE=${_l#node=} ;;
      pin=*)  HIVE_PIN=${_l#pin=} ;;
    esac
  done < "$CONF"
  [ -n "$HIVE_URL" ] && [ -n "$HIVE_NODE" ] && [ -n "$HIVE_PIN" ]
}

_epoch_of() { [ -e "$1" ] && stat -c %Y "$1" 2>/dev/null || echo 0; }
_num() { case "$1" in ''|*[!0-9]*) echo 0 ;; *) echo "$1" ;; esac; }

# ── Collect ──────────────────────────────────────────────────────────────────
collect() {
  command -v jq >/dev/null 2>&1 || { echo "jq is required: apk add jq" >&2; return 1; }
  _now=$(date +%s)

  # Health: the one line validate-wordpress.sh already exists to produce.
  if [ -x "$BIN/validate-wordpress.sh" ]; then
    _hrc=0; _hl=$("$BIN/validate-wordpress.sh" --check 2>/dev/null) || _hrc=$?
    _hl=$(printf '%s\n' "$_hl" | head -1)
  else
    _hl="validate-wordpress.sh missing"; _hrc=2
  fi
  _disk=$(df -P / 2>/dev/null | awk 'NR==2 {gsub("%","",$5); print $5}')
  _up=$(cut -d. -f1 /proc/uptime 2>/dev/null)

  # Versions.
  _wpv=$(podman exec wordpress php -r 'include "/var/www/html/wp-includes/version.php"; echo $wp_version;' 2>/dev/null | tr -cd '0-9A-Za-z.-')
  _phpv=$(podman exec wordpress php -r 'echo PHP_VERSION;' 2>/dev/null | tr -cd '0-9.')
  _dbv=$(podman exec mariadb mariadb --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)

  # Vulnerabilities: the daily scan's own report, parsed. Not re-run.
  _vat=0; _vres=unknown; _vsrc=""
  if [ -r "$VULN_STATE" ]; then
    _vat=$(_num "$(sed -n 's/^at=//p' "$VULN_STATE")")
    _vres=$(sed -n 's/^result=//p' "$VULN_STATE"); _vres=${_vres:-unknown}
  fi
  _vfind="[]"
  if [ -r "$VULN_REPORT" ]; then
    _vsrc=$(sed -n 's/^  Sources: //p' "$VULN_REPORT" | head -1)
    _vfind=$(awk '
      /^  \[(CRITICAL|HIGH|MEDIUM|LOW)\] / {
        if (sev != "") print sev "\t" comp "\t" title "\t" cve
        sev=substr($1, 2, length($1) - 2); comp=$0; sub(/^  \[[A-Z]+\] /, "", comp)
        title=""; cve=""; n=0; next }
      sev != "" && n < 3 { n++; line=$0; sub(/^ +/, "", line)
        if (n == 1) title=line
        else if (line ~ /^CVE-/) { split(line, a, " "); cve=a[1] } }
      END { if (sev != "") print sev "\t" comp "\t" title "\t" cve }' "$VULN_REPORT" \
      | head -100 \
      | jq -R -s 'split("\n") | map(select(length > 0) | split("\t")
                  | {severity: .[0], component: .[1], title: .[2], cve: .[3]})')
  fi

  # Malware: the last live-site scan.
  _mat=0; _mfind="[]"
  if [ -r "$MALWARE/last-scan-time" ]; then
    _mat=$(date -u -d "$(sed 's/T/ /; s/Z$//' "$MALWARE/last-scan-time")" +%s 2>/dev/null || echo 0)
  fi
  [ -r "$MALWARE/last-scan.tsv" ] && _mfind=$(grep -E '^(CRITICAL|HIGH|SUSPICIOUS)' "$MALWARE/last-scan.tsv" \
      | head -50 | jq -R -s 'split("\n") | map(select(length > 0) | split("\t")
                  | {severity: .[0], finding: .[1], detail: (.[2] // "")})')

  # Integrity: installed tooling vs the signed manifest (fast: cmp only),
  # and the last plugin/core checksum verification.
  _ir=unknown
  if [ -x "$BIN/wasp-verify-integrity.sh" ]; then
    _irc=0; _io=$("$BIN/wasp-verify-integrity.sh" 2>&1) || _irc=$?
    if printf '%s' "$_io" | grep -q 'No manifest on this VM'; then _ir=unsigned
    elif [ "$_irc" -eq 0 ]; then _ir=pass
    else _ir=fail; fi
    _imod=$(printf '%s\n' "$_io" | grep -c 'MODIFIED since install') || _imod=0
  fi
  _pvat=0; _pvres=unknown; _pvmod=0
  if [ -r "$VERIFY_STATE" ]; then
    _pvat=$(_num "$(sed -n 's/^at=//p' "$VERIFY_STATE")")
    _pvres=$(sed -n 's/^result=//p' "$VERIFY_STATE"); _pvres=${_pvres:-unknown}
    _pvmod=$(_num "$(sed -n 's/^modified=//p' "$VERIFY_STATE")")
  fi

  # CrowdSec.
  _csmode=local
  grep -q '^enforcement=upstream' "$ETC/crowdsec-topology" 2>/dev/null && _csmode=upstream
  _csup=false; podman exec crowdsec cscli lapi status >/dev/null 2>&1 && _csup=true
  _csdec=$(podman exec crowdsec cscli decisions list -o json 2>/dev/null | jq 'if type=="array" then length else 0 end' 2>/dev/null)
  _csal=$(podman exec crowdsec cscli alerts list --since 24h -o json 2>/dev/null)
  _csaln=$(printf '%s' "$_csal" | jq 'if type=="array" then length else 0 end' 2>/dev/null)
  _cstop=$(printf '%s' "$_csal" | jq -c 'if type=="array" then (map(.scenario // "unknown") | group_by(.) | map({scenario: .[0], count: length}) | sort_by(-.count) | .[:5]) else [] end' 2>/dev/null)
  _csb=n/a
  if [ "$_csmode" = local ]; then
    rc-service cs-firewall-bouncer status >/dev/null 2>&1 && _csb=active || _csb=stopped
  fi
  # AppSec (wasp-appsec.sh): on or off, listening, memory, watchdog restarts,
  # and how many alerts in 24 h came from in-band rules (virtual patches,
  # generic rules) -- requests refused before WordPress ran.
  _ase=false; grep -q '^enabled = 1' "$APPSEC_INI" 2>/dev/null && _ase=true
  _asl=false
  if [ "$_ase" = true ]; then
    _asc=$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:7422/ 2>/dev/null)
    case "$_asc" in ''|000) : ;; *) _asl=true ;; esac
  fi
  _asf=passthrough; grep -q '^failure_action = ban' "$APPSEC_INI" 2>/dev/null && _asf=ban
  _asm=$(_num "$(awk '{print $2}' "$APPSEC_STATE/last-mem" 2>/dev/null)")
  _asr=$(awk -v s="$(( $(date +%s) - 86400 ))" '$1 >= s' "$APPSEC_STATE/restarts" 2>/dev/null | grep -c .) || _asr=0
  _asb=$(printf '%s' "$_csal" | jq '[.[]? | select((.scenario // "") | test("vpatch|appsec|generic"))] | length' 2>/dev/null)

  # Backups.
  _bl=$(ls -1t "$BACKUP_DIR"/*.gz 2>/dev/null | head -1)
  _blat=0; [ -n "$_bl" ] && _blat=$(_epoch_of "$_bl")
  _boat=$(_num "$(cat "$ETC/offsite-last-ok" 2>/dev/null)")
  _boerr=false; [ -e "$ETC/offsite-last-error" ] && _boerr=true
  _bocfg=false; [ -r "$ETC/offsite.conf" ] && _bocfg=true

  # Egress open temporarily.
  _tmp="[]"
  [ -r "$LEDGER" ] && _tmp=$(awk 'NF>=3 {print $1 "\t" $2 "\t" $3}' "$LEDGER" \
      | jq -R -s 'split("\n") | map(select(length > 0) | split("\t")
                  | {until: (.[0] | tonumber), tag: .[1], domain: .[2]})')

  # Controls: what is switched on, read from the install record.
  _smtp=false; [ -r "$SMTP_INI" ] && grep -q '^host = .' "$SMTP_INI" && _smtp=true
  _hb=false; [ -r "$ETC/heartbeat.conf" ] && _hb=true
  _sig=verified; [ -e "$ETC/UNVERIFIED" ] && _sig=unverified
  _wf=false; grep -q '^WORDFENCE_API_KEY=.' "$ETC/vuln-sources.conf" 2>/dev/null && _wf=true

  jq -n \
    --arg node "$HIVE_NODE" --argjson now "$_now" --arg release "${WASP_RELEASE:-unknown}" \
    --arg hostname "$(hostname)" --arg domain "${WP_DOMAIN:-}" \
    --arg hl "$_hl" --argjson hrc "$(_num "$_hrc")" --argjson disk "$(_num "$_disk")" --argjson up "$(_num "$_up")" \
    --arg wpv "$_wpv" --arg phpv "$_phpv" --arg dbv "$_dbv" \
    --argjson vat "$_vat" --arg vres "$_vres" --arg vsrc "$_vsrc" --argjson vfind "${_vfind:-[]}" \
    --argjson mat "$_mat" --argjson mfind "${_mfind:-[]}" \
    --arg ir "$_ir" --argjson imod "$(_num "${_imod:-0}")" \
    --argjson pvat "$_pvat" --arg pvres "$_pvres" --argjson pvmod "$_pvmod" \
    --arg csmode "$_csmode" --argjson csup "$_csup" --argjson csdec "$(_num "$_csdec")" \
    --argjson csaln "$(_num "$_csaln")" --argjson cstop "${_cstop:-[]}" --arg csb "$_csb" \
    --argjson ase "$_ase" --argjson asl "$_asl" --arg asf "$_asf" --argjson asm "$_asm" \
    --argjson asr "$(_num "$_asr")" --argjson asb "$(_num "$_asb")" \
    --argjson blat "$_blat" --argjson boat "$_boat" --argjson boerr "$_boerr" --argjson bocfg "$_bocfg" \
    --argjson tmp "${_tmp:-[]}" \
    --arg mfa "${MFA_ENFORCE:-0}" --arg mfag "${MFA_GRACE_DAYS:-7}" \
    --arg eproxy "${EGRESS_PROXY:-0}" --arg erestrict "${RESTRICT_EGRESS:-0}" \
    --arg profile "${DEPLOYMENT_PROFILE:-standard}" --arg geoip "${GEOIP_ENABLED:-0}" \
    --arg slug "$( [ -n "${WP_ADMIN_SLUG:-}" ] && echo 1 || echo 0)" \
    --arg admincidr "$( [ -n "${ADMIN_CIDR:-}${ALLOWED_ADMIN_IP:-}" ] && echo 1 || echo 0)" \
    --arg clamav "${INSTALL_CLAMAV:-0}" --arg wpvuln "${WPVULNERABILITY:-1}" \
    --argjson wf "$_wf" --argjson smtp "$_smtp" --argjson hb "$_hb" --arg sig "$_sig" \
    '{
      schema: 1, node: $node, sent_at: $now, wasp_release: $release,
      hostname: $hostname, domain: $domain,
      health:   {check_rc: $hrc, check: $hl, disk_used_pct: $disk, uptime_s: $up},
      versions: {wordpress: $wpv, php: $phpv, mariadb: $dbv},
      vulns:    {at: $vat, result: $vres, sources: $vsrc, findings: $vfind},
      malware:  {at: $mat, findings: $mfind},
      integrity:{tooling: $ir, tooling_modified: $imod,
                 checksums_at: $pvat, checksums: $pvres, checksums_modified: $pvmod},
      crowdsec: {mode: $csmode, lapi_ok: $csup, decisions: $csdec, alerts_24h: $csaln,
                 top_scenarios: $cstop, bouncer: $csb,
                 appsec: {enabled: $ase, listening: $asl, failure_action: $asf, mem_mb: $asm,
                          watchdog_restarts_24h: $asr, blocked_24h: $asb}},
      backups:  {local_at: $blat, offsite_at: $boat, offsite_error: $boerr, offsite_configured: $bocfg},
      egress:   {temporary: $tmp},
      controls: {mfa_enforce: ($mfa == "1"), mfa_grace_days: ($mfag | tonumber? // 7),
                 egress_proxy: ($eproxy == "1"), restrict_egress: ($erestrict == "1"),
                 deployment_profile: $profile, geoip: ($geoip == "1"), login_slug: ($slug == "1"),
                 admin_ip_restricted: ($admincidr == "1"), clamav: ($clamav == "1"),
                 wpvulnerability: ($wpvuln != "0"), wordfence_feed: $wf,
                 smtp_alerts: $smtp, heartbeat: $hb, release_signature: $sig}
    }'
}

# ── Push ─────────────────────────────────────────────────────────────────────
push() {
  _load_conf || { echo "Not enrolled. Run: wasp-hive-report.sh enroll …" >&2; return 1; }
  [ -r "$TOKEN_FILE" ] || { echo "Token missing: ${TOKEN_FILE}" >&2; return 1; }
  mkdir -p "$STATE"; chmod 700 "$STATE"
  _body="$STATE/report.json"
  collect > "$_body" || return 1
  # The token goes in a header FILE: never on a command line, where `ps`
  # would show it to every local account.
  _hdr="$STATE/auth.hdr"
  ( umask 077; printf 'Authorization: Bearer %s\nX-Hive-Node: %s\n' "$(cat "$TOKEN_FILE")" "$HIVE_NODE" > "$_hdr" )
  # The address recorded by `wasp-egress hive set` is the one the firewall
  # allows, so connect to exactly that address (the name still goes in SNI
  # and Host). Never through a proxy: this is a direct, pinned connection.
  _res=""
  _hh="${HIVE_URL#https://}"; _hh="${_hh%%/*}"
  case "$_hh" in *:*) _hp="${_hh##*:}"; _hh="${_hh%:*}" ;; *) _hp=443 ;; esac
  if [ -r "$HIVE_EGRESS" ] && [ "$(sed -n 's/^host=//p' "$HIVE_EGRESS")" = "$_hh" ]; then
    _hi=$(sed -n 's/^ip=//p' "$HIVE_EGRESS")
    [ -n "$_hi" ] && [ "$_hi" != "$_hh" ] && _res="${_hh}:${_hp}:${_hi}"
  fi
  _code=$(curl -sS --max-time 30 -k --noproxy '*' ${_res:+--resolve "$_res"} --pinnedpubkey "sha256//${HIVE_PIN}" \
            -H @"$_hdr" -H 'Content-Type: application/json' \
            --data-binary @"$_body" -o "$STATE/last-response" -w '%{http_code}' \
            "${HIVE_URL%/}/api/v1/report" 2>"$STATE/last-error") || true
  rm -f "$_hdr"
  case "$_code" in
    200|204)
      date +%s > "$STATE/last-ok"; rm -f "$STATE/last-fail"
      return 0 ;;
    *)
      { printf 'at=%s\ncode=%s\n' "$(date +%s)" "${_code:-none}"; head -3 "$STATE/last-error"; } > "$STATE/last-fail"
      # A pin mismatch is the one failure that must never be "fixed" quietly:
      # it is either a re-keyed Hive or someone in the middle.
      if grep -qi 'pinned' "$STATE/last-error" 2>/dev/null; then
        logger -t wasp-hive "Hive certificate does NOT match the pinned key — report withheld. Re-enroll only if the Hive was re-keyed." 2>/dev/null || true
      else
        logger -t wasp-hive "report to ${HIVE_URL} failed (HTTP ${_code:-none})" 2>/dev/null || true
      fi
      return 1 ;;
  esac
}

case "${1:-status}" in
  enroll)
    _u="${2:-}"; _n="${3:-}"; _t="${4:-}"; _p="${5:-}"
    case "$_u" in https://*) : ;; *) echo "Usage: wasp-hive-report.sh enroll <https://hive-host> <node> <token> <pin>" >&2; exit 1 ;; esac
    case "$_n" in ''|*[!A-Za-z0-9._-]*) echo "Node name: letters, digits, . _ - only" >&2; exit 1 ;; esac
    case "$_t" in ''|*[!A-Za-z0-9_-]*) echo "That token does not look like one hive-admin prints." >&2; exit 1 ;; esac
    case "$_p" in ''|*[!A-Za-z0-9+/=]*) echo "That pin does not look like one hive-admin prints." >&2; exit 1 ;; esac
    mkdir -p "$ETC"
    { printf 'url=%s\nnode=%s\npin=%s\n' "$_u" "$_n" "$_p"; } > "$CONF"; chmod 644 "$CONF"
    ( umask 077; printf '%s\n' "$_t" > "$TOKEN_FILE" ); chmod 600 "$TOKEN_FILE"
    if push; then
      _ok "Enrolled as ${_n}. First report delivered to ${_u}."
      _note "It reports every 15 minutes from cron. Nothing on the Hive can reach this VM."
    else
      _bad "Enrolled, but the first report was not accepted:"
      sed 's/^/       /' "$STATE/last-fail" 2>/dev/null
      _note "Is ${_u} reachable from here on 443?  curl -k ${_u}/api/v1/ping"
      exit 1
    fi ;;
  send)
    push >/dev/null 2>&1 || exit 1 ;;
  show)
    _load_conf || HIVE_NODE="(not enrolled)"
    collect ;;
  status)
    echo ""
    echo "WASP Hive reporting"
    echo "━━━━━━━━━━━━━━━━━━━"
    if _load_conf; then
      printf '  Hive : %s\n  Node : %s\n  Pin  : sha256//%s\n' "$HIVE_URL" "$HIVE_NODE" "$HIVE_PIN"
      _lo=$(_num "$(cat "$STATE/last-ok" 2>/dev/null)")
      if [ "$_lo" -gt 0 ]; then
        printf '  Last delivered: %s minute(s) ago\n' "$(( ( $(date +%s) - _lo ) / 60 ))"
      else
        echo "  Last delivered: never"
      fi
      [ -r "$STATE/last-fail" ] && { echo "  Last failure:"; sed 's/^/    /' "$STATE/last-fail"; }
    else
      echo "  Not enrolled. On the Hive:  hive-admin enroll <node-name>"
      echo "  then paste the line it prints here."
    fi ;;
  leave)
    rm -f "$CONF" "$TOKEN_FILE" "$STATE/last-ok"
    _ok "This VM no longer reports. Revoke it on the Hive too: hive-admin revoke <node>" ;;
  *) sed -n '4,10p' "$0"; exit 1 ;;
esac
