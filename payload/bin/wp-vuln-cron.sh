#!/bin/sh
# Daily vulnerability scan wrapper.
#
# Exists so the scan runs ONCE. The obvious inline cron form --
#   wp-plugins.sh vulns | grep -q FINDING && wp-plugins.sh vulns | logger
# -- executes the whole scan twice: two `podman run` starts of the wp-cli
# container and one jq invocation per installed plugin, doubled. On a site
# with 30 plugins that is 120 jq calls to answer a question 60 could answer.
#
# Reports through syslog only when something is actually found. A daily job
# that says "nothing found" every day trains the operator to ignore it, and an
# ignored alert is worse than no alert because it manufactures the feeling of
# monitoring.
#
# --digest (weekly, Monday 07:15 UTC): the report that is sent whether or not
# anything was found. The daily jobs stay silent on a clean day, deliberately;
# the cost is that silence also looks like a VM whose scans stopped running or
# whose mail stopped going out. One weekly message settles that: when each scan
# last ran, whether it completed, what it found, and what egress is open. A
# missing Monday report is itself the alert.
#   wp-vuln-cron.sh --digest           build it, print it, and email it
#   wp-vuln-cron.sh --digest --print   build and print it, send nothing
set -u
OUT=$(mktemp) || exit 0
trap 'rm -f "$OUT"' EXIT INT TERM

VULN_STATE="${VULN_STATE:-/var/cache/wp-vulns/.last-scan}"
MALWARE_STATE="${MALWARE_STATE:-/var/lib/wp-malware-scan}"
STALE_HOURS="${STALE_HOURS:-48}"

if [ "${1:-}" = "--digest" ]; then
  _send=1; [ "${2:-}" = "--print" ] && _send=0
  _now=$(date +%s)
  _hn=$(hostname 2>/dev/null || echo this-vm)
  _attn=""
  _age_h() { echo $(( ( _now - $1 ) / 3600 )); }

  # A fresh vulnerability pass. WPVulnerability answers are cached for 12 hours
  # and the Wordfence feed refreshes on the same clock, so straight after the
  # daily run this costs almost nothing -- and it reports what is true now,
  # not what was true at 06:30.
  # The daily run's record is read first and put back afterwards: this pass
  # writes the same file, and must not make a daily job that stopped running
  # look as if it ran this morning.
  _vsave=""
  if [ -r "$VULN_STATE" ]; then _vsave=$(mktemp); cp "$VULN_STATE" "$_vsave"; fi
  _vrc=0
  /usr/local/bin/wp-plugins.sh vulns >"$OUT" 2>&1 || _vrc=$?
  if [ -n "$_vsave" ]; then cat "$_vsave" > "$VULN_STATE"; rm -f "$_vsave"
  else rm -f "$VULN_STATE"; fi

  BODY=$(mktemp)
  {
    printf 'Weekly security report for %s
' "$_hn"
    printf '%s

' "$(date -u '+%A %Y-%m-%d %H:%M UTC')"

    printf 'VULNERABILITIES (plugins, themes, core, PHP, MariaDB)
'
    printf '  Scheduled: daily 06:30 UTC. Alerts are sent on any finding or failed run.
'
    _src=$(sed -n 's/^  Sources: //p' "$OUT" | head -1)
    printf '  Sources  : %s
' "${_src:-unknown}"
    if [ -r "$VULN_STATE" ]; then
      _at=$(sed -n 's/^at=//p' "$VULN_STATE"); _res=$(sed -n 's/^result=//p' "$VULN_STATE")
      case "$_at" in ''|*[!0-9]*) _at=0 ;; esac
      printf '  Last run : %s (%sh ago), %s
' \
        "$(date -u -d "@${_at}" '+%Y-%m-%d %H:%M UTC' 2>/dev/null || echo "$_at")" "$(_age_h "$_at")" "${_res:-unknown}"
      [ "$(_age_h "$_at")" -gt "$STALE_HOURS" ] && _attn="${_attn}the daily vulnerability scan has not run for $(_age_h "$_at")h; "
    else
      printf '  Last run : never recorded
'
      _attn="${_attn}no daily vulnerability scan has been recorded; "
    fi
    if [ "$_vrc" -ne 0 ] || grep -q '^  INCOMPLETE:' "$OUT"; then
      printf '  Now      : INCOMPLETE -- not a clean result
'
      grep '^  INCOMPLETE:' "$OUT" | sed 's/^  /    /'
      _attn="${_attn}the vulnerability scan is incomplete; "
    fi
    _vf=$(grep -cE '^  \[(CRITICAL|HIGH|MEDIUM|LOW)\]' "$OUT") || _vf=0
    if [ "$_vf" -gt 0 ]; then
      printf '  Findings : %s\n' "$_vf"
      grep -E -A3 '^  \[(CRITICAL|HIGH|MEDIUM|LOW)\]' "$OUT" | grep -vE '^--$|^  \[NOTICE\]' | sed 's/^/  /'
    else
      printf '  Findings : none matching a disclosed vulnerability\n'
    fi
    printf '\n'

    printf 'MALWARE AND INTEGRITY\n'
    printf '  Scheduled: quick scan daily 03:30 UTC, YARA signatures Sundays 03:45 UTC.\n'
    printf '             CRITICAL findings are e-mailed when found.\n'
    if [ -r "$MALWARE_STATE/last-scan-time" ]; then
      _mt=$(cat "$MALWARE_STATE/last-scan-time")
      _ms=$(date -u -d "$(printf '%s' "$_mt" | sed 's/T/ /; s/Z$//')" +%s 2>/dev/null) || _ms=0
      _mc=$(grep -c '^CRITICAL' "$MALWARE_STATE/last-scan.tsv" 2>/dev/null) || _mc=0
      _mh=$(grep -c '^HIGH' "$MALWARE_STATE/last-scan.tsv" 2>/dev/null) || _mh=0
      printf '  Last run : %s (%sh ago): %s critical, %s high\n' "$_mt" "$(_age_h "$_ms")" "$_mc" "$_mh"
      [ "$(_age_h "$_ms")" -gt "$STALE_HOURS" ] && _attn="${_attn}the daily malware scan has not run for $(_age_h "$_ms")h; "
      grep -E '^(CRITICAL|HIGH)' "$MALWARE_STATE/last-scan.tsv" 2>/dev/null | cut -f1,2 | head -20 \
        | sed 's/\t/  /; s/^/    /'
      [ "$_mc" -gt 0 ] && _attn="${_attn}${_mc} CRITICAL malware finding(s); "
    else
      printf '  Last run : never recorded\n'
      _attn="${_attn}no malware scan has been recorded; "
    fi
    printf '\n'

    if [ -x /usr/local/bin/wasp-egress.sh ]; then
      printf 'EGRESS OPEN TEMPORARILY\n'
      /usr/local/bin/wasp-egress.sh temporary 2>/dev/null | grep -E '^  ' | sed 's/^/  /' \
        || printf '  (could not be read)\n'
      printf '\n'
    fi

    printf 'On the VM:  wp-plugins.sh vulns    wp-malware-scan.sh status    wasp-egress temporary\n'
    printf 'This report is sent every Monday. If one does not arrive, the VM or its mail is down.\n'
  } > "$BODY"

  if [ -n "$_attn" ]; then
    _subj="Weekly security report: ATTENTION -- ${_attn%; }"
  else
    _subj="Weekly security report: all scans ran, nothing found"
    [ "${_vf:-0}" -gt 0 ] && _subj="Weekly security report: ${_vf} vulnerability finding(s)"
  fi
  cat "$BODY"
  if [ "$_send" = 1 ]; then
    if [ -x /usr/local/bin/wp-notify.sh ]; then
      # Never suppressed: a weekly report that deduplicates against last week's
      # is a report that stops arriving when nothing changes.
      NOTIFY_COOLDOWN_HOURS=0 /usr/local/bin/wp-notify.sh wp-report "$_subj" "$BODY"
    else
      logger -t wp-report "wp-notify.sh missing; weekly report not sent" 2>/dev/null || true
    fi
  fi
  rm -f "$BODY"
  exit 0
fi

_rc=0
/usr/local/bin/wp-plugins.sh vulns >"$OUT" 2>&1 || _rc=$?
# Kept for wasp-hive-report.sh, which reports what this run found rather than
# scanning again. Root-only: it lists what is vulnerable on this site.
VULN_REPORT="${VULN_REPORT:-/var/cache/wp-vulns/last-report.txt}"
( umask 077; cp "$OUT" "$VULN_REPORT" 2>/dev/null ) || true

# A scan that could not run is the one result that must not be silent. This used
# to be `|| true`, then a look for findings: with no token, or a feed that stopped
# downloading, no findings were possible, so a site went unscanned with no alert
# and the job looked healthy. Alerted only while it lasts, and wp-notify
# deduplicates on the body, so a standing fault is not a daily email.
if [ "$_rc" -ne 0 ] || grep -q '^  INCOMPLETE:' "$OUT"; then
    logger -t wp-vulns "vulnerability scan did not complete (exit ${_rc}) — run: wp-plugins.sh vulns"
    grep '^  INCOMPLETE:' "$OUT" | while IFS= read -r line; do logger -t wp-vulns "  ${line}"; done
    if [ -x /usr/local/bin/wp-notify.sh ]; then
        BODY=$(mktemp)
        {
          printf 'The daily vulnerability scan on this site did not complete.\n'
          printf 'No findings below does NOT mean no vulnerabilities.\n\n'
          grep '^  INCOMPLETE:' "$OUT" || printf '  exit status %s\n' "$_rc"
          printf '\nCheck:  wp-plugins.sh vuln-sources\n'
        } > "$BODY"
        /usr/local/bin/wp-notify.sh wp-vulns "Vulnerability scan incomplete" "$BODY"
        rm -f "$BODY"
    fi
fi

# A finding line starts with two spaces and a severity in brackets. Colour is
# already suppressed here because stdout is not a terminal.
if grep -qE '^  \[(CRITICAL|HIGH|MEDIUM|LOW)\]' "$OUT"; then
    _n=$(grep -cE '^  \[(CRITICAL|HIGH|MEDIUM|LOW)\]' "$OUT")
    _c=$(grep -cE '^  \[CRITICAL\]' "$OUT" || true)
    logger -t wp-vulns "vulnerability scan: ${_n} finding(s), ${_c} critical — run: wp-plugins.sh vulns"
    grep -E '^  \[(CRITICAL|HIGH)\]' "$OUT" | while IFS= read -r line; do
        logger -t wp-vulns "  ${line}"
    done
    # Email as well, if a relay is configured. The body is the CRITICAL/HIGH
    # findings only -- wp-notify deduplicates on body content, so including
    # the whole report (which contains a timestamp) would defeat that and
    # send an identical alert every single day.
    if [ -x /usr/local/bin/wp-notify.sh ]; then
        BODY=$(mktemp)
        {
          printf 'Vulnerable plugins/themes found on this site.\n\n'
          grep -E '^  \[(CRITICAL|HIGH|MEDIUM)\]' "$OUT"
          printf '\nFull report:  wp-plugins.sh vulns\n'
          printf 'Update:       wp-plugins.sh update-plugins <slug>\n'
        } > "$BODY"
        /usr/local/bin/wp-notify.sh wp-vulns \
          "${_c} critical, ${_n} total vulnerability finding(s)" "$BODY"
        rm -f "$BODY"
    fi
fi
exit 0
