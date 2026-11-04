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
set -u
OUT=$(mktemp) || exit 0
trap 'rm -f "$OUT"' EXIT INT TERM

_rc=0
/usr/local/bin/wp-plugins.sh vulns >"$OUT" 2>&1 || _rc=$?

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
