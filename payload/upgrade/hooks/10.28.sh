#!/bin/sh
# step: wait at boot until WordPress could connect to MariaDB, not just until MariaDB answers (wp-container)
#
# Run by wasp-upgrade.sh, once, when a VM passes 10.28. /etc/init.d/wp-container
# was written at build time and is not replaced by an upgrade. Its wait before
# starting WordPress was a root ping, which answers before InnoDB is ready and
# before the WordPress user can log in, so a rebooted site showed "Error
# establishing a database connection" for up to a minute. This inserts the
# 10.28 wait (mariadb-health-check.sh --wait, up to 120s) ahead of the old
# loop, which then passes at once. Safe to repeat: a service that already has
# it is left alone. The previous file is kept beside it.
SVC="${WASP_ROOT:-}/etc/init.d/wp-container"
[ -f "$SVC" ] || { echo "no wp-container service here; skipped"; exit 0; }
if grep -q '/usr/local/bin/mariadb-health-check.sh --wait "' "$SVC"; then
  echo "already waits for WordPress's own connection; nothing to do"
  exit 0
fi
grep -q '^  _wait=0$' "$SVC" || { echo "wp-container does not have the expected wait loop; left alone (see CHANGELOG 10.28)"; exit 0; }
_bak="${SVC}.bak-10.28"
cp -p "$SVC" "$_bak" || { echo "could not back up $SVC; left alone"; exit 1; }
_tmp="${SVC}.tmp.$$"
awk '
  /^  _wait=0$/ && !done {
    print "  # 10.28 (upgrade step): wait until WordPress could connect -- its own user,"
    print "  # its database, InnoDB answering -- not only until root'"'"'s ping answers."
    print "  if [ -x /usr/local/bin/mariadb-health-check.sh ] && grep -q -- '"'"'--wait'"'"' /usr/local/bin/mariadb-health-check.sh 2>/dev/null; then"
    print "    /usr/local/bin/mariadb-health-check.sh --wait \"${WASP_DB_WAIT:-120}\" >/dev/null 2>&1 \\"
    print "      || einfo \"MariaDB not ready for WordPress after ${WASP_DB_WAIT:-120}s — starting anyway; check: mariadb-health-check.sh\""
    print "  fi"
    done = 1
  }
  { print }
' "$SVC" > "$_tmp" || { rm -f "$_tmp"; echo "could not rewrite $SVC; left alone"; exit 1; }
if ! sh -n "$_tmp" 2>/dev/null; then
  rm -f "$_tmp"; echo "the rewritten service did not parse; left alone"; exit 1
fi
cat "$_tmp" > "$SVC"; rm -f "$_tmp"
echo "wp-container now waits for WordPress's own connection at boot (previous file: ${_bak##*/})"
exit 0
