#!/bin/sh
# mariadb-health-check.sh — proves MariaDB is actually functional, not just
# that mariadbd-admin ping succeeds. See the long comment above this
# heredoc in create-wordpress-vm.sh for the full rationale.
# Usage: mariadb-health-check.sh [container_name]
#        mariadb-health-check.sh --wait [seconds] [container_name]
# Exit 0 = all critical checks passed. Exit 1 = one or more failed.
#
# --wait (10.28): wait until WordPress could connect -- its own user, its own
# database, InnoDB answering -- for up to [seconds] (120), then exit 0, or 1
# when it never did. wp-container runs it before starting WordPress at boot.
# The wait it replaced was a root `ping`, which answers before InnoDB is
# ready and while the WordPress user cannot yet log in: the gap in which a
# rebooted site said "Error establishing a database connection".
if [ "${1:-}" = "--wait" ]; then
  _max="${2:-120}"; CONTAINER="${3:-mariadb}"
  case "$_max" in ''|*[!0-9]*) _max=120 ;; esac
  _t=0
  while :; do
    _r=$(sed -n 's/^MARIADB_PASSWORD=//p' "${WASP_DB_ENV:-/etc/wordpress/env}" 2>/dev/null | head -1 \
      | podman exec -i "$CONTAINER" sh -c \
      'IFS= read -r p; MYSQL_PWD="$p"; export MYSQL_PWD
       q="SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE();"
       mariadb -u"${MARIADB_USER}" "${MARIADB_DATABASE}" -N -e "$q" 2>/dev/null ||
       mysql   -u"${MARIADB_USER}" "${MARIADB_DATABASE}" -N -e "$q" 2>/dev/null' 2>/dev/null)
    case "$_r" in
      ''|*[!0-9]*) : ;;
      *) echo "MariaDB ready for WordPress after ${_t}s"; exit 0 ;;
    esac
    [ "$_t" -ge "$_max" ] && break
    sleep 2; _t=$((_t + 2))
  done
  echo "MariaDB not ready for WordPress after ${_max}s: mariadb-health-check.sh" >&2
  exit 1
fi
CONTAINER="${1:-mariadb}"
FAIL=0

_pass() { echo "  ✔  $*"; }
_fail() { echo "  ✗  $*" >&2; FAIL=1; }

# 1) Root ping — sanity check only. Proves the server accepts TCP and root
# authenticates; proves nothing about InnoDB or WordPress's own grants.
if podman exec "$CONTAINER" sh -c \
     'mariadbd-admin ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" 2>/dev/null ||
      mariadb-admin  ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" 2>/dev/null' \
     >/dev/null 2>&1; then
  _pass "root ping"
else
  _fail "root ping failed"
fi

# 2) A real query as root — proves the SQL engine itself answers, not just
# that the ping protocol handshake succeeds (ping and query are different
# code paths inside mariadbd).
ROOT_QUERY=$(podman exec "$CONTAINER" sh -c \
  'mariadb -uroot -p"${MARIADB_ROOT_PASSWORD}" -N -e "SELECT 1;" 2>/dev/null ||
   mysql   -uroot -p"${MARIADB_ROOT_PASSWORD}" -N -e "SELECT 1;" 2>/dev/null')
if [ "$ROOT_QUERY" = "1" ]; then
  _pass "root SELECT 1"
else
  _fail "root SELECT 1 did not return 1 (got: '${ROOT_QUERY}')"
fi

# 3) The EXACT credentials WordPress itself uses — MARIADB_USER/PASSWORD/
# DATABASE and WORDPRESS_DB_* come from the same /etc/wordpress/env file, so
# this is the identical database, user, and password WordPress logs in with. A
# root-only check can report healthy while WordPress's own grants are
# broken (e.g. a botched restore, a user dropped by an errant migration) —
# proving root works is not the same as proving WordPress can log in.
#
# The password comes from the file, not the container's environment. Rotation
# changes the file and the database but not this container's environment, so
# reading ${MARIADB_PASSWORD} here failed on every VM after a rotation.
WP_QUERY=$(sed -n 's/^MARIADB_PASSWORD=//p' /etc/wordpress/env 2>/dev/null | head -1 \
  | podman exec -i "$CONTAINER" sh -c \
  'IFS= read -r p; MYSQL_PWD="$p"; export MYSQL_PWD
   mariadb -u"${MARIADB_USER}" "${MARIADB_DATABASE}" -N -e "SELECT 1;" 2>/dev/null ||
   mysql   -u"${MARIADB_USER}" "${MARIADB_DATABASE}" -N -e "SELECT 1;" 2>/dev/null')
if [ "$WP_QUERY" = "1" ]; then
  _pass "wordpress-user SELECT 1 (same credentials WordPress itself uses)"
else
  _fail "wordpress-user SELECT 1 failed — WordPress's own DB user/grants may be broken"
fi

# 4) InnoDB actually initialized — read directly via the same healthcheck.sh
# shipped in the official MariaDB image and already used as this
# container's own --health-cmd, but invoked here directly rather than
# trusting Podman's health-check timer: this script's own install-time
# comments already document that timer as unreliable on Alpine (no
# systemd/conmon poller to drive it — .State.Health.Status can sit on
# "starting" forever even once MariaDB is fully usable).
if podman exec "$CONTAINER" healthcheck.sh --connect --innodb_initialized >/dev/null 2>&1; then
  _pass "InnoDB initialized"
else
  _fail "InnoDB not confirmed initialized (healthcheck.sh --innodb_initialized)"
fi

# Informational only — recent error/corruption-flavoured log lines, surfaced
# for a human. Never gates pass/fail by itself, same rationale as
# wp-health-check.sh's own log scan: some of these can be transient noise
# (e.g. a single retried connection during startup), and the checks above
# are what actually decide health.
RECENT_ERRORS=$(podman logs --since 2m "$CONTAINER" 2>&1 \
  | grep -Ei 'error|corrupt|assertion|crashed' | tail -5)
if [ -n "$RECENT_ERRORS" ]; then
  echo "  ⚠  Recent log lines worth reviewing (informational, not fatal):"
  echo "$RECENT_ERRORS" | sed 's/^/       /'
fi

if [ "$FAIL" = "0" ]; then
  echo "  ✔  MariaDB health: ALL CRITICAL CHECKS PASSED"
  exit 0
fi
echo "  ✗  MariaDB health: ONE OR MORE CRITICAL CHECKS FAILED"
exit 1
