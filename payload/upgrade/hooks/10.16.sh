#!/bin/sh
# step: turn on security alerts where this VM has none set up (wasp-alerts.sh setup)
#
# Run by wasp-upgrade.sh, once, when a VM passes 10.16. The mu-plugin and the
# host-side cron lines come from files.map; this writes alerts.ini from the
# operator address given at install. With no address recorded it says so and
# leaves alerts off rather than guessing one.
BIN="${WASP_HOOK_BIN:-${WASP_ROOT:-}/usr/local/bin}"   # WASP_HOOK_BIN: tests only
INI="${WASP_ROOT:-}/home/wpuser/wp/secrets/alerts.ini"
if [ -r "$INI" ]; then
  echo "alerts already set up ($(sed -n 's/^[[:space:]]*to[[:space:]]*=[[:space:]]*//p' "$INI" | head -1)); nothing to do"
  exit 0
fi
[ -x "${BIN}/wasp-alerts.sh" ] || { echo "wasp-alerts.sh not installed; skipped"; exit 0; }
"${BIN}/wasp-alerts.sh" setup --quiet || true
if [ -r "$INI" ]; then
  echo "alerts on; check delivery with: wasp-alerts.sh test"
else
  echo "no operator address on record: turn alerts on with  wasp-alerts.sh setup you@example.com"
fi
exit 0
