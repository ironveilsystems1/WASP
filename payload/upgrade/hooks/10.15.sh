#!/bin/sh
# step: repair wp-admin through the reverse proxy on a VM built by 10.14 or earlier (wp-hardening.sh remoteip-fix)
#
# Run by wasp-upgrade.sh, once, when a VM passes 10.15. Safe to repeat: the
# check finds an already-repaired VM (including the hand fix) and stops there.
BIN="${WASP_HOOK_BIN:-${WASP_ROOT:-}/usr/local/bin}"   # WASP_HOOK_BIN: tests only
[ -x "${BIN}/wp-hardening.sh" ] || { echo "wp-hardening.sh not installed; skipped"; exit 0; }
if "${BIN}/wp-hardening.sh" remoteip-fix --check >/dev/null 2>&1; then
  echo "already in the 10.15 form; nothing to do"
  exit 0
fi
"${BIN}/wp-hardening.sh" remoteip-fix
