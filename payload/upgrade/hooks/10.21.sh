#!/bin/sh
# step: mask the WordPress image's own remoteip.conf on a VM provisioned before 10.6 (wp-hardening.sh remoteip-fix)
#
# Run by wasp-upgrade.sh, once, when a VM passes 10.21. The 10.15 step checked
# two files; a VM provisioned before 10.6 also lacks the mount that masks the
# image's own conf-enabled/remoteip.conf, so Apache took X-Forwarded-For from
# any private address. remoteip-fix now covers that too. Safe to repeat: an
# already-correct VM -- every VM provisioned from 10.6, or one fixed by hand --
# is reported and left alone.
BIN="${WASP_HOOK_BIN:-${WASP_ROOT:-}/usr/local/bin}"   # WASP_HOOK_BIN: tests only
[ -x "${BIN}/wp-hardening.sh" ] || { echo "wp-hardening.sh not installed; skipped"; exit 0; }
if "${BIN}/wp-hardening.sh" remoteip-fix --check >/dev/null 2>&1; then
  echo "already correct; nothing to do"
  exit 0
fi
"${BIN}/wp-hardening.sh" remoteip-fix
