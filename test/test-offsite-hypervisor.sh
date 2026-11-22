#!/usr/bin/env bash
# =============================================================================
# test-offsite-hypervisor.sh — "the hypervisor makes the offsite copies"
# =============================================================================
#
# 10.28: a VM copied off-host by its hypervisor sent nothing itself, and every
# backup reported "Off-VM backup copy FAILED", mailed with no cooldown.
# `wasp-offsite-backup.sh hypervisor "<where>"` records the operator's
# statement; `mode` tells the other tools; the backup stops reporting a failure
# and the weekly report says where the copies are made. A VM that also pushes
# its own copies keeps doing so, failures and all.
# =============================================================================
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
_p() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
_f() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n         %s\n' "$1" "${2:-}"; }
echo ""
echo "Offsite copies made at the hypervisor"
mkdir -p "$T/etc" "$T/bin"
sed -e '/^if \[ "\$(id -u)" -ne 0 \]; then$/,/^fi$/d' \
    -e "s#/etc/wp-install#$T/etc#g" \
    "$REPO/payload/bin/wasp-offsite-backup.sh" > "$T/off.sh"
_o() { ${WASP_TEST_SH:-sh} "$T/off.sh" "$@" 2>&1; }

echo ""
[ "$(_o mode)" = none ] && _p "nothing set up: mode none" || _f "mode none" "$(_o mode)"
out=$(_o status)
printf '%s' "$out" | grep -q 'NOT CONFIGURED' && printf '%s' "$out" | grep -q 'hypervisor "Proxmox Backup Server' \
  && _p "status says not configured, and how to record the hypervisor instead" || _f "status none" "$out"
printf 'at=x\nfile=y\n--- push output ---\nOff-VM backup is not configured\n' > "$T/etc/offsite-last-error"
date +%s > "$T/etc/offsite-last-ok"
out=$(_o hypervisor "Proxmox Backup Server, nightly, off-site"); rc=$?
[ "$rc" = 0 ] && [ "$(_o mode)" = hypervisor ] && _p "hypervisor \"<where>\": mode hypervisor" || _f "set" "rc=$rc $out"
grep -q '^note=Proxmox Backup Server, nightly, off-site$' "$T/etc/offsite-hypervisor" && grep -q '^since=20[0-9-]*$' "$T/etc/offsite-hypervisor" \
  && grep -q '^by=' "$T/etc/offsite-hypervisor" && _p "records where, when and by whom" || _f "record" "$(cat "$T/etc/offsite-hypervisor")"
[ ! -e "$T/etc/offsite-last-error" ] && [ ! -e "$T/etc/offsite-last-ok" ] \
  && _p "the record of pushes that will never run again is cleared" || _f "cleared" "$(ls "$T/etc")"
out=$(_o status)
printf '%s' "$out" | grep -q 'MADE AT THE HYPERVISOR' && printf '%s' "$out" | grep -q 'Proxmox Backup Server, nightly' \
  && printf '%s' "$out" | grep -q 'test a\|restore test there' && _p "status says so, and that restores are tested there" || _f "status hv" "$out"
out=$(_o push); rc=$?
[ "$rc" = 1 ] && _p "push itself still refuses (there is nothing to push to)" || _f "push" "rc=$rc $out"

grep -n 'wasp-offsite-backup.sh mode' "$REPO/payload/bin/wp-db-backup.sh" >/dev/null \
  && awk '/_OFFMODE" = hypervisor/ {h=NR} /wasp-offsite-backup.sh push/ {p=NR} END {exit !(h && p && h < p)}' "$REPO/payload/bin/wp-db-backup.sh" \
  && _p "the backup asks the mode before pushing, and does not push for 'hypervisor'" || _f "backup" ""

printf 'OFFSITE_METHOD=rclone\nOFFSITE_DEST=r2:bucket/x\n' > "$T/etc/offsite.conf"
[ "$(_o mode)" = rclone ] && _p "a VM that also pushes its own copies: mode is its method" || _f "mode both" "$(_o mode)"
out=$(_o hypervisor "PBS too")
printf '%s' "$out" | grep -q 'also sends its own copies' && _p "recording the hypervisor then says the VM's own pushes continue" || _f "both" "$out"
rm -f "$T/etc/offsite.conf"
out=$(_o hypervisor off)
[ "$(_o mode)" = none ] && [ ! -e "$T/etc/offsite-hypervisor" ] && printf '%s' "$out" | grep -q 'reports that again' \
  && _p "hypervisor off: back to none, and says what that means" || _f "off" "$out"

echo ""
echo "── the weekly report"
sed -e "s#/usr/local/bin/wp-notify.sh#$T/bin/notify#g" -e "s#/usr/local/bin/wp-plugins.sh#$T/bin/plug#g" \
    "$REPO/payload/bin/wp-vuln-cron.sh" > "$T/cron.sh"
printf '#!/bin/sh\nexit 0\n' > "$T/bin/plug"; printf '#!/bin/sh\nexit 0\n' > "$T/bin/notify"; printf '#!/bin/sh\nexit 0\n' > "$T/bin/logger"
chmod +x "$T/bin/"*
_dig() { env PATH="$T/bin:$PATH" OFFSITE_ETC="$T/etc" VULN_STATE="$T/none" MALWARE_STATE="$T/none" ${WASP_TEST_SH:-sh} "$T/cron.sh" --digest --print 2>&1; }
out=$(_dig)
printf '%s' "$out" | grep -A1 '^OFF-VM BACKUPS' | grep -q 'None: backups exist only on this VM' && _p "none: said" || _f "digest none" "$out"
_o hypervisor "Proxmox Backup Server, nightly" >/dev/null
out=$(_dig)
printf '%s' "$out" | grep -A1 '^OFF-VM BACKUPS' | grep -q 'Made at the hypervisor: Proxmox Backup Server, nightly' && _p "hypervisor: said, with where" || _f "digest hv" "$out"
_o hypervisor off >/dev/null; date +%s > "$T/etc/offsite-last-ok"; printf 'x\n' > "$T/etc/offsite-last-error"
out=$(_dig)
printf '%s' "$out" | grep -q 'Last copy sent from this VM: 0h ago' && printf '%s' "$out" | grep -q 'The last push FAILED' \
  && _p "the VM's own pushes: last copy and a failed push" || _f "digest own" "$out"

echo ""
printf '  passed %d   failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
