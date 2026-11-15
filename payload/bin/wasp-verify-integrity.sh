#!/bin/sh
# =============================================================================
# wasp-verify-integrity.sh — has the installed tooling been modified?
# =============================================================================
# Re-checks the WASP scripts on this VM against the signed release manifest.
#
# This is the more useful half of signing. Verifying a release at install time
# catches a tampered download, which is a one-off risk. Verifying the INSTALLED
# files catches something continuous and much harder to notice: an attacker who
# reached root on this VM and edited update.sh, wp-hardening.sh or the malware
# scanner to disable a control, whitelist themselves, or stop reporting.
#
# Those edits are invisible to every other check here, because every other
# check trusts the scripts it is running.
#
# LIMIT, stated plainly: an attacker with root can also edit or delete THIS
# script, and the manifest, and the key. Verification from inside a
# compromised host proves nothing about a determined attacker -- it catches
# the common case of malware that modifies files without thinking about the
# integrity check, which is most of it. For an authoritative answer, mount the
# disk from the Proxmox host and run the comparison from there.
# =============================================================================
set -u
if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then exec doas "$0" "$@"; fi
  echo "Run as root (or via doas)" >&2; exit 1
fi

SRC="${WASP_INSTALL_DIR:-/etc/wp-install}"
MAN="${SRC}/MANIFEST.sha256"
SIG="${SRC}/MANIFEST.sha256.minisig"
PUB="${SRC}/release.pub"
BIN_DIR="${WASP_BIN_DIR:-/usr/local/bin}"

echo ""
echo "WASP tooling integrity"
echo "━━━━━━━━━━━━━━━━━━━━━━"

[ -r "$MAN" ] || { echo "  No manifest on this VM — the release was unsigned."; \
                   echo "  Integrity checking needs a signed release: the maintainer"; \
                   echo "  ships MANIFEST.sha256 and MANIFEST.sha256.minisig alongside it."; exit 0; }

_key=$(cat "$PUB" 2>/dev/null)
if [ -n "$_key" ] && [ -r "$SIG" ] && command -v minisign >/dev/null 2>&1; then
  if minisign -Vm "$MAN" -P "$_key" >/dev/null 2>&1; then
    echo "  ✔ Manifest signature is valid"
  else
    echo "  ✗ MANIFEST SIGNATURE IS INVALID."
    echo "    The manifest itself was altered. Treat every result below as"
    echo "    meaningless and investigate from outside this VM."
    exit 1
  fi
else
  echo "  ⚠ Signature not checked (no key, no signature, or minisign absent)."
  echo "    Hashes below still detect accidental change, not deliberate tampering."
fi

# Compare the DEPLOYED copies under /usr/local/bin against the staged payload
# they came from, then that payload against the signed manifest. Both halves
# matter: an attacker is far more likely to edit the script that actually runs.
_diff=0
for f in "$BIN_DIR"/*.sh; do
  b=$(basename "$f")
  src="${SRC}/payload/bin/${b}"
  [ -r "$src" ] || continue
  if ! cmp -s "$f" "$src"; then
    echo "  ✗ MODIFIED since install: ${f}"
    echo "      differs from ${src}"
    _diff=$((_diff+1))
  fi
done
[ "$_diff" -eq 0 ] && echo "  ✔ All installed tools match their staged originals"

echo "  Checking staged payload against the signed manifest…"
# The manifest covers the whole release: install.sh, lib/ and hive/ run on the
# Proxmox host (or the Hive) and are never copied to this VM, and payload/
# stages/ is staged as stages/. Checking the manifest as it stands reported
# every one of those as FAILED on every VM -- a permanent discrepancy, which
# since 10.16 would have been emailed weekly and then, rightly, ignored. Only
# what a WordPress VM keeps is checked, under the name it is kept as. The
# signature above still covers the whole manifest, so a narrowed check cannot
# be fed a forged list.
_vm_man=$(mktemp) || exit 1
awk '{ p = $2; sub(/^\*/, "", p)
       if (p ~ /^payload\/stages\//) { sub(/^payload\/stages\//, "stages/", p); print $1 "  " p; next }
       if (p ~ /^payload\/[^\/]+\//) print $1 "  " p }' "$MAN" > "$_vm_man"
_n=$(grep -c . "$_vm_man") || _n=0
_res=$(cd "$SRC" 2>/dev/null && sha256sum -c "$_vm_man" 2>&1 | grep -v ': OK$' | grep -i 'FAILED\|No such\|can.t open') || _res=""
_bad=$(printf '%s\n' "$_res" | grep -ci 'FAILED') || _bad=0
rm -f "$_vm_man"
if [ "${_n:-0}" -eq 0 ]; then
  echo "  ⚠ The manifest lists no payload files; nothing staged was checked."
elif [ "${_bad:-0}" -eq 0 ]; then
  echo "  ✔ Staged payload matches the signed manifest (${_n} files)"
else
  echo "  ✗ ${_bad} staged file(s) do NOT match the signed manifest"
  printf '%s\n' "$_res" | grep -i 'FAILED' | sed 's/^/      /'
  _diff=$((_diff+_bad))
fi

echo ""
if [ "$_diff" -eq 0 ]; then
  echo "  Nothing has been modified."
  exit 0
fi
echo "  ${_diff} discrepancy(ies). Files under /usr/local/bin run as root on a"
echo "  schedule, so a modification there is a persistence mechanism until"
echo "  proven otherwise. Do not simply overwrite them — the modification is"
echo "  the evidence of how they got in."
echo "    doas wp-malware-scan.sh full"
echo "    doas podman logs --tail 100 wordpress"
exit 1
