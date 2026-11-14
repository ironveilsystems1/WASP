#!/usr/bin/env bash
# =============================================================================
# test-verify-integrity.sh — the on-VM tooling check reports real changes only
# =============================================================================
#
# wasp-verify-integrity.sh checked the release manifest as it stands -- and a
# WordPress VM keeps only payload/ (stages/ under its own name), never
# install.sh, lib/ or hive/. Every VM therefore reported dozens of FAILED
# files forever. Since 10.16 the result is emailed weekly, so that permanent
# false alarm would have trained the operator to ignore the one real one.
#
# A VM-shaped tree is built from this checkout exactly as lib/06 stages it,
# with a manifest made by the release recipe. Asserted: clean reports clean;
# a changed staged file, a changed stage, and a changed installed tool are each
# reported by name. Host shell and BusyBox (BUSYBOX=..., required).
# =============================================================================
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
_p() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
_f() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n         %s\n' "$1" "${2:-}"; }
echo ""
echo "On-VM tooling integrity check"
[ "$(id -u)" -eq 0 ] || { _f "must run as root" ""; exit 1; }
BB="${BUSYBOX:-$(command -v busybox 2>/dev/null || true)}"

# The release manifest, by the documented recipe.
( cd "$REPO" && { printf '%s\n' install.sh; find lib payload hive -type f ! -path '*/__pycache__/*' | LC_ALL=C sort; } \
    | xargs sha256sum ) > "$T/MANIFEST.sha256"

_suite() { # label shell pathprefix
  L="$1"; SH="$2"; PP="$3"; V="$T/$L/etc"; B="$T/$L/bin"
  mkdir -p "$V/payload" "$V/stages" "$B"
  for _d in "$REPO"/payload/*/; do
    _n=$(basename "$_d"); [ "$_n" = stages ] && continue
    cp -a "$_d" "$V/payload/$_n"
  done
  cp -a "$REPO/payload/stages/." "$V/stages/"
  cp "$T/MANIFEST.sha256" "$V/"
  cp "$REPO"/payload/bin/*.sh "$B/"
  _v() { env PATH="$PP" WASP_INSTALL_DIR="$V" WASP_BIN_DIR="$B" "$SH" "$REPO/payload/bin/wasp-verify-integrity.sh" 2>&1; }
  echo ""
  echo "  ── under ${L}"
  out=$(_v); rc=$?
  { [ "$rc" = 0 ] && printf '%s' "$out" | grep -q 'Nothing has been modified' \
    && ! printf '%s' "$out" | grep -q 'install.sh\|lib/\|hive/'; } \
    && _p "$L: an untouched VM reports clean (install.sh, lib/, hive/ are not expected on it)" \
    || _f "$L: clean VM not clean" "rc=$rc $(printf '%s' "$out" | tail -8)"
  printf '%s' "$out" | grep -q 'matches the signed manifest ([0-9]* files)' \
    && _p "$L: says how many staged files it checked" || _f "$L: count" "$out"
  printf '\n# planted\n' >> "$V/payload/bin/wp-notify.sh"
  out=$(_v); rc=$?
  [ "$rc" = 1 ] && printf '%s' "$out" | grep -q 'payload/bin/wp-notify.sh' \
    && _p "$L: a changed staged file is reported by name" || _f "$L: staged change missed" "$out"
  cp "$REPO/payload/bin/wp-notify.sh" "$V/payload/bin/wp-notify.sh"
  printf '\n# planted\n' >> "$V/stages/08-update-tooling.sh"
  out=$(_v); rc=$?
  [ "$rc" = 1 ] && printf '%s' "$out" | grep -q 'stages/08-update-tooling.sh' \
    && _p "$L: a changed stage (kept as stages/) is reported" || _f "$L: stage change missed" "$out"
  cp "$REPO/payload/stages/08-update-tooling.sh" "$V/stages/"
  printf '\n# planted\n' >> "$B/update.sh"
  out=$(_v); rc=$?
  [ "$rc" = 1 ] && printf '%s' "$out" | grep -q "MODIFIED since install: $B/update.sh" \
    && _p "$L: a changed installed tool is reported" || _f "$L: installed change missed" "$out"
}
_suite host /bin/sh "/usr/local/bin:/usr/bin:/bin"
if [ -n "$BB" ] && "$BB" --list >/dev/null 2>&1; then
  mkdir -p "$T/bb"; for _a in $("$BB" --list); do ln -sf "$BB" "$T/bb/$_a"; done
  _suite busybox "$T/bb/sh" "$T/bb"
else
  _f "BusyBox not found: the Alpine-shell pass did not run" "set BUSYBOX=/path/to/busybox"
fi
echo ""
echo "  verify-integrity: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" = 0 ]
