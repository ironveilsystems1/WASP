#!/usr/bin/env bash
# =============================================================================
# test-hive-role.sh — install.sh's "WASP Hive" role, the host-side parts
# =============================================================================
#
# install.sh can build a WASP Hive VM instead of a WordPress VM. A real run
# needs a Proxmox host; this exercises what can be exercised without one:
#   - lib/03 writes the Hive's ruleset (not WordPress's), and nft accepts it
#   - lib/06 stages hive/, install.sh and the manifest, writes no WordPress
#     payload, and writes a first-boot launcher that parses and passes the
#     operator's answers through, quoted
#   - an unsigned release is installed --unverified, said out loud; a signed
#     one is not
#   - install-hive.sh refuses a malformed address list before it touches
#     anything
#   - the Proxmox notes for a Hive carry no executable backticks
# lib/01's prompts for the role are syntax-checked only (they need a Proxmox
# host to run).
# =============================================================================
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
_p() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
_f() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n         %s\n' "$1" "${2:-}"; }
echo ""
echo "install.sh: the WASP Hive role"

bash -n "$REPO/lib/01-interactive-setup.sh" && _p "lib/01 (with the role choice and the Hive prompts) parses" || _f "lib/01 syntax" ""

# ── lib/03 ──
_nft=$(bash -c 'msg_ok(){ :; }; WASP_ROLE=hive SSH_CIDR="10.20.0.0/24, 10.30.0.5" HIVE_DASHBOARD_CIDR="10.20.0.0/24" HIVE_INGEST_CIDR="10.40.0.0/16";
                f(){ . "$1/lib/03-dynamic-configs.sh"; echo "after-return"; }; f "$1"; printf "%s\n" "$NFT_CONF"' _ "$REPO")
printf '%s\n' "$_nft" | grep -q 'table inet hive' && ! printf '%s\n' "$_nft" | grep -q 'wp-front' \
  && _p "lib/03 builds the Hive ruleset, and none of the WordPress one" || _f "lib/03 ruleset" "$(printf '%s' "$_nft" | head -5)"
printf '%s\n' "$_nft" | grep -q 'ip saddr { 10.20.0.0/24, 10.40.0.0/16 } tcp dport 8443 accept' \
  && _p "the service port is limited to the dashboard and WASP VM networks" || _f "service rule" "$(printf '%s' "$_nft" | grep 8443)"
printf '%s\n' "$_nft" | grep -q 'tcp dport 443 redirect to :8443' && _p "443 is redirected to the unprivileged service" || _f "redirect" ""
if command -v nft >/dev/null 2>&1; then
  printf '%s\n' "$_nft" | sed '/^after-return$/d' > "$T/hive.nft"
  nft -c -f "$T/hive.nft" 2>"$T/nft.err" && _p "nft accepts the ruleset" || _f "nft -c" "$(cat "$T/nft.err")"
fi

# ── lib/06 ──
_stage() {   # _stage <with-minisig 0|1>
  rm -rf "$T/mnt" "$T/repo"; mkdir -p "$T/mnt" "$T/repo"
  cp -a "$REPO/hive" "$REPO/install.sh" "$T/repo/"
  printf 'x  hive/hive_server.py\n' > "$T/repo/MANIFEST.sha256"
  [ "$1" = 1 ] && : > "$T/repo/MANIFEST.sha256.minisig"
  bash -c 'msg_ok(){ :; }; msg_warn(){ echo "WARN: $*"; }; msg_error(){ echo "ERR: $*"; exit 1; }
           MNT="$1" REPO_DIR="$2" WASP_ROLE=hive HN=wasp-hive HIVE_NAME="hive.mgmt.lan" SSH_CIDR="10.20.0.0/24"
           HIVE_DASHBOARD_CIDR="10.20.0.0/24" HIVE_INGEST_CIDR="10.40.0.0/16,10.41.0.0/16" WASP_PUBKEY="RWSexampleKey123+/="
           R="$3"; f(){ . "$R/lib/06-vars-and-payload-inject.sh"; echo "after-return"; }; f' _ "$T/mnt" "$T/repo" "$REPO" 2>&1
}
_o=$(_stage 1)
L="$T/mnt/etc/local.d/01-wasp-hive.start"
{ [ -r "$T/mnt/root/wasp-hive-release/hive/install-hive.sh" ] && [ -r "$T/mnt/root/wasp-hive-release/install.sh" ] \
  && [ -r "$T/mnt/root/wasp-hive-release/MANIFEST.sha256.minisig" ]; } \
  && _p "hive/, install.sh and the signed manifest are staged for verification on the VM" || _f "staging" "$_o"
[ ! -e "$T/mnt/etc/wp-install/vars.sh" ] && [ ! -d "$T/mnt/etc/wp-install/payload" ] \
  && _p "no WordPress payload or vars.sh is written for a Hive" || _f "WordPress payload staged" "$(ls "$T/mnt/etc/wp-install" 2>&1)"
printf '%s' "$_o" | grep -q '^after-return$' && _p "lib/06 returns cleanly after staging" || _f "lib/06 return" "$_o"
sh -n "$L" 2>/dev/null && _p "the first-boot launcher parses" || _f "launcher syntax" "$(cat "$L")"
# Run the launcher's install-hive.sh line with a stand-in that prints its arguments.
mkdir -p "$T/fake/hive"; printf '#!/bin/sh\nfor a in "$@"; do printf "[%%s]" "$a"; done\n' > "$T/fake/hive/install-hive.sh"
_args=$(sed -n 's|^if sh /root/wasp-hive-release/hive/install-hive.sh \(.*\) >> /var/log.*|\1|p' "$L")
_got=$(eval "sh $T/fake/hive/install-hive.sh $_args")
[ "$_got" = "[--name][hive.mgmt.lan][--ssh-cidr][10.20.0.0/24][--dashboard-cidr][10.20.0.0/24][--ingest-cidr][10.40.0.0/16,10.41.0.0/16][--pubkey][RWSexampleKey123+/=]" ] \
  && _p "the operator's answers reach install-hive.sh intact, and a signed release is not --unverified" || _f "launcher args" "$_got"
grep -q 'rm -f /etc/local.d/01-wasp-hive.start' "$L" && grep -q '/var/lib/wasp-hive/.installed' "$L" \
  && _p "the launcher removes itself only after a successful install" || _f "launcher self-removal" ""
_o=$(_stage 0)
grep -q -- '--unverified' "$L" && printf '%s' "$_o" | grep -q 'UNVERIFIED' \
  && _p "an unsigned release is installed --unverified, and the operator is told" || _f "unsigned" "$_o"

# ── install-hive.sh argument checks (before it touches anything) ──
for _bad in "--ingest-cidr 10.0.0.0/8;reboot" "--ssh-cidr 10.0.0.0/8,,10.1.0.0/16" "--dashboard-cidr fe80::/10" "--name a_b" "--pubkey RW\$(x)"; do
  _o=$(sh "$REPO/hive/install-hive.sh" $_bad 2>&1); _rc=$?
  [ "$_rc" = 2 ] && _p "install-hive.sh refuses: ${_bad}" || _f "accepted: ${_bad}" "rc=$_rc $_o"
done

# ── lib/07 notes ──
_n=$(bash -c 'WASP_ROLE=hive HN=wasp-hive HIVE_NAME=hive.mgmt.lan ADMIN_USER=hiveadmin VM_IP=192.0.2.7 ALPINE_VER=3.22 WASP_VERSION=10.13
              eval "$(sed -n "/^_wasp_hive_notes() {/,/^}/p; /^_wasp_vm_notes() {/,/^}/p" "$1/lib/07-vm-create-and-start.sh")"; _wasp_vm_notes' _ "$REPO" 2>&1)
printf '%s' "$_n" | grep -q '`ssh hiveadmin@192.0.2.7`' && printf '%s' "$_n" | grep -q '^WASP Hive' \
  && _p "the Proxmox notes describe the Hive, with commands shown and not run" || _f "notes" "$_n"

echo ""
printf '  passed %d   failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
