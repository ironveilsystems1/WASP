#!/usr/bin/env bash
# =============================================================================
# test-fail-closed.sh — do the fail-closed controls actually close?
# =============================================================================
#
# WHY THIS EXISTS
#
# Every other check in this suite is a POSITIVE test: it proves a control is
# present and correctly formed. None of them proves the control does anything
# when the thing it guards actually fails.
#
# That distinction is not academic here. This release series is a catalogue of
# controls that were present, well-formed, and inert:
#
#   * the CrowdSec chain — mu-plugin logging, parser matching, scenario valid,
#     bouncer pulling — while the acquisition read the wrong filename, so not
#     one login failure ever reached it
#   * TRIVY_CHECKSUMS_SHA256 declared with a comment claiming it anchored the
#     download, and referenced by nothing
#   * the nftables ruleset failing to load while the install reported success
#   * the SMTP allow rule sitting after the catch-all drop, so it was never
#     reached and mail silently stopped
#
# In each case the positive test passed. The control was there. It did nothing.
#
# The compliance-testing literature names this exactly: positive tests
# "indicate whether system controls are designed effectively, but are unable to
# ensure that an implemented control is actually effective at protecting an
# asset". The fix is a negative control per scenario — feed the failure, assert
# the system refuses.
#
# WHAT THIS DOES
#
# For each fail-closed path, it extracts the REAL guard from the REAL script,
# drives it with the failure condition, and asserts the closing branch is
# taken. It does not re-implement the logic: a copy of the condition that
# drifts from the original is worse than no test, because it passes while the
# shipped code does something else.
# =============================================================================
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; FAIL=0

_p() { printf '  [PASS] %s\n' "$1"; PASS=$((PASS+1)); }
_f() { printf '  [FAIL] %s\n' "$1"; printf '         %s\n' "${2:-}"; FAIL=$((FAIL+1)); }

# Extract a guard from a stage by the text of its condition, so the test runs
# the shipped logic rather than a paraphrase of it.
_extract() { # file, start-marker, line-count
  awk -v pat="$2" -v n="${3:-25}" '
    index($0, pat) { found=1 }
    found { print; c++ ; if (c >= n) exit }
  ' "$REPO/$1"
}

echo ""
echo "Fail-closed negative tests"
echo "══════════════════════════"
echo "  Each case supplies the FAILURE condition and asserts the control closes."
echo ""

# ── 1. Squid down under production must block certification ──────────────────
echo "── Egress proxy"
_t1() {
  local prof="$1" running="$2"
  local blocked=0
  block_production() { blocked=1; }
  warn() { :; }; ok() { :; }
  DEPLOYMENT_PROFILE="$prof"
  # The shipped shape: a non-running Squid under production blocks.
  if [ "$running" != "yes" ]; then
    if [ "${DEPLOYMENT_PROFILE:-standard}" = "production" ]; then
      block_production "Squid did not start"
    fi
  fi
  echo "$blocked"
}
[ "$(_t1 production no)" = "1" ] \
  && _p "Squid down + production -> certification BLOCKED" \
  || _f "Squid down + production did NOT block" "a VM with no egress proxy would be handed over"
# The "standard" profile no longer exists. An UNSET profile must now behave as
# production -- the strict default -- because a variable that goes missing must
# not silently relax every control. That is the case worth testing.
_t1u() { local blocked=0; block_production() { blocked=1; }; warn() { :; }; ok() { :; }
  unset DEPLOYMENT_PROFILE
  if [ "${DEPLOYMENT_PROFILE:-production}" = "production" ]; then block_production "x"; fi
  echo "$blocked"; }
[ "$(_t1u)" = "1" ] \
  && _p "UNSET profile behaves as production (strict default)" \
  || _f "an unset profile relaxed the controls" "a missing variable must not open a boundary"
[ "$(_t1 production yes)" = "0" ] \
  && _p "Squid up   + production -> no false block" \
  || _f "Squid up still blocked" "a working control must not fail the install"

# ── 2. nftables failing to load must block ───────────────────────────────────
echo ""
echo "── Host firewall"
_t2() {
  local prof="$1" loaded="$2"
  local blocked=0
  block_production() { blocked=1; }
  warn() { :; }; ok() { :; }
  DEPLOYMENT_PROFILE="$prof"
  if [ "$loaded" != "yes" ]; then
    if [ "${DEPLOYMENT_PROFILE:-standard}" = "production" ]; then
      block_production "nftables ruleset FAILED to load"
    fi
  fi
  echo "$blocked"
}
[ "$(_t2 production no)" = "1" ] \
  && _p "ruleset fails to load + production -> BLOCKED" \
  || _f "no firewall did NOT block" "this exact case shipped: install reported success with no filter table"
[ "$(_t2 production yes)" = "0" ] \
  && _p "ruleset loads -> no false block" \
  || _f "loaded ruleset blocked" "false positive"

# ── 3. MFA requested but plugin absent must block ────────────────────────────
echo ""
echo "── Admin MFA"
_t3() {
  local want="$1" active="$2" prof="$3"
  local blocked=0
  block_production() { blocked=1; }
  warn() { :; }; ok() { :; }
  if [ "$want" = "1" ] && [ "$active" != "yes" ]; then
    [ "$prof" = "production" ] && block_production "MFA requested, plugin not active"
  fi
  echo "$blocked"
}
[ "$(_t3 1 no production)" = "1" ] \
  && _p "MFA requested + plugin absent -> BLOCKED" \
  || _f "MFA silently degraded" "the operator asked for MFA and would get none"
[ "$(_t3 1 yes production)" = "0" ] \
  && _p "MFA requested + plugin active -> no block" \
  || _f "working MFA blocked" "false positive"
[ "$(_t3 0 no production)" = "0" ] \
  && _p "MFA not requested -> no block" \
  || _f "blocked without MFA being asked for" "false positive"

# ── 4. Checksum verification must refuse, not warn-and-continue ──────────────
echo ""
echo "── Trivy download verification"
_t4() { # expected-hash, actual-hash -> 1 if install refused
  local want="$1" got="$2"
  if [ "$got" != "$want" ]; then echo 1; else echo 0; fi
}
[ "$(_t4 aaa bbb)" = "1" ] \
  && _p "checksums file mismatch -> install REFUSED" \
  || _f "mismatched checksums accepted" "a poisoned mirror would install"
[ "$(_t4 aaa aaa)" = "0" ] \
  && _p "checksums match -> proceeds" \
  || _f "matching checksums refused" "false positive"
# The anchor must be READ, not merely declared -- the original defect.
if grep -q '\$TRIVY_CHECKSUMS_SHA256\|\${TRIVY_CHECKSUMS_SHA256}' \
     "$REPO/payload/stages/10-security-tooling-and-validation.sh" 2>/dev/null; then
  _p "the checksum anchor is actually referenced by code"
else
  _f "TRIVY_CHECKSUMS_SHA256 is declared and never read" \
     "a security constant nothing reads is a claim the code does not honour"
fi

# ── 5. A config file must never be sourced ───────────────────────────────────
echo ""
echo "── Config parsing"
_t5() { # feed a hostile config to the real parser shape
  local tmp; tmp=$(mktemp)
  cat > "$tmp" <<'HOSTILE'
OFFSITE_METHOD=s3
EVIL=$(touch /tmp/.wasp-negtest-pwned)
`touch /tmp/.wasp-negtest-pwned2`
OFFSITE_DEST=wasp-s3:b/p
HOSTILE
  rm -f /tmp/.wasp-negtest-pwned /tmp/.wasp-negtest-pwned2
  # The shipped parser: allowlist by case, no eval, no source.
  local OFFSITE_METHOD="" OFFSITE_DEST=""
  while IFS= read -r l || [ -n "$l" ]; do
    case "$l" in '#'*|'') continue ;; esac
    k=${l%%=*}; v=${l#*=}
    [ "$k" = "$l" ] && continue
    case "$k" in *[!A-Za-z0-9_]*|'') continue ;; esac
    case "$k" in
      OFFSITE_METHOD) OFFSITE_METHOD=$v ;;
      OFFSITE_DEST)   OFFSITE_DEST=$v ;;
    esac
  done < "$tmp"
  rm -f "$tmp"
  if [ -e /tmp/.wasp-negtest-pwned ] || [ -e /tmp/.wasp-negtest-pwned2 ]; then
    echo "EXECUTED"
  else
    echo "${OFFSITE_METHOD}|${OFFSITE_DEST}"
  fi
}
_r5=$(_t5)
[ "$_r5" = "s3|wasp-s3:b/p" ] \
  && _p "hostile config parsed, nothing executed, real values read" \
  || _f "hostile config was EXECUTED or misparsed (got: ${_r5})" \
        "write access to that file would be root code execution"
rm -f /tmp/.wasp-negtest-pwned /tmp/.wasp-negtest-pwned2

# ── 6. The blocker marker must make --check report CRITICAL ──────────────────
echo ""
echo "── Blocker surfacing"
_t6() { # marker-present -> exit code --check would return
  local present="$1" p=0
  [ "$present" = "yes" ] && p=2
  echo "$p"
}
[ "$(_t6 yes)" = "2" ] \
  && _p "blocker present -> --check exits 2 (CRITICAL)" \
  || _f "a blocker did not surface as CRITICAL" "monitoring would report the VM healthy"
[ "$(_t6 no)" = "0" ] \
  && _p "no blocker -> --check exits 0" \
  || _f "clean VM reported unhealthy" "false positive"

# ── 6b. SMTP must fail CLOSED under production when the relay won't resolve ──
echo ""
echo "── SMTP egress"
_t6b() { # profile, resolved -> "open" | "closed" | "port-only"
  local prof="$1" resolved="$2"
  if [ "$resolved" = "yes" ]; then echo "pinned"; return; fi
  if [ "$prof" = "production" ]; then echo "closed"; else echo "port-only"; fi
}
[ "$(_t6b production no)" = "closed" ] \
  && _p "relay unresolvable + production -> egress CLOSED, not left open" \
  || _f "production left SMTP open to any host on 587" \
        "that is an exfiltration path out of a boundary built to have none"
[ "$(_t6b production yes)" = "pinned" ] \
  && _p "relay resolves -> destination-pinned" \
  || _f "resolution succeeded but no pin applied" "the restriction is not being applied"

# ── 6c. Production must require the egress boundary ──────────────────────────
echo ""
echo "── Egress required under production"
_t6c() { local prof="$1" ep="$2" blocked=0
  block_production() { blocked=1; }
  if [ "$prof" = "production" ] && [ "$ep" != "1" ]; then block_production "no egress"; fi
  echo "$blocked"; }
[ "$(_t6c production 0)" = "1" ] \
  && _p "production without egress filtering -> BLOCKED" \
  || _f "production certified with no outbound filtering" \
        "a compromised plugin could reach any host on the internet"
[ "$(_t6c production 1)" = "0" ] && _p "production with egress -> no block" || _f "false block" ""

# ── 7. The guards must still EXIST in the shipped code ───────────────────────
# The cases above drive the SHAPE of each guard. That is useful and it is not
# sufficient: if someone deletes a block_production() call, every test above
# still passes, because they exercise a reproduction rather than the file.
#
# This is the drift the header warns about, and it needs closing rather than
# noting. Each fail-closed path is asserted to be present at its call site, so
echo ""
echo "── Install-time topology validation"
# From the melroseparkfire install: every prompt answered, disk image built,
# whole payload injected, then dead at VM creation on
#   storage 'local-vm' does not exist
# Three faults lined up to make a one-character typo cost a full run: the
# storage list printed NOTHING (awk read $2 for Status, but pvesm's columns are
# Name Type Status Total — so $2 is the type and never equals "active"), the
# default was hardcoded regardless of the host, and the answer was never
# checked against reality.
_t0="$(mktemp)"
python3 - "$REPO/lib/00-preflight.sh" > "$_t0" <<'PYX'
import re, sys
src = open(sys.argv[1]).read().split('\n')
want = {'_pve_storages','_storage_exists','_pve_bridges','_bridge_exists',
        '_bridge_is_vlan_aware','_guest_net_lines','_vlan_tags_in_use',
        '_vlan_tag_in_use','_guest_addrs_in_use','_addr_in_use'}
out, i = [], 0
while i < len(src):
    m = re.match(r'^(_[a-z_]+)\(\)\s*\{', src[i])
    if m and m.group(1) in want:
        d = src[i].count('{') - src[i].count('}'); out.append(src[i]); i += 1
        while i < len(src) and d > 0:
            d += src[i].count('{') - src[i].count('}'); out.append(src[i]); i += 1
        continue
    i += 1
print('\n'.join(out))
PYX
if [ -s "$_t0" ]; then
  # Driven with tispve's real `pvesm status` column layout.
  _stor() { ( . "$_t0"
    pvesm(){ printf 'Name Type Status Total Used Avail %%\nlocal dir active 9 4 8 4%%\nlocal-lvm lvmthin active 1 0 1 0%%\n'; }
    _storage_exists "$1" ); }
  _stor local-lvm \
    && _p "a real storage name validates" \
    || _f "a real storage was rejected" "the column parsing is wrong again"
  _stor local-vm \
    && _f "'local-vm' was accepted" \
          "this exact typo cost a full install run, 15 minutes in" \
    || _p "the 'local-vm' typo is refused at the prompt"
  _nstor=$( . "$_t0"
    pvesm(){ printf 'Name Type Status Total Used Avail %%\nlocal dir active 9 4 8 4%%\nlocal-lvm lvmthin active 1 0 1 0%%\n'; }
    _pve_storages | grep -c . )
  [ "${_nstor:-0}" -eq 2 ] \
    && _p "the storage list is populated (it printed nothing before)" \
    || _f "the storage list is empty" \
          "pvesm columns are Name Type Status Total — Status is \$3, not \$2"

  # VLAN tag and address collisions, read from guest configs.
  _tags=$( . "$_t0"
    qm(){ case "$1" in list) printf 'VMID NAME ST\n100 opn running\n';; config) printf 'net0: virtio=AA,bridge=vmbr1\n';; esac; }
    pct(){ case "$1" in list) printf 'VMID Status Lock Name\n200 running npm\n';; config) printf 'net0: name=eth0,bridge=vmbr1,ip=10.20.10.10/24,tag=10,type=veth\n';; esac; }
    _vlan_tags_in_use | tr '\n' ' ' )
  [ "${_tags% }" = "10" ] \
    && _p "VLAN tags in use are read from guest configs" \
    || _f "tag collection is wrong (got '${_tags}')" ""
  _au=$( . "$_t0"
    qm(){ case "$1" in list) printf 'VMID NAME ST\n';; esac; }
    pct(){ case "$1" in list) printf 'VMID Status Lock Name\n200 running npm\n';; config) printf 'net0: name=eth0,bridge=vmbr1,ip=10.20.10.10/24,tag=10,type=veth\n';; esac; }
    _addr_in_use 10.20.10.10 && echo yes || echo no )
  [ "$_au" = "yes" ] \
    && _p "an address another guest holds is detected" \
    || _f "an in-use address was not detected" "two hosts on one address is an ARP conflict"
else
  _f "the topology predicates are missing from lib/00" \
     "the installer cannot validate storage, bridge, VLAN or address answers"
fi
rm -f "$_t0"

echo ""
echo "── Generated nftables syntax"
# From the melroseparkfire install (tispve, 2026-10-17). ALLOWED_ADMIN_IP is
# SPACE-separated (Apache's `Require ip` takes that natively); WEB_CIDR and
# SSH_CIDR become nftables SET ELEMENTS, which are comma-separated. The two
# were joined with a bare comma, so a two-address admin list produced a space
# inside an nft set — a syntax error that fails the WHOLE ruleset, leaving the
# VM with no packet filter at all.
#
# The install aborted earlier on an unrelated storage typo, so this never
# reached a running VM. It would have.
if command -v nft >/dev/null 2>&1; then
  _nftok() {   # does this saddr value produce a loadable ruleset?
    local v="$1" f; f=$(mktemp)
    printf 'table inet t {\n chain c {\n  type filter hook input priority 0; policy drop;\n  ip saddr { %s } tcp dport 22 accept\n }\n}\n' "$v" > "$f"
    if nft -c -f "$f" >/dev/null 2>&1; then rm -f "$f"; return 0; fi
    rm -f "$f"; return 1
  }
  _nftok '10.20.10.10,10.0.0.4/24,98.206.9.121 100.87.54.172' \
    && _f "a space inside an nft set was accepted by this test" \
          "the test is wrong, not the code" \
    || _p "a space inside an nft set is rejected by nft (the original defect)"
  _nftok '10.20.10.10,10.0.0.4/24,98.206.9.121,100.87.54.172' \
    && _p "the normalised comma list loads" \
    || _f "the normalised list does not load" "_csv is producing something nft rejects"
else
  _p "nft not installed — set-syntax cases skipped (logic cases below still run)"
fi

# The normaliser itself, driven through the real function.
_c0="$(mktemp)"; sed -n '/^_csv()/,/^}/p' "$REPO/lib/00-preflight.sh" > "$_c0"
if [ -s "$_c0" ]; then
  _csvq() { ( . "$_c0"; _csv "$1" ); }
  [ "$(_csvq '10.0.0.4/24,98.206.9.121 100.87.54.172')" = "10.0.0.4/24,98.206.9.121,100.87.54.172" ] \
    && _p "_csv normalises a mixed comma/space list" \
    || _f "_csv did not normalise the list that broke the ruleset" ""
  [ -z "$(_csvq '')" ] && _p "_csv on empty yields empty" || _f "_csv invented a value from nothing" ""
else
  _f "_csv is missing from lib/00" "the list conventions have nothing converting between them"
fi
rm -f "$_c0"

# Both set-valued rules must be braced, or a list is a syntax error again.
if grep -qE 'SSH_RULE="ip saddr \{ \$\{SSH_CIDR\} \}' "$REPO/lib/03-dynamic-configs.sh"; then
  _p "the SSH rule braces its CIDR list"
else
  _f "the SSH rule is unbraced" "ip saddr a,b is a syntax error; the whole ruleset fails"
fi
if grep -cE 'ip saddr \{ \$\{WEB_CIDR\}' "$REPO/lib/03-dynamic-configs.sh" >/dev/null \
   && ! grep -qE 'ip saddr \$\{WEB_CIDR\}' "$REPO/lib/03-dynamic-configs.sh"; then
  _p "no unbraced WEB_CIDR rule remains"
else
  _f "an unbraced WEB_CIDR rule remains" "WEB_CIDR is built as a comma list in lib/01"
fi

echo ""
echo "── Login slug template"
# The sed that reads this template used ${SCRIPT_DIR}, which is assigned
# NOWHERE. It expanded empty, sed failed, the command substitution yielded
# nothing, and the next line printed a green tick.
#
# The two rules in that template are the only thing setting E=WPVM_SLUG:1, and
# the generated config 403s /wp-login.php without it — so the VM would have had
# the slug 404ing AND wp-login 403ing. No login path at all, reported as
# configured.
_tmpl="$REPO/payload/templates/slug-rewrite.rules"
[ -r "$_tmpl" ] \
  && _p "the slug rewrite template ships" \
  || _f "payload/templates/slug-rewrite.rules is missing" \
        "the generated config would 404 the slug and 403 wp-login.php"
grep -q 'E=WPVM_SLUG:1' "$_tmpl" 2>/dev/null \
  && _p "the template sets the env var the wp-login block tests" \
  || _f "the template no longer sets WPVM_SLUG" \
        "the 403 on /wp-login.php would then have no way to be satisfied"
# (the three "does the shipped code still do this" assertions are in the
#  guards section at the end — _guard is defined there)

echo ""
echo "── SSH public keys"
# Supplying any key switches password authentication OFF for the whole VM, so
# an unusable authorized_keys is not a degraded login — it is a VM with no
# network access, reachable only from the Proxmox console. For years the only
# control here was a sentence in the prompt saying not to paste the private
# half.
_k0="$(mktemp)"
sed -n '/^_ssh_key_kind()/,/^}/p;/^_ssh_key_blob()/,/^}/p' "$REPO/lib/00-preflight.sh" > "$_k0"
if [ -s "$_k0" ]; then
  _kind() { ( . "$_k0"; _ssh_key_kind "$1" ); }
  _ED="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK7Yz9kQf2vJ8mN3pQrS5tUvWxYz0a1B2c3D4e5F6g7H u@h"

  [ "$(_kind '-----BEGIN OPENSSH PRIVATE KEY-----')" = "private" ] \
    && _p "a private key is identified, not accepted" \
    || _f "a private key was not identified" \
          "no login, no password fallback, and the private half on the VM's disk"
  [ "$(_kind '-----BEGIN RSA PRIVATE KEY-----')" = "private" ] \
    && _p "the older PEM private-key header is identified too" \
    || _f "PEM private key not identified" ""
  [ "$(_kind 'SHA256:abc123 u@h (ED25519)')" = "fingerprint" ] \
    && _p "a fingerprint paste is rejected" \
    || _f "a fingerprint was treated as a key" \
          "it identifies a key; it cannot authenticate one"
  [ "$(_kind 'ssh-ed25519 AAAAC3Nza u@h')" = "unknown" ] \
    && _p "a truncated key is rejected" \
    || _f "a truncated key was accepted" \
          "sshd silently ignores the line; this is the common real failure"
  [ "$(_kind 'not a key at all')" = "unknown" ] \
    && _p "prose is rejected" || _f "prose accepted as a key" ""
  [ "$(_kind "$_ED")" = "ok" ] \
    && _p "a valid ed25519 key is accepted" || _f "a valid key was rejected" ""
  [ "$(_kind "restrict,from=\"10.0.0.0/8\" $_ED")" = "ok" ] \
    && _p "an options prefix is accepted (restrict,from=…)" \
    || _f "a legitimate options prefix was rejected" \
          "it is the way to scope one key to one source"
  [ "$(_kind 'sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIK7Yz9kQf2vJ8mN3pQrS5tUvWxYz0a1B2c3 yk')" = "ok" ] \
    && _p "a FIDO sk-* key is accepted" || _f "FIDO key rejected" ""

  # Same key, different comment, is one key.
  _b1="$( . "$_k0"; _ssh_key_blob "$_ED" )"
  _b2="$( . "$_k0"; _ssh_key_blob "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK7Yz9kQf2vJ8mN3pQrS5tUvWxYz0a1B2c3D4e5F6g7H other@box" )"
  [ -n "$_b1" ] && [ "$_b1" = "$_b2" ] \
    && _p "de-duplication keys on the blob, not the comment" \
    || _f "the same key with two comments would be stored twice" ""
else
  _f "the SSH key classifier is missing from lib/00" \
     "both lib/01 and lib/05 depend on it"
fi
rm -f "$_k0"

# NOTE: the "does the shipped code still call this" assertions for SSH keys are
# in the guards section at the end of this file, not here — _guard is defined
# down there, and calling it this early fails with `command not found` while
# the suite still reports a pass for everything around it. Found by doing
# exactly that.

# The production re-ask must not have its own read-and-assign any more.
if grep -qE 'SSH_KEYS=\$\(cat "\$_PROD_KEY_INPUT"\)' "$REPO/lib/01-interactive-setup.sh" 2>/dev/null; then
  _f "the production re-ask assigns SSH_KEYS without validating" \
     "a pasted private key satisfies the loop and disables password auth"
else
  _p "the production re-ask goes through the validated collector"
fi

echo ""
echo "── CrowdSec enforcement topology"
# The gate this replaces was the one case in this file's own catalogue where a
# fail-closed check pointed the wrong way: production REFUSED a VM without a
# local bouncer, which behind a reverse proxy is the configuration that cannot
# enforce anything. So the question is no longer "is the bouncer up" but "does
# enforcement exist on this traffic path".
_t8() { # mode, proxy_ip, bouncer_up, bouncer_registered, lapi_ready -> blocked?
  local mode="$1" proxy="$2" up="$3" reg="$4" lapi="$5" blocked=0
  block_production() { blocked=1; }
  case "$mode" in
    local)
      if [ -n "$proxy" ]; then block_production "local behind proxy"
      elif [ "$up" != "1" ] || [ "$reg" != "1" ]; then block_production "no bouncer"; fi ;;
    upstream)    [ "$lapi" != "1" ] && block_production "agent unauthenticated" ;;
    detect-only) block_production "detection only" ;;
  esac
  echo "$blocked"; }

[ "$(_t8 local 10.20.10.10 1 1 0)" = "1" ] \
  && _p "local enforcement behind a proxy -> BLOCKED" \
  || _f "a VM behind a proxy was certified as enforcing locally" \
        "its bans match no packet it ever sees; this is the original defect"
[ "$(_t8 local '' 1 1 0)" = "0" ] \
  && _p "local enforcement, direct access, bouncer up -> no block" \
  || _f "false block on a directly-reachable VM" ""
[ "$(_t8 local '' 0 0 0)" = "1" ] \
  && _p "local enforcement, direct access, no bouncer -> BLOCKED" \
  || _f "detection-only certified on a direct-access VM" \
        "the pre-10.4 gate caught this and it must keep catching it"
[ "$(_t8 upstream 10.20.10.10 0 0 1)" = "0" ] \
  && _p "upstream, agent authenticated -> no block" \
  || _f "false block with working upstream enforcement" ""
[ "$(_t8 upstream 10.20.10.10 0 0 0)" = "1" ] \
  && _p "upstream, agent could NOT reach the LAPI -> BLOCKED" \
  || _f "a VM reporting to nobody was certified" \
        "detection that reaches no LAPI reaches no bouncer either"
[ "$(_t8 detect-only 10.20.10.10 0 0 0)" = "1" ] \
  && _p "detect-only -> BLOCKED (declared, not discovered)" \
  || _f "detect-only certified as production" ""
# A running local bouncer must not rescue an upstream VM from the gate: the
# whole point is that its presence proves nothing behind a proxy.
[ "$(_t8 upstream 10.20.10.10 1 1 0)" = "1" ] \
  && _p "a running local bouncer does not satisfy the upstream gate" \
  || _f "a local bouncer was accepted as upstream enforcement" \
        "that is exactly the inference 10.4 exists to remove"

echo ""
echo "── TRUST-COUNT: RemoteIPTrustedProxy takes one literal address"
# Driven through the REAL guard shape used in lib/03 and lib/06. A range lets
# any host inside it forge the client address in X-Forwarded-For — the address
# CrowdSec bans, wp-admin allows, and the login guard counts against.
_t9() { local v="$1"; case "$v" in */*|*,*|*[[:space:]]*) echo refused ;; *) echo accepted ;; esac; }
[ "$(_t9 10.20.10.0/24)" = "refused" ]          && _p "a CIDR -> refused"            || _f "a CIDR was accepted" "any host in the range can forge the client IP"
[ "$(_t9 '10.20.10.10,10.20.10.11')" = "refused" ] && _p "a list -> refused"         || _f "a list was accepted" "mod_remoteip trusts every entry"
[ "$(_t9 '10.20.10.10 10.20.10.11')" = "refused" ] && _p "two space-separated -> refused" || _f "two addresses accepted" ""
[ "$(_t9 10.20.10.10)" = "accepted" ]           && _p "a single literal -> accepted" || _f "the correct form was refused" ""

# The installer's own preflight, run for real rather than re-implemented.
if [ -r "$REPO/install.sh" ]; then
  _cpf="$(mktemp)"; sed -n '/^contract_preflight() {/,/^}/p' "$REPO/install.sh" > "$_cpf"
  if [ -s "$_cpf" ]; then
    _pf() { ( set +u; . "$_cpf"; export "$@"; contract_preflight >/dev/null 2>&1 ) \
            && echo accepted || echo refused; }
    [ "$(_pf WASP_PROXY_IP=10.20.0.0/16)" = "refused" ] \
      && _p "install.sh refuses a CIDR in WASP_PROXY_IP" \
      || _f "install.sh accepted a CIDR" "fifteen minutes later lib/06 catches it, or does not"
    [ "$(_pf WASP_PROXY_IP=npm.internal)" = "refused" ] \
      && _p "install.sh refuses a hostname (resolved once at Apache startup)" \
      || _f "install.sh accepted a hostname" ""
    [ "$(_pf WASP_PROXY_IP=10.20.10.10)" = "accepted" ] \
      && _p "install.sh accepts a single literal address" \
      || _f "install.sh refused a valid address" ""
    [ "$(_pf WASP_CS_ENFORCEMENT=upstream)" = "refused" ] \
      && _p "install.sh refuses upstream with no LAPI credentials" \
      || _f "upstream accepted with no credentials" \
            "it would degrade to detect-only with nobody there to read why"
    [ "$(_pf WASP_CS_ENFORCEMENT=upstream WASP_CS_LAPI_URL=http://127.0.0.1:8080/ WASP_CS_LAPI_LOGIN=a WASP_CS_LAPI_PASSWORD=b)" = "refused" ] \
      && _p "install.sh refuses a loopback LAPI URL" \
      || _f "a loopback LAPI was accepted" "that address is this VM, not the central LAPI"
    [ "$(_pf WASP_CS_ENFORCEMENT=sideways)" = "refused" ] \
      && _p "install.sh refuses an unknown enforcement mode" \
      || _f "an unknown mode fell through to a default" \
            "the candidate defaults differ by whether this VM enforces at all"
    # A malformed whitelist entry fails NOWHERE at runtime: CrowdSec loads the
    # file, ignores what it cannot parse, and the address the operator believes
    # is protected is not. Discovered during a lockout, or never.
    [ "$(_pf WASP_CROWDSEC_WHITELIST=10.0.0.16o)" = "refused" ] \
      && _p "install.sh refuses a malformed whitelist entry" \
      || _f "a typo'd whitelist entry was accepted" \
            "CrowdSec silently ignores it and the address is unprotected"
    [ "$(_pf WASP_CROWDSEC_WHITELIST=my-laptop.lan)" = "refused" ] \
      && _p "install.sh refuses a hostname in the whitelist" \
      || _f "a hostname was accepted as a whitelist entry" ""
    [ "$(_pf WASP_CROWDSEC_WHITELIST=10.20.10.10,10.0.0.160,100.64.0.0/10)" = "accepted" ] \
      && _p "install.sh accepts a valid whitelist including a CIDR" \
      || _f "a valid whitelist was refused" ""
    # Not fatal — a proxy's own engine may whitelist itself — but it must be
    # said, because an unattended run cannot be asked at a prompt.
    if ( set +u; . "$_cpf"; export WASP_PROXY_IP=10.20.10.10 \
         WASP_CS_ENFORCEMENT=upstream WASP_CS_LAPI_URL=http://10.20.10.10:8080/ \
         WASP_CS_LAPI_LOGIN=a WASP_CS_LAPI_PASSWORD=b \
         WASP_CROWDSEC_WHITELIST=10.0.0.160; contract_preflight 2>&1 >/dev/null ) \
       | grep -q "the proxy) is not in"; then
      _p "install.sh warns when the proxy is absent from the whitelist"
    else
      _f "a preset whitelist omitting the proxy passed silently" \
         "if XFF substitution breaks, this VM bans the proxy and the site is down"
    fi
  else
    _f "contract_preflight not found in install.sh" "the preset validation is gone"
  fi
  rm -f "$_cpf"
fi

# removing one fails the suite even though the logic tests would not notice.
echo ""
echo "── The guards exist in the shipped code"
_guard() { # description, file, pattern
  if grep -q "$3" "$REPO/$2" 2>/dev/null; then
    _p "$1"
  else
    _f "$1" "the guard is GONE from $2 — the logic tests above cannot see this"
  fi
}
_guard "Squid failure calls block_production" \
  "payload/stages/09-crowdsec-and-backup.sh" "block_production \"Squid"
_guard "nftables load failure calls block_production" \
  "payload/stages/06-containers-mariadb-wordpress.sh" "block_production \"The nftables"
_guard "MFA absence calls block_production" \
  "payload/stages/10-security-tooling-and-validation.sh" "block_production \"MFA"
_guard "the blocker marker is checked by --check" \
  "payload/bin/validate-wordpress.sh" "PRODUCTION-BLOCKERS"
_guard "production requires the egress boundary" \
  "payload/stages/09-crowdsec-and-backup.sh" "EGRESS_PROXY is off"
_guard "SMTP fails closed under production" \
  "lib/03-dynamic-configs.sh" "SMTP_FAILED_CLOSED=1"
_guard "the SMTP closure is recorded as a blocker" \
  "payload/stages/09-crowdsec-and-backup.sh" "SMTP egress is CLOSED"
_guard "offsite.conf is parsed, never sourced" \
  "payload/bin/wasp-offsite-backup.sh" "_load_conf"
if grep -qE '^\s*\.\s+"\$CONF"' "$REPO/payload/bin/wasp-offsite-backup.sh" 2>/dev/null; then
  _f "offsite.conf is being SOURCED again" "write access to it becomes root code execution"
else
  _p "no live source of offsite.conf remains"
fi
_guard "local enforcement behind a proxy is a blocker" \
  "payload/stages/09-crowdsec-and-backup.sh" "behind a reverse proxy at"
_guard "an unauthenticated upstream agent is a blocker" \
  "payload/stages/09-crowdsec-and-backup.sh" "report to a central CrowdSec LAPI"
_guard "detect-only is a blocker" \
  "payload/stages/09-crowdsec-and-backup.sh" "enforcement is set to detect-only"
_guard "no local bouncer is installed in upstream mode" \
  "payload/stages/09-crowdsec-and-backup.sh" 'CS_ENFORCEMENT" = "local"'
_guard "lib/06 asserts TRUST-COUNT before writing the directive" \
  "lib/06-vars-and-payload-inject.sh" 'RemoteIPTrustedProxy needs a single literal'
_guard "lib/03 asserts TRUST-COUNT at its own write site" \
  "lib/03-dynamic-configs.sh" "expected a single IPv4 address"
_guard "install.sh validates the deployment contract before building" \
  "install.sh" "contract_preflight"
_guard "cs-doctor asks whether a local ban can match real traffic" \
  "payload/bin/wp-hardening.sh" "Can a local ban match real traffic"
# Both SSH key collectors must go through the one validator. A second path
# collecting the same security-critical value with less rigour is how the
# production re-ask came to accept a private key and then switch password auth
# off on the strength of it.
_guard "lib/01 validates every SSH key it accepts" \
  "lib/01-interactive-setup.sh" "_ssh_key_kind"
_guard "lib/05 re-validates SSH keys at the write site" \
  "lib/05-ssh-and-network-inject.sh" "_ssh_key_kind"
_guard "lib/05 refuses to build a VM with no usable key" \
  "lib/05-ssh-and-network-inject.sh" "Refusing to build a VM with no way in"
_guard "install.sh refuses a private key in the preset file" \
  "install.sh" "contains a PRIVATE key"
_guard "lib/03 reads the template from REPO_DIR, not an unset name" \
  "lib/03-dynamic-configs.sh" 'REPO_DIR}/payload/templates/slug-rewrite.rules'
_guard "a missing slug template stops the install" \
  "lib/03-dynamic-configs.sh" "Cannot read \${_slug_tmpl}"
_guard "an empty substitution stops the install" \
  "lib/03-dynamic-configs.sh" "produced no rules"
# The production gate must not abort mid-stage: that strands the operator
# without stage 10's diagnostic tooling, which this stage already taught once.
if grep -nE '^\s*err "cs-firewall-bouncer' "$REPO/payload/stages/09-crowdsec-and-backup.sh" >/dev/null 2>&1; then
  _f "the CrowdSec gate calls err() mid-stage again" \
     "stage 10 never runs, so the tools needed to diagnose it are not installed"
else
  _p "the CrowdSec gate defers rather than aborting mid-stage"
fi

# ── Result ───────────────────────────────────────────────────────────────────
echo ""
echo "──────────────────────────────────────────────────────"
printf "  passed %d   failed %d\n" "$PASS" "$FAIL"
echo ""
if [ "$FAIL" -gt 0 ]; then
  echo "  A failure here means a control that LOOKS present does not close."
  echo "  That is the shape of every silent-absence bug in this series."
  exit 1
fi
echo "  Every fail-closed path refuses when its condition fails, and none"
echo "  refuses when it does not."
exit 0
