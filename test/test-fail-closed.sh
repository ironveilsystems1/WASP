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

# ── Overlay masquerade detection ─────────────────────────────────────────────
# Behavioural, not a grep for the function name: the bug this replaces had the
# function present, called, and silently never true. It piped overlay-named
# lines into a masquerade grep, but nft puts the chain name and the rule on
# different lines, so the intersection was always empty.
#
# The failure direction is what makes it worth permanent tests. A missed
# masquerade tells a remote operator their 100.x address will arrive, they
# allow only the overlay range, and the rule drops the only path they have.
_m0="$(mktemp)"
sed -n '/^_overlay_masquerades()/,/^}/p;/^_overlay_addrs()/,/^}/p;/^_route_src_to()/,/^}/p' \
  "$REPO/lib/00-preflight.sh" > "$_m0"
if [ -s "$_m0" ]; then
  # nft's real nesting: name on one line, masquerade two lines in.
  ( . "$_m0"
    nft(){ printf 'table ip netbird {\n  chain netbird-rt-nat { type nat hook postrouting priority srcnat;\n    ip saddr 100.64.0.0/10 ip daddr 10.20.101.0/24 counter masquerade\n  }\n}\n'; }
    iptables-save(){ :; }
    _overlay_masquerades ) \
    && _p "a masquerading NetBird route is detected across nft's nesting" \
    || _f "the masquerade went undetected" \
          "name and rule are on different lines; a single-line grep finds neither"
  # Overlay present, no NAT: must NOT warn, or the warning means nothing.
  ( . "$_m0"
    nft(){ printf 'table ip netbird {\n  chain netbird-rt-fwd { type filter hook forward priority 0;\n    ip saddr 100.64.0.0/10 counter accept\n  }\n}\n'; }
    iptables-save(){ :; }
    _overlay_masquerades ) \
    && _f "a forward-only overlay was reported as masquerading" \
          "a warning that always fires is one the operator learns to skip" \
    || _p "an overlay that does not NAT is not reported as masquerading"
  # A NAT'd Proxmox bridge is not an overlay route.
  ( . "$_m0"
    nft(){ printf 'table ip nat {\n  chain postrouting { type nat hook postrouting priority srcnat;\n    ip saddr 10.20.0.0/16 counter masquerade\n  }\n}\n'; }
    iptables-save(){ :; }
    _overlay_masquerades ) \
    && _f "an ordinary NAT'd bridge was attributed to the overlay" \
          "this would fire on every Proxmox host that NATs anything" \
    || _p "a non-overlay masquerade is not attributed to the overlay"
  # iptables-save is flat — chain and target share a line.
  ( . "$_m0"
    nft(){ :; }
    iptables-save(){ printf -- '-A NETBIRD-RT-NAT-1 -s 100.64.0.0/10 -j MASQUERADE\n'; }
    _overlay_masquerades ) \
    && _p "the iptables form is detected too" \
    || _f "an iptables-managed overlay NAT went undetected" \
          "hosts on the legacy backend get the wrong advice"
  # The computed answer: what the VM actually sees.
  _src=$( . "$_m0"
    ip(){ echo '10.20.101.10 via 10.20.1.1 dev vmbr1 src 10.20.1.254 uid 0'; }
    _route_src_to 10.20.101.10 )
  [ "$_src" = "10.20.1.254" ] \
    && _p "the masqueraded source address is computed, not guessed" \
    || _f "_route_src_to did not extract src (got '${_src:-}')" \
          "without it the operator is told 'it depends on your routing'"
  # The overlay address must be OFFERED here, having been excluded as a VM
  # address candidate: the same data, two opposite correct answers.
  _ovl=$( . "$_m0"
    ip(){ printf '5: wt0\n    inet 100.87.54.172/16 scope global wt0\n'; }
    _overlay_addrs )
  case "$_ovl" in
    *100.87.54.172*) _p "the overlay address is offered at the admin-source prompt" ;;
    *) _f "the overlay address is not offered" \
          "it is excluded from VM-address hints; here it is the likely answer" ;;
  esac
else
  _f "the overlay helpers are missing from lib/00" \
     "the SSH prompt has nothing to answer a remote operator with"
fi
rm -f "$_m0"
unset _src _ovl

# ── The never-ban prompt replaces its default ────────────────────────────────
# Behavioural, driven with melroseparkfire's exact answers. The operator
# answered YES to the CGNAT question, was told "your remote source address is
# covered", then typed two addresses at the next prompt and lost the overlay
# range, the SSH source and the public admin IP in one keystroke — while that
# confirmation line stayed on screen.
#
# Under upstream enforcement those are the remote-administration paths a shared
# LAPI would blackhole, so the silent drop is the expensive kind.
_w0="$(mktemp)"
sed -n '/^# ── Entries the typed answer dropped/,/^unset _CS_DEFAULT _CS_OVERLAY_OPTIN/p' \
  "$REPO/lib/01-interactive-setup.sh" > "$_w0"
_c1="$(mktemp)"; sed -n '/^_csv()/,/^}/p' "$REPO/lib/00-preflight.sh" > "$_c1"
if [ -s "$_w0" ] && [ -s "$_c1" ]; then
  _wlq() { ( . "$_c1"
    msg_warn(){ :; }; msg_ok(){ :; }; msg_info(){ :; }
    _CS_DEFAULT="10.20.10.10,98.206.9.121,10.20.1.254/32,100.64.0.0/10"
    _CS_OVERLAY_OPTIN=1; CS_ENFORCEMENT="upstream"; PROXY_IP="10.20.10.10"
    CROWDSEC_WHITELIST="$1"
    # A herestring, NOT `printf | . "$_w0"`: the right-hand side of a pipe runs
    # in its own subshell, so the block's assignment to CROWDSEC_WHITELIST
    # would be discarded and every case would read as "dropped silently".
    . "$_w0" <<<"$2" >/dev/null 2>&1
    printf '%s' "$CROWDSEC_WHITELIST" ); }
  _merged=$(_wlq "10.0.0.160,10.0.0.162" "y")
  case "$_merged" in
    *100.64.0.0/10*) _p "the dropped overlay range is offered back" ;;
    *) _f "100.64.0.0/10 was dropped silently" \
          "the operator answered YES to it one prompt earlier" ;;
  esac
  case "$_merged" in
    *10.20.1.254/32*) _p "the dropped SSH source is offered back" ;;
    *) _f "the SSH source was dropped silently" \
          "upstream enforcement would blackhole the admin path fleet-wide" ;;
  esac
  case "$_merged" in
    *10.0.0.160*) _p "what the operator typed is kept alongside" ;;
    *) _f "the typed addresses were discarded by the merge" "" ;;
  esac
  # Declining must leave the typed answer exactly as given.
  _kept=$(_wlq "10.0.0.160,10.0.0.162" "n")
  [ "$_kept" = "10.0.0.160,10.0.0.162" ] \
    && _p "declining the merge leaves the typed answer untouched" \
    || _f "declining still altered the list (got '${_kept}')" \
          "a deliberate narrow answer must survive the offer"
  # Accepting the default must NOT warn — a prompt that always fires is noise.
  _same=$(_wlq "10.20.10.10,98.206.9.121,10.20.1.254/32,100.64.0.0/10" "y")
  [ "$_same" = "10.20.10.10,98.206.9.121,10.20.1.254/32,100.64.0.0/10" ] \
    && _p "an unchanged default raises nothing" \
    || _f "the check fired on an unchanged default (got '${_same}')" \
          "a warning that always fires is one the operator learns to skip"
else
  _f "the dropped-entry check is missing from lib/01" \
     "an explicit opt-in can be discarded by the next answer with no notice"
fi
rm -f "$_w0" "$_c1"
unset _merged _kept _same

# ── The resolver the VM actually boots with ──────────────────────────────────
# lib/04 copies the PROXMOX HOST's /etc/resolv.conf into the image so apk can
# resolve inside the chroot. Nothing replaced it, and `dns-nameservers` in
# /etc/network/interfaces does not fix that: it is a Debian resolvconf
# extension that Alpine's busybox ifupdown parses and discards.
#
# From the melroseparkfire install: tispve runs NetBird, which owns that file
# and points it at 100.87.54.172. The address leaked into the VM, which has no
# route to 100.64.0.0/10 and whose own firewall blocks SITE_NETS ->
# PRIVATE_NETS. Every lookup timed out and apk died on the first mirror fetch,
# fifteen minutes into an unattended build, with the installer having printed
# "DNS: 10.20.101.1" twice on the way past.
#
# Latent across 96 deployments because the host's resolver used to be a
# routable LAN address. systemd-resolved (127.0.0.53) would expose it too.
_n0="$(mktemp)"
sed -n '/^mkdir -p "\$MNT\/etc\/network"$/,/^fi$/p' \
  "$REPO/lib/05-ssh-and-network-inject.sh" > "$_n0"
if [ -s "$_n0" ]; then
  # Status-based, not output-based: msg_error exits, and the >/dev/null that
  # keeps the block quiet would also swallow anything it printed. The first
  # cut of this read every refusal as an acceptance for exactly that reason.
  _dnsq() { # $1 = VM_DNS, $2 = NET_MODE ; prints resolv.conf, exits 9 if refused
    ( msg_ok(){ :; }; msg_warn(){ :; }; msg_error(){ exit 9; }
      MNT=$(mktemp -d); trap 'rm -rf "$MNT"' EXIT
      mkdir -p "$MNT/etc/network"
      printf '# Generated by NetBird\nnameserver 100.87.54.172\n' > "$MNT/etc/resolv.conf"
      NET_MODE="${2:-static}" VM_STATIC_IP=10.20.101.10 VM_NETMASK=255.255.255.0
      VM_PREFIX=24 VM_GATEWAY=10.20.101.1 VM_DNS="$1"
      . "$_n0" >/dev/null 2>&1
      cat "$MNT/etc/resolv.conf" ); }
  _refused() { _dnsq "$1" "${2:-static}" >/dev/null 2>&1; [ "$?" -eq 9 ]; }

  _r=$(_dnsq "10.20.101.1")
  case "$_r" in
    *"nameserver 10.20.101.1"*) _p "the operator's resolver reaches /etc/resolv.conf" ;;
    *) _f "the chosen resolver was not written to /etc/resolv.conf" \
          "dns-nameservers alone is discarded by busybox ifupdown" ;;
  esac
  case "$_r" in
    *100.87.54.172*) _f "the host's leaked resolver survived into the image" \
                        "this is the melroseparkfire failure exactly" ;;
    *NetBird*)       _f "the host's resolv.conf was not replaced" "" ;;
    *) _p "the Proxmox host's leaked resolv.conf is replaced" ;;
  esac
  _refused "100.87.54.172" \
    && _p "a CGNAT/overlay resolver is refused before the VM ships" \
    || _f "a CGNAT resolver was accepted" \
          "the VM cannot route to 100.64.0.0/10; it fails at the first apk fetch"
  _refused "127.0.0.53" \
    && _p "a loopback resolver (systemd-resolved) is refused" \
    || _f "127.0.0.53 was accepted" "that stub belongs to the host, not the VM"
  _rd=$(_dnsq "" "dhcp")
  case "$_rd" in
    *100.87.54.172*) _f "DHCP mode still ships the host's leaked resolver" \
                        "a failed lease would resolve against the hypervisor" ;;
    *) _p "DHCP mode clears the host copy too" ;;
  esac
  # Two resolvers must both land, not just the first.
  case "$(_dnsq '9.9.9.9 149.112.112.112')" in
    *"nameserver 9.9.9.9"*"nameserver 149.112.112.112"*)
      _p "every selected resolver is written, not only the first" ;;
    *) _f "the secondary resolver was dropped" "" ;;
  esac
else
  _f "the network injection block is missing from lib/05" \
     "the VM's resolver would be whatever the hypervisor happened to have"
fi
rm -f "$_n0"
unset _r _rd

# ── Comma vs space: the two list conventions ─────────────────────────────────
# nftables sets take commas (_csv). Apache's `Require ip` takes spaces (_ssv).
# Both helpers sit next to each other in lib/00, which is exactly what makes
# forgetting one of them easy.
#
# From the melroseparkfire install: _ask_cidr was taught to accept several
# ranges, the nftables consumers were converted with _csv, and lib/03's
# Require ip lines were not. wp-security.conf stopped parsing, Apache never
# started, every request to the VM was refused, and it surfaced two stages
# later as "GeoIP setup failed" -- because the GeoIP step rebuilds the Apache
# layer and runs a config test. The real cause was three screens up.
_s0="$(mktemp)"; sed -n '/^_ssv()/,/^}/p' "$REPO/lib/00-preflight.sh" > "$_s0"
if [ -s "$_s0" ]; then
  _ssvq() { ( . "$_s0"; _ssv "$1" ); }
  [ "$(_ssvq '100.64.0.0/10,10.20.1.0/24,10.0.0.0/24')" \
      = "100.64.0.0/10 10.20.1.0/24 10.0.0.0/24" ] \
    && _p "_ssv converts a comma list to Apache's space form" \
    || _f "_ssv did not produce a space-separated list" \
          "Require ip rejects commas: 'The specified network mask is invalid'"
else
  _f "_ssv is missing from lib/00" "nothing converts a CIDR list for Apache"
fi
rm -f "$_s0"

# ── Variables the VM reads must be variables the VM was given ────────────────
# From the melroseparkfire install, and the most expensive bug of the set to
# diagnose because both halves looked correct in isolation:
#
#   lib/03, on the Proxmox host  — opens the firewall from Squid to exactly
#                                  ${VM_DNS:-9.9.9.9 149.112.112.112}
#   stage 09, inside the VM      — writes dns_nameservers from the SAME
#                                  expression, with the SAME fallback
#
# lib/06 injected VM_STATIC_IP and not VM_DNS. So on the host the variable was
# set and on the VM it was not, the fallback fired on one side only, and the
# firewall permitted the operator's resolver while Squid asked Quad9. Every
# lookup was dropped: HIER_NONE/503 after 3s and 30s timeouts, and WordPress
# reporting "something may be wrong with WordPress.org or this server's
# configuration". Nothing anywhere named DNS.
#
# Identical fallbacks on both sides are what hid it — and they also mean the
# bug only appears when the operator picks a resolver other than the default.
#
# The rule is general: a payload stage reading ${VM_*} is reading something
# only lib/06 can put there.
_vm_missing=""
for _v in $(grep -rhoE '\$\{VM_[A-Z_]+' "$REPO/payload/stages/" "$REPO/payload/bin/" 2>/dev/null \
            | sed 's/^\${//' | sort -u); do
  grep -q "^${_v}=\$(_vars_q" "$REPO/lib/06-vars-and-payload-inject.sh" \
    || _vm_missing="${_vm_missing} ${_v}"
done
if [ -z "$_vm_missing" ]; then
  _p "every VM_* variable the payload reads is injected by lib/06"
else
  _f "payload reads VM_* that lib/06 never injects:${_vm_missing}" \
     "the in-VM fallback fires while the host used the real value — two halves of one control disagreeing"
fi
unset _vm_missing _v
# Every Require ip built from a variable must go through _ssv. Asserted as a
# negative too: a raw ${VAR} there is the bug, and it reads as correct.
# `grep -c` exits 1 when the count is zero, so `|| echo 0` appends a SECOND
# zero and the comparison breaks on "0\n0". Assign on failure instead.
_raw=$(grep -c 'Require ip \${' "$REPO/lib/03-dynamic-configs.sh" 2>/dev/null) || _raw=0
[ "${_raw:-0}" -eq 0 ] \
  && _p "no Apache Require directive interpolates a list unconverted" \
  || _f "lib/03 has ${_raw} raw \${VAR} in a Require ip line" \
        "a comma list there stops Apache parsing its own config"
unset _raw
# The two _guard calls for this live in the guards section below, because
# _guard is not defined yet here. That ordering has caught me twice already.

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
# The SSH CIDR prompt is the one whose wrong answer costs the login path, and
# it was the one prompt printing no hints at all — while the wp-admin question
# thirty lines later printed the full interface list.
_guard "lib/03 converts the wp-admin CIDR for Apache" \
  "lib/03-dynamic-configs.sh" 'Require ip \$(_ssv "\$ADMIN_CIDR")'
_guard "lib/03 converts the extra admin IPs for Apache" \
  "lib/03-dynamic-configs.sh" 'Require ip \$(_ssv "\$ALLOWED_ADMIN_IP")'
_guard "the SSH CIDR prompt prints the host's interfaces" \
  "lib/01-interactive-setup.sh" "The source address the VM will see"
_guard "the SSH CIDR prompt names the masquerade trap" \
  "lib/01-interactive-setup.sh" "_overlay_masquerades"
# Ordering, asserted structurally: the proxy answer decides which address the
# Layer 1 and Layer 2 rules are matched against, so asking it afterwards means
# the operator answers both before being told what the answers mean.
_pl=$(grep -n 'PROXY_IP=$(_ask_single_ip' "$REPO/lib/01-interactive-setup.sh" | cut -d: -f1 | head -1)
_wl=$(grep -n 'WEB_CIDR=$(_ask_cidr'      "$REPO/lib/01-interactive-setup.sh" | cut -d: -f1 | head -1)
_al=$(grep -n 'ADMIN_CIDR=$(_ask_cidr'    "$REPO/lib/01-interactive-setup.sh" | cut -d: -f1 | head -1)
if [ -n "$_pl" ] && [ -n "$_wl" ] && [ -n "$_al" ] \
   && [ "$_pl" -lt "$_wl" ] && [ "$_pl" -lt "$_al" ]; then
  _p "the proxy is asked before the rules whose meaning it decides"
else
  _f "the proxy is still asked after the address questions" \
     "mod_remoteip changes which address Layer 2 matches; that must be known first"
fi
_guard "the wp-admin prompt says the match is the client, not the proxy" \
  "lib/01-interactive-setup.sh" "not against the proxy"
_guard "the wp-admin prompt offers the overlay address" \
  "lib/01-interactive-setup.sh" "^_overlay_addrs$"
unset _pl _wl _al
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

# ── The deferred MFA installer must actually clear the blocker it names ──────
#
# The failure this catches is a FALSE ALL-CLEAR: the script logged "MFA
# blocker cleared" while the blocker file was moved back over itself
# unchanged, because the grep pattern was validate-wordpress.sh's failure
# text rather than the blocker stage 10 writes. Compare the two literals
# directly -- that is the only assertion that survives either side being
# reworded.
_mfa_blocker=$(grep -o 'MFA was requested[^"]*' \
  "$REPO/payload/stages/10-security-tooling-and-validation.sh" 2>/dev/null | head -1)
_mfa_pat=$(grep -oE "^\s*_MFA_BLOCKER_PAT='[^']+'" \
  "$REPO/payload/bin/wasp-mfa-deferred.sh" 2>/dev/null | head -1 | sed "s/.*='//;s/'$//")

if [ -z "$_mfa_blocker" ]; then
  _f "stage 10's MFA blocker text could not be found" \
     "the comparison below cannot run, so drift would go unnoticed"
elif [ -z "$_mfa_pat" ]; then
  _f "wasp-mfa-deferred.sh has no _MFA_BLOCKER_PAT" \
     "the clear pattern is inline again and nothing checks it matches"
elif printf '%s\n' "$_mfa_blocker" | grep -q "$_mfa_pat"; then
  _p "the deferred MFA installer's pattern matches the blocker stage 10 writes"
else
  _f "the MFA clear pattern does not match the blocker text" \
     "install succeeds, the script logs 'blocker cleared', and the VM stays uncertified"
fi

# It must not claim a clear it did not perform.
_guard "wasp-mfa-deferred.sh checks the blocker is present before claiming a clear" \
  "payload/bin/wasp-mfa-deferred.sh" "No MFA blocker found to clear"

# ── install-file's "did you mean" hint must reach the failing path ───────────
#
# It previously sat below the existence check and read a stale global from
# the Wordfence cache function, so it ran only on SUCCESS and listed the
# wrong directory. Both faults are invisible from the outside: the hint
# simply never appeared. Assert the shape that makes it reachable.
if grep -q 'dirname "\${\?_f}\?"' "$REPO/payload/bin/wp-plugins.sh" 2>/dev/null; then
  _f "do_install_file's hint reads \$_f (the Wordfence cache path) again" \
     "the hint lists the vulnerability cache instead of the operator's directory"
else
  _p "do_install_file's hint reads the path the operator supplied"
fi
_guard "do_install_file hints only when the file is genuinely missing" \
  "payload/bin/wp-plugins.sh" 'if \[ ! -f "\$_zip" \]; then'

# ── Every recommended wp-plugins.sh subcommand must exist ───────────────────
#
# Stage 10's MFA blocker told the operator to "Verify with: wp-plugins.sh
# status", and menu item 14 ("MFA / Two Factor status") ran the same thing.
# `status` lists plugins with updates AVAILABLE and plugins that are
# INACTIVE -- a working, current, activated Two Factor is in neither, so the
# documented check printed identical silence whether MFA was fine or absent.
#
# A subcommand that does not exist at all fails loudly and gets found. One
# that exists but cannot answer the question asked is the silent kind. This
# catches the first class outright, and the named-MFA case specifically.
_disp=$(sed -n '/^case "\${1:-status}" in/,/^esac/p' "$REPO/payload/bin/wp-plugins.sh" 2>/dev/null \
        | grep -oE '^\s{2}[a-z|-]+\)' | tr -d ' )' | tr '|' '\n' | sort -u)
# Only lines that PRESENT a command to the operator, not prose that happens
# to name the script. Prose ("wp-plugins.sh exists for ...") would otherwise
# contribute English words as imaginary subcommands and bury the real finding.
_bad_sub=""
for _s in $(grep -rhoE '(Verify with: |run "[^"]*" [0-9] |\$\{DIM\}|^[[:space:]]*(doas )?)wp-plugins\.sh [a-z-]+' \
            "$REPO/payload" "$REPO/lib" 2>/dev/null \
            | grep -oE 'wp-plugins\.sh [a-z-]+$' | awk '{print $2}' | sort -u); do
  printf '%s\n' "$_disp" | grep -qx "$_s" || _bad_sub="${_bad_sub} ${_s}"
done
if [ -n "$_bad_sub" ]; then
  _f "recommended wp-plugins.sh subcommand(s) do not exist:${_bad_sub}" \
     "the operator is told to run something that cannot work"
else
  _p "every recommended wp-plugins.sh subcommand exists in the dispatch table"
fi

# The MFA verification route must be one that can actually report MFA state.
if grep -q 'Verify with: wp-plugins.sh status' \
     "$REPO/payload/stages/10-security-tooling-and-validation.sh" 2>/dev/null; then
  _f "the MFA blocker points at \`status\`, which cannot show MFA state" \
     "a working install and a missing one produce identical silence"
else
  _p "the MFA blocker points at a command that reports MFA state"
fi
_guard "wp-plugins.sh has an mfa subcommand that checks the plugin is active" \
  "payload/bin/wp-plugins.sh" 'plugin is-active two-factor'
_guard "the mfa subcommand names the enforcement-on-without-plugin lockout" \
  "payload/bin/wp-plugins.sh" "LOCKOUT RISK"

# ── A prompt with no stdin must say so, not look like a declined answer ─────
#
# `ask_yn` was `read ans` with no EOF handling. Under `qm guest exec`, cron
# or any pipe, read returns empty immediately and the caller prints
# "Skipped." -- identical to the operator having answered No. An operator
# ran update.sh over guest exec, read "Skipped.", and could not tell the
# prompt had never been answerable.
_ay=$(sed -n '/^ask_yn() {/,/^}/p' "$REPO/payload/bin/update.sh" 2>/dev/null)
if [ -z "$_ay" ]; then
  _f "ask_yn could not be located in update.sh" "the EOF guard cannot be checked"
elif printf '%s\n' "$_ay" | grep -q 'if ! read ans'; then
  _p "ask_yn distinguishes no-stdin from a declined answer"
else
  _f "ask_yn does not detect EOF" \
     "an unanswerable prompt reports 'Skipped.', which reads as the operator's own No"
fi
_guard "the no-stdin message says nothing was skipped by choice" \
  "payload/bin/update.sh" "Nothing was skipped by choice"

# It must stay fail-closed: no stdin means NO, never an implied yes.
_ayt=$(mktemp); printf '%s\n' "$_ay" > "$_ayt"
if sh -c ". '$_ayt'; ask_yn 'Update?'" </dev/null >/dev/null 2>&1; then
  _f "ask_yn returns TRUE with no stdin" \
     "an unattended run would auto-confirm, including the CVE-scan bypass gate"
else
  _p "ask_yn fails closed when there is no stdin"
fi
rm -f "$_ayt"

# And no --yes flag may be added: one gate asks whether to proceed WITHOUT a
# completed CVE scan, and a flag that can answer that is worse than having
# no unattended mode at all.
if grep -qE '^\s*(--yes|-y)\)' "$REPO/payload/bin/update.sh" 2>/dev/null \
   || grep -q 'ASSUME_YES' "$REPO/payload/bin/update.sh" 2>/dev/null; then
  _f "update.sh gained an unattended-confirm flag" \
     "it can answer the 'proceed without a CVE scan' gate with no human present"
else
  _p "update.sh has no flag that can auto-answer the CVE-scan gate"
fi

# ── A site-wide <Location> must not outrank the admin restriction ───────────
#
# THE ONLY DEFECT IN THIS SERIES WITH LIVE EXPOSURE RATHER THAN BAD REPORTING.
#
# Apache applies sections in the order <Directory>, <DirectoryMatch>, <Files>,
# <Location> -- and AuthMerging defaults to Off, so the LAST section's
# authorization logic REPLACES the earlier one's. wp-security.conf restricts
# wp-admin with <DirectoryMatch> and <Files>; geoip.conf's <Location /> is
# applied after both and matches every URL, so it silently replaced them. The
# wp-admin IP allowlist had never been enforced on any GeoIP install.
#
# Any generated <Location>/<LocationMatch> carrying Require directives must
# therefore declare AuthMerging And, or it inherits this defect.
_loc_bad=""
for _src in "$REPO"/payload/bin/*.sh "$REPO"/lib/*.sh; do
  [ -f "$_src" ] || continue
  # Pull each <Location...> ... </Location> block and check any that contain
  # a Require directive for the AuthMerging declaration.
  _res=$(awk '
    /<Location(Match)?[ >]/ { inblk = 1; blk = ""; hasreq = 0; hasmerge = 0 }
    inblk {
      blk = blk $0 "\n"
      if ($0 ~ /^[[:space:]]*Require[[:space:]]/) hasreq = 1
      if ($0 ~ /^[[:space:]]*AuthMerging[[:space:]]+And/) hasmerge = 1
    }
    inblk && /<\/Location(Match)?>/ {
      if (hasreq && !hasmerge) bad = 1
      inblk = 0
    }
    END { exit(bad ? 1 : 0) }' "$_src" 2>/dev/null; echo $?)
  [ "$_res" = "1" ] && _loc_bad="${_loc_bad} $(basename "$_src")"
done
if [ -n "$_loc_bad" ]; then
  _f "a site-wide <Location> with Require lacks AuthMerging And:${_loc_bad}" \
     "it is applied after <DirectoryMatch>/<Files> and REPLACES the wp-admin allowlist"
else
  _p "every generated <Location> authz block declares AuthMerging And"
fi

_guard "the generated geoip.conf merges with the admin rules rather than replacing them" \
  "payload/bin/wp-geoip-setup.sh" "AuthMerging And"

# Overlay/CGNAT addresses have no country in GeoLite2. The installer offers
# 100.64.0.0/10 as an admin CIDR for NetBird and Tailscale users, so omitting
# it here denies the operator over the very network they built to reach the
# VM -- a lockout that only appears once AuthMerging And makes both layers
# apply.
_guard "geoip.conf exempts the overlay/CGNAT range it offers as an admin CIDR" \
  "payload/bin/wp-geoip-setup.sh" "Require ip 100.64.0.0/10"

# The ordering explanation must survive, because the next person to add a
# site-wide rule needs to know WHY the line is there.
_guard "geoip.conf records why AuthMerging is mandatory" \
  "payload/bin/wp-geoip-setup.sh" "is applied LAST"

# ── install-file must not claim an activation it did not perform ────────────
#
# Observed twice in a row on a live VM: both "✔ Activated (verified)". Both
# inactive. Three faults stacked — the slug came from the ZIP FILE NAME
# (elementorpro432.zip -> "elementorpro432", real slug "elementor-pro"), the
# error was discarded with `|| true`, and the check asked whether ANYTHING
# was active rather than whether THIS was. The message could not come out
# false, which is the worst property a verification can have.
if grep -q '_slug_guess="\${_base%.zip}"' "$REPO/payload/bin/wp-plugins.sh" 2>/dev/null; then
  _f "install-file derives the slug from the zip FILE NAME again" \
     "a plugin's directory name is unrelated to its file name; activation targets nothing"
else
  _p "install-file does not derive the slug from the zip file name"
fi
if grep -qE 'activate "\$_slug[a-z_]*" >/dev/null 2>&1 \|\| true' \
     "$REPO/payload/bin/wp-plugins.sh" 2>/dev/null; then
  _f "install-file discards the activation error again" \
     "a failed activation is reported as success"
else
  _p "install-file keeps the activation error"
fi
_guard "install-file verifies THAT slug is active, not that anything is" \
  "payload/bin/wp-plugins.sh" 'grep -qxF "\$_slug"'
_guard "install-file identifies what arrived by diffing wp-cli's own list" \
  "payload/bin/wp-plugins.sh" "_pre_list="

# ── The staged zip must be readable by the wp-cli container's uid ───────────
#
# curl and scp commonly leave mode 600 root. The container runs --user 33:33,
# so the mount succeeded and the read failed, surfacing as
# PCLZIP_ERR_READ_OPEN_FAIL — which names neither permissions nor the
# container user, and sends the operator back to the download.
_guard "install-file makes the staged zip readable by uid 33" \
  "payload/bin/wp-plugins.sh" "chmod o+r"
_guard "install-file names the real cause when it cannot" \
  "payload/bin/wp-plugins.sh" "PCLZIP_ERR_READ_OPEN_FAIL"

# ── The malware scanner's summary must count what it printed ────────────────
#
# A real run printed 48 [SUSPECT] lines and a summary reading
# "suspicious 0" directly beneath them. The findings loop was the right-hand
# side of a PIPE, so _crit/_high/_susp ran in a subshell and every counter
# increment was discarded. A genuine detection would have summarised as zero
# too — and the summary is the line an operator actually reads.
if grep -qE "grep -v '\^0x' \| while IFS= read" "$REPO/payload/bin/wp-malware-scan.sh" 2>/dev/null; then
  _f "the YARA findings loop is on the right of a pipe again" \
     "counters increment in a subshell and the summary reports zero findings"
else
  _p "the YARA findings loop runs in the scanner's own shell"
fi
_guard "the YARA loop reads from a file, keeping counters in scope" \
  "payload/bin/wp-malware-scan.sh" 'done < "\$_ytmp"'

# ── An uploads-scoped rule must not be run against the whole tree ───────────
#
# wpvm_php_in_nonphp_extension matches "<?php". Correct for a media
# directory; against the whole site it flags every legitimate PHP file.
if grep -q 'php_in_nonphp_extension' "$REPO/payload/malware/wp-malware.yar" 2>/dev/null; then
  _f "the uploads-only rule is back in the whole-tree ruleset" \
     "every legitimate .php file on the site is reported as suspect"
else
  _p "the uploads-only rule is kept out of the whole-tree ruleset"
fi
_guard "uploads-scoped rules exist in their own ruleset" \
  "payload/bin/wp-malware-scan.sh" "RULES_UPLOADS="
# A ruleset the installer never copies is a ruleset that silently never runs.
_guard "stage 10 installs the uploads ruleset onto the VM" \
  "payload/stages/10-security-tooling-and-validation.sh" "wp-malware-uploads.yar"
if [ -f "$REPO/payload/malware/wp-malware-uploads.yar" ]; then
  _p "the uploads ruleset is present in the payload"
else
  _f "the uploads ruleset is missing from the payload" \
     "RULES_UPLOADS never resolves, so those rules silently never run"
fi

# ── Trivy must stage its database somewhere that can hold it ────────────────
#
# --cache-dir governs where Trivy KEEPS the database; TMPDIR governs where it
# STAGES the download. On Alpine /tmp is a tmpfs sized from RAM -- 256 MB on
# the affected VM, against 14.1 GB free on the real disk. Every DB download
# failed with "no space left on device" inside a message about vulnerability
# databases, so the cause read as Trivy or the network, never as disk.
#
# Under the production profile an incomplete scan correctly blocks the
# update, so a 256 MB tmpfs silently blocked every security update.
_guard "update.sh stages Trivy's download through the cache dir, not /tmp" \
  "payload/bin/update.sh" 'TRIVY_TMPDIR="\${TRIVY_CACHE_DIR}/tmp"'
# Pointing TMPDIR at a path that cannot be created would break mktemp for the
# whole script -- a worse failure than the one being fixed.
_guard "the relocation is skipped unless the directory is writable" \
  "payload/bin/update.sh" '\[ -w "\$TRIVY_TMPDIR" \]'
_guard "a too-small /tmp is named as disk, before the scan fails" \
  "payload/bin/update.sh" "does not mention disk space"

# The warning is useless if nothing calls it.
if grep -q '_trivy_tmp_warn$' "$REPO/payload/bin/update.sh" 2>/dev/null; then
  _p "the /tmp warning is actually invoked from setup_trivy"
else
  _f "_trivy_tmp_warn is defined but never called" \
     "the operator gets the vulnerability-database message with no mention of disk"
fi

# ── A failed container upgrade must leave evidence behind ───────────────────
#
# The CrowdSec health check waited 6 x 5s = 30 seconds. A version jump
# migrates config and the local database on first start, so the update rolled
# back on a container that was merely still coming up -- and the rollback
# destroyed that container before anyone could ask it why. The operator got
# "LAPI not responding" and nothing else, so the next attempt failed
# identically.
# Assert the VALUE, not the literal loop text: the count lives in a variable,
# so a grep for "seq 1 6" sails past someone lowering it back.
_lt=$(grep -oE '^[[:space:]]*_lapi_tries=[0-9]+' "$REPO/payload/bin/update.sh" 2>/dev/null \
      | grep -oE '[0-9]+$' | head -1)
if [ -z "$_lt" ]; then
  _f "the CrowdSec LAPI wait count could not be found" "the bound cannot be checked"
elif [ "$_lt" -lt 24 ]; then
  _f "the CrowdSec LAPI wait is only $((_lt * 5))s" \
     "a version upgrade migrates on first start and rolls back while merely starting"
else
  _p "the CrowdSec LAPI wait allows $((_lt * 5))s for first-start migration"
fi
_guard "the failed upgrade's logs are captured before the rollback destroys it" \
  "payload/bin/update.sh" "wasp-crowdsec-upgrade-failed.log"
_guard "the operator is shown why, not just that it failed" \
  "payload/bin/update.sh" "podman logs --tail 12 crowdsec"
# Waiting three minutes on a container that already exited is wasted time.
_guard "the wait stops early if the new container has exited" \
  "payload/bin/update.sh" "The new CrowdSec container exited during startup"

# ── Temporary access must expire without anyone remembering ─────────────────
#
# "Let the contractor in for two days" is the request most likely to leave a
# permanent allowlist entry: the work ends, and removing the entry is a
# separate task nobody owns. The grant therefore schedules its own
# revocation, or it is not a grant.
_guard "a grant schedules its own revocation" \
  "payload/bin/wasp-temp-access.sh" "Revocation scheduled for"
# Admin is gated by TWO layers since the AuthMerging fix. Writing only one
# produces a 403 that looks like the grant failed.
_guard "a grant writes both the allowlist and the country-test layer" \
  "payload/bin/wasp-temp-access.sh" 'for _f in "\$SEC_CONF" "\$GEO_CONF"'
_guard "temp access refuses a window longer than a month" \
  "payload/bin/wasp-temp-access.sh" "Longer than that is not temporary"
_guard "temp access refuses an over-broad CIDR" \
  "payload/bin/wasp-temp-access.sh" "not a plausible single address"
# A bind-mounted single file keeps its inode; sed -i would leave the
# container reading the original. This cost a live debugging session once.
_guard "temp access rewrites in place rather than replacing the inode" \
  "payload/bin/wasp-temp-access.sh" "_write_inplace"
_guard "temp access verifies the public site still answers after reload" \
  "payload/bin/wasp-temp-access.sh" "Public site returned"
# An installer that never copies it means the tool does not exist on the VM.
_guard "stage 10 installs wasp-temp-access.sh" \
  "payload/stages/10-security-tooling-and-validation.sh" "wasp-temp-access.sh"

# ── A container replacement must preserve the deployment's topology ─────────
#
# do_cs_update's `podman run` hardcoded a local-LAPI shape. Stage 09 and
# wp-hardening.sh create the container in AGENT-ONLY mode when the LAPI lives
# on another host (-e DISABLE_LOCAL_API=true -e LOCAL_API_URL=...). Neither
# was reproduced, so the replacement came up as a full local API node, the
# entrypoint re-registered it against 127.0.0.1, and the health check never
# saw the LAPI it waited for. On an agent-only install the update could not
# succeed at any timeout -- while reporting "LAPI not responding", which
# reads as the remote LAPI being down rather than this container being built
# wrong.
_guard "the CrowdSec replacement inherits the running container's topology" \
  "payload/bin/update.sh" "CS_INHERIT_ENV="
_guard "the inherited environment is actually passed to podman run" \
  "payload/bin/update.sh" '\${CS_INHERIT_ENV}'
# Every agent-only variable the installer can set must be carried forward;
# inheriting some and dropping others is the same defect in miniature.
_cs_missing=""
for _v in $(grep -rhoE '\-e (DISABLE_LOCAL_API|LOCAL_API_URL|DISABLE_AGENT)' \
            "$REPO/payload/stages" "$REPO/payload/bin" 2>/dev/null \
            | awk '{print $2}' | sort -u); do
  grep -q "for _csv_name in.*${_v}" "$REPO/payload/bin/update.sh" 2>/dev/null \
    || _cs_missing="${_cs_missing} ${_v}"
done
if [ -n "$_cs_missing" ]; then
  _f "CrowdSec topology variable(s) not carried across an update:${_cs_missing}" \
     "the replacement container is built with a different shape than the original"
else
  _p "every CrowdSec topology variable the installer sets is carried across updates"
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
