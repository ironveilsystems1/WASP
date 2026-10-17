#!/usr/bin/env bash
# =============================================================================
# test-topology.sh — does wasp-topology.sh read a host correctly, and is its
#                    machine-readable output actually machine-readable?
# =============================================================================
#
# WHY THIS EXISTS
#
# The topology tool decides the addresses, VLAN tags and VM IDs that three VMs
# are built with, and every one of those is a silent failure when wrong: a
# reused VLAN tag puts two trust boundaries on one segment and both keep
# working; a colliding subnet makes a remote site invisible over an overlay; a
# tag on a non-VLAN-aware bridge is accepted and delivered untagged.
#
# It also cannot be tested on a Proxmox host from here, which is exactly the
# situation that produces untested provisioning code. So the tool reads every
# fact through one source function that can be pointed at a fixture bundle, and
# this drives it against two bundles: a segmented host modelled on a real
# deployment, and a flat single-bridge homelab.
#
# Three of these cases are regressions for defects found while writing it:
#
#   * `pct list` and `qm list` do not share a column layout, so a fixed field
#     index named every container "running"
#   * loopback appeared in "subnets in use", which is noise in the one list an
#     operator scans for a real collision
#   * --vars printed the map to stdout alongside the assignments, so
#     `eval "$(... --vars)"` tried to execute the box-drawing characters of the
#     header and failed with `command not found` on a line of ═ — a message
#     naming neither the tool nor the cause
# =============================================================================
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="$REPO/tools/wasp-topology.sh"
SITEB="$REPO/test/fixtures/topology-siteb"
FLAT="$REPO/test/fixtures/topology-flat"
PASS=0; FAIL=0

_p() { printf '  [PASS] %s\n' "$1"; PASS=$((PASS+1)); }
_f() { printf '  [FAIL] %s\n' "$1"; [ -n "${2:-}" ] && printf '         %s\n' "$2"; FAIL=$((FAIL+1)); }

echo ""
echo "Topology discovery"
echo "══════════════════"

if [ ! -f "$TOOL" ]; then
  _f "wasp-topology.sh is missing" "nothing can be planned without it"
  printf '\n  passed %d   failed %d\n' "$PASS" "$FAIL"; exit 1
fi
for d in "$SITEB" "$FLAT"; do
  [ -d "$d" ] || { _f "fixture missing: $d" "the tool cannot be tested without one"; }
done

_map()  { bash "$TOOL" --from "$1" 2>/dev/null; }
_plan() { bash "$TOOL" --from "$1" --plan 2>/dev/null; }
_vars() { bash "$TOOL" --from "$1" --plan --vars 2>/dev/null; }

# ── Reading a host ───────────────────────────────────────────────────────────
echo ""
echo "── Reading a segmented host"
out="$(_map "$SITEB")"

printf '%s' "$out" | grep -q 'vmbr1.*VLAN-aware' \
  && _p "the VLAN-aware trunk bridge is identified" \
  || _f "vmbr1 not reported as VLAN-aware" \
        "a tag on a non-aware bridge is delivered untagged with no error"
printf '%s' "$out" | grep -qE 'vmbr0.*not VLAN-aware' \
  && _p "a non-VLAN-aware bridge is distinguished from an aware one" \
  || _f "vmbr0 not reported as non-VLAN-aware" ""

# REGRESSION: pct list is `VMID Status Lock Name`; qm list is `VMID NAME ...`.
# A fixed field index gave every container the name "running".
printf '%s' "$out" | grep -q 'npmplus' \
  && _p "container names are read from pct list's own column order" \
  || _f "container name wrong" "pct list puts Name last; qm list puts it second"
printf '%s' "$out" | grep -qE '^\s+120\s+ct\s+meshcentral' \
  && _p "each container maps to its own name" \
  || _f "container/name pairing is wrong" ""
printf '%s' "$out" | grep -qE '^\s+100\s+vm\s+opnsense' \
  && _p "VM names are read from qm list's column order" \
  || _f "VM name wrong" ""

printf '%s' "$out" | grep -q '10.20.10.10/24' \
  && _p "guest addresses are read out of the guest config" \
  || _f "guest address not found" "the plan cannot avoid what it cannot see"
printf '%s' "$out" | grep -qE 'VLAN tags in use' \
  && printf '%s' "$out" | grep -qE '^\s+10 20 30' \
  && _p "VLAN tags in use are collected (10, 20, 30)" \
  || _f "tags in use not collected correctly" ""

# REGRESSION: loopback is on every host and collides with nothing. Listing it
# makes a genuine collision harder to spot in the list an operator scans.
printf '%s' "$out" | grep -A6 'Subnets in use' | grep -q '127\.' \
  && _f "loopback appears in 'subnets in use'" "noise in the collision list" \
  || _p "loopback is excluded from the subnet list"

# ── The plan avoids what it found ────────────────────────────────────────────
echo ""
echo "── Planning around an occupied host"
plan="$(_plan "$SITEB")"

# Tags 10, 20 and 30 are taken in this fixture.
if printf '%s' "$plan" | grep -qE '^\s+NPMplus\s+[0-9]+\s+(10|20|30)\s'; then
  _f "the plan reused a VLAN tag already in use" \
     "two trust boundaries on one segment, and both keep working"
else
  _p "the plan avoids VLAN tags already in use"
fi
# 10.20.x is occupied, so the site octet must move.
printf '%s' "$plan" | grep -q 'Site octet     10.30' \
  && _p "the plan moves to an unused site octet (10.30.x)" \
  || _f "the plan reused an occupied site octet" \
        "an overlapping subnet makes the remote site invisible over an overlay"
# VMIDs 100/120/200/300 are taken; nextid says 301.
if printf '%s' "$plan" | grep -qE '^\s+(OPNsense|NPMplus|WASP)\s+(100|120|200|300)\s'; then
  _f "the plan reused an existing VM ID" "qm create would refuse, mid-stack"
else
  _p "the plan avoids VM IDs already in use"
fi

# The documented convention: tenant sites live in the 101+ band so a firewall
# log is legible without a lookup table, and the firewall generator names
# segments from the same convention.
printf '%s' "$plan" | grep -qE '^\s+WASP\s+[0-9]+\s+1[0-9][0-9]\s' \
  && _p "the tenant VLAN lands in the documented 101+ band" \
  || _f "tenant VLAN outside the 101+ band" \
        "the generated firewall rules would name a different segment"

# On a clean host the plan should reproduce the canonical layout, because the
# conventions are supposed to be encoded rather than improvised.
flatplan="$(_plan "$FLAT")"
printf '%s' "$flatplan" | grep -q '10.20.10.10/24' \
  && printf '%s' "$flatplan" | grep -q '10.20.101.10/24' \
  && _p "a clean host yields the canonical 10.20.10.10 / 10.20.101.10 layout" \
  || _f "clean-host plan does not match the documented convention" ""

# ── The three are tuned to each other ────────────────────────────────────────
echo ""
echo "── Cross-VM wiring"
printf '%s' "$flatplan" | grep -q 'WASP trusts   10.20.10.10' \
  && _p "WASP's trusted proxy is the planned NPMplus address" \
  || _f "the trusted proxy does not match the planned proxy address" \
        "this is the TRUST-COUNT value; wrong means forged client IPs"
printf '%s' "$flatplan" | grep -q 'http://10.20.10.10:8080/' \
  && _p "the LAPI URL points at the planned proxy, not loopback" \
  || _f "LAPI URL wrong" "a loopback LAPI serves no remote agent"
printf '%s' "$flatplan" | grep -q 'backend CIDR' \
  && _p "the proxy is told the WASP segment as a backend CIDR" \
  || _f "backend CIDR not stated" ""

# ── --vars is machine-readable ───────────────────────────────────────────────
echo ""
echo "── --vars output"
v="$(_vars "$FLAT")"

# REGRESSION: the map used to land on stdout with the vars.
if printf '%s\n' "$v" | grep -qE '═|║|╔|Findings|Bridges'; then
  _f "--vars wrote the map to stdout" \
     "eval of this fails with 'command not found' on a line of box characters"
else
  _p "stdout carries no narration"
fi
# Every non-blank, non-comment line must be a plain NAME=value assignment.
bad="$(printf '%s\n' "$v" | grep -vE '^\s*(#|$)' | grep -vE '^[A-Z_][A-Z0-9_]*=[^ ]*$' || true)"
[ -z "$bad" ] \
  && _p "every emitted line is a plain NAME=value assignment" \
  || _f "non-assignment lines in --vars output" "$(printf '%s' "$bad" | head -2)"

# And it must actually eval, which is the only test that matters.
if ( set -eu; eval "$v"; [ -n "${WASP_PROXY_IP:-}" ] && [ -n "${STACK_BRIDGE:-}" ] \
     && [ -n "${WASP_CS_LAPI_URL:-}" ] && [ -n "${NPMPLUS_VMID:-}" ] ) 2>/dev/null; then
  _p "the output evals and sets the names the installer consumes"
else
  _f "--vars output does not eval cleanly" "the whole point of the mode"
fi
# The names must be the ones WASP's installer actually reads, or the handoff is
# a rename away from doing nothing.
for n in WASP_PROXY_IP WASP_CS_ENFORCEMENT WASP_CS_LAPI_URL WASP_CROWDSEC_WHITELIST; do
  if grep -q "$n" "$REPO/install.sh" 2>/dev/null; then
    printf '%s\n' "$v" | grep -q "^${n}=" \
      && _p "emits ${n}, which install.sh reads" \
      || _f "install.sh reads ${n} and --vars does not emit it" ""
  else
    _f "install.sh no longer reads ${n}" "the topology handoff is stale"
  fi
done

# ── Findings fire where they should ──────────────────────────────────────────
echo ""
echo "── Findings"
flatmap="$(_map "$FLAT")"
printf '%s' "$flatmap" | grep -q 'No bridge is VLAN-aware' \
  && _p "a host with no VLAN-aware bridge is flagged" \
  || _f "no VLAN-aware bridge was not flagged" \
        "every tag in the plan would be silently delivered untagged"
printf '%s' "$flatmap" | grep -q 'One bridge only' \
  && _p "a single-bridge host is flagged as a lockout risk" \
  || _f "single-bridge host not flagged" ""
printf '%s' "$out" | grep -q 'nothing to flag' \
  && _f "the segmented host reported no findings" \
        "VM 100 has no address in its config and that must be stated" \
  || _p "the segmented host still reports its addressless VM"

# ── Argument handling ────────────────────────────────────────────────────────
echo ""
echo "── Arguments"
bash "$TOOL" --nonsense >/dev/null 2>&1 \
  && _f "an unknown argument was accepted" \
        "a mistyped --plan that prints the map reads as the tool disagreeing" \
  || _p "an unknown argument is rejected"
bash "$TOOL" --from /nonexistent-bundle-dir >/dev/null 2>&1 \
  && _f "a missing bundle directory was accepted" "" \
  || _p "a missing bundle directory is refused"
bash "$TOOL" --help 2>/dev/null | grep -q 'collect' \
  && _p "--help documents the modes" \
  || _f "--help does not describe the modes" ""

# A collect/read round trip, because that is the support path: an operator
# sends a bundle and it has to produce the same plan on another machine.
echo ""
echo "── Collect round trip"
_tmp="$(mktemp -d)"
if bash "$TOOL" --from "$SITEB" --collect "$_tmp" >/dev/null 2>&1; then
  a="$(_plan "$SITEB" | grep -E '^\s+(OPNsense|NPMplus|WASP)\s')"
  b="$(_plan "$_tmp"  | grep -E '^\s+(OPNsense|NPMplus|WASP)\s')"
  [ -n "$a" ] && [ "$a" = "$b" ] \
    && _p "a collected bundle re-plans identically" \
    || _f "re-planning a collected bundle gave a different stack" \
          "a support bundle that does not reproduce the plan is misleading"
else
  _f "--collect failed" ""
fi
rm -rf "$_tmp"

# ── Result ───────────────────────────────────────────────────────────────────
echo ""
printf '  passed %d   failed %d\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  echo ""
  echo "  The topology tool decides the addresses three VMs are built with."
  echo "  A failure here is a stack built on values that collide with the host."
  exit 1
fi
exit 0
