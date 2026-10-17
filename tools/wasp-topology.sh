#!/usr/bin/env bash
# =============================================================================
# wasp-topology.sh — map a Proxmox host's network, then propose a stack that
#                    collides with nothing already on it.
# =============================================================================
#
# Run this ON THE PROXMOX HOST. It reads only; it changes nothing.
#
# WHY THIS EXISTS
#
# WASP, NPMplus and OPNsense can be generated already tuned to each other —
# the proxy pinned to the WASP VM's address, the firewall's VLANs and rules
# matching the segments the VMs actually land on. None of that can be generated
# without knowing what the host already has, and every one of those values is a
# silent failure when it is wrong:
#
#   * a VLAN tag reused by an existing guest puts two trust boundaries on one
#     segment, and both keep working
#   * a subnet that collides with another site makes the remote site invisible
#     over an overlay, because the directly-connected route wins
#   * a VLAN tag on a bridge that is not VLAN-aware is accepted by Proxmox and
#     silently untagged
#   * an address already held by a guest produces an ARP conflict that presents
#     as intermittent packet loss
#
# Each of those is cheap to detect here and expensive to find later, which is
# the whole argument for this being a command rather than a checklist.
#
# WHAT IT DOES NOT DO
#
# It does not scan the network. Everything comes from the host's own
# configuration and the guest definitions Proxmox already holds, so it is safe
# on a production host and it cannot see a device that Proxmox does not know
# about. A statically-addressed appliance on a VLAN with no Proxmox guest on it
# is invisible here, and `--plan` can therefore propose a subnet something else
# is using. That limit is printed with the plan rather than left implicit.
#
# USAGE
#
#   wasp-topology.sh                  the map, and what is wrong with it
#   wasp-topology.sh --plan           the map, plus a proposed 3-VM stack
#   wasp-topology.sh --plan --vars    just the shell assignments, for a stack build
#   wasp-topology.sh --collect DIR    write a support bundle (reads only)
#   wasp-topology.sh --from DIR       read a bundle instead of the live host
#
# --from exists for two reasons that matter equally: it is how this tool is
# tested without a Proxmox host, and it is how an operator can send their
# topology for review without giving anyone access to the hypervisor.
# =============================================================================
set -u

RD=$'\033[0;31m'; GN=$'\033[0;32m'; YW=$'\033[0;33m'
BL=$'\033[0;36m';  BLD=$'\033[1m';   CL=$'\033[0m'
if [ ! -t 1 ]; then RD=""; GN=""; YW=""; BL=""; BLD=""; CL=""; fi

MODE="map"; FROM_DIR=""; COLLECT_DIR=""; WANT_VARS=0; SITE_OCTET=""
PREF_BRIDGE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --plan)      MODE="plan" ;;
    --vars)      WANT_VARS=1; MODE="plan" ;;
    --from)      FROM_DIR="${2:-}"; shift ;;
    --collect)   COLLECT_DIR="${2:-}"; shift ;;
    --bridge)    PREF_BRIDGE="${2:-}"; shift ;;
    --site-octet) SITE_OCTET="${2:-}"; shift ;;
    -h|--help)
      sed -n '3,46p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *)
      # Rejecting an unknown argument rather than ignoring it: a mistyped
      # --plan that silently prints the map looks like the tool disagreeing
      # with you, and that is a confusing place to start.
      printf '%sUnknown argument: %s%s\n' "$RD" "$1" "$CL" >&2
      printf 'Try: %s --help\n' "$0" >&2
      exit 2 ;;
  esac
  shift
done

if [ -n "$FROM_DIR" ] && [ ! -d "$FROM_DIR" ]; then
  printf '%sNo such bundle directory: %s%s\n' "$RD" "$FROM_DIR" "$CL" >&2
  exit 1
fi

# ── Source abstraction ───────────────────────────────────────────────────────
# Every fact comes through _src, so the live-host path and the bundle path
# cannot drift: there is exactly one place that decides where a fact comes
# from. A second collection path written for testing is a path that stops
# matching the real one and then tests the wrong thing.
_src() {                       # _src <logical-name> <command...>
  local name="$1"; shift
  if [ -n "$FROM_DIR" ]; then
    [ -f "$FROM_DIR/$name" ] && cat "$FROM_DIR/$name"
    return 0
  fi
  command -v "$1" >/dev/null 2>&1 || return 0
  "$@" 2>/dev/null || true
}

# Deliberately `ip -o` and plain text rather than `ip -j` and jq, or python3.
# Neither jq nor python3 is guaranteed on a Proxmox host, and a topology tool
# that cannot run until you install something is a tool that gets skipped at
# exactly the moment it would have helped. awk and sed are always there.
_ip_addr()   { _src ip-addr   ip -o addr show; }
_ip_link()   { _src ip-link   ip -o link show; }
_ip_route()  { _src ip-route  ip route show; }
_ifaces()    { if [ -n "$FROM_DIR" ]; then [ -f "$FROM_DIR/interfaces" ] && cat "$FROM_DIR/interfaces"; else cat /etc/network/interfaces 2>/dev/null; fi; }
_brvlan()    { _src bridge-vlan bridge vlan show; }
_qm_list()   { _src qm-list    qm list; }
_pct_list()  { _src pct-list   pct list; }
_storage()   { _src storage    pvesm status; }
_nextid()    { _src nextid     pvesh get /cluster/nextid; }
_guest_conf() {                # _guest_conf <vm|ct> <id>
  local kind="$1" id="$2"
  if [ -n "$FROM_DIR" ]; then
    [ -f "$FROM_DIR/conf-${kind}-${id}" ] && cat "$FROM_DIR/conf-${kind}-${id}"
    return 0
  fi
  case "$kind" in
    vm) command -v qm  >/dev/null 2>&1 && qm  config "$id" 2>/dev/null ;;
    ct) command -v pct >/dev/null 2>&1 && pct config "$id" 2>/dev/null ;;
  esac
  return 0
}

# ── --collect ────────────────────────────────────────────────────────────────
if [ -n "$COLLECT_DIR" ]; then
  mkdir -p "$COLLECT_DIR" || exit 1
  _ip_addr  > "$COLLECT_DIR/ip-addr"
  _ip_link  > "$COLLECT_DIR/ip-link"
  _ip_route > "$COLLECT_DIR/ip-route"
  _ifaces   > "$COLLECT_DIR/interfaces"
  _brvlan   > "$COLLECT_DIR/bridge-vlan"
  _qm_list  > "$COLLECT_DIR/qm-list"
  _pct_list > "$COLLECT_DIR/pct-list"
  _storage  > "$COLLECT_DIR/storage"
  _nextid   > "$COLLECT_DIR/nextid"
  _qm_list  | awk 'NR>1 && $1 ~ /^[0-9]+$/ {print $1}' | while read -r _i; do
    _guest_conf vm "$_i" > "$COLLECT_DIR/conf-vm-${_i}"
  done
  _pct_list | awk 'NR>1 && $1 ~ /^[0-9]+$/ {print $1}' | while read -r _i; do
    _guest_conf ct "$_i" > "$COLLECT_DIR/conf-ct-${_i}"
  done
  # Said rather than assumed: a bundle is a configuration export, and a guest
  # config can carry a cloud-init password or an SSH key. The operator decides
  # whether to send it, and can only decide that if they are told.
  printf '%sBundle written: %s%s\n' "$GN" "$COLLECT_DIR" "$CL"
  printf 'It contains interface, route and guest configuration — review before\n'
  printf 'sharing it. Guest configs can include cloud-init credentials.\n'
  printf 'Read it back with:  %s --from %s --plan\n' "$0" "$COLLECT_DIR"
  exit 0
fi

# ── Collect into memory ──────────────────────────────────────────────────────
IP_ADDR="$(_ip_addr)"; IP_ROUTE="$(_ip_route)"; IFACES="$(_ifaces)"
BRVLAN="$(_brvlan)";   QM="$(_qm_list)";        PCT="$(_pct_list)"
STOR="$(_storage)";    NEXTID="$(printf '%s' "$(_nextid)" | tr -dc '0-9')"

if [ -z "$IP_ADDR" ] && [ -z "$IFACES" ]; then
  printf '%sNothing to read.%s\n' "$RD" "$CL" >&2
  if [ -n "$FROM_DIR" ]; then
    printf 'The bundle at %s has no ip-addr or interfaces file.\n' "$FROM_DIR" >&2
  else
    printf 'This does not look like a Proxmox host — no ip(8) output and no\n' >&2
    printf '/etc/network/interfaces. Run it on the hypervisor.\n' >&2
  fi
  exit 1
fi

# Bridges, and whether each is VLAN-aware. The distinction is load-bearing:
# Proxmox accepts a VLAN tag on a guest attached to a non-VLAN-aware bridge and
# silently delivers the frames untagged, so the guest comes up on the wrong
# segment with no error anywhere.
BRIDGES="$(printf '%s\n' "$IFACES" | awk '/^iface[[:space:]]+vmbr/ {print $2}' | sort -u)"
[ -z "$BRIDGES" ] && BRIDGES="$(printf '%s\n' "$IP_ADDR" | awk -F': ' '$2 ~ /^vmbr/ {print $2}' | sort -u)"

_bridge_vlan_aware() {         # 0 = aware
  printf '%s\n' "$IFACES" | awk -v b="$1" '
    $1=="iface" && $2==b {inb=1; next}
    inb && /^iface[[:space:]]/ {inb=0}
    inb && /bridge[-_]vlan[-_]aware[[:space:]]+yes/ {found=1}
    END {exit !found}'
}

_host_addr_on() {              # the host's own CIDR on an interface
  printf '%s\n' "$IP_ADDR" | awk -v d="$1" '$2==d && $3=="inet" {print $4; exit}'
}

# ── Guest inventory ──────────────────────────────────────────────────────────
# One line per guest NIC: id|kind|name|bridge|vlan|addr
GUESTS=""
_scan_guests() {
  local kind="$1" list="$2" id name conf
  # The two listings do NOT share a column layout, and treating them as if they
  # do gives every container the name "running":
  #   qm list   VMID NAME STATUS MEM BOOTDISK PID        -> name is $2
  #   pct list  VMID Status Lock Name                    -> name is last
  # Lock is usually empty, so its column collapses and a fixed index lands on
  # the wrong field. $NF is correct either way for pct.
  printf '%s\n' "$list" \
  | awk -v k="$kind" 'NR>1 && $1 ~ /^[0-9]+$/ {print $1"\t"(k=="vm" ? $2 : $NF)}' \
  | while IFS=$'\t' read -r id name; do
      [ -z "$id" ] && continue
      conf="$(_guest_conf "$kind" "$id")"
      [ -z "$conf" ] && { printf '%s|%s|%s|?|-|-\n' "$id" "$kind" "$name"; continue; }
      # net0: virtio=AA:BB...,bridge=vmbr1,tag=101   (qm)
      # net0: name=eth0,bridge=vmbr1,ip=10.20.10.10/24,gw=...,tag=10  (pct)
      printf '%s\n' "$conf" | grep -E '^net[0-9]+:' | while read -r nl; do
        local br tag ipa
        br=$(printf '%s' "$nl"  | sed -n 's/.*bridge=\([^,]*\).*/\1/p')
        tag=$(printf '%s' "$nl" | sed -n 's/.*[,:= ]tag=\([0-9]*\).*/\1/p')
        ipa=$(printf '%s' "$nl" | sed -n 's/.*[,:= ]ip=\([^,]*\).*/\1/p')
        printf '%s|%s|%s|%s|%s|%s\n' \
          "$id" "$kind" "$name" "${br:-?}" "${tag:--}" "${ipa:--}"
      done
    done
}
GUESTS="$(_scan_guests vm "$QM"; _scan_guests ct "$PCT")"

USED_TAGS="$(printf '%s\n' "$GUESTS" | awk -F'|' '$5 ~ /^[0-9]+$/ {print $5}' | sort -n -u)"
USED_IDS="$(printf '%s\n' "$QM" "$PCT" | awk 'NR>0 && $1 ~ /^[0-9]+$/ {print $1}' | sort -n -u)"

# Subnets in use: the host's own, plus every guest address, plus routes. All
# three, because any one of them alone misses a real collision.
# Loopback and link-local are excluded: they are on every host, they collide
# with nothing, and listing them makes a genuine collision harder to spot in
# the output. A findings list that carries noise gets skimmed.
_norm24() {
  printf '%s' "$1" | awk -F'[./]' '
    NF>=4 && $1!="127" && !($1=="169" && $2=="254") {print $1"."$2"."$3".0/24"}'
}
USED_NETS="$( {
    printf '%s\n' "$IP_ADDR" | awk '$3=="inet" {print $4}'
    printf '%s\n' "$GUESTS"  | awk -F'|' '$6 ~ /[0-9]/ {print $6}'
    printf '%s\n' "$IP_ROUTE" | awk '$1 ~ /\// {print $1}'
  } | while read -r c; do [ -n "$c" ] && _norm24 "$c"; done | sort -u )"
USED_OCTET2="$(printf '%s\n' "$USED_NETS" | awk -F. '$1=="10" {print $2}' | sort -n -u)"

# ── stdout is data, stderr is narration ──────────────────────────────────────
# Under --vars the map and findings move to stderr and stdout carries nothing
# but the assignments, so `eval "$(wasp-topology.sh --plan --vars)"` works.
#
# Found by trying it: the first version printed the map to stdout alongside the
# vars, so the eval tried to execute the box-drawing characters of the header
# and failed with `command not found` on a line of ═ characters — a message
# that names neither the tool nor the cause. A "machine-readable" mode that is
# not machine-readable is the same shape as every other defect in this
# project: it exists, it looks right, and it does not work.
#
# The human still sees everything on a terminal; only a command substitution
# filters it out, which is exactly who should be filtering it.
if [ "$WANT_VARS" -eq 1 ]; then exec 3>&1 1>&2; else exec 3>&1; fi

# ── Map ──────────────────────────────────────────────────────────────────────
printf '\n%s╔══════════════════════════════════════════════════════════════╗%s\n' "$BLD" "$CL"
printf '%s║  Proxmox network topology%-37s║%s\n' "$BLD" "" "$CL"
printf '%s╚══════════════════════════════════════════════════════════════╝%s\n' "$BLD" "$CL"
[ -n "$FROM_DIR" ] && printf '%s  (read from bundle %s — not this host)%s\n' "$YW" "$FROM_DIR" "$CL"
printf '\n'

printf '%sBridges%s\n' "$BLD" "$CL"
if [ -z "$BRIDGES" ]; then
  printf '  %snone found%s\n' "$RD" "$CL"
else
  for b in $BRIDGES; do
    _ha="$(_host_addr_on "$b")"
    if _bridge_vlan_aware "$b"; then _va="${GN}VLAN-aware${CL}"; else _va="${YW}not VLAN-aware${CL}"; fi
    printf '  %-10s %-18s %s\n' "$b" "${_ha:-no host address}" "$_va"
  done
fi

printf '\n%sGuests%s\n' "$BLD" "$CL"
if [ -z "$GUESTS" ]; then
  printf '  none\n'
else
  printf '  %-6s %-4s %-20s %-9s %-6s %s\n' "ID" "KIND" "NAME" "BRIDGE" "VLAN" "ADDRESS"
  printf '%s\n' "$GUESTS" | while IFS='|' read -r id kind name br tag addr; do
    [ -z "$id" ] && continue
    printf '  %-6s %-4s %-20s %-9s %-6s %s\n' \
      "$id" "$kind" "${name:0:20}" "$br" "$tag" "$addr"
  done
fi

printf '\n%sSubnets in use%s\n' "$BLD" "$CL"
if [ -z "$USED_NETS" ]; then printf '  none detected\n'
else printf '%s\n' "$USED_NETS" | sed 's/^/  /'; fi

printf '\n%sVLAN tags in use%s\n' "$BLD" "$CL"
if [ -z "$USED_TAGS" ]; then printf '  none\n'
else printf '  %s\n' "$(printf '%s ' $USED_TAGS)"; fi

if [ -n "$STOR" ]; then
  printf '\n%sStorage%s\n' "$BLD" "$CL"
  printf '%s\n' "$STOR" | awk 'NR==1 || $3=="active" {printf "  %s\n", $0}' | head -12
fi

# ── Findings ─────────────────────────────────────────────────────────────────
# Each finding names the silent consequence, not just the condition. A warning
# that says "no VLAN-aware bridge" and stops is a warning that gets dismissed.
FINDINGS=0
_find() { FINDINGS=$((FINDINGS+1)); printf '  %s[%d]%s %s\n' "$YW" "$FINDINGS" "$CL" "$1"; }
_findr(){ FINDINGS=$((FINDINGS+1)); printf '  %s[%d]%s %s\n' "$RD" "$FINDINGS" "$CL" "$1"; }

printf '\n%sFindings%s\n' "$BLD" "$CL"

_AWARE=""
for b in $BRIDGES; do _bridge_vlan_aware "$b" && _AWARE="${_AWARE} $b"; done
_AWARE="${_AWARE# }"

if [ -z "$BRIDGES" ]; then
  _findr "No vmbr bridge found. Nothing can be attached to a network."
elif [ -z "$_AWARE" ]; then
  _findr "No bridge is VLAN-aware. Proxmox ACCEPTS a VLAN tag on a guest
      attached to one of these and delivers the frames untagged — the guest
      comes up on the wrong segment and nothing reports an error.
      A segmented stack needs 'bridge-vlan-aware yes' on the trunk bridge.
      Changing it is a network change on a live host: wrap it in a revert
      timer before you apply it."
fi

_n_br=$(printf '%s\n' "$BRIDGES" | grep -c . || true)
if [ "${_n_br:-0}" -eq 1 ] && [ -n "$BRIDGES" ]; then
  _find "One bridge only (${BRIDGES}), carrying this host's own address.
      An OPNsense VM placed on it becomes the gateway for the segment you are
      administering the hypervisor from, so a wrong firewall rule locks you
      out of Proxmox as well as the guests. Plan a second bridge for the
      trunk, or keep console access to hand."
fi

_noaddr=$(printf '%s\n' "$GUESTS" | awk -F'|' '$6=="-" {print $1}' | sort -u | tr '\n' ' ')
if [ -n "${_noaddr// /}" ]; then
  # Covers VMs as well as containers, and VMs are the common case: a qm guest's
  # address lives inside the guest, never in its Proxmox config, so a full-VM
  # host looks addressless here while being entirely static. Saying "containers"
  # would have made this read as a container-only caveat.
  _find "No address in the Proxmox config for: ${_noaddr%% }
      Normal for VMs — a qm guest's address is set inside the guest, not in
      its config — and it means those addresses are invisible to the
      collision checks. This tool reads configuration; it does not scan."
fi

# A subnet in use twice is a real conflict and worth naming precisely.
_dupe="$(printf '%s\n' "$USED_NETS" | sort | uniq -d)"
[ -n "$_dupe" ] && _find "Subnet appears more than once: $(printf '%s ' $_dupe)"

if [ -z "$NEXTID" ]; then
  _find "Could not ask Proxmox for the next free VM ID (pvesh unavailable).
      The plan below starts from a guess; check it against 'qm list'."
fi

[ "$FINDINGS" -eq 0 ] && printf '  %snothing to flag%s\n' "$GN" "$CL"

[ "$MODE" = "map" ] && { printf '\n'; exit 0; }

# ── Plan ─────────────────────────────────────────────────────────────────────
# Conventions taken from OPNSENSE.md rather than invented here, because the
# firewall config generator and this plan have to agree or the generated rules
# name segments that do not exist:
#
#   * one VLAN per trust boundary
#   * the third octet IS the VLAN tag, always — so a firewall log is legible
#     without a lookup table
#   * each site gets its own second octet; a subnet reused across two sites
#     makes the remote one invisible over an overlay, because the
#     directly-connected route wins
#   * .1 gateway, .10-.49 static servers, .100-.200 DHCP
_free_tag() {                  # first unused tag at or above $1
  local t="$1"
  while printf '%s\n' "$USED_TAGS" | grep -qx "$t"; do t=$((t+1)); done
  printf '%s' "$t"
}
_free_id() {                   # first unused id at or above $1
  local i="$1"
  while printf '%s\n' "$USED_IDS" | grep -qx "$i"; do i=$((i+1)); done
  printf '%s' "$i"
}

if [ -z "$SITE_OCTET" ]; then
  SITE_OCTET=20
  while printf '%s\n' "$USED_OCTET2" | grep -qx "$SITE_OCTET"; do
    SITE_OCTET=$((SITE_OCTET+10))
    [ "$SITE_OCTET" -gt 250 ] && { SITE_OCTET=20; break; }
  done
fi

# Bands, not "first free above 10". Both documented sites put the proxy on a
# low tag and tenant sites in a 101+ band, and the firewall config generator
# names segments from the same convention — so picking 11 and 12 here would
# produce a plan that is valid, collision-free, and disagrees with every other
# document about which segment a tag means. Tenant 101 also leaves 11-99 free
# for the service segments a stack grows into.
T_PROXY=$(_free_tag 10)
T_SITE=$(_free_tag 101)
N_PROXY="10.${SITE_OCTET}.${T_PROXY}"
N_SITE="10.${SITE_OCTET}.${T_SITE}"

ID_FW=$(_free_id "${NEXTID:-100}")
ID_PROXY=$(_free_id $((ID_FW+1)))
ID_WASP=$(_free_id $((ID_PROXY+1)))

TRUNK="${PREF_BRIDGE:-${_AWARE%% *}}"
[ -z "$TRUNK" ] && TRUNK="${BRIDGES%%$'\n'*}"

if [ "$WANT_VARS" -eq 1 ]; then
  # Exactly the names install.sh and the generators consume, so this output can
  # be sourced rather than retyped. Retyping six addresses across three VMs is
  # where a stack build goes wrong.
  cat >&3 <<VARS
# wasp-topology.sh --vars — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Review every line before sourcing. These avoid collisions with what this
# host already has; they cannot avoid collisions with devices Proxmox does
# not know about.
STACK_BRIDGE=${TRUNK}
STACK_SITE_OCTET=${SITE_OCTET}

OPNSENSE_VMID=${ID_FW}
OPNSENSE_LAN=10.${SITE_OCTET}.1.1/24

NPMPLUS_VMID=${ID_PROXY}
NPMPLUS_VLAN=${T_PROXY}
NPMPLUS_IP_CIDR=${N_PROXY}.10/24
NPMPLUS_GW=${N_PROXY}.1

WASP_VMID=${ID_WASP}
WASP_VLAN=${T_SITE}
WASP_IP_CIDR=${N_SITE}.10/24
WASP_GW=${N_SITE}.1

# Consumed by WASP's installer directly:
WASP_PROXY_IP=${N_PROXY}.10
WASP_CS_ENFORCEMENT=upstream
WASP_CS_LAPI_URL=http://${N_PROXY}.10:8080/
WASP_CROWDSEC_WHITELIST=${N_PROXY}.10,100.64.0.0/10
VARS
  exit 0
fi

printf '\n%s╔══════════════════════════════════════════════════════════════╗%s\n' "$BLD" "$CL"
printf '%s║  Proposed stack%-47s║%s\n' "$BLD" "" "$CL"
printf '%s╚══════════════════════════════════════════════════════════════╝%s\n' "$BLD" "$CL"
printf '\n  Trunk bridge   %s\n' "$TRUNK"
printf '  Site octet     10.%s.x.x   (unused on this host)\n' "$SITE_OCTET"
printf '\n  %-12s %-6s %-5s %-18s %s\n' "ROLE" "VMID" "VLAN" "ADDRESS" "GATEWAY"
printf '  %-12s %-6s %-5s %-18s %s\n' "OPNsense" "$ID_FW"    "-"        "10.${SITE_OCTET}.1.1/24" "(is the gateway)"
printf '  %-12s %-6s %-5s %-18s %s\n' "NPMplus"  "$ID_PROXY" "$T_PROXY" "${N_PROXY}.10/24"        "${N_PROXY}.1"
printf '  %-12s %-6s %-5s %-18s %s\n' "WASP"     "$ID_WASP"  "$T_SITE"  "${N_SITE}.10/24"         "${N_SITE}.1"

printf '\n%sHow these three are tuned to each other%s\n' "$BLD" "$CL"
printf '  WASP trusts   %s   as its single literal RemoteIPTrustedProxy\n' "${N_PROXY}.10"
printf '  WASP reports  bans to the LAPI at http://%s:8080/\n' "${N_PROXY}.10"
printf '  NPMplus knows %s/24 as a backend CIDR\n' "${N_SITE}.0"
printf '  OPNsense gets a %s segment and a %s segment, the proxy-to-backend\n' "PROXY" "WP01"
printf '                rule, and the agent-to-LAPI rule on the backend side\n'

printf '\n%sBefore you build from this%s\n' "$BLD" "$CL"
printf '  %sThis tool reads Proxmox configuration — it does not scan.%s A\n' "$YW" "$CL"
printf '  statically-addressed appliance on a VLAN with no Proxmox guest on it\n'
printf '  is invisible here, so confirm these subnets and tags really are free\n'
printf '  on the wire. From the host:\n'
printf '      %sip neigh show | grep -E "10\\.%s\\."%s   (nothing = nothing seen)\n' "$BL" "$SITE_OCTET" "$CL"
printf '      %sip route get %s.10%s\n' "$BL" "$N_PROXY" "$CL"
# arping is the better test and is NOT installed by default on Proxmox — it
# lives in iputils-arping. Naming it as the primary check would be the same
# defect check-tool-availability.py exists to catch in the docs: an
# instruction that fails on a clean host and reads like a network fault.
printf '  A positive ARP probe is better still, if you have it:\n'
printf '      %sarping -c2 -I %s %s.10%s\n' "$BL" "$TRUNK" "$N_PROXY" "$CL"
printf '      (not installed by default:  apt install iputils-arping)\n'
if [ -z "$_AWARE" ]; then
  printf '  %sAnd the VLAN tags above cannot work until a bridge is VLAN-aware.%s\n' "$RD" "$CL"
fi
printf '\n  Machine-readable:  %s --plan --vars\n' "$0"
printf '\n'
