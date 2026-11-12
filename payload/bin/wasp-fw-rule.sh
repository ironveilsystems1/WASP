#!/bin/sh
# =============================================================================
# wasp-fw-rule.sh — single named firewall rules that WASP tools add at runtime
# =============================================================================
#   wasp-fw-rule.sh add <tag> input|output <nft rule expression>
#   wasp-fw-rule.sh del <tag>
#   wasp-fw-rule.sh list
#
# Two tools need one precise rule each, after install, that must survive a
# reboot:
#   wasp-appsec.sh  the WordPress container may reach CrowdSec's AppSec
#                   listener on the host           (input,  tag "appsec")
#   wasp-egress.sh  this VM may reach its WASP Hive on a port other than 443
#                   under RESTRICT_EGRESS=1        (output, tag "hive")
#
# Each rule is applied to the running ruleset AND written to
# /etc/wp-install/wasp-rules.nft, which /etc/nftables.nft includes. Doing only
# the first is lost on reboot; doing only the second is a change that appears
# to have had no effect. Every rule carries the comment "wasp:<tag>", which is
# how `del` finds it again, live and on disk.
#
# Input rules are appended (the input chain ends in its drop POLICY, so an
# appended accept is reached). Output rules are inserted at the top, because
# the restricted output chain ends in an explicit `drop`: an appended accept
# would never be reached. Callers must therefore never pass an output rule for
# a management port (8006, 8007, 3128, 5900-5999) or mail (25, 465, 587):
# inserted first, it would bypass the blocks that sit above the egress list.
# This script refuses those ports itself as well.
#
# The persisted file is checked with `nft -c` against the whole ruleset before
# it is kept. A rule that does not parse is never left where the next boot
# would load it: a ruleset that fails to load leaves the VM with no firewall.
# =============================================================================
set -u

if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then exec doas "$0" "$@"; fi
  echo "Run as root (or via doas)" >&2; exit 1
fi

FILE=${WASP_RULES_FILE:-/etc/wp-install/wasp-rules.nft}
MAIN=${NFT_MAIN:-/etc/nftables.nft}
NFT=${NFT_BIN:-nft}
TABLE="inet filter"

_header() {
  printf '# Runtime rules added by WASP tools (wasp-fw-rule.sh). Included from\n'
  printf '# /etc/nftables.nft. Do not delete: empty is valid, missing is fatal.\n'
}

_ensure_file() {
  mkdir -p "$(dirname "$FILE")"
  [ -f "$FILE" ] || { _header > "$FILE"; chmod 644 "$FILE"; }
  if [ -f "$MAIN" ] && ! grep -qF "include \"$FILE\"" "$MAIN"; then
    printf '\ninclude "%s"\n' "$FILE" >> "$MAIN"
  fi
}

_valid_tag() { case "$1" in ''|*[!a-z0-9-]*) return 1 ;; esac; [ "${#1}" -le 24 ]; }

_check_ports() {   # refuse output rules that would sit above the management / mail blocks
  for _w in $*; do
    case "$_w" in
      8006|8007|3128|25|465|587) return 1 ;;
      59[0-9][0-9]) return 1 ;;
    esac
  done
  return 0
}

_del_live() {
  for _ch in input output; do
    $NFT -a list chain $TABLE "$_ch" 2>/dev/null \
      | sed -n "s/.*comment \"wasp:$1\".*# handle \([0-9][0-9]*\).*/\1/p" \
      | while read -r _h; do $NFT delete rule $TABLE "$_ch" handle "$_h" 2>/dev/null; done
  done
}

_del_file() {
  [ -f "$FILE" ] || return 0
  grep -vF "comment \"wasp:$1\"" "$FILE" > "$FILE.tmp" 2>/dev/null
  mv -f "$FILE.tmp" "$FILE"
}

case "${1:-list}" in
  add)
    _tag="${2:-}"; _chain="${3:-}"
    shift 3 2>/dev/null || { echo "Usage: wasp-fw-rule.sh add <tag> input|output <rule>" >&2; exit 2; }
    _rule="$*"
    _valid_tag "$_tag" || { echo "Tag: lowercase letters, digits and - (24 at most)" >&2; exit 2; }
    case "$_chain" in
      input)  _verb=add ;;
      output) _verb=insert
              _check_ports $_rule || { echo "Refused: that port is blocked above the egress list on purpose." >&2; exit 2; } ;;
      *) echo "Chain must be input or output" >&2; exit 2 ;;
    esac
    case "$_rule" in *accept) : ;; *) echo "Only accept rules are added here" >&2; exit 2 ;; esac
    case "$_rule" in *'"'*|*';'*|*'{'*|*'}'*|*'#'*) echo "Refused: rule contains characters that are not needed here" >&2; exit 2 ;; esac
    _ensure_file
    cp -p "$FILE" "$FILE.prev"
    _del_file "$_tag"
    printf '%s rule %s %s %s comment "wasp:%s"\n' "$_verb" "$TABLE" "$_chain" "$_rule" "$_tag" >> "$FILE"
    if [ -f "$MAIN" ] && ! $NFT -c -f "$MAIN" >/dev/null 2>"$FILE.err"; then
      mv -f "$FILE.prev" "$FILE"
      echo "✗ The rule does not load with the rest of the ruleset — nothing changed:" >&2
      sed 's/^/    /' "$FILE.err" >&2; rm -f "$FILE.err"
      exit 1
    fi
    rm -f "$FILE.prev" "$FILE.err"
    _del_live "$_tag"
    # shellcheck disable=SC2086
    if ! $NFT $_verb rule $TABLE "$_chain" $_rule comment "\"wasp:$_tag\"" 2>/dev/null; then
      echo "✗ Saved for the next boot, but not applied now — is nftables loaded? (rc-service nftables status)" >&2
      exit 1
    fi
    echo "✔ firewall: ${_chain} rule wasp:${_tag} — live now, and kept across reboots" ;;
  del)
    _valid_tag "${2:-}" || { echo "Usage: wasp-fw-rule.sh del <tag>" >&2; exit 2; }
    _del_live "$2"; _del_file "$2"
    echo "✔ firewall: rule wasp:$2 removed" ;;
  list)
    echo "  Live:"
    for _ch in input output; do
      $NFT list chain $TABLE "$_ch" 2>/dev/null | grep 'comment "wasp:' | sed "s/^[[:space:]]*/    $_ch  /"
    done
    echo "  Persisted (${FILE}):"
    grep -v '^#' "$FILE" 2>/dev/null | grep . | sed 's/^/    /' || echo "    (none)" ;;
  *) sed -n '4,6p' "$0"; exit 2 ;;
esac
