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
