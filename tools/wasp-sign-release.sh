#!/usr/bin/env bash
# =============================================================================
# wasp-sign-release.sh — sign a WASP release so install.sh will verify it
# =============================================================================
#
# Run this ON YOUR BUILD MACHINE, from the root of a clean checkout.
# It never runs on a Proxmox host and never on a provisioned VM.
#
#   ./tools/wasp-sign-release.sh              sign, using ~/.minisign/wasp.key
#   ./tools/wasp-sign-release.sh --keygen     create the keypair (once, ever)
#   ./tools/wasp-sign-release.sh --check      verify what is already here
#   ./tools/wasp-sign-release.sh --dns        print the TXT record to publish
#   ./tools/wasp-sign-release.sh --key PATH   use a secret key elsewhere
#
# WHAT install.sh ACTUALLY VERIFIES, which is what this has to produce
#
#   1. WASP_PUBKEY is non-empty in install.sh        (else: "unsigned build")
#   2. MANIFEST.sha256 and MANIFEST.sha256.minisig both exist
#   3. minisign -Vm MANIFEST.sha256 -P "$WASP_PUBKEY"   passes
#   4. sha256sum -c MANIFEST.sha256, run from the release root, passes
#   5. the key in install.sh matches the TXT record at WASP_KEY_DNS
#
# Steps 3 and 4 are different questions and both matter. The signature proves
# the manifest is authentic; the hashes prove the files match that manifest. A
# release with only one of them is not a verified release.
#
# ── THE ORDERING TRAP ────────────────────────────────────────────────────────
#
# install.sh is ITSELF in the manifest, and the public key is embedded IN
# install.sh. So embedding the key changes install.sh, which changes its hash.
#
# Embed first, hash second, sign third. Any other order produces a release
# whose signature is valid and whose `sha256sum -c` fails on install.sh —
# which reads as "a shipped file was modified after signing", i.e. exactly
# like tampering. This script enforces the order rather than documenting it.
#
# ── WHAT IS SIGNED ───────────────────────────────────────────────────────────
#
# install.sh, lib/ and payload/ — the files that execute during an install or
# land on the VM. Not docs/, not test/, not tools/. That set is enforced
# independently by test/check-manifest-coverage.py, so the two cannot drift.
#
# tools/ being unsigned is a known gap, recorded in docs/STACK-DESIGN.md.
# Including it here without also changing that check and verify_release()
# would just move the inconsistency.
# =============================================================================
set -euo pipefail

RD=$'\033[0;31m'; GN=$'\033[0;32m'; YW=$'\033[0;33m'
BL=$'\033[0;36m'; BLD=$'\033[1m';  CL=$'\033[0m'
[ -t 1 ] || { RD=""; GN=""; YW=""; BL=""; BLD=""; CL=""; }

die()  { printf '%s✗%s  %s\n' "$RD" "$CL" "$*" >&2; exit 1; }
ok()   { printf '%s✔%s  %s\n' "$GN" "$CL" "$*"; }
warn() { printf '%s⚠%s  %s\n' "$YW" "$CL" "$*"; }
note() { printf '%s➜%s  %s\n' "$BL" "$CL" "$*"; }

SECKEY="${WASP_SECKEY:-$HOME/.minisign/wasp.key}"
PUBKEY_FILE="${SECKEY%.key}.pub"
MODE="sign"

while [ $# -gt 0 ]; do
  case "$1" in
    --keygen) MODE="keygen" ;;
    --check)  MODE="check" ;;
    --dns)    MODE="dns" ;;
    --key)    SECKEY="${2:-}"; PUBKEY_FILE="${SECKEY%.key}.pub"; shift ;;
    -h|--help) sed -n '3,45p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "Unknown argument: $1  (try --help)" ;;
  esac
  shift
done

command -v minisign >/dev/null 2>&1 \
  || die "minisign is not installed.  apt install minisign  /  brew install minisign"

# Refuse to run anywhere but a release root. Signing the wrong directory
# produces a manifest listing nothing, which still signs cleanly.
[ -f install.sh ] && [ -d lib ] && [ -d payload ] \
  || die "Run this from the root of a WASP checkout (expected install.sh, lib/, payload/)."

MANIFEST=MANIFEST.sha256
SIG="${MANIFEST}.minisig"
KEY_DNS=$(sed -n 's/^WASP_KEY_DNS="\${WASP_KEY_DNS:-\([^}"]*\)}".*/\1/p' install.sh | head -1)
KEY_DNS="${KEY_DNS:-minisign._wasp.ironveil.systems}"
RELEASE=$(sed -n 's/^WASP_RELEASE="\([^"]*\)".*/\1/p' install.sh | head -1)

# ── The signed file set ──────────────────────────────────────────────────────
# One definition, used by both sign and check. Paths are relative with no
# leading ./ because install.sh runs `sha256sum -c` from the release root and
# check-manifest-coverage.py compares against exactly these names.
_signed_files() { printf '%s\n' install.sh; find lib payload -type f | LC_ALL=C sort; }

# ── --keygen ─────────────────────────────────────────────────────────────────
if [ "$MODE" = "keygen" ]; then
  [ -f "$SECKEY" ] && die "A secret key already exists at ${SECKEY}.
   Generating a new one does NOT invalidate old releases, but every client
   must be told to trust the new key. If you mean to rotate, move the old
   key aside deliberately and read the rotation notes in --help."
  mkdir -p "$(dirname "$SECKEY")"; chmod 700 "$(dirname "$SECKEY")"
  printf '%s\n' "${BLD}Generating the release signing keypair${CL}"
  printf '  Use a strong passphrase. It is the only thing protecting the key\n'
  printf '  if the build machine is compromised, and minisign will ask for it\n'
  printf '  on every signature — which is the point.\n\n'
  minisign -G -s "$SECKEY" -p "$PUBKEY_FILE"
  chmod 600 "$SECKEY"
  ok "Secret key: ${SECKEY}  (chmod 600)"
  ok "Public key: ${PUBKEY_FILE}"
  echo ""
  warn "Back the secret key up NOW, to two places, before you sign anything."
  note "Lose it and you cannot sign new releases — existing ones still verify,"
  note "but every client must be told to trust a replacement key."
  note "Record both locations in docs/KEY-CUSTODY.md → Release signing."
  echo ""
  note "Next:  ./tools/wasp-sign-release.sh --dns     then publish that record"
  exit 0
fi

# ── Read the public key ──────────────────────────────────────────────────────
# minisign.pub is two lines: an untrusted comment, then the key. Only the key
# line goes in install.sh and in DNS, because install.sh greps for ^RW.
_pub_line() {
  [ -f "$PUBKEY_FILE" ] || die "No public key at ${PUBKEY_FILE}
   Generate one:  ./tools/wasp-sign-release.sh --keygen
   Or point at an existing key:  --key /path/to/wasp.key"
  grep -m1 '^RW' "$PUBKEY_FILE" \
    || die "${PUBKEY_FILE} has no key line starting with RW — is it a minisign public key?"
}

# ── --dns ────────────────────────────────────────────────────────────────────
if [ "$MODE" = "dns" ]; then
  PUB=$(_pub_line)
  cat <<DNS

${BLD}Publish this TXT record${CL}

  Name   ${KEY_DNS}
  Type   TXT
  TTL    3600
  Value  ${PUB}

The VALUE IS THE KEY LINE ONLY — no comment line, no quotes of your own, no
'minisign public key:' prefix. install.sh greps the answer for ^RW and
compares it byte for byte against the key embedded in install.sh, so an extra
character is a mismatch, and a mismatch is reported to the operator as either
a rotated key or an install.sh that did not come from you.

Some DNS panels add the quotes themselves. Check the result rather than the
form you typed:

  dig +short TXT ${KEY_DNS}

Expect exactly one line, which after stripping quotes equals the Value above.
More than one TXT record on that name is a problem: install.sh takes the first
RW line it sees, so a stale record can win.

${BLD}Enable DNSSEC on the zone.${CL} Without it this lookup is spoofable on the
network path, and install.sh says so explicitly rather than implying the match
proves anything:

  "(not DNSSEC-validated — corroboration, not proof)"

The signature check is the control that decides authenticity. This record is a
second, independent place to notice that the key changed — which is why it
should not live on the same system as the key.

DNS
  exit 0
fi

# ── --check ──────────────────────────────────────────────────────────────────
# Runs the same four checks install.sh runs, in the same order, so a release
# can be proven good before it is published rather than on a client's host.
if [ "$MODE" = "check" ]; then
  printf '%s\n\n' "${BLD}Verifying this release the way install.sh will${CL}"
  rc=0
  EMB=$(sed -n 's/^WASP_PUBKEY="\${WASP_PUBKEY:-\([^}"]*\)}".*/\1/p' install.sh | head -1)

  printf '  %-44s ' "1. WASP_PUBKEY embedded in install.sh"
  if [ -n "$EMB" ]; then echo "yes"
  else echo "NO"; rc=1
       printf '       install.sh reports "this build is unsigned" and refuses.\n'; fi

  printf '  %-44s ' "2. manifest and signature present"
  if [ -f "$MANIFEST" ] && [ -f "$SIG" ]; then echo "yes"
  else echo "NO"; rc=1; fi

  printf '  %-44s ' "3. signature valid for the embedded key"
  if [ -n "$EMB" ] && [ -f "$SIG" ]; then
    if out=$(minisign -Vm "$MANIFEST" -P "$EMB" 2>&1); then
      echo "yes"
      printf '       %s\n' "$(printf '%s' "$out" | grep -i 'trusted comment' || true)"
    else echo "NO"; rc=1; printf '       %s\n' "$out"; fi
  else echo "skipped"; fi

  printf '  %-44s ' "4. every file matches its hash"
  if [ -f "$MANIFEST" ]; then
    if sha256sum -c --quiet "$MANIFEST" 2>/dev/null; then echo "yes"
    else echo "NO"; rc=1
         printf '       The signature can be valid while this fails — that means a\n'
         printf '       file changed after signing. Re-sign; do not hand-edit.\n'; fi
  else echo "skipped"; fi

  # Coverage, which a valid signature over an incomplete manifest would hide.
  printf '  %-44s ' "5. manifest covers the whole signed set"
  if [ -f "$MANIFEST" ]; then
    _missing=$(comm -23 <(_signed_files) <(awk '{print $2}' "$MANIFEST" | sed 's|^\*||' | LC_ALL=C sort) | head -5)
    if [ -z "$_missing" ]; then echo "yes"
    else echo "NO"; rc=1
         printf '       not signed: %s\n' "$(printf '%s ' $_missing)"; fi
  else echo "skipped"; fi

  printf '  %-44s ' "6. DNS record matches the embedded key"
  if ! command -v dig >/dev/null 2>&1; then echo "skipped (no dig)"
  elif [ -z "$EMB" ]; then echo "skipped"
  else
    _p=$(dig +short +timeout=5 TXT "$KEY_DNS" 2>/dev/null | tr -d '"\r' | grep -E '^RW' | head -1)
    if [ -z "$_p" ]; then echo "no record at ${KEY_DNS}"
         printf '       Not fatal for the installer, which skips the cross-check.\n'
         printf '       Publish it:  ./tools/wasp-sign-release.sh --dns\n'
    elif [ "$_p" = "$EMB" ]; then echo "yes"
    else echo "MISMATCH"; rc=1
         printf '       embedded: %s\n       published: %s\n' "$EMB" "$_p"; fi
  fi

  echo ""
  if [ "$rc" -eq 0 ]; then
    ok "This release verifies. install.sh will accept it."
  else
    die "Not a publishable release. Fix the above and re-sign."
  fi
  exit 0
fi

# ── sign ─────────────────────────────────────────────────────────────────────
PUB=$(_pub_line)
[ -f "$SECKEY" ] || die "No secret key at ${SECKEY}
   Generate one:  ./tools/wasp-sign-release.sh --keygen"

printf '%s\n' "${BLD}Signing WASP ${RELEASE:-(no version found)}${CL}"
[ -n "$RELEASE" ] || warn "No WASP_RELEASE found in install.sh — the trusted comment will be vague."

# Refuse to sign a dirty or unverified tree. A signature's only meaning is
# "this is what the project published"; signing whatever happens to be in the
# working directory, including an abandoned experiment, empties it out.
if [ -d .git ] && command -v git >/dev/null 2>&1; then
  if [ -n "$(git status --porcelain -- install.sh lib payload 2>/dev/null)" ]; then
    warn "Uncommitted changes in the signed file set:"
    git status --porcelain -- install.sh lib payload | sed 's/^/      /'
    echo ""
    printf '  Sign anyway? [y/N] : '
    read -r _d; case "${_d:-n}" in y|Y) : ;; *) die "Stopped. Commit first." ;; esac
  else
    ok "Working tree clean for install.sh, lib/ and payload/"
  fi
  note "Commit: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
fi

if [ -x test/run-all-checks.sh ] || [ -f test/run-all-checks.sh ]; then
  printf '\n%s\n' "${BLD}Running the check suite first${CL}"
  note "A signature says these files are authentic, not that they work."
  note "Signing a build that fails its own checks publishes the failure."
  if bash test/run-all-checks.sh >/tmp/.wasp-sign-checks.$$ 2>&1; then
    ok "All checks passed"
  else
    tail -25 /tmp/.wasp-sign-checks.$$ | sed 's/^/      /'
    rm -f /tmp/.wasp-sign-checks.$$
    printf '\n  Sign a release that fails its checks? [y/N] : '
    read -r _c; case "${_c:-n}" in y|Y) warn "Signing a failing build." ;; *) die "Stopped." ;; esac
  fi
  rm -f /tmp/.wasp-sign-checks.$$
fi

# ── 1. Embed the key FIRST ───────────────────────────────────────────────────
# Before hashing, because install.sh is in the manifest. See the ordering trap
# in the header.
printf '\n%s\n' "${BLD}1. Embedding the public key in install.sh${CL}"
CUR=$(sed -n 's/^WASP_PUBKEY="\${WASP_PUBKEY:-\([^}"]*\)}".*/\1/p' install.sh | head -1)
if [ "$CUR" = "$PUB" ]; then
  ok "Already embedded and current"
else
  [ -n "$CUR" ] && warn "Replacing a different embedded key — this is a key rotation."
  # The whole line is rewritten rather than patched in place, so the result is
  # the same whether the field was empty or held an older key.
  tmp=$(mktemp)
  _repl="WASP_PUBKEY=\"\${WASP_PUBKEY:-${PUB}}\"    # release key; empty = unsigned build"
  sed "s|^WASP_PUBKEY=\"\\\${WASP_PUBKEY:-[^}\"]*}\".*|${_repl}|" install.sh > "$tmp"
  grep -q "WASP_PUBKEY=\"\${WASP_PUBKEY:-${PUB}}\"" "$tmp" \
    || { rm -f "$tmp"; die "Could not embed the key — the WASP_PUBKEY line in install.sh is not in the expected shape.
   Expected:  WASP_PUBKEY=\"\\\${WASP_PUBKEY:-}\"    # ...
   Edit it by hand, then re-run."; }
  mv "$tmp" install.sh
  ok "Embedded: ${PUB}"
fi

# ── 2. Build the manifest ────────────────────────────────────────────────────
printf '\n%s\n' "${BLD}2. Building ${MANIFEST}${CL}"
rm -f "$MANIFEST" "$SIG"
_signed_files | xargs sha256sum > "$MANIFEST"
ok "$(wc -l < "$MANIFEST") files hashed"
sha256sum -c --quiet "$MANIFEST" || die "The manifest does not verify against the tree it was just built from."
ok "Manifest verifies against the working tree"

# ── 3. Sign it ───────────────────────────────────────────────────────────────
printf '\n%s\n' "${BLD}3. Signing the manifest${CL}"
note "minisign will ask for the key passphrase."
# -t sets the TRUSTED comment, which is covered by the signature and therefore
# cannot be altered without the secret key. install.sh prints it, so it is the
# one place a version string is trustworthy — an attacker can relabel a tarball
# but not this.
# Built in steps, not one expression. The first version embedded
#   $([ -d .git ] && printf ' — %s' "$(git rev-parse ...)")
# which under `set -e` kills the script at the ASSIGNMENT whenever .git is
# absent: the substitution's last command is the failed test, so the whole
# assignment exits 1. The symptom was the script stopping silently after
# printing "minisign will ask for the key passphrase" — no error, no signature,
# and minisign never ran. A conditional inside a captured substitution is the
# exact pattern check-seterr-capture.py exists for.
_commit=""
if [ -d .git ] && command -v git >/dev/null 2>&1; then
  _commit=$(git rev-parse --short HEAD 2>/dev/null || true)
fi
TRUSTED="WASP ${RELEASE:-unversioned} — signed $(date -u +%Y-%m-%dT%H:%M:%SZ)${_commit:+ — ${_commit}}"
minisign -Sm "$MANIFEST" -s "$SECKEY" -t "$TRUSTED"
[ -f "$SIG" ] || die "minisign did not produce ${SIG}"
ok "Signed: ${SIG}"

# ── 4. Verify as the installer will ──────────────────────────────────────────
printf '\n%s\n' "${BLD}4. Verifying exactly as install.sh does${CL}"
minisign -Vm "$MANIFEST" -P "$PUB" | sed 's/^/      /'
sha256sum -c --quiet "$MANIFEST" && ok "All files match the signed manifest"

cat <<DONE

${GN}Release signed.${CL}

  Ship these two alongside install.sh, lib/ and payload/:
      ${MANIFEST}
      ${SIG}

  A GitHub release tarball built from this commit already contains them. A
  tarball built from a tag you signed BEFORE committing the embedded key does
  not, and fails on install.sh's hash — re-sign after committing.

  ${BLD}Confirm, then publish:${CL}
      ./tools/wasp-sign-release.sh --check
      ./tools/wasp-sign-release.sh --dns

  ${BLD}What an operator should run:${CL}
      minisign -Vm MANIFEST.sha256 -P "\$(dig +short TXT ${KEY_DNS} | tr -d '\"')"
      sha256sum -c MANIFEST.sha256

DONE
