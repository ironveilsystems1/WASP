#!/usr/bin/env bash
# =============================================================================
# install.sh — WordPress VM provisioning entry point (Proxmox VE host)
# =============================================================================
# Run this ON THE PROXMOX HOST as root. It builds a hardened Alpine +
# Podman (WordPress + MariaDB) + CrowdSec VM: downloads and verifies the
# Alpine cloud image, injects configuration and the in-VM installer directly
# onto the disk image (no network dependency inside the VM for the initial
# file layout), then creates and starts the Proxmox VM.
#
# This used to be one 8,694-line script. It is now this thin entry point
# plus lib/*.sh (sourced below, in order) and payload/ (files copied onto
# the VM disk for the in-VM installer to use). See README.md for the full
# repository layout and CHANGELOG.md for what changed and why.
#
# USAGE — two supported ways to run this, both fully supported, not one
# "real" way and one fallback:
#
#   1. Single command, no git required (Proxmox does not ship git by
#      default, and this avoids installing it just to fetch a script):
#        curl -fsSL -O https://raw.githubusercontent.com/ironveilsystems1/WASP/refs/heads/main/install.sh
#        chmod +x install.sh
#        sudo ./install.sh
#      install.sh notices it's running standalone (no sibling lib/ or
#      payload/) and fetches the rest of the repository itself -- see
#      "Self-bootstrap" below for exactly what that does and why.
#
#   2. A full clone, if you already have git or want the whole history:
#        git clone https://github.com/ironveilsystems1/WASP.git
#        cd WASP
#        sudo ./install.sh
#      install.sh finds lib/ and payload/ right next to itself and skips
#      the self-bootstrap step entirely -- nothing is downloaded twice.
#
# Every prompt, default, generated file, and VM setting is unchanged from
# v8-1 -- this is a reorganization, not a rewrite. See CHANGELOG.md.
# =============================================================================
set -e

# ── Self-bootstrap ────────────────────────────────────────────────────────────
# Added for the curl-one-liner usage above. install.sh on its own is not
# enough to build the VM -- lib/*.sh has to run somewhere, and payload/ has
# to physically exist somewhere to be copied onto the VM disk. When a full
# checkout isn't there already, this fetches ONLY what's missing: the
# GitHub-generated tarball of the whole repo (no git needed -- it's a plain
# HTTPS download GitHub builds on request), into a temp directory that is
# deleted again when this script exits, by the SAME cleanup() trap that
# already tears down every other temp resource this install creates (see
# lib/00-preflight.sh) -- "minimize what's loaded onto the Proxmox host"
# means during the ~15-minute run, not permanently, and this doesn't touch
# a real git clone (REPO_DIR then points at YOUR directory, never deleted).
#
# Verifying what you run: this downloads over HTTPS (TLS already rules out
# tampering in transit) from whatever WPVM_REPO_REF names -- "main" by
# default, i.e. whatever is on the branch right now. That is the right
# default for "always get the latest fixes" but it is a materially weaker
# integrity story than pinning to a specific commit: a floating branch
# means a future compromise of the repo is fetched by every install run
# from that point on, with nothing here to catch it. If you want a fixed,
# reviewable reference instead of "whatever main is today," set
# WPVM_REPO_REF to a specific commit SHA (from this repo's own commit
# history) before running:
#   WPVM_REPO_REF=<40-char-sha> sudo -E ./install.sh
# This is the same trade-off, and the same trust model, as any single-file
# "curl | bash" installer (Docker's, rustup's, Homebrew's) -- no download-
# time checksum can substitute for that, since a checksum published in the
# same repo it's meant to verify is checking the repo against itself, not
# against an independent source. What a checksum-of-this-download CAN
# catch -- truncation, a corrupted transfer, a wrong URL -- it does; see
# the size and structure checks below.
# Repository moved to the IronVeil Systems organisation. GitHub redirects the
# old owner/name indefinitely, so existing clones keep working — but a new
# install should fetch from the current path rather than rely on a redirect
# that is a courtesy, not a guarantee.
REPO_OWNER="ironveilsystems1"
# Repository renamed to WASP. GitHub redirects the old name indefinitely, so an
# existing clone or a bookmarked URL keeps working -- but new installs should
# fetch from the current name, not rely on a redirect that is a courtesy rather
# than a guarantee.
REPO_NAME="WASP"
REPO_REF="${WPVM_REPO_REF:-main}"

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_WPVM_BOOTSTRAP_DIR=""   # set below only if a fetch actually happens; read by
                         # lib/00-preflight.sh's cleanup() trap

if [[ -d "${SELF_DIR}/lib" && -d "${SELF_DIR}/payload" ]]; then
  REPO_DIR="$SELF_DIR"
else
  echo "install.sh is running standalone (no sibling lib/ or payload/) —"
  echo "fetching ${REPO_OWNER}/${REPO_NAME}@${REPO_REF}..."
  command -v curl >/dev/null 2>&1 || { echo "FATAL: curl not found." >&2; exit 1; }
  command -v tar  >/dev/null 2>&1 || { echo "FATAL: tar not found."  >&2; exit 1; }

  _WPVM_BOOTSTRAP_DIR=$(mktemp -d /tmp/wpvm-bootstrap.XXXXXX) \
    || { echo "FATAL: could not create a temp directory." >&2; exit 1; }

  # Commit SHAs (7-40 hex chars) use a bare .../archive/<sha>.tar.gz;
  # anything else is treated as a branch name, needing the refs/heads/
  # prefix. (Tags aren't auto-detected here -- pass a commit SHA if you
  # want a fixed reference; branches cover the floating-default case.)
  if [[ "$REPO_REF" =~ ^[0-9a-f]{7,40}$ ]]; then
    TARBALL_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/${REPO_REF}.tar.gz"
  else
    TARBALL_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/refs/heads/${REPO_REF}.tar.gz"
  fi

  ARCHIVE="${_WPVM_BOOTSTRAP_DIR}/src.tar.gz"
  curl -fsSL "$TARBALL_URL" -o "$ARCHIVE" || {
    echo "FATAL: could not download ${TARBALL_URL}" >&2
    echo "  Check network access from this host, and that '${REPO_REF}' is a real branch or commit." >&2
    rm -rf "$_WPVM_BOOTSTRAP_DIR"
    exit 1
  }

  # Sanity check, not a security check (see the note above): a 404/error
  # page saved as if it were the archive is a few hundred bytes; the real
  # thing is not. Catches a wrong URL or an unexpected redirect target,
  # not a deliberately-crafted malicious archive of a plausible size.
  ARCHIVE_SIZE=$(wc -c < "$ARCHIVE" 2>/dev/null || echo 0)
  if (( ARCHIVE_SIZE < 10000 )); then
    echo "FATAL: downloaded archive is only ${ARCHIVE_SIZE} bytes — that's not a real repository archive." >&2
    echo "  URL was: ${TARBALL_URL}" >&2
    rm -rf "$_WPVM_BOOTSTRAP_DIR"
    exit 1
  fi

  tar -xzf "$ARCHIVE" -C "$_WPVM_BOOTSTRAP_DIR" || {
    echo "FATAL: downloaded file is not a valid .tar.gz archive." >&2
    rm -rf "$_WPVM_BOOTSTRAP_DIR"
    exit 1
  }
  rm -f "$ARCHIVE"

  # GitHub names the extracted top-level directory "<repo>-<ref>" (with
  # slashes in the ref sanitized) -- rather than hardcode that naming, just
  # take whatever single top-level directory the archive produced.
  REPO_DIR=$(find "$_WPVM_BOOTSTRAP_DIR" -mindepth 1 -maxdepth 1 -type d | head -1)
  if [[ -z "$REPO_DIR" || ! -d "${REPO_DIR}/lib" || ! -d "${REPO_DIR}/payload" ]]; then
    echo "FATAL: extracted archive doesn't look like ${REPO_NAME} (no lib/ or payload/ inside)." >&2
    rm -rf "$_WPVM_BOOTSTRAP_DIR"
    exit 1
  fi
  echo "Fetched $(find "$REPO_DIR" -type f | wc -l) files into a temp directory (removed when this script exits)."
fi

# ── Release signature verification ────────────────────────────────────────────
# The public key is embedded here rather than fetched, because a key fetched
# alongside the thing it verifies proves nothing. Publish this fingerprint
# somewhere that is NOT this repository -- a project site, a release
# announcement -- so it can be checked against an independent source once.
# After that, a repository compromise cannot go unnoticed: the attacker would
# have to change this line too, and anyone who recorded the key sees it.
#
# Honest scope: for a first-time user who fetches install.sh and the release
# from the same place, this is not a root of trust. It is tamper-evidence
# with a short, checkable identifier -- which is meaningfully better than an
# unsigned curl|bash, and is not the same as a trusted supply chain.
# ── Build identity ───────────────────────────────────────────────────────────
# Written to /etc/wp-install/vars.sh at install and shown by the banner, the
# validator and the test report.
#
# This exists because of a real, expensive confusion: a VM installed from an
# earlier build served its login page at "/<slug>-login", a later build moved
# it to the bare "/<slug>", and several hours were spent diagnosing an
# imagined fault in mod_remoteip, nftables and nginx before anyone established
# which of the two was actually running. Logs and diagnostics that do not
# state their build cannot be reasoned about safely.
#
# Bump this whenever behaviour changes in a way an operator would notice.
# ONE version. WASP_RELEASE and WASP_VERSION are the same value and both exist
# only because the rest of the codebase references each of them.
#
# There used to be two: a semantic release plus a date build stamp, on the
# argument that a single number cannot say WHICH 10.2 a VM is running. That was
# a reasonable argument and it lost to reality — the date stamp was wrong for
# weeks, reading 2026.08.x through most of September, because nothing verified
# it and nobody reads a build stamp closely enough to notice. An identifier
# that is silently wrong is worse than one that carries less information.
#
# If a build stamp is wanted again later, generate it rather than typing it.
WASP_RELEASE="10.4"
WASP_VERSION="10.4"
WASP_VERSION_NOTE="Reverse-proxy enforcement gap closed: CrowdSec enforcement topology is chosen, not assumed; TRUST-COUNT asserted at both write sites; split-horizon loopback; proxy settings presettable"

# Persist a durable record that this install skipped signature verification.
# validate-wordpress.sh and wasp-testreport.sh surface it, so an unverified
# lab build can never be quietly mistaken for a verified one later -- the
# state lives on disk, not just in the install log that scrolls away.
_mark_unverified() {
  mkdir -p /etc/wp-install 2>/dev/null || true
  {
    echo "UNVERIFIED_INSTALL=1"
    echo "UNVERIFIED_REASON=\"${1:-unspecified}\""
    echo "UNVERIFIED_AT=\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\""
  } > /etc/wp-install/UNVERIFIED 2>/dev/null || true
  chmod 644 /etc/wp-install/UNVERIFIED 2>/dev/null || true
}

WASP_PUBKEY="${WASP_PUBKEY:-RWSi+SUZQWeFKd9yTC3Q7xAEADUph345WdgwOOlxK+dV40GHEqMsFTPc}"    # set to the release key; empty = unsigned build

# Where the key fingerprint is published independently of this repository.
# The point of a second location is DIFFERENT CREDENTIALS, not merely a
# different URL: a Gist or a Pages site on the same GitHub account falls to
# exactly the compromise this is meant to make visible. A DNS record is held
# at the registrar, which is a separate account entirely.
WASP_KEY_DNS="${WASP_KEY_DNS:-minisign._wasp.ironveil.systems}"

# Cross-check the embedded key against that DNS record.
#
# HONEST SCOPE, because this is easy to overstate: plain DNS is spoofable by
# anyone on the network path, so this is CORROBORATION, not a second root of
# trust. It answers "does the key baked into this file match the one published
# under separate credentials?" -- which catches a repository compromise that
# swapped both the release and the embedded key, and catches nothing at all
# against an attacker who also controls your resolver. With DNSSEC on the zone
# it is meaningfully stronger. Treat a mismatch as serious and a match as
# reassuring rather than conclusive.
verify_key_dns() {
  [[ -n "$WASP_PUBKEY" ]] || return 0
  [[ "${WASP_SKIP_KEY_DNS:-0}" == "1" ]] && return 0
  command -v dig >/dev/null 2>&1 || command -v host >/dev/null 2>&1 || {
    echo "  (dig/host not present — skipping the DNS key cross-check)"; return 0; }

  local published=""
  if command -v dig >/dev/null 2>&1; then
    published=$(dig +short +timeout=5 +tries=2 TXT "$WASP_KEY_DNS" 2>/dev/null \
                | tr -d '"' | tr -d '\r' | grep -E '^RW' | head -1)
  else
    published=$(host -t TXT "$WASP_KEY_DNS" 2>/dev/null \
                | sed -n 's/.*"\(RW[^"]*\)".*/\1/p' | head -1)
  fi

  if [[ -z "$published" ]]; then
    # Not fatal: the record may not be published yet, DNS may be filtered, or
    # the host may have no outbound resolver. Saying so is more useful than
    # failing on an absence that has many innocent causes.
    echo "  No key record at ${WASP_KEY_DNS} — cross-check skipped."
    return 0
  fi
  if [[ "$published" == "$WASP_PUBKEY" ]]; then
    # Report whether the answer was DNSSEC-validated, rather than implying it
    # was. `dig +dnssec` sets the AD (Authenticated Data) flag only when the
    # resolver validated the chain; without it this lookup is spoofable on the
    # network path and the match is weaker corroboration than it looks.
    local _ad=""
    if command -v dig >/dev/null 2>&1; then
      _ad=$(dig +dnssec +timeout=5 TXT "$WASP_KEY_DNS" 2>/dev/null | grep -c "flags:.* ad[ ;]") || _ad=0
    fi
    if [[ "${_ad:-0}" -gt 0 ]]; then
      echo "  ✔ Embedded key matches ${WASP_KEY_DNS} (DNSSEC-validated)"
    else
      echo "  ✔ Embedded key matches ${WASP_KEY_DNS}"
      echo "    (not DNSSEC-validated — corroboration, not proof: a resolver on"
      echo "     the network path could return this answer. Enable DNSSEC on the"
      echo "     zone, and use a validating resolver, to strengthen it.)"
    fi
    return 0
  fi
  echo "" >&2
  echo "  ✗ KEY MISMATCH." >&2
  echo "      embedded in install.sh : ${WASP_PUBKEY}" >&2
  echo "      published in DNS       : ${published}" >&2
  echo "" >&2
  echo "  These should be identical. Either the release key was rotated and" >&2
  echo "  this copy of install.sh is stale, or this copy of install.sh did not" >&2
  echo "  come from the project. Do not proceed until you know which." >&2
  echo "  Check independently: https://ironveil.systems/wasp-signing-key/" >&2
  if [[ "${WASP_REQUIRE_SIGNATURE:-0}" == "1" ]]; then
    echo "  FATAL: WASP_REQUIRE_SIGNATURE=1." >&2; exit 1
  fi
  # Not fatal by default: a stale checkout after a legitimate key rotation
  # would otherwise brick every install, and the signature check below is the
  # control that actually decides whether these files are authentic.
  printf "  Continue anyway? [y/N] : " >&2
  read -r _kc
  [[ "${_kc}" =~ ^[Yy] ]] || { echo "  Aborted." >&2; exit 1; }
}

verify_release() {
  local dir="$1"
  local man="${dir}/MANIFEST.sha256"
  local sig="${man}.minisig"

  # Whether an unverifiable release is fatal is decided by the deployment
  # profile, not by an environment variable the operator has to remember.
  #
  # A third-party review put this plainly: making the strongest supply-chain
  # control opt-in via WASP_REQUIRE_SIGNATURE=1 means it is off exactly when
  # it matters, because nobody types it. Every other verification here already
  # follows the profile — Alpine's SHA-512, digest pinning, the CrowdSec
  # bouncer, sysctls, GeoIP — and signature checking is the one that was
  # inconsistent.
  #
  # production : unverifiable is FATAL.
  # standard   : warn and continue, which is right for a lab VM and stated as
  #              such rather than presented as verified.
  # WASP_REQUIRE_SIGNATURE=1 still forces fatal regardless, for anyone
  # scripting installs outside the profile mechanism.
  # DEPLOYMENT_PROFILE is deliberately NOT consulted here: it does not exist
  # yet at this point in the run. Only an explicit environment variable can
  # tighten this further than the default refusal below.
  _sig_required=0
  [[ "${WASP_REQUIRE_SIGNATURE:-0}" == "1" ]] && _sig_required=1

  # NOTE ON ORDERING: this runs during the self-bootstrap, before lib/01 asks
  # for the deployment profile — so keying the decision off DEPLOYMENT_PROFILE
  # would never fire. Verification has to happen before anything is sourced,
  # which is exactly why it cannot consult an answer collected later.
  #
  # So the default is REFUSE, and proceeding requires typing a word. A warning
  # that scrolls past is not a decision; a prompt that will not accept Enter
  # is. Non-interactive runs abort outright, because an unattended install
  # cannot meaningfully consent to running unverified code as root.
  _sig_fail() {
    echo "" >&2
    echo "════════════════════════════════════════════════════════════" >&2
    echo " RELEASE COULD NOT BE VERIFIED" >&2
    echo "════════════════════════════════════════════════════════════" >&2
    echo "  $1" >&2
    echo "" >&2
    echo "  This script is about to source and execute these files as root on" >&2
    echo "  your hypervisor. Unverified, there is nothing establishing they are" >&2
    echo "  what the project published." >&2
    echo "" >&2
    if [[ "$_sig_required" == "1" ]]; then
      echo "  WASP_REQUIRE_SIGNATURE=1 is set. Refusing." >&2
      exit 1
    fi
    # A certified production install must not proceed unverified by ANY path.
    # An MSP that ships client sites cannot have "signature check failed, but
    # someone set a bypass variable" as a reachable outcome -- the whole point
    # of signing is defeated if a flag skips it. So under
    # DEPLOYMENT_PROFILE=production, neither the noninteractive
    # WASP_ACCEPT_UNVERIFIED escape nor the interactive UNVERIFIED prompt is
    # available; the only fix is a correctly signed build.
    # There is no "standard" profile to fall back to any more -- one profile
    # means one set of guarantees. The only escape is an env var, deliberately:
    # nobody sets an environment variable by accident at the end of a long day,
    # whereas an interactive prompt gets answered wrong routinely.
    #
    # A VM built this way is stamped UNVERIFIED permanently. It will build, so
    # a development checkout is usable, and it can never be certified -- which
    # is the honest outcome for code whose provenance was never established.
    if [[ "${WASP_DEV_UNVERIFIED:-0}" == "1" ]]; then
      echo "  WASP_DEV_UNVERIFIED=1 — proceeding without signature verification." >&2
      echo "  This VM will be marked UNVERIFIED and cannot be certified." >&2
      echo "  Never use this for a client deployment." >&2
      mkdir -p /etc/wp-install 2>/dev/null || true
      printf 'WASP_DEV_UNVERIFIED=1\n' > /etc/wp-install/UNVERIFIED 2>/dev/null || true
    else
      echo "  An unverified install is not permitted." >&2
      echo "" >&2
      echo "  Signature verification must pass: WASP_PUBKEY set, and a valid" >&2
      echo "  MANIFEST.sha256 with its .minisig present. That is what a client" >&2
      echo "  deployment requires and there is no profile that waives it." >&2
      echo "" >&2
      echo "  For a DEVELOPMENT checkout with no signed release:" >&2
      echo "    WASP_DEV_UNVERIFIED=1 ./install.sh" >&2
      echo "  The resulting VM is permanently marked UNVERIFIED." >&2
      exit 1
    fi
    if [[ ! -t 0 ]]; then
      echo "  Not an interactive session, so this cannot be confirmed. Refusing." >&2
      echo "  To install unverified deliberately, run interactively, or set" >&2
      echo "  WASP_ACCEPT_UNVERIFIED=1 having understood the above." >&2
      [[ "${WASP_ACCEPT_UNVERIFIED:-0}" == "1" ]] || exit 1
      echo "  WASP_ACCEPT_UNVERIFIED=1 — continuing unverified." >&2
      _mark_unverified "noninteractive WASP_ACCEPT_UNVERIFIED=1"
      return 0
    fi
    printf "  Type UNVERIFIED to proceed anyway, anything else to stop: " >&2
    read -r _uv
    [[ "$_uv" == "UNVERIFIED" ]] || { echo "  Stopped." >&2; exit 1; }
    echo "  Proceeding UNVERIFIED at your explicit request." >&2
    _mark_unverified "interactive UNVERIFIED confirmation"
    return 0
  }

  if [[ -z "$WASP_PUBKEY" ]]; then
    _sig_fail "this build is unsigned — no release key is configured, so the fetched files cannot be verified."
    return 0
  fi
  if [[ ! -f "$man" || ! -f "$sig" ]]; then
    _sig_fail "no signed manifest in this release (expected MANIFEST.sha256 and MANIFEST.sha256.minisig)."
    return 0
  fi
  if ! command -v minisign >/dev/null 2>&1; then
    # Deliberately not silently downgraded to "hashes only": hashes from an
    # unverified manifest catch corruption, not tampering, and reporting that
    # as verification would be worse than reporting nothing.
    _sig_fail "minisign is not installed, so the release SIGNATURE cannot be checked (apt install minisign)."
    return 0
  fi

  verify_key_dns
  echo "Verifying release signature…"
  local out
  if ! out=$(minisign -Vm "$man" -P "$WASP_PUBKEY" 2>&1); then
    echo "FATAL: the release manifest signature is NOT valid." >&2
    echo "  ${out}" >&2
    echo "  Either this release was not signed with the expected key, or the" >&2
    echo "  files were altered after signing. Not proceeding." >&2
    exit 1
  fi
  # The trusted comment is covered by the signature, so the version it names
  # cannot be forged without the secret key.
  echo "  ${out}" | grep -i "trusted comment" || true

  echo "Verifying file hashes against the signed manifest…"
  local bad=0
  ( cd "$dir" && sha256sum -c --quiet MANIFEST.sha256 ) || bad=1
  if [[ $bad -ne 0 ]]; then
    echo "FATAL: a file does not match the signed manifest." >&2
    echo "  The signature was valid, so the manifest itself is authentic —" >&2
    echo "  which means a shipped file was modified after signing." >&2
    exit 1
  fi
  echo "  All files match the signed manifest."
}
verify_release "$REPO_DIR"

# ── Deployment-contract preflight ────────────────────────────────────────────
# Validates the WASP_* deployment presets BEFORE anything is downloaded,
# mounted or created.
#
# Why here and not in lib/01, where these values are used: the build takes
# about fifteen minutes and lib/06 is roughly twelve of them in. A preset typo
# caught there costs a quarter of an hour and a half-built VM to clean up; the
# same typo costs two seconds here. For a fleet rollout -- ten tenants behind
# one proxy, which is what the presets exist for -- that difference is the
# difference between a loop you can run and a loop you have to babysit.
#
# These are refusals, not warnings. Each one is a value that decides a security
# property, and a security property that defaults quietly when its input is
# malformed is the failure shape this whole project keeps finding.
contract_preflight() {
  local fail=0

  # TRUST-COUNT. RemoteIPTrustedProxy must name exactly ONE literal address:
  # mod_remoteip walks X-Forwarded-For from the right, popping entries while
  # they match a trusted proxy, and takes the first untrusted one as the
  # client. A range therefore lets any host inside it prepend whatever client
  # address it likes and have Apache believe it -- and that forged address is
  # what CrowdSec bans, what the wp-admin restriction allows, and what the
  # login guard counts attempts against. One compromised neighbour becomes an
  # authentication bypass. lib/03 and lib/06 assert this again where they
  # write the directive; this catches it before the clock starts.
  if [[ -n "${WASP_PROXY_IP:-}" ]]; then
    if [[ "$WASP_PROXY_IP" =~ [/,[:space:]] ]]; then
      echo "FATAL: WASP_PROXY_IP='${WASP_PROXY_IP}' is a range or a list." >&2
      echo "  RemoteIPTrustedProxy takes one literal address. A range lets any" >&2
      echo "  host inside it forge the client IP in X-Forwarded-For, which is" >&2
      echo "  the address CrowdSec bans and the one wp-admin checks." >&2
      echo "  Use the proxy's own address, e.g. WASP_PROXY_IP=10.20.10.10" >&2
      fail=1
    elif [[ ! "$WASP_PROXY_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
      echo "FATAL: WASP_PROXY_IP='${WASP_PROXY_IP}' is not an IPv4 address." >&2
      echo "  A hostname is not usable here — Apache resolves RemoteIPTrustedProxy" >&2
      echo "  once at startup, so a name that later resolves elsewhere leaves" >&2
      echo "  Apache trusting an address nothing told it about." >&2
      fail=1
    fi
  fi

  # The enforcement mode decides whether a bouncer is installed at all, so an
  # unrecognised value cannot be allowed to fall through to a default: the two
  # candidate defaults differ by whether this VM enforces anything.
  if [[ -n "${WASP_CS_ENFORCEMENT:-}" ]]; then
    case "$WASP_CS_ENFORCEMENT" in
      local|upstream|detect-only) : ;;
      *) echo "FATAL: WASP_CS_ENFORCEMENT='${WASP_CS_ENFORCEMENT}' is not recognised." >&2
         echo "  Expected one of:" >&2
         echo "    local        bouncer on this VM. Only enforces when clients" >&2
         echo "                 reach it directly." >&2
         echo "    upstream     detect here, enforce at the proxy or firewall." >&2
         echo "                 Needs WASP_CS_LAPI_URL, _LOGIN and _PASSWORD." >&2
         echo "    detect-only  alerts, no enforcement. Recorded as a blocker." >&2
         fail=1 ;;
    esac

    # upstream with a missing credential becomes detect-only in stage 09 and
    # says so — correct behaviour for an interactive install where the operator
    # is there to read it, and wrong for a scripted one where nobody is. An
    # unattended run that asked for enforcement and got none is exactly the
    # silent downgrade the preset was meant to prevent, so refuse instead.
    if [[ "$WASP_CS_ENFORCEMENT" == "upstream" ]]; then
      local missing=""
      [[ -z "${WASP_CS_LAPI_URL:-}" ]]      && missing="${missing} WASP_CS_LAPI_URL"
      [[ -z "${WASP_CS_LAPI_LOGIN:-}" ]]    && missing="${missing} WASP_CS_LAPI_LOGIN"
      [[ -z "${WASP_CS_LAPI_PASSWORD:-}" ]] && missing="${missing} WASP_CS_LAPI_PASSWORD"
      if [[ -n "$missing" ]]; then
        echo "FATAL: upstream enforcement is missing:${missing}" >&2
        echo "  Without all three the agent authenticates nowhere, and this VM" >&2
        echo "  detects attacks that reach no bouncer — indistinguishable from" >&2
        echo "  working, from here." >&2
        echo "  Register the machine on the LAPI host first:" >&2
        echo "    cscli machines add <login> --password '<password>'" >&2
        fail=1
      fi
      if [[ -n "${WASP_CS_LAPI_URL:-}" && ! "$WASP_CS_LAPI_URL" =~ ^https?:// ]]; then
        echo "FATAL: WASP_CS_LAPI_URL='${WASP_CS_LAPI_URL}' needs a scheme, e.g." >&2
        echo "  http://10.20.10.10:8080/" >&2
        fail=1
      fi
      # A loopback LAPI cannot serve an agent in another VM. Caught here
      # because the symptom — an agent that starts cleanly and reports
      # nothing — points at credentials, and the cause is an address.
      if [[ "${WASP_CS_LAPI_URL:-}" =~ ^https?://(127\.|localhost) ]]; then
        echo "FATAL: WASP_CS_LAPI_URL points at loopback (${WASP_CS_LAPI_URL})." >&2
        echo "  That is this VM, not the central LAPI. A stock CrowdSec install" >&2
        echo "  binds 127.0.0.1:8080 and is unreachable from anywhere else —" >&2
        echo "  publishing it is a change on the LAPI host, not here." >&2
        fail=1
      fi
    fi

    # local enforcement behind a proxy is the configuration that cannot work.
    # Stage 09 records it as a production blocker, which is the right place for
    # the decision — but if it was asked for by preset rather than chosen at a
    # prompt, nobody read the explanation, so say it now.
    if [[ "$WASP_CS_ENFORCEMENT" == "local" && -n "${WASP_PROXY_IP:-}" ]]; then
      echo "NOTE: local enforcement with a proxy at ${WASP_PROXY_IP}." >&2
      echo "  Every request will arrive from that address, so a ban on a real" >&2
      echo "  client address matches nothing this VM sees. The install will" >&2
      echo "  continue and record a production blocker." >&2
      echo "  Correct unless the proxy preserves the client source address at" >&2
      echo "  layer 3, or clients can also reach this VM directly." >&2
    fi
  fi

  # SSH key presets. The full classification lives in lib/00 and runs on every
  # key; this catches the two that are worth catching before a fifteen-minute
  # build, and it cannot call that helper because this function runs before
  # lib/00 is sourced.
  if [[ -n "${WASP_SSH_KEY_FILE:-}" ]]; then
    local kf="$WASP_SSH_KEY_FILE"
    [[ "$kf" == "~/"* ]] && kf="${HOME}/${kf#\~/}"
    if [[ ! -f "$kf" ]]; then
      # Silently loading nothing is the bad outcome: with no key the install
      # falls back to password auth, or under production stops to ask — either
      # way the preset did not do what the runbook says it does.
      echo "FATAL: WASP_SSH_KEY_FILE='${WASP_SSH_KEY_FILE}' does not exist." >&2
      echo "  No keys would be loaded, and the install would fall back to a" >&2
      echo "  password or stop to ask — so a scripted run would not be doing" >&2
      echo "  what its runbook says." >&2
      fail=1
    elif [[ ! -r "$kf" ]]; then
      echo "FATAL: WASP_SSH_KEY_FILE='${kf}' is not readable." >&2
      fail=1
    elif grep -q 'PRIVATE KEY' "$kf" 2>/dev/null; then
      # Refused early and loudly. A private key here would end up on the VM's
      # disk and in the install log, which is a new keypair rather than a typo.
      echo "FATAL: WASP_SSH_KEY_FILE='${kf}' contains a PRIVATE key." >&2
      echo "  Point this at the .pub file. A private key in authorized_keys" >&2
      echo "  gives no login AND puts the private half on the VM's disk and in" >&2
      echo "  the install log — treat that keypair as compromised." >&2
      fail=1
    fi
  fi
  if [[ -n "${WASP_SSH_KEYS:-}" ]] && [[ "$WASP_SSH_KEYS" == *"PRIVATE KEY"* ]]; then
    echo "FATAL: WASP_SSH_KEYS contains a PRIVATE key. Use the .pub contents." >&2
    fail=1
  fi

  if [[ -n "${WASP_LOOPBACK_HOSTS:-}" ]]; then
    case "$WASP_LOOPBACK_HOSTS" in
      0|1|y|Y|n|N|yes|no) : ;;
      *) echo "FATAL: WASP_LOOPBACK_HOSTS='${WASP_LOOPBACK_HOSTS}' — expected 1 or 0." >&2
         fail=1 ;;
    esac
  fi

  # The whitelist is validated here for a different reason than the others:
  # a malformed entry does not fail anywhere. CrowdSec loads the file, ignores
  # the entry it cannot parse, and the address the operator believes is
  # protected simply is not — discovered when a lockout happens, which is the
  # worst possible moment to find out. The interactive prompt validates each
  # entry; a preset would otherwise skip that.
  if [[ -n "${WASP_CROWDSEC_WHITELIST:-}" ]]; then
    local bad="" entry
    local oldifs="$IFS"; IFS=','
    for entry in $WASP_CROWDSEC_WHITELIST; do
      IFS="$oldifs"
      entry="${entry//[[:space:]]/}"
      [[ -z "$entry" ]] && { IFS=','; continue; }
      if [[ ! "$entry" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
        bad="${bad:+$bad, }$entry"
      fi
      IFS=','
    done
    IFS="$oldifs"
    if [[ -n "$bad" ]]; then
      echo "FATAL: WASP_CROWDSEC_WHITELIST has entries that are not an IPv4" >&2
      echo "  address or CIDR: ${bad}" >&2
      echo "  CrowdSec would load the file, ignore these, and never say so —" >&2
      echo "  so the addresses you believe are protected would not be." >&2
      fail=1
    fi
    # Not fatal, because a proxy's own engine may whitelist itself, but worth
    # saying out loud: an unattended run cannot be asked this at a prompt.
    if [[ -n "${WASP_PROXY_IP:-}" ]] \
       && [[ ",${WASP_CROWDSEC_WHITELIST}," != *",${WASP_PROXY_IP},"* ]]; then
      echo "NOTE: ${WASP_PROXY_IP} (the proxy) is not in WASP_CROWDSEC_WHITELIST." >&2
      echo "  If X-Forwarded-For substitution ever breaks, this VM sees every" >&2
      echo "  request as coming from the proxy — one brute-force attempt then" >&2
      echo "  bans it and the site is down for every visitor." >&2
      if [[ "${WASP_CS_ENFORCEMENT:-}" == "upstream" ]]; then
        echo "  With upstream enforcement that ban is shared, so it is every" >&2
        echo "  site behind that proxy, not just this one." >&2
      fi
    fi
  fi

  if [[ $fail -ne 0 ]]; then
    echo "" >&2
    echo "Nothing has been created. Fix the above and re-run." >&2
    exit 1
  fi

  # Echo the contract when any of it was preset, so an unattended run leaves a
  # record of what it was told rather than only what it did.
  if [[ -n "${WASP_PROXY_IP:-}${WASP_CS_ENFORCEMENT:-}${WASP_LOOPBACK_HOSTS:-}${WASP_CROWDSEC_WHITELIST:-}${WASP_SSH_KEY_FILE:-}${WASP_SSH_KEYS:-}" ]]; then
    echo "Deployment contract (from the environment):"
    [[ -n "${WASP_SSH_KEY_FILE:-}" ]] && echo "  ssh keys from     ${WASP_SSH_KEY_FILE}"
    [[ -n "${WASP_SSH_KEYS:-}" ]]     && echo "  ssh keys inline   $(printf '%s' "$WASP_SSH_KEYS" | grep -c . ) line(s)"
    [[ -n "${WASP_PROXY_IP:-}" ]]       && echo "  trusted proxy    ${WASP_PROXY_IP}  (single literal address)"
    [[ -n "${WASP_CS_ENFORCEMENT:-}" ]] && echo "  cs enforcement   ${WASP_CS_ENFORCEMENT}${WASP_CS_LAPI_URL:+  → ${WASP_CS_LAPI_URL}}"
    [[ -n "${WASP_CS_LAPI_LOGIN:-}" ]]  && echo "  cs machine       ${WASP_CS_LAPI_LOGIN}"
    [[ -n "${WASP_CROWDSEC_WHITELIST:-}" ]] && echo "  never ban        ${WASP_CROWDSEC_WHITELIST}"
    [[ -n "${WASP_LOOPBACK_HOSTS:-}" ]] && echo "  loopback         ${WASP_LOOPBACK_HOSTS}"
    echo ""
  fi
}
contract_preflight

LIB_DIR="${REPO_DIR}/lib"

# ── Run each phase in order, in THIS shell (so every variable set by one ────
#    phase -- VMID, ROOT_PASS, ALPINE_URL, MNT, and so on -- stays in scope
#    for every later phase, exactly as it would in one unsplit script). ──────
. "${LIB_DIR}/00-preflight.sh"
. "${LIB_DIR}/01-interactive-setup.sh"
. "${LIB_DIR}/02-image-and-disk.sh"
. "${LIB_DIR}/03-dynamic-configs.sh"
. "${LIB_DIR}/04-nbd-mount-and-chroot.sh"
. "${LIB_DIR}/05-ssh-and-network-inject.sh"
. "${LIB_DIR}/06-vars-and-payload-inject.sh"
. "${LIB_DIR}/07-vm-create-and-start.sh"
