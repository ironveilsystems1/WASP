#!/bin/sh
# =============================================================================
# wasp-upgrade.sh — bring this VM's WASP tooling up to a new release
# =============================================================================
#   wasp-upgrade.sh check <release> [--diff]   verify it and show what would change
#   wasp-upgrade.sh apply <release> [--yes] [--force]
#                                              verify, back up, change, check
#   wasp-upgrade.sh rollback [backup]          put back what the last upgrade replaced
#   wasp-upgrade.sh status                     version, upgrade history, backups
#
# <release> is the release tarball (wasp-X.tar.gz) or the unpacked directory.
# A VM that predates this tool runs it from the release itself, once:
#   doas sh /root/wasp-X/payload/bin/wasp-upgrade.sh apply /root/wasp-X
#
# WHY
#
# VMs do not update their own tooling. Until 10.18 each release's CHANGELOG
# carried a block of commands to paste, and every release added to it: copy the
# payload, install the tools, install a new mu-plugin, rewrite one cron line,
# append two more. Pasted by hand on a fleet, that drifts -- a step skipped on
# one VM, a cron line appended twice on another -- and nothing checked that the
# release being pasted was the one that was signed.
#
# WHAT IT DOES
#
#   1. Verifies the release: the minisign signature on MANIFEST.sha256 against
#      the key PINNED ON THIS VM when it was built (release.pub) -- never a key
#      the release brings with it -- then every file against the manifest, and
#      refuses files the manifest does not list.
#   2. Plans: which tools, mu-plugins, rules and cron lines change, and which
#      build-time configuration changed upstream (reported, never replaced).
#      A tool or mu-plugin that differs from what was installed blocks the
#      upgrade: an edited script that runs as root is evidence (--force to
#      overwrite it anyway, after looking).
#   3. Backs up everything it will touch, then applies payload/upgrade/files.map
#      from the new release. Safe to run twice: a second run changes nothing.
#   4. Runs the release's upgrade hooks (payload/upgrade/hooks/<version>.sh) for
#      every version passed, checks each mu-plugin with PHP inside the wordpress
#      container, the site's health, and the tooling against the manifest.
#      A mu-plugin that fails PHP's check after install is put back at once: an
#      mu-plugin fatal takes the whole site down and cannot be undone from wp-admin.
#
# WHAT IT DOES NOT DO
#
# Rebuild the VM, change containers or images (update.sh does that), or replace
# configuration written at build time. Those files hold this VM's own values;
# the plan lists the ones that changed and the CHANGELOG says what to do.
# =============================================================================
set -u
if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then exec doas "$0" "$@"; fi
  echo "Run as root (or via doas)" >&2; exit 1
fi
umask 022

R="${WASP_ROOT:-}"                       # a filesystem prefix: the tests use one
SRC="${R}/etc/wp-install"
STAGED="${SRC}/payload"
STAGES="${SRC}/stages"
VARS="${SRC}/vars.sh"
STATE="${R}/var/lib/wasp-upgrade"
BACKUPS="${STATE}/backups"
HISTORY="${STATE}/history.log"
CRONTAB="${R}/etc/crontabs/root"
KEEP_BACKUPS="${WASP_UPGRADE_KEEP:-5}"

_ok()   { printf '  \033[32m✔\033[0m  %s\n' "$1"; }
_bad()  { printf '  \033[31m✗\033[0m  %s\n' "$1"; }
_warn() { printf '  \033[33m⚠\033[0m  %s\n' "$1"; }
_note() { printf '     %s\n' "$1"; }
_hdr()  { echo ""; echo "$1"; echo "$1" | sed 's/./━/g'; }
_die()  { _bad "$1"; [ -n "${2:-}" ] && _note "$2"; _cleanup; exit "${3:-2}"; }

_WORK=""; _LOCKED=0
_cleanup() {
  [ -n "$_WORK" ] && rm -rf "$_WORK"
  [ "$_LOCKED" = 1 ] && rmdir "${STATE}/lock" 2>/dev/null
  _WORK=""; _LOCKED=0
}
trap '_cleanup' EXIT
trap '_cleanup; exit 130' INT TERM

_lock() {
  mkdir -p "$STATE" "$BACKUPS" && chmod 0700 "$STATE" "$BACKUPS"
  mkdir "${STATE}/lock" 2>/dev/null \
    || _die "Another upgrade or rollback is running (${STATE}/lock)." \
            "If none is, remove that directory and run this again." 3
  _LOCKED=1
}

_unq() { sed -e 's/^["'"'"']//' -e 's/["'"'"']$//'; }
_var() { [ -r "$VARS" ] && sed -n "s/^$1=//p" "$VARS" | head -1 | _unq; }
_sq()  { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

# Version compare: prints -1, 0 or 1. Numeric per dotted part; "unknown" is oldest.
_vercmp() {
  awk -v a="$1" -v b="$2" 'BEGIN {
    if (a == b) { print 0; exit } if (a !~ /^[0-9]/) { print -1; exit } if (b !~ /^[0-9]/) { print 1; exit }
    na = split(a, x, "."); nb = split(b, y, "."); n = na > nb ? na : nb
    for (i = 1; i <= n; i++) { p = x[i] + 0; q = y[i] + 0
      if (p < q) { print -1; exit } if (p > q) { print 1; exit } }
    print 0 }'
}

_stat() { # file -> "+added −removed" line counts against another file
  if [ ! -e "$1" ]; then printf 'new, %s lines' "$(wc -l < "$2" | tr -d ' ')"; return; fi
  diff -U0 "$1" "$2" 2>/dev/null | awk '/^(\+\+\+|---)/ {next} /^\+/ {a++} /^-/ {d++}
                                        END {printf "+%d −%d lines", a, d}'
}

# ── the release ──────────────────────────────────────────────────────────────
REL=""
_open_release() {
  _in="${1:-}"
  [ -n "$_in" ] || _die "Name the release: the wasp-X.tar.gz tarball or its unpacked directory."
  _WORK=$(mktemp -d "${STATE}/work.XXXXXX") || _die "Cannot create a work directory under ${STATE}"
  if [ -d "$_in" ]; then
    REL=$(cd "$_in" && pwd)
  elif [ -f "$_in" ]; then
    case "$_in" in *.tar.gz|*.tgz) : ;; *) _die "Not a release tarball: ${_in}" ;; esac
    # Untrusted until verified: refuse absolute paths, .. and links before
    # extracting, and never restore the archive's owners.
    _list=$(tar tzf "$_in" 2>/dev/null) || _die "Cannot read ${_in} as a gzip tarball."
    printf '%s\n' "$_list" | grep -qE '(^/|(^|/)\.\.(/|$))' \
      && _die "The archive holds an absolute or ../ path. Not extracting it." "" 2
    mkdir -p "${_WORK}/rel"
    tar xzof "$_in" -C "${_WORK}/rel" 2>/dev/null || _die "Extracting ${_in} failed."
    if find "${_WORK}/rel" -type l | grep -q .; then
      _die "The archive holds symbolic links; a WASP release has none. Not using it."
    fi
    _top=$(find "${_WORK}/rel" -mindepth 1 -maxdepth 1 -type d)
    [ "$(printf '%s\n' "$_top" | grep -c .)" = 1 ] || _die "Expected one top-level directory in ${_in}."
    REL="$_top"
  else
    _die "No such file or directory: ${_in}"
  fi
  [ -r "${REL}/install.sh" ] && [ -r "${REL}/MANIFEST.sha256" ] && [ -d "${REL}/payload/bin" ] \
    && [ -r "${REL}/payload/upgrade/files.map" ] \
    || _die "${_in} is not a WASP release this tool can apply (needs install.sh, MANIFEST.sha256, payload/upgrade/files.map)."
  REL_VER=$(sed -n 's/^WASP_VERSION="\([^"]*\)".*/\1/p' "${REL}/install.sh" | head -1)
  REL_NOTE=$(sed -n 's/^WASP_VERSION_NOTE="\(.*\)"[[:space:]]*$/\1/p' "${REL}/install.sh" | head -1)
  [ -n "$REL_VER" ] || _die "The release's install.sh does not state WASP_VERSION."
  CUR_VER=$(_var WASP_VERSION); [ -n "$CUR_VER" ] || CUR_VER=unknown
}

_KEY=""; _UNSIGNED=0; _SIGNED=0
_verify() {
  _hdr "Release ${REL_VER}"
  _man="${REL}/MANIFEST.sha256"
  if [ -r "${_man}.minisig" ]; then
    [ -n "$_KEY" ] || _KEY=$(head -1 "${SRC}/release.pub" 2>/dev/null | tr -d ' \r')
    [ -n "$_KEY" ] || _die "No release key is pinned on this VM (${SRC}/release.pub is empty)." \
      "Pass the key you trust with --pubkey RW... (SIGNING.md); a key read from the release itself would prove nothing."
    if ! command -v minisign >/dev/null 2>&1; then
      _note "minisign is not installed; installing it (apk add minisign)…"
      apk add --no-cache minisign >/dev/null 2>&1 || true
      command -v minisign >/dev/null 2>&1 || _die "minisign is not installed and could not be installed." \
        "doas apk add minisign   then run this again."
    fi
    minisign -Vqm "$_man" -P "$_KEY" >/dev/null 2>&1 \
      || _die "SIGNATURE INVALID for ${_man}." \
              "This is not the release that was signed with the key pinned on this VM. Nothing was changed."
    _SIGNED=1
    _ok "Signature valid (key $(printf '%s' "$_KEY" | cut -c1-12)…)"
  elif [ "$_UNSIGNED" = 1 ]; then
    _warn "UNSIGNED release, accepted with --unsigned: the file hashes below prove the files"
    _note "match their manifest, not who made it."
  else
    _die "This release is not signed (no MANIFEST.sha256.minisig)." \
         "Sign it first (SIGNING.md), or pass --unsigned to accept an unsigned build knowingly."
  fi
  _bad_files=$(cd "$REL" && sha256sum -c MANIFEST.sha256 2>&1 | grep -v ': OK$') || _bad_files=""
  if [ -n "$_bad_files" ]; then
    _bad "Files do not match the manifest:"; printf '%s\n' "$_bad_files" | head -10 | sed 's/^/       /'
    _die "Not using this release." "" 2
  fi
  awk '{ p = $2; sub(/^\*/, "", p); print p }' "$_man" | sort > "${_WORK}/listed"
  ( cd "$REL" && find payload -type f ! -path '*/__pycache__/*' | sort ) > "${_WORK}/present"
  _extra=$(awk 'NR == FNR { m[$0] = 1; next } !($0 in m)' "${_WORK}/listed" "${_WORK}/present")
  [ -z "$_extra" ] || { _bad "Files the manifest does not list:"; printf '%s\n' "$_extra" | head -10 | sed 's/^/       /'
                        _die "Not using this release." "" 2; }
  _ok "$(grep -c . "${_WORK}/listed") files match the signed manifest; nothing unlisted"
}

# ── the plan ─────────────────────────────────────────────────────────────────
# Written to ${_WORK}/plan as tab-separated actions the apply step executes:
#   install <kind> <src> <dest> <mode> <owner>     remove <dest>     keep <dest> <why>
_BLOCKED=0
_mu_value() { # installed file, define name -> its value as installed
  [ -r "$1" ] && sed -n "s/.*define( *'$2', *'\{0,1\}\([^') ]*\)'\{0,1\} *).*/\1/p" "$1" | head -1
}
_render_mu() { # src out name installed -> 0 ok, 3 not used here, 2 unrendered
  cp "$1" "$2" || return 2
  case "$3" in
    00-wpvm-login-slug.php)
      _slug=$(_mu_value "$4" WPVM_LOGIN_SLUG)
      case "$_slug" in ''|WPVM_SLUG_PLACEHOLDER) _slug=$(_var WP_ADMIN_SLUG) ;; esac
      [ -n "$_slug" ] || return 3
      case "$_slug" in *[!a-z0-9-]*) return 2 ;; esac
      sed -i "s|WPVM_SLUG_PLACEHOLDER|${_slug}|g" "$2" ;;
    03-wpvm-mfa-enforce.php)
      _enf=$(_mu_value "$4" WPVM_MFA_ENFORCE); _grace=$(_mu_value "$4" WPVM_MFA_GRACE_DAYS)
      case "$_enf" in 0|1) : ;; *) _enf=$(_var MFA_ENFORCE); _enf=${_enf:-0} ;; esac
      case "$_grace" in ''|*[!0-9]*) _grace=$(_var MFA_GRACE_DAYS); _grace=${_grace:-7} ;; esac
      sed -i -e "s|WPVM_MFA_ENFORCE_PLACEHOLDER|${_enf}|g" -e "s|WPVM_MFA_GRACE_PLACEHOLDER|${_grace}|g" "$2" ;;
  esac
  grep -q '_PLACEHOLDER' "$2" && return 2
  return 0
}

_cron_lines() { [ -r "$1" ] && grep -v '^[[:space:]]*#' "$1" | grep -v '^[[:space:]]*$'; }
_cron_cmd()   { printf '%s\n' "$1" | awk '{ $1 = $2 = $3 = $4 = $5 = ""; sub(/^ +/, ""); print }'; }

_plan() {
  : > "${_WORK}/plan"; : > "${_WORK}/covered"; : > "${_WORK}/cron.add"; : > "${_WORK}/cron.del"
  _n_tool=0; _n_mu=0; _n_file=0
  _report="${_WORK}/report"; : > "$_report"
  _out() { printf '%s\n' "$1" >> "$_report"; }

  while read -r _kind _src _dest _mode _own; do
    case "$_kind" in ''|\#*) continue ;; esac
    case "$_kind" in
    tool|file|mu)
      for _new in ${REL}/payload/${_src}; do
        [ -f "$_new" ] || continue
        _rel=${_new#${REL}/payload/}; _base=$(basename "$_new")
        printf '%s\n' "$_rel" >> "${_WORK}/covered"
        case "$_dest" in */) _d="${_dest}${_base}" ;; *) _d="$_dest" ;; esac
        _inst="${R}${_d}"; _old="${STAGED}/${_rel}"
        if [ "$_kind" = mu ]; then
          _render_mu "$_new" "${_WORK}/mu.${_base}" "$_base" "$_inst"; _rc=$?
          [ "$_rc" = 3 ] && continue
          [ "$_rc" = 2 ] && { _out "  ✗ mu   ${_base}: could not be rendered for this VM (a placeholder remains)"; _BLOCKED=1; continue; }
          if [ -e "$_inst" ] && [ -r "$_old" ]; then
            _render_mu "$_old" "${_WORK}/old.${_base}" "$_base" "$_inst" >/dev/null 2>&1
            if ! cmp -s "$_inst" "${_WORK}/old.${_base}" && ! cmp -s "$_inst" "${_WORK}/mu.${_base}"; then
              _out "  ✗ mu   ${_base}: differs from what was installed — changed on this VM"
              _BLOCKED=1; printf 'blocked\tmu\t%s\t%s\t%s\t%s\n' "${_WORK}/mu.${_base}" "$_d" "$_mode" "$_own" >> "${_WORK}/plan"
              continue
            fi
          fi
          cmp -s "$_inst" "${_WORK}/mu.${_base}" && continue
          _out "  ~ mu   ${_base}   ($(_stat "$_inst" "${_WORK}/mu.${_base}"))"
          printf 'install\tmu\t%s\t%s\t%s\t%s\n' "${_WORK}/mu.${_base}" "$_d" "$_mode" "$_own" >> "${_WORK}/plan"
          _n_mu=$((_n_mu+1)); continue
        fi
        cmp -s "$_inst" "$_new" && continue
        if [ -e "$_inst" ] && [ -r "$_old" ] && ! cmp -s "$_inst" "$_old"; then
          # Before 10.20 wp-geoip-setup.sh rewrote update.sh's PINNED_WP_VER line
          # (only a fallback: pinned.env holds the pin). That one line, and only
          # it, is WASP's own edit, not a sign of tampering.
          if [ "$_kind" = tool ] && [ "$_base" = update.sh ] \
             && [ "$(grep -v '^PINNED_WP_VER=' "$_inst" | cksum)" = "$(grep -v '^PINNED_WP_VER=' "$_old" | cksum)" ]; then
            _out "  ~ tool update.sh   ($(_stat "$_inst" "$_new"); its PINNED_WP_VER line was set by GeoIP setup before 10.20 — the pin itself is in pinned.env)"
            printf 'install\t%s\t%s\t%s\t%s\t%s\n' "$_kind" "$_new" "$_d" "$_mode" "$_own" >> "${_WORK}/plan"
            _n_tool=$((_n_tool+1)); continue
          fi
          if [ "$_kind" = tool ]; then
            _out "  ✗ tool ${_base}: MODIFIED since it was installed (differs from ${_old})"
            _BLOCKED=1; printf 'blocked\ttool\t%s\t%s\t%s\t%s\n' "$_new" "$_d" "$_mode" "$_own" >> "${_WORK}/plan"
            continue
          fi
          _out "  · file ${_d}: changed on this VM — kept; the new version is staged at ${STAGED}/${_rel}"
          continue
        fi
        _out "  ~ ${_kind} $( [ "$_kind" = tool ] && echo "$_base" || echo "$_d")   ($(_stat "$_inst" "$_new"))"
        printf 'install\t%s\t%s\t%s\t%s\t%s\n' "$_kind" "$_new" "$_d" "$_mode" "$_own" >> "${_WORK}/plan"
        if [ "$_kind" = tool ]; then _n_tool=$((_n_tool+1)); else _n_file=$((_n_file+1)); fi
      done
      # A tool the release no longer ships, installed from the staged copy.
      if [ "$_kind" = tool ]; then
        case "$_dest" in */) : ;; *) continue ;; esac
        for _old in ${STAGED}/${_src}; do
          [ -f "$_old" ] || continue
          _base=$(basename "$_old"); [ -e "${REL}/payload/${_old#${STAGED}/}" ] && continue
          _inst="${R}${_dest}${_base}"; [ -e "$_inst" ] || continue
          if cmp -s "$_inst" "$_old"; then
            _out "  − tool ${_base}: no longer shipped — removed"
            printf 'remove\ttool\t-\t%s\t-\t-\n' "${_dest}${_base}" >> "${_WORK}/plan"; _n_tool=$((_n_tool+1))
          else
            _out "  · tool ${_base}: no longer shipped, but changed on this VM — kept"
          fi
        done
      fi ;;
    cron)
      printf '%s\n' "$_src" >> "${_WORK}/covered"
      _cron_lines "${REL}/payload/${_src}" > "${_WORK}/cn"
      _cron_lines "${STAGED}/${_src}" > "${_WORK}/co"
      _cron_lines "$CRONTAB" > "${_WORK}/ct"
      if [ "$_dest" = if-present ]; then
        _hit=$(awk 'NR == FNR { m[$0] = 1; next } ($0 in m)' "${_WORK}/ct" "${_WORK}/cn" "${_WORK}/co" 2>/dev/null | head -1)
        [ -n "$_hit" ] || continue
      fi
      # Removed: shipped before (staged copy, or the retired list), not now, installed exactly.
      { awk 'NR == FNR { m[$0] = 1; next } !($0 in m)' "${_WORK}/cn" "${_WORK}/co"
        _cron_lines "${REL}/payload/upgrade/cron-retired.txt"; } | sort -u > "${_WORK}/gone"
      awk 'NR == FNR { m[$0] = 1; next } ($0 in m)' "${_WORK}/ct" "${_WORK}/gone" >> "${_WORK}/cron.del"
      # Added: shipped now, not installed exactly. Same command, other schedule
      # = changed on this VM: left alone, said.
      while IFS= read -r _line; do
        grep -qxF "$_line" "${_WORK}/ct" && continue
        _cmd=$(_cron_cmd "$_line")
        _mine=$(while IFS= read -r _l; do [ "$(_cron_cmd "$_l")" = "$_cmd" ] && printf '%s\n' "$_l"; done < "${_WORK}/ct" | head -1)
        if [ -n "$_mine" ] && ! grep -qxF "$_mine" "${_WORK}/gone"; then
          _out "  · cron schedule changed on this VM, kept: ${_mine}"
          continue
        fi
        printf '%s\n' "$_line" >> "${_WORK}/cron.add"
      done < "${_WORK}/cn" ;;
    esac
  done < "${REL}/payload/upgrade/files.map"
  # A retired line is listed once, however many cron files named it.
  sort -u "${_WORK}/cron.del" -o "${_WORK}/cron.del"

  # Configuration written at build time: staged, reported, not replaced.
  ( cd "${REL}/payload" && find . -type f ! -path './stages/*' ! -path './upgrade/*' ! -path '*/__pycache__/*' \
      ! -name install-wordpress.sh | sed 's#^\./##' | sort ) > "${_WORK}/all"
  awk 'NR == FNR { m[$0] = 1; next } !($0 in m)' "${_WORK}/covered" "${_WORK}/all" > "${_WORK}/buildtime"
  : > "${_WORK}/cfg"
  while IFS= read -r _f; do
    case "$_f" in bin/*|mu-plugins/*|php-tools/*|cron/*) continue ;; esac
    cmp -s "${REL}/payload/${_f}" "${STAGED}/${_f}" || printf '%s\n' "$_f" >> "${_WORK}/cfg"
  done < "${_WORK}/buildtime"
  _n_staged=0
  for _f in $(cd "${REL}/payload" && find php-tools stages -type f 2>/dev/null); do
    _t="${STAGED}/${_f}"; case "$_f" in stages/*) _t="${STAGES}/${_f#stages/}" ;; esac
    cmp -s "${REL}/payload/${_f}" "$_t" || _n_staged=$((_n_staged+1))
  done
  _N_CHANGES=$((_n_tool + _n_mu + _n_file + $(grep -c . "${_WORK}/cron.add") + $(grep -c . "${_WORK}/cron.del")))
  _n_hooks=0; : > "${_WORK}/hooks"
  for _h in "${REL}"/payload/upgrade/hooks/*.sh; do
    [ -f "$_h" ] || continue
    _hv=$(basename "$_h" .sh)
    [ "$(_vercmp "$_hv" "$CUR_VER")" = 1 ] && [ "$(_vercmp "$_hv" "$REL_VER")" != 1 ] || continue
    printf '%s\t%s\n' "$_hv" "$_h" >> "${_WORK}/hooks"; _n_hooks=$((_n_hooks+1))
  done
  sort -t '	' -k1,1 "${_WORK}/hooks" > "${_WORK}/hooks.s" 2>/dev/null; mv "${_WORK}/hooks.s" "${_WORK}/hooks"
}

_show_plan() {
  _hdr "Upgrade plan: ${CUR_VER} → ${REL_VER}"
  case "$(_vercmp "$REL_VER" "$CUR_VER")" in
    0)  _note "This VM already reports ${CUR_VER}. Applying again makes the installed files match it." ;;
    -1) _warn "${REL_VER} is OLDER than this VM's ${CUR_VER}. apply refuses this without --allow-downgrade." ;;
  esac
  if [ -s "${_WORK}/report" ]; then cat "${_WORK}/report"; fi
  while IFS= read -r _l; do echo "  + cron $_l"; done < "${_WORK}/cron.add"
  while IFS= read -r _l; do echo "  − cron $_l"; done < "${_WORK}/cron.del"
  [ "${_n_staged:-0}" -gt 0 ] && _note "${_n_staged} staged file(s) (stages, php-tools) updated with the release"
  if [ -s "${_WORK}/hooks" ]; then
    while IFS='	' read -r _hv _h; do
      echo "  » after the files: the ${_hv} upgrade step — $(sed -n 's/^# *step: *//p' "$_h" | head -1)"
    done < "${_WORK}/hooks"
  fi
  if [ -s "${_WORK}/cfg" ]; then
    echo ""
    echo "  Configuration written when this VM was built changed upstream. Not replaced: these"
    echo "  hold this VM's own values. The ${REL_VER} CHANGELOG says whether any needs action:"
    sed 's/^/       /' "${_WORK}/cfg"
  fi
  echo ""
  if [ "$_BLOCKED" = 1 ]; then
    _bad "Blocked: a tool or mu-plugin above was changed on this VM since it was installed."
    _note "Look at it before anything replaces it — the change is the evidence of how:"
    _note "  diff <installed> ${STAGED}/<same path>      wasp-verify-integrity.sh"
    _note "Then re-run with --force to overwrite it."
  elif [ "${_N_CHANGES:-0}" -eq 0 ] && [ ! -s "${_WORK}/hooks" ] && [ "${_n_staged:-0}" -eq 0 ]; then
    _ok "Nothing to change: the installed tooling already matches ${REL_VER}."
  else
    _ok "${_N_CHANGES} change(s) to apply."
  fi
}

_show_diffs() {
  _hdr "Differences"
  while IFS='	' read -r _a _k _s _d _m _o; do
    [ "$_a" = install ] || continue
    [ "$_k" = tool ] && continue
    echo "── ${_d}"; diff -u "${R}${_d}" "$_s" 2>/dev/null | tail -n +3 | head -200
  done < "${_WORK}/plan"
  while IFS='	' read -r _a _k _s _d _m _o; do
    [ "$_a" = install ] && [ "$_k" = tool ] || continue
    echo "── ${_d}   ($(_stat "${R}${_d}" "$_s"); see the CHANGELOG)"
  done < "${_WORK}/plan"
}

# ── apply ────────────────────────────────────────────────────────────────────
_lint_mu() { # file -> PHP's own syntax check, inside the wordpress container
  if [ -n "${WASP_UPGRADE_LINT:-}" ]; then ${WASP_UPGRADE_LINT} "$1" >/dev/null 2>&1; return; fi
  podman exec -i wordpress php -l < "$1" >/dev/null 2>&1
}
_lint_ready() {
  [ -n "${WASP_UPGRADE_LINT:-}" ] && return 0
  podman ps --filter 'name=^wordpress$' --filter status=running --format '{{.Names}}' 2>/dev/null | grep -qx wordpress
}
_put() { # src dest mode owner: replace atomically (a new inode, so a running script is untouched)
  mkdir -p "$(dirname "$2")" || return 1
  cp "$1" "$2.wasp-new.$$" && chmod "$3" "$2.wasp-new.$$" \
    && { [ -n "${WASP_ROOT:-}" ] || chown "$4" "$2.wasp-new.$$"; } \
    && mv -f "$2.wasp-new.$$" "$2" || { rm -f "$2.wasp-new.$$"; return 1; }
}

_backup() {
  _ts=$(date -u +%Y%m%dT%H%M%SZ)
  _bk="${BACKUPS}/${_ts}-from-${CUR_VER}.tar.gz"
  : > "${_WORK}/bk.list"; : > "${_WORK}/created"
  for _p in etc/wp-install etc/crontabs/root; do [ -e "${R}/${_p}" ] && printf '%s\n' "$_p" >> "${_WORK}/bk.list"; done
  while IFS='	' read -r _a _k _s _d _m _o; do
    case "$_a" in install|remove) : ;; *) continue ;; esac
    _dd=${_d#/}
    if [ -e "${R}/${_dd}" ]; then printf '%s\n' "$_dd" >> "${_WORK}/bk.list"
    else printf '%s\n' "$_dd" >> "${_WORK}/created"; fi
  done < "${_WORK}/plan"
  for _p in etc/wp-install/MANIFEST.sha256 etc/wp-install/MANIFEST.sha256.minisig etc/crontabs/root; do
    [ -e "${R}/${_p}" ] || printf '%s\n' "$_p" >> "${_WORK}/created"
  done
  sort -u "${_WORK}/bk.list" -o "${_WORK}/bk.list"
  # shellcheck disable=SC2046
  tar czf "$_bk" -C "${R}/" $(cat "${_WORK}/bk.list") 2>/dev/null \
    || { rm -f "$_bk"; _die "The backup could not be written (${_bk}). Nothing was changed."; }
  # Beside it: what the upgrade created (rollback removes those) and the version it came from.
  cp "${_WORK}/created" "${_bk%.tar.gz}.created" && printf '%s\n' "$CUR_VER" > "${_bk%.tar.gz}.from"
  chmod 0600 "$_bk" "${_bk%.tar.gz}.created" "${_bk%.tar.gz}.from"
  _ok "Backed up what this upgrade replaces: ${_bk}"
  # Oldest first, keep the newest N.
  ls -1 "$BACKUPS"/*.tar.gz 2>/dev/null | sort \
    | awk -v k="$KEEP_BACKUPS" '{ a[NR] = $0 } END { for (i = 1; i <= NR - k; i++) print a[i] }' \
    | while IFS= read -r _old; do rm -f "$_old" "${_old%.tar.gz}.created" "${_old%.tar.gz}.from"; done
  BACKUP="$_bk"
}

_apply_files() {
  _fail=0
  while IFS='	' read -r _a _k _s _d _m _o; do
    case "$_a" in
      install) _put "$_s" "${R}${_d}" "$_m" "$_o" || { _bad "Could not install ${_d}"; _fail=1; } ;;
      remove)  rm -f "${R}${_d}" ;;
    esac
  done < "${_WORK}/plan"
  [ "$_fail" = 0 ] && _ok "Tools, rules and mu-plugins installed"
  # Cron: drop retired lines, append new ones under a dated header.
  if [ -s "${_WORK}/cron.del" ] || [ -s "${_WORK}/cron.add" ]; then
    _ct="${_WORK}/crontab.new"; : > "$_ct"
    [ -r "$CRONTAB" ] && awk 'NR == FNR { d[$0] = 1; next } !($0 in d)' "${_WORK}/cron.del" "$CRONTAB" > "$_ct"
    if [ -s "${_WORK}/cron.add" ]; then
      printf '# Added by wasp-upgrade.sh %s → %s on %s\n' "$CUR_VER" "$REL_VER" "$(date -u +%Y-%m-%d)" >> "$_ct"
      cat "${_WORK}/cron.add" >> "$_ct"
    fi
    mkdir -p "$(dirname "$CRONTAB")"
    cat "$_ct" > "$CRONTAB" && chmod 0600 "$CRONTAB"
    _ok "Cron: $(grep -c . "${_WORK}/cron.add") line(s) added, $(grep -c . "${_WORK}/cron.del") removed"
  fi
  # The staged copy: what integrity checks, rollbacks and the next upgrade compare against.
  _stg="${_WORK}/staged"; mkdir -p "$_stg"
  for _p in "${REL}"/payload/*/; do
    _name=$(basename "$_p"); [ "$_name" = stages ] && continue
    cp -a "$_p" "${_stg}/${_name}"
  done
  rm -rf "${_stg}"/*/__pycache__
  rm -rf "$STAGED" && mv "$_stg" "$STAGED"
  rm -rf "$STAGES" && mkdir -p "$STAGES" && cp -a "${REL}/payload/stages/." "$STAGES/"
  cp "${REL}/MANIFEST.sha256" "${SRC}/MANIFEST.sha256"
  if [ -r "${REL}/MANIFEST.sha256.minisig" ]; then cp "${REL}/MANIFEST.sha256.minisig" "${SRC}/"
  else rm -f "${SRC}/MANIFEST.sha256.minisig"; fi
  chmod 0644 "${SRC}/MANIFEST.sha256"
  # The build identity every tool prints.
  if [ -w "$VARS" ]; then
    _v="${_WORK}/vars.new"
    grep -v '^WASP_VERSION=\|^WASP_RELEASE=\|^WASP_VERSION_NOTE=' "$VARS" > "$_v"
    { printf 'WASP_VERSION=%s\n' "$(_sq "$REL_VER")"; printf 'WASP_RELEASE=%s\n' "$(_sq "$REL_VER")"
      printf 'WASP_VERSION_NOTE=%s\n' "$(_sq "$REL_NOTE")"; } >> "$_v"
    cat "$_v" > "$VARS"
  fi
  _ok "Staged payload, manifest and version updated to ${REL_VER}"
  return "$_fail"
}

_run_hooks() {
  [ -s "${_WORK}/hooks" ] || return 0
  _hfail=0
  while IFS='	' read -r _hv _h; do
    _hs="${STAGED}/upgrade/hooks/${_hv}.sh"   # the verified copy, now staged
    echo "  » ${_hv}: $(sed -n 's/^# *step: *//p' "$_hs" | head -1)"
    WASP_UPGRADE_FROM="$CUR_VER" WASP_UPGRADE_TO="$REL_VER" WASP_ROOT="$R" sh "$_hs" > "${_WORK}/hook.out" 2>&1
    _hrc=$?
    sed 's/^/       /' "${_WORK}/hook.out"
    [ "$_hrc" = 0 ] || { _bad "The ${_hv} step did not complete (exit ${_hrc}); run it again by hand: sh ${_hs}"; _hfail=1; }
  done < "${_WORK}/hooks"
  return "$_hfail"
}

_after_checks() {
  _hdr "After the ${_WHAT:-upgrade}"
  _ret=0
  if _lint_ready; then
    for _mu in "${R}/home/wpuser/wp/html/wp-content/mu-plugins"/*.php; do
      [ -f "$_mu" ] || continue
      _b=$(basename "$_mu")
      [ -e "${STAGED}/mu-plugins/${_b}" ] || continue
      if ! _lint_mu "$_mu"; then
        _bad "${_b} fails PHP's syntax check — an mu-plugin fatal takes the site down. Putting the previous copy back."
        tar xzf "$BACKUP" -C "${R}/" "home/wpuser/wp/html/wp-content/mu-plugins/${_b}" 2>/dev/null || rm -f "$_mu"
        _ret=1
      fi
    done
    [ "$_ret" = 0 ] && _ok "WordPress mu-plugins pass PHP's syntax check"
  else
    _warn "The wordpress container is not running: mu-plugins were not checked by PHP."
  fi
  if [ -z "${WASP_ROOT:-}" ] && [ -x /usr/local/bin/wp-health-check.sh ]; then
    if /usr/local/bin/wp-health-check.sh wordpress 80 >/dev/null 2>&1; then _ok "The site answers"
    else _bad "The site's health check fails. If it passed before:  wasp-upgrade.sh rollback"; _ret=1; fi
  fi
  _vi="${R}/usr/local/bin/wasp-verify-integrity.sh"
  if [ -x "$_vi" ] && [ -z "${WASP_ROOT:-}" ]; then
    if "$_vi" >/dev/null 2>&1; then _ok "Installed tools match the ${REL_VER} manifest"
    else _bad "wasp-verify-integrity.sh reports differences — run it to see them"; _ret=1; fi
  fi
  return "$_ret"
}

_confirm() {
  [ "${_YES:-0}" = 1 ] && return 0
  [ -t 0 ] || _die "Not a terminal: re-run with --yes to apply without the prompt." "" 1
  printf '  Apply this upgrade? Type UPGRADE to continue: '
  read -r _ans
  _ans=$(printf '%s' "$_ans" | tr -d ' \t\r')   # a pasted space is not part of the word
  [ "$_ans" = UPGRADE ] || _die "Not applied." "" 1
}

_history() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >> "$HISTORY"; }

# ── commands ─────────────────────────────────────────────────────────────────
_cmd="${1:-}"; [ $# -gt 0 ] && shift
_target=""; _DIFF=0; _YES=0; _FORCE=0; _DOWN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --diff) _DIFF=1 ;;
    --yes|-y) _YES=1 ;;
    --force) _FORCE=1 ;;
    --allow-downgrade) _DOWN=1 ;;
    --unsigned) _UNSIGNED=1 ;;
    --pubkey) shift; _KEY="${1:-}"
              case "$_KEY" in RW*) : ;; *) echo "--pubkey: a minisign public key starts with RW" >&2; exit 2 ;; esac ;;
    --pubkey=*) _KEY="${1#--pubkey=}" ;;
    -*) echo "Unknown option: $1" >&2; exit 2 ;;
    *) [ -z "$_target" ] && _target="$1" || { echo "One release at a time: $1" >&2; exit 2; } ;;
  esac
  shift
done

case "$_cmd" in
check)
  _lock; _open_release "$_target"; _verify; _plan; _show_plan
  [ "$_DIFF" = 1 ] && _show_diffs
  echo ""
  [ "$_BLOCKED" = 1 ] && exit 1
  _note "To apply:  wasp-upgrade.sh apply ${_target}"
  exit 0 ;;

apply)
  _lock; _open_release "$_target"; _verify; _plan; _show_plan
  if [ "$(_vercmp "$REL_VER" "$CUR_VER")" = -1 ] && [ "$_DOWN" != 1 ]; then
    _die "Refusing to move this VM back from ${CUR_VER} to ${REL_VER}." \
         "To return to the state before the last upgrade, use: wasp-upgrade.sh rollback" 1
  fi
  if [ "$_BLOCKED" = 1 ]; then
    [ "$_FORCE" = 1 ] || _die "Not applied: see Blocked above." "" 1
    _warn "--force: overwriting the files above. Their current copies go into the backup."
    _BLOCKED=0; _fp="${_WORK}/plan.forced"
    sed 's/^blocked	/install	/' "${_WORK}/plan" > "$_fp" && mv "$_fp" "${_WORK}/plan"
    _N_CHANGES=$(grep -c '^install\|^remove' "${_WORK}/plan")
  fi
  if [ "${_N_CHANGES:-0}" -eq 0 ] && [ ! -s "${_WORK}/hooks" ] && [ "${_n_staged:-0}" -eq 0 ] \
     && [ ! -s "${_WORK}/cfg" ] && [ "$CUR_VER" = "$REL_VER" ] \
     && cmp -s "${REL}/MANIFEST.sha256" "${SRC}/MANIFEST.sha256"; then
    echo ""; _ok "Already up to date. Nothing was changed."; exit 0
  fi
  # Every mu-plugin about to be installed is checked by PHP first: none goes
  # in unchecked, and a failure here has changed nothing.
  if grep -q '^install	mu' "${_WORK}/plan"; then
    _lint_ready || _die "The wordpress container is not running, so the new mu-plugins cannot be checked by PHP." \
                        "Start it (doas rc-service wp-container start), then run this again. Nothing was changed."
    while IFS='	' read -r _a _k _s _d _m _o; do
      [ "$_a" = install ] && [ "$_k" = mu ] || continue
      _lint_mu "$_s" || _die "$(basename "$_d") from ${REL_VER} fails PHP's syntax check here. Nothing was changed."
    done < "${_WORK}/plan"
  fi
  echo ""; _confirm
  _hdr "Applying ${REL_VER}"
  _backup
  _apply_files; _rc=$?
  _run_hooks || _rc=1
  _after_checks || _rc=1
  _history "upgrade ${CUR_VER} -> ${REL_VER} $( [ "$_rc" = 0 ] && echo ok || echo with-problems) backup=$(basename "$BACKUP")$( [ "$_SIGNED" = 1 ] || echo ' UNSIGNED')"
  echo ""
  if [ "$_rc" = 0 ]; then _ok "This VM now runs WASP ${REL_VER}."
  else _warn "Upgraded to ${REL_VER} with problems above. To put the previous state back:  wasp-upgrade.sh rollback"; fi
  exit "$_rc" ;;

rollback)
  _lock
  _bk="$_target"
  [ -n "$_bk" ] || _bk=$(ls -1 "$BACKUPS"/*.tar.gz 2>/dev/null | sort | tail -1)
  case "$_bk" in /*) : ;; ?*) [ -f "$_bk" ] || _bk="${BACKUPS}/${_bk}" ;; esac
  [ -n "$_bk" ] && [ -f "$_bk" ] || _die "No upgrade backup to roll back to (${BACKUPS} is empty)."
  CUR_VER=$(_var WASP_VERSION); _from=$(cat "${_bk%.tar.gz}.from" 2>/dev/null)
  _hdr "Roll back ${CUR_VER:-?} → ${_from:-?}"
  _note "From ${_bk}"
  _note "Restores the tools, mu-plugins, rules, cron, staged payload and version that"
  _note "were in place before that upgrade, and removes what it added."
  _confirm_rb() {
    [ "$_YES" = 1 ] && return 0
    [ -t 0 ] || _die "Not a terminal: re-run with --yes." "" 1
    printf '  Type ROLLBACK to continue: '; read -r _ans; _ans=$(printf '%s' "$_ans" | tr -d ' \t\r'); [ "$_ans" = ROLLBACK ] || _die "Not rolled back." "" 1
  }
  _confirm_rb
  # The staged trees are restored whole, so nothing the upgrade added lingers.
  if tar tzf "$_bk" 2>/dev/null | grep -q '^etc/wp-install/payload/'; then rm -rf "$STAGED" "$STAGES"; fi
  tar xzf "$_bk" -C "${R}/" 2>/dev/null || _die "Extracting ${_bk} failed."
  [ -r "${_bk%.tar.gz}.created" ] && while IFS= read -r _c; do
    case "$_c" in ''|/*|*..*) continue ;; esac; rm -f "${R}/${_c}"
  done < "${_bk%.tar.gz}.created"
  _history "rollback ${CUR_VER:-?} -> ${_from:-?} from=$(basename "$_bk")"
  _ok "Rolled back to ${_from:-the previous state}."
  BACKUP="$_bk"; REL_VER="${_from:-previous}"; _WHAT=rollback
  _after_checks || exit 1
  exit 0 ;;

status)
  _hdr "WASP on this VM"
  echo "  Version : $(_var WASP_VERSION || true)"
  _n=$(_var WASP_VERSION_NOTE); [ -n "$_n" ] && echo "  Note    : $(printf '%s' "$_n" | cut -c1-110)…"
  if [ -s "$HISTORY" ]; then echo ""; echo "  Upgrade history (newest last):"; tail -10 "$HISTORY" | sed 's/^/    /'
  else echo ""; echo "  No upgrades recorded: this VM runs the release it was built with."; fi
  if ls "$BACKUPS"/*.tar.gz >/dev/null 2>&1; then
    echo ""; echo "  Backups (rollback restores the newest):"
    ls -1 "$BACKUPS"/*.tar.gz | sort | sed 's#.*/#    #'
  fi
  echo ""; exit 0 ;;

*)
  sed -n '3,9p' "$0" | sed 's/^# \{0,1\}//'
  exit 2 ;;
esac
