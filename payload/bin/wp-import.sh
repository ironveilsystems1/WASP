#!/bin/sh
# =============================================================================
# wp-import.sh — get a site backup onto this VM, and see what is in it
# =============================================================================
#   wp-import.sh where                 how to get an archive here
#   wp-import.sh fetch s3 <path>       pull from your object storage
#   wp-import.sh fetch url <url> [sha256]
#   wp-import.sh list                  what has arrived
#   wp-import.sh inspect <file>        what is inside it — NOTHING is extracted
#   wp-import.sh extract <file>        unpack to staging, outside the docroot
#   wp-import.sh scan [id]             scan staged files AND the dump
#   wp-import.sh staged                what is currently staged
#   wp-import.sh apply [id]            normalise, import, re-harden, remediate
#                [--accept-findings] [--force] [--no-remediate] [--keep-files]
#   wp-import.sh restore [file|set]    extract, scan and apply in one go; cleans up
#   wp-import.sh clean <id> | --all | --stale <days>
#                                      remove leftover copies of imported sites
#
# UpdraftPlus: give extract or restore ANY part of the set (or nothing, if it
# is the only thing in the inbox) and every part is taken together.
#
# Reads zip, tar.gz, gzip dumps and All-in-One WP Migration .wpress archives.
#
# `inspect` is deliberately the first thing built. "Tell me what is in this
# backup before I touch it" is useful on its own, and it is the only part of
# the import pipeline with no destructive failure mode. Everything after it
# writes to disk; this only reads.
#
# WHY INSPECT NEVER EXTRACTS
#
# Reading an archive's index is safe. Extracting is where path traversal,
# link escapes and decompression bombs happen. Those are checked HERE,
# against the listing, so a hostile archive is refused before any of its
# contents exist on disk. extract checks the listing again, then checks what
# actually landed, because a listing is only as good as the tool that read it.
# =============================================================================
set -u

if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then exec doas "$0" "$@"; fi
  echo "Run as root (or via doas)" >&2; exit 1
fi
[ -r /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh

INBOX=/var/lib/wasp-import/incoming
STAGING=/var/lib/wasp-import/staging
WP_ROOT=/home/wpuser/wp/html
RCLONE_CONF=/etc/wp-install/rclone.conf
WPRESS_READER=/usr/local/lib/wasp/wasp-wpress-reader.php
THREATS=/usr/local/bin/wasp-threats.sh
# Only the WORDPRESS_* values. The root password stays out of containers that
# run site code. A VM built before 10.10 has just the one file.
WP_ENV_FILE=/etc/wordpress/wp.env
[ -r "$WP_ENV_FILE" ] || WP_ENV_FILE=/etc/wordpress/env
mkdir -p "$INBOX" "$STAGING" 2>/dev/null || true
chmod 700 "$STAGING" 2>/dev/null || true
# Same owner and mode as stage 08. This used to be a flat `chmod 750` on every
# run, which took away the group write that `scp -O` as the admin user needs,
# so the first import broke every later upload. Not world-readable: a client's
# backup contains their database.
if [ -n "${ADMIN_USER:-}" ] && id "$ADMIN_USER" >/dev/null 2>&1; then
  chown "root:${ADMIN_USER}" "$INBOX" 2>/dev/null || true
  chmod 2770 "$INBOX" 2>/dev/null || true
else
  chmod 750 "$INBOX" 2>/dev/null || true
fi

# ── Archive safety ──────────────────────────────────────────────────────────
# A backup needs plain files and directories, nothing else. Hard links matter
# as much as symlinks: BusyBox tar follows a hard-link target out of the
# extraction directory (CVE-2026-26158), and `cp -a` then copies that file's
# CONTENT into the docroot. Reproduced: a member linked to /etc/wordpress/env
# passed inspect, extract, scan and apply, and came out in uploads, mode 644.
#
# The pattern covers both listing styles. GNU tar marks hard links with a
# leading "h" and "link to". BusyBox prints them as regular files with " -> ".
_tar_special() { tar -tzvf "$1" 2>/dev/null | grep -cE '^[^-d]| -> | link to '; }

# `unzip -Z` is Info-ZIP only. BusyBox unzip rejects it, and that used to leave
# the listing empty, so every check below was skipped without a word. Callers
# refuse when these return nothing for a file that is a zip.
_zip_members() { unzip -Z1 "$1" 2>/dev/null; }
_zip_special() { unzip -Z "$1" 2>/dev/null | grep -c '^l'; }

# The WordPress root inside a staged tree: the shallowest directory holding
# wp-content alongside wp-includes or wp-config.php. Prints nothing if none.
# Used by apply AND scan. scan used to be pointed at the top of the staging
# tree, so for a nested archive (a cPanel account puts the site at
# <account>/public_html/) every structural check looked at a wp-content that
# did not exist and printed [ok]. "No PHP files in wp-content/uploads" on the
# first field test meant "no wp-content/uploads here", not "none found".
_site_root() {
  if [ -d "$1/wp-content" ]; then printf '%s\n' "$1"; return; fi
  _sr=$(find "$1" -maxdepth 6 -type d -name wp-content 2>/dev/null \
        | while IFS= read -r _c; do
            _p=$(dirname "$_c")
            if [ -d "${_p}/wp-includes" ] || [ -f "${_p}/wp-config.php" ]; then
              printf '%s\t%s\n' "$(printf '%s' "$_c" | tr -cd / | wc -c)" "$_c"
            fi
          done | sort -n | head -1 | cut -f2)
  [ -n "$_sr" ] && dirname "$_sr"
}
_zip_bytes()   { unzip -l "$1" 2>/dev/null | tail -1 | awk '{print $1+0}'; }

# ── UpdraftPlus sets ─────────────────────────────────────────────────────────
# UpdraftPlus splits ONE backup into several files sharing a prefix:
#   backup_2026-11-01-0300_Site_Name_0a1b2c3d4e5f-db.gz
#   …-plugins.zip  …-themes.zip  …-uploads.zip (…-uploads2.zip …)  …-others.zip
# and optionally -mu-plugins, -wpcore and -more. Each zip holds the folders
# that live INSIDE wp-content (plugins/, themes/, uploads/, and for -others,
# whatever else was there), so the parts only make a site once they are
# unpacked into one wp-content. Naming any one part names the whole set.
#
# This used to mean unpacking and re-packing by hand -- outside the checks
# this tool exists for. extract and restore now take the set as one import.
_UPD_RE='^(backup_[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{4}_.+_[0-9a-f]{12})-(db|plugins|themes|uploads|others|mu-plugins|wpcore|more)([0-9]*)\.(zip|gz|gz\.crypt)$'
_updraft_prefix() { basename "$1" | sed -nE "s/${_UPD_RE}/\1/p"; }
_updraft_entity() { basename "$1" | sed -nE "s/${_UPD_RE}/\2/p"; }
# Every part of one set in a directory, by exact prefix.
_updraft_parts() {
  for _up in "$1"/backup_*; do
    [ -f "$_up" ] || continue
    [ "$(_updraft_prefix "$_up")" = "$2" ] && printf '%s\n' "$_up"
  done | LC_ALL=C sort
}
# The distinct sets in a directory.
_updraft_sets() {
  for _up in "$1"/backup_*; do
    [ -f "$_up" ] && _updraft_prefix "$_up"
  done | LC_ALL=C sort -u
}
# What the set holds and lacks. Returns 1 when it cannot be imported.
_updraft_report() {   # <dir> <prefix>
  _ur=0
  printf '  UpdraftPlus set: %s\n' "$2"
  _uparts=$(_updraft_parts "$1" "$2")
  for _ue in db plugins themes uploads others mu-plugins wpcore more; do
    _un=$(printf '%s\n' "$_uparts" | while IFS= read -r _p; do
            [ -n "$_p" ] && [ "$(_updraft_entity "$_p")" = "$_ue" ] && echo x; done | grep -c x) || _un=0
    case "$_ue" in
      db)
        if printf '%s\n' "$_uparts" | grep -q -- '-db[0-9]*\.gz\.crypt$'; then
          _bad "database   encrypted (-db.gz.crypt). Decrypt it in UpdraftPlus first:"
          _note "             Existing backups → the backup → Database → Decrypt, then download."
          _ur=1
        elif [ "$_un" -gt 0 ]; then printf '    %-10s %s\n' database "present"
        else
          _bad "database   MISSING — the -db.gz file. Without it there are no posts, pages or settings."
          _ur=1
        fi ;;
      plugins|themes|uploads)
        if [ "$_un" -gt 0 ]; then printf '    %-10s %s\n' "$_ue" "present$([ "$_un" -gt 1 ] && echo " (${_un} parts)")"
        else _warn "$(printf '%-10s' "$_ue") missing — the site's ${_ue} will not be imported"; fi ;;
      others)
        [ "$_un" -gt 0 ] && printf '    %-10s %s\n' others "present (scanned; only plugins, themes and uploads are imported)" ;;
      mu-plugins)
        [ "$_un" -gt 0 ] && printf '    %-10s %s\n' mu-plugins "present (scanned; withheld at import, as always)" ;;
      wpcore|more)
        [ "$_un" -gt 0 ] && printf '    %-10s %s\n' "$_ue" "present — not part of wp-content, not used" ;;
    esac
  done
  return $_ur
}
# Hostile-member checks for one zip, before anything is written.
_zip_hostile() {
  _zl=$(_zip_members "$1")
  if [ -z "$_zl" ]; then
    _bad "$(basename "$1"): a zip whose member list could not be read, so it cannot be checked"
    _note "  Reading it needs Info-ZIP:  doas apk add unzip"
    return 2
  fi
  _zh=0
  printf '%s\n' "$_zl" | grep -q '\.\./' && { _bad "$(basename "$1"): path traversal in member names"; _zh=1; }
  printf '%s\n' "$_zl" | grep -q '^/' && { _bad "$(basename "$1"): absolute paths in member names"; _zh=1; }
  _zs=$(_zip_special "$1") || _zs=0
  [ "${_zs:-0}" -gt 0 ] && { _bad "$(basename "$1"): ${_zs} link or special member(s)"; _zh=1; }
  [ "$_zh" = 0 ] || return 2
  return 0
}
_abs() { printf '%s/%s\n' "$(cd "$(dirname "$1")" && pwd)" "$(basename "$1")"; }

# ── Cleanup ──────────────────────────────────────────────────────────────────
# What an import leaves behind is a full copy of a client's site and database,
# twice: the archives in the inbox and the unpacked staging set. Neither is
# needed once the site is live, and both are exactly what nobody should find on
# a disk later. Removed:
#   - the staging copy (files/ and db/)
#   - the source archives it was made from, as recorded at extract -- and only
#     those, and only inside the inbox: nothing outside it is ever deleted
# Kept, because they are evidence and they are small:
#   - quarantined/  files withheld from the import (renamed, obfuscated, mu-plugins)
#   - meta/         what was staged, shell history copies, the source list
# A set that was never applied has nothing to keep and is removed whole.
_cleanup_set() {   # <id>
  _cs="${STAGING}/$1"
  [ -d "$_cs" ] || return 1
  _ck=$(du -sk "$_cs" 2>/dev/null | cut -f1)
  _cn=0
  if [ -r "$_cs/meta/sources.txt" ]; then
    while IFS= read -r _s; do
      case "$_s" in "${INBOX}"/*) : ;; *) continue ;; esac
      case "$_s" in */../*|*/./*) continue ;; esac
      [ -f "$_s" ] || continue
      _ck=$(( _ck + $(du -sk "$_s" 2>/dev/null | cut -f1) ))
      rm -f "$_s" && _cn=$(( _cn + 1 ))
    done < "$_cs/meta/sources.txt"
  fi
  if grep -q "id=$1 " "${STAGING}/import-log.txt" 2>/dev/null; then
    rm -rf "$_cs/files" "$_cs/db"
    [ -n "$(ls -A "$_cs/quarantined" 2>/dev/null)" ] || rm -rf "$_cs/quarantined"
    _kept=$(du -sk "$_cs" 2>/dev/null | cut -f1)
    _ok "Cleaned up $1: $(( (_ck - _kept) / 1024 )) MB freed, ${_cn} source archive(s) removed"
    if [ -d "$_cs/quarantined" ]; then
      _note "Kept as evidence: ${_cs}/quarantined and meta/ (${_kept} KB)"
    else
      _note "Kept: ${_cs}/meta (${_kept} KB) — what was imported, for the record"
    fi
  else
    rm -rf "$_cs"
    _ok "Removed staging set $1 (never imported): $(( _ck / 1024 )) MB freed, ${_cn} source archive(s) removed"
  fi
  [ "$(cat "${STAGING}/.latest" 2>/dev/null)" = "$1" ] && [ ! -d "$_cs/files" ] && rm -f "${STAGING}/.latest"
  return 0
}

# Links and special files in a tree that has already been written. This is the
# check that does not depend on any listing. It prints a count, and returns
# non-zero when it could not look, which callers treat as a refusal.
_staged_special() {
  _ss=$(find "$1" \( ! -type f ! -type d \) -o \( -type f -links +1 \) 2>/dev/null) || return 1
  [ -n "$_ss" ] || { echo 0; return 0; }
  printf '%s\n' "$_ss" | wc -l
}

_ok()   { printf '  \033[32m✔\033[0m  %s\n' "$1"; }
_bad()  { printf '  \033[31m✗\033[0m  %s\n' "$1" >&2; }
_warn() { printf '  \033[33m⚠\033[0m  %s\n' "$1"; }
_note() { printf '     %s\n' "$1"; }
_hdr()  { printf '\n\033[1m%s\033[0m\n%s\n' "$1" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; }

_wpcli_image() {
  _wi=$(sed -n 's/^WPCLI_IMAGE=//p' /etc/wp-install/pinned.env 2>/dev/null | tr -d '"' | head -1)
  [ -n "$_wi" ] || _wi="docker.io/library/wordpress:cli"
  printf '%s' "$_wi"
}

# ── .wpress: the reader runs in a box, not on the VM ─────────────────────────
# A custom binary parser fed an untrusted file is exactly the code to keep away
# from this host, so it runs in the pinned wp-cli image: no network, read-only
# root, no capabilities, an unprivileged uid, bounded memory, and write access
# to the staging directories and nothing else.
#
#   _wpress_run <archive> <staging|-> <reader mode> [reader args...]
#
# --group-add: the archive arrives root- or admin-group owned at mode 640. A
# bind mount of the file itself needs no directory access, only that group.
# The colon check is because `-v` would split the path on it.
_wpress_run() {
  _wr_a=$1; _wr_s=$2; _wr_m=$3; shift 3
  case "$_wr_a" in
    *:*) _bad "The archive path contains ':', which a bind mount cannot express. Rename it."
         return 1 ;;
  esac
  [ -r "$WPRESS_READER" ] || { _bad "Reader missing: ${WPRESS_READER}"; return 1; }
  if [ "$_wr_s" = "-" ]; then
    # shellcheck disable=SC2086
    podman run --rm -i --network none --read-only \
      --cap-drop ALL --security-opt no-new-privileges:true \
      --user 33:33 --group-add "$(stat -c %g "$_wr_a")" \
      --pids-limit 16 --memory 512m \
      --tmpfs /tmp:size=8M,noexec,nosuid,nodev \
      -v "${WPRESS_READER}:/wasp/reader.php:ro" \
      -v "${_wr_a}:/wasp/archive.wpress:ro" \
      --entrypoint php "$(_wpcli_image)" \
      -d memory_limit=256M /wasp/reader.php "$_wr_m" /wasp/archive.wpress "$@"
  else
    # shellcheck disable=SC2086
    podman run --rm -i --network none --read-only \
      --cap-drop ALL --security-opt no-new-privileges:true \
      --user 33:33 --group-add "$(stat -c %g "$_wr_a")" \
      --pids-limit 16 --memory 512m \
      --tmpfs /tmp:size=8M,noexec,nosuid,nodev \
      -v "${WPRESS_READER}:/wasp/reader.php:ro" \
      -v "${_wr_a}:/wasp/archive.wpress:ro" \
      -v "${_wr_s}/files:/wasp/out/files" \
      -v "${_wr_s}/db:/wasp/out/db" \
      -v "${_wr_s}/meta:/wasp/out/meta" \
      --entrypoint php "$(_wpcli_image)" \
      -d memory_limit=256M /wasp/reader.php "$_wr_m" /wasp/archive.wpress /wasp/out "$@"
  fi
}

# Reader exit codes -> what the operator is told. 2 is hostile or damaged and
# has no override, per the design's gate table.
_wpress_status() {
  case "$1" in
    0) return 0 ;;
    2) _bad "REFUSED. This archive is hostile or damaged; see the line above."
       _note "Nothing was written. A .wpress that stops part way is usually an"
       _note "interrupted upload: compare its size with the original." ;;
    3) _bad "This archive cannot be imported as it stands; see the line above." ;;
    *) _bad "The .wpress reader did not run (status ${1})."
       _note "Is the wp-cli image present?  podman images | grep wordpress"
       _note "Is the archive readable by its group?  chmod 640 <file>" ;;
  esac
  return 1
}

_wpress_read_meta() {  # key -> value, from the reader's scan output in $_wpx
  printf '%s\n' "$_wpx" | sed -n "s/^M $1 //p" | head -1
}

case "${1:-where}" in

# ── How to get a file here ───────────────────────────────────────────────────
where)
  cat <<INSTRUCTIONS

Getting a backup onto this VM
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Everything lands in ${INBOX}

  Pick whichever is least effort. They are equivalent afterwards.

  1. OBJECT STORAGE — easiest if you already configured off-VM backups
  ─────────────────────────────────────────────────────────────────────
     The same credentials already work; nothing new to set up.

       Upload the file to your bucket from any machine, then:
         wp-import.sh fetch s3 <bucket>/<path>/backup.zip

     No object storage? Cloudflare R2's free tier is 10 GB, which is
     more than most WordPress sites, and a browser upload avoids the
     command line entirely.

  2. SCP FROM YOUR WORKSTATION — the -O is required, not optional
  ───────────────────────────────────────────────────────────────
       scp -O backup.zip ${ADMIN_USER:-admin}@${VM_STATIC_IP:-vm-ip}:${INBOX}/

     SSH here only accepts a key, so use the same key you use for the
     terminal.

     Without -O you get:
         subsystem request failed on channel 0
     which reads like a network fault and is not one. This VM's
     sshd_config is written with no 'Subsystem sftp', so there is no
     sftp-server to answer, and OpenSSH 9+ uses SFTP for scp by
     default. -O forces the original SCP protocol, which needs none.

     The same absence means a GUI client — FileZilla, WinSCP,
     Cyberduck — CANNOT drag a file in here. They all speak SFTP.
     Use scp -O, option 1, or option 3.

  3. DIRECT LINK — Dropbox, Drive, WeTransfer, anywhere with a URL
  ────────────────────────────────────────────────────────────────
       wp-import.sh fetch url 'https://…/backup.zip'

     Use the DIRECT download link, not the share page — a share page
     downloads an HTML file that looks like a backup and is not one.
     Most services offer "copy download link" separately.

  4. FROM THE PROXMOX HOST — if the file is already there
  ───────────────────────────────────────────────────────
       scp -O /path/to/backup.zip root@${VM_STATIC_IP:-vm-ip}:${INBOX}/

  ── Then ──────────────────────────────────────────────────────────
       wp-import.sh restore          the whole import, one command
     or step by step:
       wp-import.sh list
       wp-import.sh inspect <file>

  UpdraftPlus: copy EVERY file of the backup here (backup_*-db.gz and
  all the backup_*.zip). They are imported together as one site.

  Inspect only reads. It will not extract or install anything, so it is
  safe to run on a backup you do not trust — which is the point.

  ── Space ─────────────────────────────────────────────────────────
       $(df -h / | awk 'NR==2{print "  "$4" free of "$2}')

  Allow roughly three times the archive size: the file, its extraction,
  and working room. Running out mid-import leaves a broken site and no
  import, so this is checked before anything starts.

INSTRUCTIONS
  ;;

# ── Fetch ────────────────────────────────────────────────────────────────────
fetch)
  _m="${2:-}"; _src="${3:-}"; _sum="${4:-}"
  [ -n "$_src" ] || { echo "Usage: wp-import.sh fetch [s3|url] <source> [sha256]" >&2; exit 1; }

  # Refuse early rather than filling the disk. A failed import that also took
  # the live site down with it is the worst outcome available here.
  _free=$(df -Pk / | awk 'NR==2{print $4}')
  [ "${_free:-0}" -lt 2097152 ] && {
    _bad "Less than 2 GB free. Fetching could fill the disk and take the site down."
    _note "wp-hardening.sh disk"
    exit 1; }

  case "$_m" in
    s3|rclone)
      command -v rclone >/dev/null 2>&1 || { _bad "rclone not installed: apk add rclone"; exit 1; }
      [ -r "$RCLONE_CONF" ] || {
        _bad "No rclone configuration at ${RCLONE_CONF}"
        _note "Off-VM backup sets this up. Configure it, or use: wp-import.sh fetch url <url>"
        exit 1; }
      # Reuse the remote already configured for backups. A second set of
      # credentials for the same bucket is a second thing to rotate and
      # forget.
      _rem=$(sed -n 's/^\[\(.*\)\]$/\1/p' "$RCLONE_CONF" | head -1)
      case "$_src" in *:*) _full="$_src" ;; *) _full="${_rem}:${_src}" ;; esac
      _note "Fetching ${_full} …"
      rclone --config "$RCLONE_CONF" copy --progress "$_full" "$INBOX/" || {
        _bad "Fetch failed."
        _note "List what is there:  rclone --config ${RCLONE_CONF} ls ${_rem}:"
        exit 1; }
      ;;
    url)
      case "$_src" in https://*|http://*) : ;; *) _bad "Give a http(s) URL"; exit 1 ;; esac
      _name=$(basename "${_src%%\?*}")
      # BUG FIX: a share link ends in an ACCESS TOKEN, not a filename:
      #   .../share/<id>/backup/client-a.zip/<token>
      # basename gave the token, so a 653 MB archive landed with no
      # extension and a name that matches nothing the operator asked for.
      # `inspect client-a.zip` then reported "Not found", which reads as the
      # download having failed when it had in fact succeeded.
      #
      # Prefer a path segment that looks like an archive, which is where
      # these services put the real name.
      case "$_name" in
        *.zip|*.tar|*.tar.gz|*.tgz|*.tar.bz2|*.tar.xz|*.gz|*.sql|*.wpress) : ;;
        *)
          _cand=$(printf '%s' "${_src%%\?*}" | tr '/' '\n' \
                  | grep -iE '\.(zip|tar|tar\.gz|tgz|tar\.bz2|tar\.xz|wpress|sql)$' \
                  | tail -1)
          if [ -n "$_cand" ]; then
            _note "URL ends in a token; using '${_cand}' from the path instead."
            _name="$_cand"
          fi ;;
      esac
      case "$_name" in ''|*/*) _name="import-$(date -u +%Y%m%d-%H%M%S).bin" ;; esac
      # BUG FIX: this called curl with no proxy. On every VM running the
      # egress filtering that is the whole point of this product, the request
      # is dropped at the firewall and the download simply fails -- so a
      # documented path could not work on a correctly configured install.
      #
      # Squid is the only reachable destination for outbound HTTP here, and
      # the fetch must also be allowlisted: an import source is an arbitrary
      # host, so `wasp-egress.sh allow <host>` is part of this workflow, not
      # an obstacle to route around.
      _imp_proxy=""
      if [ "${EGRESS_PROXY:-0}" = "1" ] || podman container exists squid 2>/dev/null; then
        _imp_proxy="${WASP_PROXY_URL:-http://10.89.10.2:3128}"
        _note "Fetching through the egress proxy (${_imp_proxy})."
        _note "  Dropbox, Drive, OneDrive, WeTransfer, Box and SyncedTool open by"
        _note "  themselves for this download. Any other host, if refused:"
        _note "    doas wasp-egress.sh import-source add $(printf '%s' "$_src" | sed 's|^[a-z]*://||; s|[/:?#].*||')"
      fi
      # A file-sharing service, or a named import source, opens for this
      # download and closes after it -- under its own tag, so closing it never
      # closes something an operator opened for the same host. A share link
      # redirects (Dropbox to dropboxusercontent.com, Drive to
      # usercontent.google.com), so a service opens as the whole set of hosts
      # its downloads use. See `fileshare` in wasp-egress.sh.
      _imp_win=0
      _imp_tag="import-$$"
      _imp_close() {
        [ "$_imp_win" = 1 ] || return 0
        _imp_win=0
        /usr/local/bin/wasp-egress.sh close --tag "$_imp_tag" >/dev/null 2>&1 \
          || _warn "Could not close the download's egress now. It expires by itself within the hour."
      }
      _imp_host=$(printf '%s' "$_src" | sed 's|^[a-zA-Z]*://||; s|[/:?#].*||' | tr 'A-Z' 'a-z')
      if [ -n "$_imp_proxy" ]; then
        _imp_fs=$(/usr/local/bin/wasp-egress.sh fileshare match "$_imp_host" 2>/dev/null) || _imp_fs=""
        _imp_ok=1
        if [ -n "$_imp_fs" ]; then
          /usr/local/bin/wasp-egress.sh fileshare open "$_imp_fs" --for 60 --tag "$_imp_tag" \
            --reason "import download from ${_imp_host}" >/dev/null || _imp_ok=0
          _imp_what="${_imp_fs}"
        elif /usr/local/bin/wasp-egress.sh import-source has "$_imp_host" 2>/dev/null; then
          /usr/local/bin/wasp-egress.sh allow "$_imp_host" --for 60 --tag "$_imp_tag" \
            --reason "import download from ${_imp_host}" >/dev/null || _imp_ok=0
          _imp_what="${_imp_host}"
        else
          _imp_what=""
        fi
        if [ -n "$_imp_what" ]; then
          if [ "$_imp_ok" = 1 ]; then
            _imp_win=1
            trap '_imp_close' EXIT
            trap 'exit 130' INT TERM
            _note "Opened ${_imp_what} for this download only (60 minutes at most)."
            sleep 2   # squid -k reconfigure returns before the new list is live
          else
            _bad "Could not open egress for ${_imp_what}."
            exit 1
          fi
        fi
      fi
      _note "Downloading to ${INBOX}/${_name} …"
      if [ -n "$_imp_proxy" ]; then
        curl -fL --progress-bar -x "$_imp_proxy" -o "${INBOX}/${_name}" "$_src" \
          || { _bad "Download failed."
               _note "A 403 from the proxy means the host is not allowlisted."
               _note "Check:  podman exec squid tail -5 /var/log/squid/access.log"
               exit 1; }
      else
        curl -fL --progress-bar -o "${INBOX}/${_name}" "$_src" || { _bad "Download failed."; exit 1; }
      fi
      _imp_close
      # A share page returns HTML that is the right shape and the wrong thing.
      # Catching it here saves a confusing failure three steps later.
      if head -c 512 "${INBOX}/${_name}" | grep -qi '<!doctype html\|<html'; then
        _bad "That downloaded an HTML page, not an archive."
        _note "You probably used the share link. Look for 'copy download link' instead."
        rm -f "${INBOX}/${_name}"; exit 1
      fi
      if [ -n "$_sum" ]; then
        _got=$(sha256sum "${INBOX}/${_name}" | awk '{print $1}')
        [ "$_got" = "$_sum" ] && _ok "Checksum matches" || {
          _bad "CHECKSUM MISMATCH — the file is not what you expected."
          _note "expected ${_sum}"; _note "got      ${_got}"
          rm -f "${INBOX}/${_name}"; exit 1; }
      else
        _warn "No checksum given. The download is unverified."
        _note "If you have one:  wp-import.sh fetch url <url> <sha256>"
      fi
      ;;
    *) echo "Usage: wp-import.sh fetch [s3|url] <source> [sha256]" >&2; exit 1 ;;
  esac
  chmod 640 "$INBOX"/* 2>/dev/null || true
  _ok "Done. Next:  wp-import.sh list"
  ;;

# ── List ─────────────────────────────────────────────────────────────────────
list)
  _hdr "Archives in ${INBOX}"
  if [ -z "$(ls -A "$INBOX" 2>/dev/null)" ]; then
    echo "  (empty)"
    echo ""
    echo "  How to get one here:  wp-import.sh where"
    exit 0
  fi
  ls -lh "$INBOX" | tail -n +2 | awk '{printf "  %-46s %8s  %s %s\n", $9, $5, $6, $7}'
  _sets=$(_updraft_sets "$INBOX")
  if [ -n "$_sets" ]; then
    echo ""
    printf '%s\n' "$_sets" | while IFS= read -r _px; do
      _updraft_report "$INBOX" "$_px" || true
    done
    echo ""
    echo "  An UpdraftPlus set imports as one:  wp-import.sh restore"
  fi
  echo ""
  echo "  Inspect one:  wp-import.sh inspect <name>"
  echo "  All in one :  wp-import.sh restore [name]   (extract, scan, import, clean up)"
  df -h / | awk 'NR==2{printf "  Disk: %s free of %s\n", $4, $2}'
  ;;

# ── Inspect ──────────────────────────────────────────────────────────────────
inspect)
  _f="${2:-}"
  [ -n "$_f" ] || { echo "Usage: wp-import.sh inspect <file>" >&2; exit 1; }
  [ -f "$_f" ] || _f="${INBOX}/${_f}"
  [ -f "$_f" ] || { _bad "Not found: ${2}"; _note "wp-import.sh list"; exit 1; }

  _hdr "Inspecting $(basename "$_f")"
  _sz=$(stat -c %s "$_f"); _szh=$(du -h "$_f" | cut -f1)
  printf '  Size : %s\n  Type : %s\n\n' "$_szh" "$(file -b "$_f" 2>/dev/null || echo unknown)"

  # ── Format ────────────────────────────────────────────────────────────────
  _fmt="unknown"; _listing=""
  case "$(basename "$_f")" in
    *.wpress)
      _fmt="All-in-One WP Migration (.wpress)"
      # The whole archive is walked and its checksum verified here, which is
      # the one place inspect reads more than an index: this format has none.
      _note "Reading every header and verifying the checksum…"
      _wprc=0; _wpx=$(_wpress_run "$_f" - scan </dev/null) || _wprc=$?
      _wpress_status "$_wprc" || exit "$_wprc"
      _listing=$(printf '%s\n' "$_wpx" | sed -n 's/^F [0-9]* //p')
      printf '  Source site : %s\n' "$(_wpress_read_meta site_url)"
      printf '  WordPress   : %s   exported by plugin %s\n' \
        "$(_wpress_read_meta wp_version)" "$(_wpress_read_meta plugin_version)"
      printf '  Theme       : %s\n' "$(_wpress_read_meta stylesheet)"
      printf '  Checksum    : %s\n' \
        "$([ "$(_wpress_read_meta format)" = crc ] && echo "verified ($(_wpress_read_meta archive_crc))" || echo "none (exported before plugin 7.104)")"
      [ -n "$(_wpress_read_meta compression)" ] && \
        _note "Compressed: $(_wpress_read_meta compression)"
      [ "$(_wpress_read_meta encrypted)" = 1 ] && \
        _warn "Password-protected. Names are readable; extract will ask for the password."
      [ "$(_wpress_read_meta multisite)" = 1 ] && {
        _bad "Multisite export. WASP is single-site: export the one site instead."; exit 3; }
      [ "$(_wpress_read_meta database)" = 1 ] || \
        _bad "No database.sql: this was exported with the database excluded."
      [ "$(_wpress_read_meta plugins_rejected)" = 0 ] || \
        _bad "$(_wpress_read_meta plugins_rejected) active-plugin name(s) in package.json are not plausible names — ignored. A real export does not produce these."
      echo ""
      ;;
    backup_*-db.gz|backup_*.gz) _fmt="UpdraftPlus (database part)" ;;
    backup_*.zip)               _fmt="UpdraftPlus (files part)" ;;
  esac
  _upx=$(_updraft_prefix "$_f")
  if [ -n "$_upx" ]; then
    _updraft_report "$(dirname "$_f")" "$_upx" || true
    _note "This is one part of a set. extract or restore takes every part together."
    echo ""
  fi

  _is_zip=0
  if tar -tzf "$_f" >/dev/null 2>&1; then
    [ "$_fmt" = "unknown" ] && _fmt="tar.gz"
    _listing=$(tar -tzf "$_f" 2>/dev/null)
  elif unzip -l "$_f" >/dev/null 2>&1; then
    [ "$_fmt" = "unknown" ] && _fmt="zip"
    _is_zip=1
    _listing=$(_zip_members "$_f")
    if [ -z "$_listing" ]; then
      _bad "This is a zip, but its member list could not be read."
      _note "Reading it needs Info-ZIP. BusyBox unzip cannot list members:"
      _note "  doas apk add unzip"
      exit 2
    fi
  elif gzip -t "$_f" >/dev/null 2>&1; then
    [ "$_fmt" = "unknown" ] && _fmt="gzip (probably a SQL dump)"
  fi
  # A cPanel account export: the site at <account>/public_html/, beside the
  # panel's own state. Probably the commonest shape a migrating site arrives
  # in, and it used to be reported as "unknown". Its .bash_history is worth
  # more than any scanner: on the first field test it dated the previous
  # clean-up to the minute and named the file that cleaner had renamed.
  _cpanel=0
  if [ -n "$_listing" ] && printf '%s\n' "$_listing" | grep -qE '(^|/)public_html/wp-(content|includes|config\.php)' \
     && printf '%s\n' "$_listing" | grep -qE '(^|/)(\.cpanel|\.trash|\.cagefs|\.softaculous|\.bash_history|mail|etc|ssl|tmp|logs|public_ftp)(/|$)'; then
    _cpanel=1
    [ "$_fmt" = tar.gz ] || [ "$_fmt" = zip ] && _fmt="${_fmt}, cPanel account export"
  fi
  printf '  Format : %s\n' "$_fmt"
  if [ "$_cpanel" = 1 ]; then
    _note "The site is under public_html/. Only that is imported; the rest is"
    _note "the panel's own state, kept in staging as evidence."
    _bh=$(printf '%s\n' "$_listing" | grep -E '(^|/)\.(bash|zsh|mysql|sh)_history$' | head -5)
    if [ -n "$_bh" ]; then
      _warn "Shell history is included — read it before anything else:"
      printf '%s\n' "$_bh" | sed 's/^/       /'
      _note "  It shows what the last person with a shell did. extract prints the"
      _note "  WordPress-related commands from it."
    fi
  fi

  # ── Hostile members — checked BEFORE anything is extracted ────────────────
  # This is the reason inspect exists as a separate step. Every item here is
  # something that does damage at extraction time, so it has to be caught
  # while the contents are still only names in an index.
  if [ -n "$_listing" ]; then
    _n=$(printf '%s\n' "$_listing" | grep -c .) || _n=0
    printf '  Members: %s\n\n' "$_n"

    _hostile=0
    _trav=$(printf '%s\n' "$_listing" | grep -c '\.\./') || _trav=0
    [ "${_trav:-0}" -gt 0 ] && { _bad "${_trav} member(s) contain '../' — path traversal"
      _note "Extraction would write OUTSIDE the target directory."
      _hostile=$(( _hostile + _trav )); }
    _abs=$(printf '%s\n' "$_listing" | grep -c '^/') || _abs=0
    [ "${_abs:-0}" -gt 0 ] && { _bad "${_abs} member(s) use absolute paths"; _hostile=$(( _hostile + _abs )); }
    _lnk=0
    if [ "$_is_zip" = 1 ]; then
      _lnk=$(_zip_special "$_f") || _lnk=0
    elif tar -tzvf "$_f" >/dev/null 2>&1; then
      _lnk=$(_tar_special "$_f") || _lnk=0
    fi
    [ "${_lnk:-0}" -gt 0 ] && { _bad "${_lnk} link or special member(s)"
      _note "A backup does not need them. Links can reach outside the target."
      _hostile=$(( _hostile + _lnk )); }
    [ "$_hostile" -eq 0 ] && _ok "No path traversal, absolute paths or links"

    # ── Content the operator should know about ──────────────────────────────
    echo ""
    # Duplicator needs both halves. This was a suffix match on installer.php,
    # which also hit Composer's .../Installers/*Installer.php and around a
    # hundred similar ordinary files, while the same report said "Type:
    # unknown". A package is an exact installer.php beside an *archive.zip
    # (or .daf), or the dup-installer/ directory that archive unpacks.
    # Duplicator never puts its installer inside wp-content, and a plugin's own
    # installer.php is not a finding.
    _dupi=$(printf '%s\n' "$_listing" | grep -E '(^|/)installer\.php$' | grep -v 'wp-content/') || _dupi=""
    _dupa=0
    if [ -n "$_dupi" ]; then
      while IFS= read -r _di; do
        case "$_di" in
          */*) _dd="${_di%/*}/" ;;
          *)   _dd="" ;;
        esac
        printf '%s\n' "$_listing" | while IFS= read -r _m; do
          case "$_m" in "${_dd}"*) _r="${_m#"$_dd"}"; case "$_r" in */*) ;; *archive.zip|*archive.daf) echo y ;; esac ;; esac
        done | grep -q y && _dupa=1
      done <<DUPEOF
$_dupi
DUPEOF
    fi
    printf '%s\n' "$_listing" | grep -qE '(^|/)dup-installer/|(^|/)installer-backup\.php$' && _dupa=1
    if [ "$_dupa" = 1 ]; then
      _bad "Contains a Duplicator package (installer with its archive)"
      _note "This is a documented site-takeover vector. It will be deleted,"
      _note "never executed — do not run it yourself either."
    elif [ -n "$_dupi" ]; then
      _note "installer.php outside wp-content, with no Duplicator archive beside it."
      _note "  Removed at extract all the same: nothing in a site root needs one."
    fi

    # PHP in uploads, with WordPress's directory-index guards counted apart.
    # Plugins write uploads/<dir>/index.php holding "<?php // Silence is
    # golden." to stop directory listing. Six of them were reported as "the
    # single strongest indicator that the source site was compromised" while
    # the real malware went unmentioned. Only names are visible here, so the
    # verdict on index.php waits for `scan`, which reads the content.
    _upphp=$(printf '%s\n' "$_listing" | grep -E 'wp-content/uploads/.*\.(php[0-9]?|phtml|phar)$') || _upphp=""
    _guard=$(printf '%s\n' "$_upphp" | grep -c '/index\.php$') || _guard=0
    _php=$(printf '%s\n' "$_upphp" | grep -v '/index\.php$' | grep -c .) || _php=0
    if [ "${_php:-0}" -gt 0 ]; then
      _bad "${_php} executable PHP file(s) inside uploads"
      _note "Nothing legitimate puts PHP there. This is the single strongest"
      _note "indicator that the source site was compromised."
      printf '%s\n' "$_upphp" | grep -v '/index\.php$' | head -10 | sed 's/^/       /'
    elif [ "${_guard:-0}" -gt 0 ]; then
      _ok "No PHP in uploads beyond ${_guard} directory-index guard(s) — content checked at scan"
    else
      _ok "No PHP in uploads"
    fi

    # PHP renamed so it no longer runs: _x7Qe2k.php -> _x7Qe2k.php.bak. That
    # is what someone does to a file they found and were afraid of. No build
    # process, plugin or backup tool produces names like this, and the one
    # real piece of malware in the first field test was exactly this shape:
    # disarmed, still present, reported by nothing.
    _ren=$(printf '%s\n' "$_listing" | grep -iE '\.(php[0-9]?|phtml|phar)(\.(bak|bk|old|orig|save|sav|back|backup|copy|disabled?|off|suspected|quarantined?|infected|hacked|malware|txt|tmp)|~)$') || _ren=""
    _renn=$(printf '%s\n' "$_ren" | grep -c .) || _renn=0
    if [ "${_renn:-0}" -gt 0 ]; then
      _rcfg=$(printf '%s\n' "$_ren" | grep -c 'wp-config\.php') || _rcfg=0
      _roth=$(( _renn - _rcfg ))
      if [ "$_roth" -gt 0 ]; then
        _warn "${_roth} PHP file(s) renamed so they no longer run — read each one"
        _note "  Someone disarmed these instead of deleting them, usually because"
        _note "  they looked malicious."
        printf '%s\n' "$_ren" | grep -v 'wp-config\.php' | head -10 | sed 's/^/       /'
      fi
      [ "$_rcfg" -gt 0 ] && _note "${_rcfg} renamed copy(ies) of wp-config.php (the old host's database password) — discarded"
    fi

    # Only top-level *.php in mu-plugins autoloads. This counted the bare
    # directory entry as a file and said "active on arrival" about a .php.bak.
    _mufiles=$(printf '%s\n' "$_listing" | grep 'wp-content/mu-plugins/.' | grep -v '/$') || _mufiles=""
    _mu=$(printf '%s\n' "$_mufiles" | grep -c .) || _mu=0
    _muact=$(printf '%s\n' "$_mufiles" | grep -cE 'wp-content/mu-plugins/[^/]+\.php$') || _muact=0
    if [ "${_muact:-0}" -gt 0 ]; then
      _warn "${_muact} must-use plugin(s) would load on arrival, with no activation step"
      _note "  Withheld at apply. Read them before restoring any."
    fi
    [ $(( _mu - _muact )) -gt 0 ] && _note "$(( _mu - _muact )) other file(s) in mu-plugins — WordPress does not load them; withheld at apply"

    _cfg=$(printf '%s\n' "$_listing" | grep -c 'wp-config\.php$') || _cfg=0
    [ "${_cfg:-0}" -gt 0 ] && _note "Contains wp-config.php — will be discarded; this VM's own config wins"

    _core=$(printf '%s\n' "$_listing" | grep -c '^\(\./\)\?wp-includes/') || _core=0
    [ "${_core:-0}" -gt 0 ] && _note "Contains WordPress core — will be discarded in favour of the pinned image"

    _plug=$(printf '%s\n' "$_listing" | grep -oE 'wp-content/plugins/[^/]+' | sort -u | grep -c .) || _plug=0
    _thm=$(printf '%s\n' "$_listing" | grep -oE 'wp-content/themes/[^/]+' | sort -u | grep -c .) || _thm=0
    echo ""
    printf '  Plugins: %s   Themes: %s\n' "$_plug" "$_thm"

    # ── Expansion ratio ─────────────────────────────────────────────────────
    _un=$(tar -tzvf "$_f" 2>/dev/null | awk '{s+=$3} END{print s+0}')
    [ "$_is_zip" = 1 ] && _un=$(_zip_bytes "$_f")
    [ -n "${_wpx:-}" ] && _un=$(_wpress_read_meta stored_bytes)
    if [ "${_un:-0}" -gt 0 ]; then
      _ratio=$(( _un / (_sz > 0 ? _sz : 1) ))
      printf '  Expands to roughly %s (ratio %sx)\n' "$(numfmt --to=iec "$_un" 2>/dev/null || echo "${_un}B")" "$_ratio"
      [ "$_ratio" -gt 100 ] && _warn "Very high compression ratio — possible decompression bomb"
      _need=$(( _un / 1024 * 3 ))
      _free=$(df -Pk / | awk 'NR==2{print $4}')
      [ "${_free:-0}" -lt "$_need" ] && _bad "Not enough disk: needs ~$(( _need / 1048576 ))GB free, have $(( _free / 1048576 ))GB"
    fi

    echo ""
    if [ "$_hostile" -gt 0 ]; then
      _bad "REFUSED: this archive contains members that can reach outside"
      _bad "the extraction directory. There is no legitimate reason for that."
      exit 2
    fi
    if [ "${_php:-0}" -gt 0 ] || [ "${_dup:-0}" -gt 0 ]; then
      _warn "Findings above. Importable, but treat the source as compromised:"
      _note "the flagged files will be quarantined rather than installed."
      exit 1
    fi
    _ok "Nothing structurally hostile found."
    _note "This is an index check, not a malware scan — a backdoored plugin"
    _note "looks exactly like a normal one from here. The full scan runs on"
    _note "the extracted contents, before anything is imported."
  else
    _note "Could not read an index. If this is a SQL dump, that is expected."
    printf '  First lines:\n'
    { gzip -dc "$_f" 2>/dev/null || cat "$_f"; } | head -5 | sed 's/^/    /'
  fi
  ;;

# ── Extract ──────────────────────────────────────────────────────────────────
extract)
  _f="${2:-}"
  [ -n "$_f" ] || { echo "Usage: wp-import.sh extract <file>" >&2; exit 1; }
  [ -f "$_f" ] || _f="${INBOX}/${_f}"
  # An UpdraftPlus set may be named by its prefix alone.
  if [ ! -f "$_f" ] && [ -n "$(_updraft_parts "$INBOX" "${2:-}")" ]; then
    _f=$(_updraft_parts "$INBOX" "$2" | head -1)
  fi
  [ -f "$_f" ] || { _bad "Not found: ${2}"; exit 1; }
  _f=$(_abs "$_f")
  _upx=$(_updraft_prefix "$_f")
  _is_wpress=0

  if [ -n "$_upx" ]; then
  # ── UpdraftPlus: every part of the set into ONE staging set ──────────────
  _updir=$(dirname "$_f")
  echo ""
  _updraft_report "$_updir" "$_upx" || { _bad "This set cannot be imported as it is."; exit 3; }
  _upparts=$(_updraft_parts "$_updir" "$_upx")
  # Every zip is checked before ANY is unpacked: one hostile part refuses the set.
  _uh=0; _un=0
  for _p in $(printf '%s\n' "$_upparts" | grep '\.zip$'); do
    _zip_hostile "$_p" || _uh=1
    _un=$(( _un + $(_zip_bytes "$_p") ))
  done
  [ "$_uh" = 0 ] || { _bad "Refusing the whole set. Nothing legitimate needs these."; exit 2; }
  _udb=$(printf '%s\n' "$_upparts" | grep -- '-db[0-9]*\.gz$' | head -1)
  gzip -t "$_udb" 2>/dev/null || { _bad "$(basename "$_udb") is not a readable gzip — re-download it."; exit 2; }
  _un=$(( _un + $(stat -c %s "$_udb") * 8 ))
  _needk=$(( _un / 1024 + 524288 ))
  _freek=$(df -Pk / | awk 'NR==2{print $4}')
  [ "${_freek:-0}" -lt "$_needk" ] && {
    _bad "Not enough disk: needs ~$(( _needk / 1048576 ))GB, have $(( _freek / 1048576 ))GB"; exit 1; }

  _id="$(date -u +%Y%m%d-%H%M%S)-updraft-$(printf '%s' "$_upx" | sed -E 's/^backup_([0-9-]+)_.*/\1/' | cut -c1-15)"
  _st="${STAGING}/${_id}"
  if [ -e "$_st" ]; then _bad "Staging set ${_id} already exists. Wait a second and retry."; exit 1; fi
  mkdir -p "${_st}/files/wp-content" "${_st}/db" "${_st}/meta"
  chmod 700 "$_st"
  printf '%s\n' "$_upparts" > "${_st}/meta/sources.txt"
  _note "Extracting the set to ${_st}/files/wp-content …"
  for _p in $(printf '%s\n' "$_upparts" | grep '\.zip$'); do
    case "$(_updraft_entity "$_p")" in
      wpcore|more) _note "  skipped $(basename "$_p") (not wp-content)"; continue ;;
    esac
    # -n: never overwrite. Two parts claiming the same file is not a real set.
    unzip -q -n "$_p" -d "${_st}/files/wp-content" 2>/dev/null \
      || { _bad "Extraction failed: $(basename "$_p")"; rm -rf "$_st"; exit 1; }
    printf '     %-12s %s\n' "$(_updraft_entity "$_p")" "$(basename "$_p")"
  done
  cp "$_udb" "${_st}/db/"
  else

  # Re-run the hostile-member checks. inspect already did this, but extraction
  # must not depend on the operator having run inspect first -- a security
  # check that only fires when someone remembers to ask for it is not a
  # control.
  _listing=""; _is_zip=0
  if tar -tzf "$_f" >/dev/null 2>&1; then
    _listing=$(tar -tzf "$_f" 2>/dev/null)
  elif unzip -l "$_f" >/dev/null 2>&1; then
    _is_zip=1
    _listing=$(_zip_members "$_f")
    if [ -z "$_listing" ]; then
      _bad "This is a zip, but its member list could not be read, so it cannot"
      _bad "be checked. Refusing to extract it unchecked."
      _note "Reading it needs Info-ZIP:  doas apk add unzip"
      exit 2
    fi
  fi
  if [ -n "$_listing" ]; then
    _h=0
    printf '%s\n' "$_listing" | grep -q '\.\./' && { _bad "Path traversal in archive members"; _h=1; }
    printf '%s\n' "$_listing" | grep -q '^/'      && { _bad "Absolute paths in archive members"; _h=1; }
    _lnk=0
    if [ "$_is_zip" = 1 ]; then
      _lnk=$(_zip_special "$_f") || _lnk=0
    else
      _lnk=$(_tar_special "$_f") || _lnk=0
    fi
    [ "${_lnk:-0}" -gt 0 ] && { _bad "${_lnk} link or special member(s) in the archive"; _h=1; }
    [ "$_h" = 1 ] && { _bad "Refusing to extract. Nothing legitimate needs these."; exit 2; }
  fi

  _id="$(date -u +%Y%m%d-%H%M%S)-$(basename "$_f" | tr -c 'a-zA-Z0-9._-' '_' | cut -c1-32)"
  _st="${STAGING}/${_id}"
  # The id has one-second resolution. Re-using one would merge two extractions,
  # and every failure path below removes the directory, so a clash would delete
  # the earlier, good staging set.
  if [ -e "$_st" ]; then
    _bad "Staging set ${_id} already exists. Wait a second and retry."
    exit 1
  fi
  mkdir -p "${_st}/files" "${_st}/db" "${_st}/meta"
  chmod 700 "$_st"
  # What this set was made from, so clean-up can remove exactly that.
  printf '%s\n' "$_f" > "${_st}/meta/sources.txt"
  case "$(basename "$_f")" in *.wpress) _is_wpress=1 ;; esac

  # Space check before writing, not after. Running out mid-extract leaves a
  # half-populated staging directory and a disk too full for the live site to
  # write its own logs or backups.
  _un=$(tar -tzvf "$_f" 2>/dev/null | awk '{s+=$3} END{print s+0}')
  [ "$_is_zip" = 1 ] && _un=$(_zip_bytes "$_f")
  if [ "${_un:-0}" -gt 0 ]; then
    _needk=$(( _un / 1024 + 524288 ))
    _freek=$(df -Pk / | awk 'NR==2{print $4}')
    [ "${_freek:-0}" -lt "$_needk" ] && {
      _bad "Not enough disk: needs ~$(( _needk / 1048576 ))GB, have $(( _freek / 1048576 ))GB"
      rm -rf "$_st"; exit 1; }
  fi

  if [ "$_is_wpress" = 1 ]; then
    # Hostile members, sizes and the checksum are all re-checked by the reader
    # before it writes, so this does not depend on inspect having been run.
    # 512 MB stays free for the live site; a compressed archive's real size is
    # only known as it decodes, so the limit is enforced while writing.
    _freek=$(df -Pk / | awk 'NR==2{print $4}')
    _sizek=$(( $(stat -c %s "$_f") / 1024 ))
    if [ "${_freek:-0}" -lt $(( _sizek + 524288 )) ]; then
      _bad "Not enough disk: needs ~$(( (_sizek + 524288) / 1048576 ))GB, have $(( _freek / 1048576 ))GB"
      rm -rf "$_st"; exit 1
    fi
    _budget=$(( (_freek - 524288) * 1024 ))

    _wprc=0; _wpx=$(_wpress_run "$_f" - scan </dev/null) || _wprc=$?
    _wpress_status "$_wprc" || { rm -rf "$_st"; exit "$_wprc"; }

    # The password goes to the reader on stdin. printf is a shell builtin, so
    # it never appears in a process listing, and the reader writes it nowhere.
    _pwopt=""; _wpw=""
    if [ "$(_wpress_read_meta encrypted)" = 1 ]; then
      if [ ! -t 0 ]; then
        _bad "This archive is password-protected and there is no terminal to ask on."
        _note "Run it from a console: qm terminal <vmid>"
        rm -rf "$_st"; exit 3
      fi
      printf '  Archive password: '
      stty -echo 2>/dev/null
      IFS= read -r _wpw || _wpw=""
      stty echo 2>/dev/null
      echo ""
      _pwopt="--password-stdin"
    fi

    # Unprivileged inside, so only these three directories are writable to it.
    chown 33:33 "${_st}/files" "${_st}/db" "${_st}/meta"
    _note "Extracting to ${_st}/files/wp-content …"
    # shellcheck disable=SC2086
    printf '%s\n' "$_wpw" | _wpress_run "$_f" "$_st" extract \
      "--max-bytes=${_budget}" $_pwopt
    _wprc=$?
    _wpw=""
    chown -R root:root "$_st" 2>/dev/null
    _wpress_status "$_wprc" || { rm -rf "$_st"; exit "$_wprc"; }

    # The format cannot express a link or a device. Anything other than plain
    # files and directories means something other than the reader wrote here.
    _odd=$(find "$_st" ! -type f ! -type d 2>/dev/null | grep -c .) || _odd=0
    if [ "${_odd:-0}" -gt 0 ]; then
      _bad "REFUSED: ${_odd} non-regular file(s) in the extracted tree."
      rm -rf "$_st"; exit 2
    fi

    # database.sql names everything with the plugin's placeholder. Turned back
    # into the source site's real prefix HERE, before anything else reads the
    # dump, because the scan below and `apply` both key on table names:
    # unconverted, the option-row check matches nothing and reports "No code in
    # option rows", and the prefix detection reads the wrong thing entirely.
    _pfx=$(sed -n 's/^db_prefix=//p' "${_st}/meta/wpress.meta" | head -1)
    case "$_pfx" in ''|*[!A-Za-z0-9_]*)
      _warn "No usable table prefix in package.json — assuming wp_"; _pfx=wp_ ;; esac
    _dmp="${_st}/db/database.sql"
    if ! sed "s/SERVMASK_PREFIX_/${_pfx}/g" "$_dmp" > "${_dmp}.tmp" \
       || ! mv "${_dmp}.tmp" "$_dmp"; then
      _bad "Could not normalise the dump's table prefix."
      rm -rf "$_st"; exit 1
    fi
    if grep -q 'SERVMASK_PREFIX_' "$_dmp"; then
      _bad "The dump still carries the plugin's placeholder prefix."
      rm -rf "$_st"; exit 1
    fi
    if [ "$(sed -n 's/^file_crc_mismatch=//p' "${_st}/meta/wpress.meta")" != 0 ]; then
      _warn "$(sed -n 's/^file_crc_mismatch=//p' "${_st}/meta/wpress.meta") file(s) did not match their stored checksum."
    fi
    _wm=$(sed -n 's/^plugins_missing=//p' "${_st}/meta/wpress.meta")
    [ "${_wm:-0}" = 0 ] || _warn "${_wm} plugin(s) were active on the source but are not in this archive."
  fi

  [ "$_is_wpress" = 1 ] || [ -n "$_upx" ] || _note "Extracting to ${_st}/files …"
  # --no-same-owner / --no-same-permissions: never honour ownership or mode
  # bits from an untrusted archive. A setuid binary or a root-owned file
  # inside a client's backup is not something to reproduce faithfully.
  if [ "$_is_wpress" = 1 ]; then
    :
  elif tar -tzf "$_f" >/dev/null 2>&1; then
    tar -xzf "$_f" -C "${_st}/files" --no-same-owner --no-same-permissions 2>/dev/null \
      || { _bad "Extraction failed"; rm -rf "$_st"; exit 1; }
  elif unzip -l "$_f" >/dev/null 2>&1; then
    unzip -q -o "$_f" -d "${_st}/files" 2>/dev/null \
      || { _bad "Extraction failed"; rm -rf "$_st"; exit 1; }
  elif gzip -t "$_f" >/dev/null 2>&1; then
    cp "$_f" "${_st}/db/$(basename "$_f")"
    _note "Gzip input treated as a database dump"
  else
    _bad "Unrecognised archive format"; rm -rf "$_st"; exit 1
  fi
  fi   # end of the single-archive path (the UpdraftPlus path is above)

  # What actually landed, checked before anything touches it. This has to come
  # before the chmod below: on a hard link, chmod changes the file it points at.
  if ! _sp=$(_staged_special "${_st}/files"); then
    _bad "Could not check the extracted files for links. Refusing to continue."
    rm -rf "$_st"; exit 2
  fi
  if [ "${_sp:-1}" -gt 0 ]; then
    _bad "${_sp} link or special file(s) landed in staging. Nothing was imported."
    _note "If a real backup holds hard links, re-pack it without them:"
    _note "  tar --hard-dereference -czf site.tar.gz <dir>"
    rm -rf "$_st"; exit 2
  fi

  # Nothing extracted is executable. The staging directory is not served and
  # nothing here should be run, so removing the bit costs nothing and removes
  # a whole class of accident -- including an operator or a script invoking
  # something from the archive without meaning to.
  find "${_st}/files" -type f -exec chmod a-x {} + 2>/dev/null || true
  find "${_st}/files" -type d -exec chmod 700 {} + 2>/dev/null || true

  # Duplicator's installer is removed immediately, not at import. It is a
  # documented takeover vector and there is no stage at which keeping it is
  # useful. Not inside wp-content: Duplicator never writes there, and this
  # used to delete any plugin's own includes/installer.php by name, breaking
  # that plugin without a word.
  _dupn=$(find "${_st}/files" -path '*/wp-content/*' -prune -o -type f \
            \( -name 'installer.php' -o -name 'installer-backup.php' \) -print 2>/dev/null \
          | grep -c .) || _dupn=0
  if [ "${_dupn:-0}" -gt 0 ]; then
    find "${_st}/files" -path '*/wp-content/*' -prune -o -type f \
         \( -name 'installer.php' -o -name 'installer-backup.php' \) -exec rm -f {} + 2>/dev/null
    _warn "Removed ${_dupn} installer file(s) from outside wp-content — never executed"
  fi
  if find "${_st}/files" -path '*/wp-content/*' -prune -o -type d -name dup-installer -print 2>/dev/null | grep -q .; then
    find "${_st}/files" -path '*/wp-content/*' -prune -o -type d -name dup-installer -exec rm -rf {} + 2>/dev/null
    _warn "Removed Duplicator's dup-installer/ — never executed"
  fi

  # Collect any SQL dumps into db/ so the scan knows where to look.
  #
  # BUG FIX: maxdepth 3 missed the common case. UpdraftPlus writes its
  # backups to wp-content/updraft/, which inside a cPanel account archive is
  # <account>/public_html/wp-content/updraft/ -- depth 5. The dump was
  # present and reported as absent, so the operator extracted it by hand.
  #
  # Depth is not the only issue: an archive routinely holds SEVERAL dumps
  # from different dates (UpdraftPlus keeps a retention set). Silently
  # taking the first one found is how a site gets restored from a backup
  # eighteen months older than the operator believed. Collect them all and,
  # when there is more than one, refuse to guess.
  #
  # Not for .wpress: its dump is one known member, already in db/. Sweeping the
  # tree there would pull schema.sql out of any plugin that ships one, breaking
  # the plugin and tripping the several-dumps refusal below.
  [ "$_is_wpress" = 1 ] || find "${_st}/files" -maxdepth 8 \
    \( -name '*.sql' -o -name '*.sql.gz' -o -name '*-db.gz' -o -name '*.sql.bz2' \) \
    -exec mv {} "${_st}/db/" \; 2>/dev/null || true

  _ndumps=$(ls -1 "${_st}/db" 2>/dev/null | grep -c .) || _ndumps=0
  if [ "${_ndumps:-0}" -gt 1 ]; then
    echo ""
    _warn "${_ndumps} database dumps found. This archive holds more than one."
    _note "  Dates matter: restoring the wrong one silently reverts the site"
    _note "  to whenever that backup was taken."
    ls -1t "${_st}/db" 2>/dev/null | while IFS= read -r _d; do
      printf '    %-58s %s\n' "$_d" \
        "$(date -u -r "${_st}/db/${_d}" '+%Y-%m-%d %H:%M' 2>/dev/null || echo '?')"
    done
    _note "  Keep the one you want and remove the rest before importing:"
    _note "    rm ${_st}/db/<unwanted>"
  fi

  _nf=$(find "${_st}/files" -type f 2>/dev/null | grep -c .) || _nf=0
  _nd=$(ls -1 "${_st}/db" 2>/dev/null | grep -c .) || _nd=0
  printf '%s\n' "$_id" > "${STAGING}/.latest"
  echo ""
  _ok "Extracted: ${_nf} file(s), ${_nd} database dump(s)"
  _note "Staging: ${_st}"
  _note "Nothing is executable and nothing is web-reachable."

  # Shell history from the source account. The WordPress-related lines are
  # printed, and a copy is kept with the staging set's metadata; nothing in it
  # is run. It can hold a password typed on a command line, so it stays root-
  # only and is printed filtered, not whole.
  _bhs=$(find "${_st}/files" -maxdepth 3 -type f \( -name '.bash_history' -o -name '.zsh_history' -o -name '.sh_history' \) 2>/dev/null | head -3)
  if [ -n "$_bhs" ]; then
    mkdir -p "${_st}/meta"
    _hdr "Shell history in the archive"
    printf '%s\n' "$_bhs" | while IFS= read -r _bhf; do
      cp "$_bhf" "${_st}/meta/$(basename "$_bhf").$(printf '%s' "$_bhf" | cksum | cut -d' ' -f1)" 2>/dev/null
      _bhn=$(grep -c . "$_bhf" 2>/dev/null) || _bhn=0
      printf '  %s (%s lines)\n' "${_bhf#${_st}/files/}" "$_bhn"
      grep -nE '(^|[ ;/])(wp |wp-cli|mv |rm |cp |chmod |chown |curl |wget |php |unzip |tar |mysql|mariadb|crontab|nano |vi |vim |cat ).*(wp-|\.php|plugins|uploads|mu-plugins|cron|\.sql)' "$_bhf" 2>/dev/null \
        | tail -25 | cut -c1-160 | sed 's/^/     /'
    done
    chmod -R go-rwx "${_st}/meta" 2>/dev/null || true
    _note "Look for: a plugin deactivated, a file renamed or deleted, a security"
    _note "plugin switched off. Each names something scan should be asked about."
  fi
  echo ""
  _note "Next:  wp-import.sh scan ${_id}"
  ;;

# ── Scan ─────────────────────────────────────────────────────────────────────
scan)
  _id="${2:-}"
  [ -n "$_id" ] || _id=$(cat "${STAGING}/.latest" 2>/dev/null)
  [ -n "$_id" ] || { echo "Usage: wp-import.sh scan <id>   (wp-import.sh staged)" >&2; exit 1; }
  _st="${STAGING}/${_id}"
  [ -d "$_st" ] || { _bad "No staging directory ${_id}"; exit 1; }

  _hdr "Scanning ${_id}"
  _crit=0; _high=0

  # ── Files: reuse the existing scanner against the staged tree ────────────
  # Pointed at the site root, not the top of the staging tree. See _site_root.
  _scanroot=$(_site_root "${_st}/files")
  if [ -z "$_scanroot" ]; then
    _scanroot="${_st}/files"
    _warn "No WordPress site root found — structural checks have nothing to check"
    _note "  Signatures still run over everything staged."
  elif [ "$_scanroot" != "${_st}/files" ]; then
    _note "Site root: ${_scanroot#${_st}/}"
  fi
  if [ -x /usr/local/bin/wp-malware-scan.sh ]; then
    _note "File scan (structural + signatures) …"
    # This said "signatures" for years while running only `structural`.
    for _sc in structural yara; do
      # Both at the site root: it is what apply copies, and the uploads-only
      # YARA rules look for wp-content/uploads beneath --path.
      _so=$(/usr/local/bin/wp-malware-scan.sh --path "$_scanroot" "$_sc" 2>&1)
      printf '%s\n' "$_so" | sed 's/^/  /'
      _mc=$(printf '%s\n' "$_so" | grep -c '\[CRITICAL\]') || _mc=0
      _mh=$(printf '%s\n' "$_so" | grep -c '\[HIGH\]') || _mh=0
      _crit=$(( _crit + _mc )); _high=$(( _high + _mh ))
    done
  else
    _warn "wp-malware-scan.sh not available — file scan skipped"
  fi

  # ── Database dump: scanned as a FILE, before it is ever loaded ───────────
  # This is the point of the exercise. Loading a dump and then querying it is
  # the same mistake as extracting into the docroot: by the time you look, the
  # thing you were checking for has already happened.
  _hdr "Database dump"
  _dumps=$(ls -1 "${_st}/db"/* 2>/dev/null)
  if [ -z "$_dumps" ]; then
    _warn "No SQL dump found. A files-only backup imports content but no site."
  else
    for _d in $_dumps; do
      printf '  %s (%s)\n' "$(basename "$_d")" "$(du -h "$_d" | cut -f1)"
      _rd() { case "$_d" in *.gz) gzip -dc "$_d" 2>/dev/null ;; *) cat "$_d" ;; esac; }

      # Autoloaded options are the highest-value target: they run on every
      # page load, are invisible in the filesystem, and survive any file clean.
      # Any prefix. This pattern used to require one beginning "wp", so a dump
      # from a site that changed its prefix -- which hardening guides advise --
      # matched nothing here and reported "No code in option rows".
      _ao=$(_rd | grep -ciE "INSERT INTO [\`\"]?[a-z0-9_]*options[\`\"]?.*(eval\(|base64_decode|<\?php|gzinflate|assert\()") || _ao=0
      if [ "${_ao:-0}" -gt 0 ]; then
        _bad "${_ao} option row(s) contain code"
        _note "Autoloaded options run on EVERY page load and survive a file clean."
        _crit=$(( _crit + _ao ))
      else _ok "No code in option rows"; fi

      # Scheduled events. A backdoor here re-creates files after you clean
      # them, and the operator concludes the malware "came back".
      # Quote-agnostic: mysqldump emits single quotes, but exports from
      # phpMyAdmin, Adminer and several backup plugins use double. A pattern
      # matching only one style silently passes the dumps produced by the
      # other -- and this check exists for the persistence mechanism most
      # likely to be missed, so failing quietly is the worst outcome.
      _cr=$(_rd | grep -ciE "['\"]cron['\"].*(eval|base64_decode|https?://)") || _cr=0
      if [ "${_cr:-0}" -gt 0 ]; then
        _bad "Scheduled-task (cron) option looks suspicious"
        _note "This is the persistence mechanism that makes malware appear to"
        _note "return after cleaning. The cron option is cleared at import."
        _high=$(( _high + 1 ))
      else _ok "Scheduled tasks look ordinary"; fi

      # Accounts, by name. "17 row(s) mention administrator" is what this used
      # to say, and on the field test the backdoor account took forty minutes
      # to find by hand. The users table is read as text -- the dump is still
      # not loaded -- and each account checked for the signs of being planted.
      _upfx=$(_rd | sed -n 's/^CREATE TABLE [`"]\{0,1\}\([A-Za-z0-9_]*\)usermeta[`"]\{0,1\}.*/\1/p' | head -1)
      _uu=$(_rd | sh "$THREATS" dump-users "$_upfx" 2>/dev/null)
      _uc=$(_rd | sh "$THREATS" dump-caps "$_upfx" 2>/dev/null)
      _ut=$(printf '%s\n' "$_uu" | awk -F '\t' -v caps="$_uc" '
              BEGIN { n=split(caps, L, "\n"); for (i=1;i<=n;i++) { split(L[i], kv, "\t"); c[kv[1]]=kv[2] } }
              NF { print $0 "\t" c[$1] }')
      if [ -z "$_uu" ]; then
        _note "No user rows could be read from this dump — review after import: wp-forensics.sh admins"
      else
        _uadm=$(printf '%s\n' "$_ut" | awk -F '\t' '$5 ~ /administrator/')
        printf '     %s account(s), %s administrator(s):\n' \
          "$(printf '%s\n' "$_uu" | grep -c .)" "$(printf '%s\n' "$_uadm" | grep -c .)"
        printf '%s\n' "$_uadm" | awk -F '\t' 'NF {printf "       id %-5s %-24s %-36s %s\n", $1, $2, $3, $4}'
        _usus=$(printf '%s\n' "$_ut" | sh "$THREATS" suspect-users 2>/dev/null)
        if [ -n "$_usus" ]; then
          printf '%s\n' "$_usus" | while IFS="$(printf '\t')" read -r _uid _ul _ue _ur _sig _role; do
            _bad "Account looks planted: ${_ul} <${_ue}> id ${_uid}, registered ${_ur}, role ${_role}"
            _note "  signals: ${_sig}"
          done
          _note "Locked automatically at apply (role removed, password and e-mail replaced),"
          _note "not deleted. Review afterwards: wp-forensics.sh admins"
          _high=$(( _high + $(printf '%s\n' "$_usus" | grep -c .) ))
        else
          _ok "No account shows two or more signs of being planted"
        fi
      fi

      _sp=$(_rd | grep -ciE "<script[^>]*>(eval|document\.write|atob)") || _sp=0
      [ "${_sp:-0}" -gt 0 ] && { _warn "${_sp} row(s) contain inline script — often injected SEO spam"
                                 _high=$(( _high + 1 )); } \
                            || _ok "No obvious injected script in content"

      _su=$(_rd | grep -oE "'siteurl','[^']*'" | head -1 | sed "s/.*,'//;s/'//")
      [ -n "$_su" ] && _note "Source siteurl: ${_su}  (rewritten at import)"
    done
  fi

  # ── Known vulnerabilities, before this code is installed ─────────────────
  # The cheapest moment to learn a plugin is vulnerable is now: nothing is live.
  # Versions come from the file headers as TEXT. Nothing staged is executed, and
  # wp-cli is not used because it would load the code to read its version.
  # An unverified version is still only a claim by the archive: a site can lie
  # about being patched, which is why the full scan runs again after import.
  _hdr "Known vulnerabilities in the staged plugins and themes"
  _vuln_unchecked=0
  _pd=$(find "${_st}/files" -maxdepth 7 -type d -path '*/wp-content/plugins' 2>/dev/null \
        | awk '{n=gsub("/","/"); print n "\t" $0}' | sort -n | head -1 | cut -f2)
  _vinv="${_st}/meta/vuln-inventory.csv"
  mkdir -p "${_st}/meta"; : > "$_vinv"
  _vtext() { sed -n '1,80p' "$1" 2>/dev/null | tr -d '\r' \
             | sed -n 's/^[ 	/*#@]*Version:[ 	]*\([0-9A-Za-z.+_-]*\).*/\1/p' | head -1; }
  if [ -n "$_pd" ]; then
    for _pp in "$_pd"/*/; do
      [ -d "$_pp" ] || continue
      _sl=$(basename "$_pp")
      for _mf in "$_pp"*.php; do
        [ -f "$_mf" ] || continue
        if sed -n '1,80p' "$_mf" 2>/dev/null | grep -qE '^[ 	/*#@]*Plugin Name:'; then
          _ve=$(_vtext "$_mf")
          [ -n "$_ve" ] && printf 'plugin,%s,%s\n' "$_sl" "$_ve" >> "$_vinv"
          break
        fi
      done
    done
    for _tt in "$(dirname "$_pd")"/themes/*/; do
      [ -f "${_tt}style.css" ] || continue
      _ve=$(_vtext "${_tt}style.css")
      [ -n "$_ve" ] && printf 'theme,%s,%s\n' "$(basename "$_tt")" "$_ve" >> "$_vinv"
    done
  fi
  if [ ! -s "$_vinv" ]; then
    _note "No plugin or theme versions could be read from the staged tree."
    _vuln_unchecked=1
  elif [ ! -x /usr/local/bin/wp-plugins.sh ]; then
    _warn "wp-plugins.sh not available — staged components not checked"
    _vuln_unchecked=1
  else
    _vrc=0
    _vout=$(/usr/local/bin/wp-plugins.sh vulns --inventory "$_vinv" 2>&1) || _vrc=$?
    printf '%s\n' "$_vout" | grep -E '^  \[|^        |^  INCOMPLETE:|^  Sources:' || true
    _vh=$(printf '%s\n' "$_vout" | grep -cE '^  \[(CRITICAL|HIGH)\]') || _vh=0
    # HIGH, not CRITICAL. A vulnerable plugin is a door, not proof anyone came
    # through it, and an old site is the normal reason to be importing.
    if [ "${_vh:-0}" -gt 0 ]; then
      _high=$(( _high + _vh ))
      _warn "${_vh} serious known vulnerabilit(ies) in the staged site. Each is also a"
      _note "likely way in, if the source was compromised."
    fi
    if [ "$_vrc" -ne 0 ]; then
      _vuln_unchecked=1
      _warn "These were NOT fully checked (see INCOMPLETE above)."
    elif [ "${_vh:-0}" -eq 0 ]; then
      _ok "No serious known vulnerabilities in the staged versions"
    fi
  fi

  # ── Verdict ──────────────────────────────────────────────────────────────
  _hdr "Verdict"
  printf '  critical %s   high %s\n\n' "$_crit" "$_high"
  {
    printf '%s  id=%s critical=%s high=%s\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$_id" "$_crit" "$_high"
  } >> "${STAGING}/scan-log.txt"

  if [ "$_crit" -gt 0 ]; then
    _bad "CRITICAL findings. Import would carry a live compromise across."
    _note "Flagged files are quarantined rather than imported, but the source"
    _note "site should be treated as compromised: whatever put them there may"
    _note "also be in a plugin, a theme, or the database."
    _note ""
    _note "  wp-import.sh report ${_id}      full detail"
    _note "  wp-plugins.sh vulns             which plugin was the likely door"
    exit 2
  fi
  if [ "$_high" -gt 0 ]; then
    _warn "Findings worth reading before importing."
    exit 1
  fi
  _ok "Nothing critical found in the staged content."
  [ "${_vuln_unchecked:-0}" = 1 ] && _warn "Known-vulnerability check did not run or did not finish."
  _note "That is a statement about what the scanners detect, not proof the"
  _note "site is clean. A backdoored plugin looks like a working plugin."
  ;;

# ── Staged ───────────────────────────────────────────────────────────────────
staged)
  _hdr "Staged imports"
  if [ -z "$(ls -A "$STAGING" 2>/dev/null | grep -v '^\.' )" ]; then
    echo "  (none)"; exit 0
  fi
  for _d in "$STAGING"/*/; do
    [ -d "$_d" ] || continue
    _fc=$(find "$_d/files" -type f 2>/dev/null | grep -c .) || _fc=0
    printf '  %-40s %8s  %s file(s)\n' "$(basename "$_d")" \
      "$(du -sh "$_d" 2>/dev/null | cut -f1)" "$_fc"
  done
  echo ""
  echo "  Scan:   wp-import.sh scan <id>"
  echo "  Remove: wp-import.sh clean <id>     (and the archives it came from)"
  [ -s "${STAGING}/scan-log.txt" ] && { echo ""; echo "  Scan history:"; tail -5 "${STAGING}/scan-log.txt" | sed 's/^/    /'; }
  ;;

# ── Apply ────────────────────────────────────────────────────────────────────
apply)
  _id="${2:-}"; shift 2 2>/dev/null || shift $# 
  [ -n "$_id" ] || _id=$(cat "${STAGING}/.latest" 2>/dev/null)
  _force=0; _accept=0; _remed=1; _keep=0
  for _a in "$@"; do
    case "$_a" in
      --force) _force=1 ;;
      --accept-findings) _accept=1 ;;
      --no-remediate) _remed=0 ;;
      --keep-files) _keep=1 ;;
    esac
  done
  _st="${STAGING}/${_id}"
  [ -d "$_st" ] || { _bad "No staging directory ${_id}"; _note "wp-import.sh staged"; exit 1; }

  _hdr "Import ${_id}"

  # ── Gate ─────────────────────────────────────────────────────────────────
  # Refusing outright is wrong: people import compromised sites deliberately,
  # in order to clean them. Proceeding silently defeats the tool. So the gate
  # is graded, and every override is recorded.
  _last=$(grep "id=${_id}" "${STAGING}/scan-log.txt" 2>/dev/null | tail -1)
  if [ -z "$_last" ]; then
    _bad "This staging set has not been scanned."
    _note "wp-import.sh scan ${_id}"
    exit 1
  fi
  _c=$(printf '%s' "$_last" | sed -n 's/.*critical=\([0-9]*\).*/\1/p')
  _h=$(printf '%s' "$_last" | sed -n 's/.*high=\([0-9]*\).*/\1/p')
  printf '  Last scan: %s critical, %s high\n\n' "${_c:-?}" "${_h:-?}"
  if [ "${_c:-0}" -gt 0 ] && [ "$_force" != 1 ]; then
    _bad "CRITICAL findings. Refusing without --force."
    _note "Flagged files are quarantined rather than imported, but whatever put"
    _note "them there may also be in a plugin, a theme, or the database."
    _note "  wp-import.sh scan ${_id}"
    exit 2
  fi
  if [ "${_h:-0}" -gt 0 ] && [ "$_accept" != 1 ] && [ "$_force" != 1 ]; then
    _bad "HIGH findings. Re-run with --accept-findings to proceed."
    exit 1
  fi

  # ── Safety backup, mandatory ─────────────────────────────────────────────
  # Before anything is replaced. An import that goes wrong without this leaves
  # neither the old site nor a working new one.
  _note "Backing up the CURRENT site before replacing anything…"
  if ! /usr/local/bin/wp-db-backup.sh >/dev/null 2>&1; then
    _bad "Could not back up the current database. Refusing to import."
    _note "An import without a way back is not an import, it is a replacement."
    exit 1
  fi
  _ok "Current database backed up"

  echo ""
  _warn "This REPLACES the site's content, plugins, themes and database."
  _note "Core, wp-config.php, .htaccess and mu-plugins are NOT imported —"
  _note "this VM's own are kept, because those are exactly where a compromised"
  _note "source hides things that survive a content clean."
  printf "  Type IMPORT to proceed: "
  # BUG FIX: a bare `read` cannot tell "the operator declined" from "there is
  # nobody to ask". Run under `qm guest exec`, cron or any pipe, read returns
  # immediately on EOF and this printed "Cancelled — nothing changed", which
  # is exactly what it prints when the operator types anything else.
  #
  # An operator ran this over the guest agent, read "Cancelled", and
  # reasonably took it as their own answer -- then ran the follow-up steps
  # against a database that had never been imported. Say which it was.
  if ! read -r _cf; then
    echo ""
    echo "  ✗  No input available — this confirmation cannot be answered here." >&2
    echo "     Nothing was cancelled by choice; there was no one to ask." >&2
    echo "" >&2
    echo "     An import replaces the site's database. That confirmation stays" >&2
    echo "     interactive by design. Run it from a terminal:" >&2
    echo "       qm terminal <vmid>      (stay attached — detaching kills it)" >&2
    echo "       or the hypervisor's console" >&2
    exit 1
  fi
  [ "$_cf" = "IMPORT" ] || { echo "  Cancelled — nothing changed."; exit 0; }

  # ── Normalise ────────────────────────────────────────────────────────────
  _hdr "Normalising"
  _q="${_st}/quarantined"; mkdir -p "$_q"
  _src="${_st}/files"
  # Checked here too. A set staged by an older build, or changed by hand since
  # extract, reaches `cp -a` below, and a link or a hard link would be copied
  # into the docroot.
  if ! _sp=$(_staged_special "$_src"); then
    _bad "Could not check the staged files for links. Nothing was imported."
    exit 2
  fi
  if [ "${_sp:-1}" -gt 0 ]; then
    _bad "${_sp} link or special file(s) in this staging set. Nothing was imported."
    _note "Remove it with:  rm -rf ${_st}"
    exit 2
  fi
  # Some archives nest the site. A cPanel/WHM full-account backup puts it at
  # <account>/public_html/, which is depth 2 -- and this searched to
  # maxdepth 2 for wp-content itself, i.e. depth 3. It therefore found
  # nothing, and the operator worked around the pipeline by extracting and
  # copying by hand. That detour bypassed the scan gate, and the tree they
  # copied in contained a webshell.
  #
  # So the depth limit was not a cosmetic bug: it is what pushed a
  # compromised upload tree past the control designed to catch it.
  #
  # Search deeper, but choose carefully. A real backup contains DECOYS --
  # wp-content/updraft/plugins-old/, upgrade-temp-backup/, nested archives
  # of previous sites -- each with their own wp-content. Two rules:
  #
  #   1. A site root has wp-content AND (wp-includes OR wp-config.php).
  #      A backup folder inside wp-content has neither.
  #   2. Prefer the SHALLOWEST match. The real site is always closer to the
  #      archive root than a backup buried inside it.
  if [ ! -d "${_src}/wp-content" ]; then
    _cand=$(_site_root "$_src")
    if [ -n "$_cand" ]; then
      _src="$_cand"
      _note "Site root: ${_src#${_st}/}"
    else
      # Say so rather than silently importing nothing. An import that
      # quietly finds no files looks identical to one with nothing to do.
      _warn "No WordPress site root found in the archive."
      _note "  Looked for a directory holding wp-content alongside"
      _note "  wp-includes or wp-config.php, up to 6 levels deep."
      _note "  Contents:"
      find "$_src" -maxdepth 2 -type d 2>/dev/null | sed "s|^${_src}|    .|" | head -12
    fi
  fi

  for _drop in wp-config.php wp-config-sample.php .htaccess .user.ini; do
    [ -e "${_src}/${_drop}" ] && { mv "${_src}/${_drop}" "$_q/" 2>/dev/null
      _note "Withheld ${_drop} — this VM's own is authoritative"; }
  done
  for _cd in wp-admin wp-includes; do
    [ -d "${_src}/${_cd}" ] && { rm -rf "${_src:?}/${_cd}"
      _note "Discarded ${_cd} — core comes from the pinned image"; }
  done
  find "$_src" -maxdepth 1 -name 'wp-*.php' ! -name 'wp-config.php' -delete 2>/dev/null
  if [ -d "${_src}/wp-content/mu-plugins" ]; then
    mv "${_src}/wp-content/mu-plugins" "$_q/mu-plugins" 2>/dev/null
    _warn "Withheld mu-plugins — they activate on arrival with no opt-in"
  fi
  # Anything executable in uploads. Quarantined, not deleted: it is evidence.
  _qp=0
  find "${_src}/wp-content/uploads" -type f \
       \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' -o -name '*.php[0-9]' \) \
       2>/dev/null | while IFS= read -r _bf; do
    # Keep the relative path. Moved flat, six uploads/*/index.php became one
    # file and two webshells with the same name became one piece of evidence.
    _rel="${_bf#"${_src}/wp-content/uploads/"}"
    mkdir -p "$_q/uploads/$(dirname "$_rel")"; mv "$_bf" "$_q/uploads/${_rel}" 2>/dev/null
  done
  # Index guards are set aside too -- they are still PHP -- but not reported
  # as executable files: that wording is for files someone should read.
  _qp=$(find "$_q/uploads" -type f ! -name index.php 2>/dev/null | grep -c .) || _qp=0
  _qg=$(find "$_q/uploads" -type f -name index.php 2>/dev/null | grep -c .) || _qg=0
  [ "${_qp:-0}" -gt 0 ] && _warn "Quarantined ${_qp} executable file(s) from uploads"
  [ "${_qg:-0}" -gt 0 ] && _note "Set aside ${_qg} index.php file(s) from uploads — scan names any that are not plain directory-index guards"

  # ── What the scan named, kept out before anything is copied ──────────────
  # PHP renamed so it does not run, and escape-obfuscated PHP anywhere a
  # plugin or theme does not live. Neither is needed by a working site; both
  # were the malware on the first real import. Set aside with their paths, as
  # evidence. Obfuscated files inside plugins are left for the plugin repair
  # after import, which replaces a modified wordpress.org plugin wholesale.
  if [ "$_remed" = 1 ] && [ -r "$THREATS" ]; then
    _rmq=0; mkdir -p "${_st}/meta"
    { sh "$THREATS" renamed "${_src}/wp-content" 2>/dev/null
      sh "$THREATS" obfuscated "${_src}/wp-content" 2>/dev/null | cut -f3 \
        | grep -vE '/wp-content/(plugins|themes)/' ; } | sort -u > "${_st}/meta/remediate-files.txt"
    while IFS= read -r _rf; do
      [ -f "$_rf" ] || continue
      _rel="${_rf#"${_src}/"}"
      mkdir -p "$_q/remediated/$(dirname "$_rel")"
      mv "$_rf" "$_q/remediated/${_rel}" && _rmq=$((_rmq + 1)) \
        && _note "Kept out: ${_rel}"
    done < "${_st}/meta/remediate-files.txt"
    [ "$_rmq" -gt 0 ] && _warn "Kept ${_rmq} renamed or obfuscated PHP file(s) out of the import (in ${_q}/remediated)"
  fi

  # ── Files ────────────────────────────────────────────────────────────────
  _hdr "Importing content"
  for _d in uploads plugins themes; do
    [ -d "${_src}/wp-content/${_d}" ] || continue
    mkdir -p "${WP_ROOT}/wp-content/${_d}"
    cp -a "${_src}/wp-content/${_d}/." "${WP_ROOT}/wp-content/${_d}/" 2>/dev/null
    _n=$(find "${_src}/wp-content/${_d}" -type f 2>/dev/null | grep -c .) || _n=0
    _ok "${_d}: ${_n} file(s)"
  done
  chown -R 33:33 "${WP_ROOT}/wp-content" 2>/dev/null || true
  find "${WP_ROOT}/wp-content/uploads" -type f -exec chmod 644 {} + 2>/dev/null || true

  # ── Database ─────────────────────────────────────────────────────────────
  _hdr "Importing database"
  # BUG FIX: this was `ls -1 ... | head -1`, which takes the first
  # ALPHABETICALLY. An UpdraftPlus retention set holds several dated dumps,
  # and backup_2025-08-21... sorts before backup_2026-04-14..., so the
  # oldest was chosen silently. Restoring a site to eighteen months earlier
  # than the operator believes is not a failure they would notice quickly:
  # the site comes up, looks plausible, and is simply missing a year of
  # content.
  #
  # Refuse to guess. Which backup to restore is a decision, not a default.
  _dumps=$(ls -1 "${_st}/db"/* 2>/dev/null | grep -v '/normalised\.sql$' || true)
  _ndump=$(printf '%s\n' "$_dumps" | grep -c . 2>/dev/null) || _ndump=0
  if [ "${_ndump:-0}" -gt 1 ]; then
    _bad "${_ndump} database dumps are staged. Refusing to choose between them."
    printf '%s\n' "$_dumps" | while IFS= read -r _d; do
      [ -n "$_d" ] || continue
      printf '    %-58s %s\n' "$(basename "$_d")" \
        "$(date -u -r "$_d" '+%Y-%m-%d %H:%M' 2>/dev/null || echo '?')" >&2
    done
    _note "  Dates matter: the oldest sorts first, so a silent pick would"
    _note "  have restored the stalest one. Keep one and re-run:"
    _note "    rm ${_st}/db/<unwanted>  &&  wp-import.sh apply ${_id}"
    exit 1
  fi
  _dump=$(printf '%s\n' "$_dumps" | head -1)
  if [ -z "$_dump" ]; then
    _warn "No dump — files imported, database unchanged."
  else
    _ourpfx=$(podman exec mariadb sh -c 'printf %s "${WORDPRESS_TABLE_PREFIX:-wp_}"' 2>/dev/null || printf 'wp_')
    _rd() { case "$_dump" in *.gz) gzip -dc "$_dump" ;; *) cat "$_dump" ;; esac; }
    _theirpfx=$(_rd | grep -oiE "INSERT INTO [\`\"']?[a-z0-9_]+options[\`\"']?" | head -1 \
                | grep -oE '[a-z0-9_]+options' | sed 's/options$//')
    [ -n "$_theirpfx" ] || _theirpfx="wp_"
    # A .wpress states its prefix, which beats inferring one from the first
    # table ending in "options": wp_aiowps_options sorts ahead of wp_options.
    _wmpfx=$(sed -n 's/^db_prefix=//p' "${_st}/meta/wpress.meta" 2>/dev/null | head -1)
    case "$_wmpfx" in ''|*[!A-Za-z0-9_]*) : ;; *) _theirpfx="$_wmpfx" ;; esac
    printf '  Source prefix: %s   This VM: %s\n' "$_theirpfx" "$_ourpfx"

    _sql="${_st}/db/normalised.sql"
    if [ "$_theirpfx" != "$_ourpfx" ]; then
      # Rewriting the prefix is NOT just table names. wp_capabilities,
      # wp_user_level and wp_user_roles are stored as meta_key / option_name
      # VALUES and carry the prefix too. Rewriting tables alone is the classic
      # "changed the prefix and lost admin access" — the user rows import
      # fine and nobody has any capabilities.
      _note "Rewriting prefix, including capability keys…"
      # Quote-agnostic on the meta keys. mysqldump emits single quotes;
      # phpMyAdmin, Adminer and several backup plugins emit double. Matching
      # only one style rewrites the table names and leaves the capability
      # keys alone -- which imports every user with NO capabilities and locks
      # the administrator out of the site that was just imported. That is the
      # classic "changed the prefix and lost admin access", and it presents as
      # a successful import.
      _rd | sed -E \
        -e "s/\`${_theirpfx}/\`${_ourpfx}/g" \
        -e "s/(['\"])${_theirpfx}(capabilities|user_level|user_roles|user-settings|user-settings-time|dashboard_quick_press_last_post_id)\\1/\\1${_ourpfx}\\2\\1/g" \
        > "$_sql"
    else
      _rd > "$_sql"
    fi

    if podman exec -i mariadb sh -c \
         'exec mariadb -u root -p"$MARIADB_ROOT_PASSWORD" "${WORDPRESS_DB_NAME:-wordpress}"' \
         < "$_sql" 2>/dev/null; then
      _ok "Database imported"

      # ── Prefix keys, settled in SQL rather than in text ──────────────────
      #
      # BUG FIX (found on a live VM, 2026-10-20): the sed above rewrote the
      # TABLE names correctly and left the capability KEYS behind, so the
      # import "succeeded" and the site had no roles at all:
      #
      #   wp-cli:  Error: Role doesn't exist: administrator
      #   admins:  (empty)
      #
      # The regex is right and works under both GNU and busybox sed, so the
      # cause is dump-format specific -- quoting, line wrapping, extended
      # inserts, whatever that particular backup plugin emits. Which is the
      # point: rewriting VALUES by pattern-matching SQL text is guessing at
      # someone else's serialiser. Table names must be rewritten in text
      # because they are structural, but the keys do not have to be.
      #
      # So assert the outcome in SQL, where it is exact and format-blind.
      # This runs whether or not the text pass appeared to work, because
      # "appeared to work" is precisely what went wrong.
      if [ "$_theirpfx" != "$_ourpfx" ]; then
        # Compared with LEFT(), never LIKE. In LIKE, "_" matches any single
        # character, so the source prefix "wp_" as a pattern also matched this
        # VM's own "wp5c1e9a_": the count reported correctly renamed keys as
        # stranded, and a second apply rewrote wp5c1e9a_capabilities to
        # wp5c1e9a_c1e9a_capabilities -- every user losing every role while
        # the check printed the same number. An exact byte comparison has no
        # wildcards, and once a run succeeds nothing starts with the source
        # prefix, so running it again changes nothing.
        _oldhex=$(printf '%s' "$_theirpfx" | od -An -tx1 | tr -d ' \n')
        _newhex=$(printf '%s' "$_ourpfx"   | od -An -tx1 | tr -d ' \n')
        _plen=${#_theirpfx}
        _cut=$(( _plen + 1 ))
        _fixsql="UPDATE ${_ourpfx}options  SET option_name = CONCAT(0x${_newhex}, SUBSTRING(option_name, ${_cut})) WHERE LEFT(option_name, ${_plen}) = 0x${_oldhex};
UPDATE ${_ourpfx}usermeta SET meta_key   = CONCAT(0x${_newhex}, SUBSTRING(meta_key,   ${_cut})) WHERE LEFT(meta_key, ${_plen}) = 0x${_oldhex};
SELECT CONCAT('stranded-remaining:', (SELECT COUNT(*) FROM ${_ourpfx}options WHERE LEFT(option_name, ${_plen}) = 0x${_oldhex}) + (SELECT COUNT(*) FROM ${_ourpfx}usermeta WHERE LEFT(meta_key, ${_plen}) = 0x${_oldhex}));"
        _fixout=$(printf '%s\n' "$_fixsql" | podman exec -i mariadb sh -c \
                    'exec mariadb -u root -p"$MARIADB_ROOT_PASSWORD" -N -B "${WORDPRESS_DB_NAME:-wordpress}"' \
                    2>/dev/null | grep '^stranded-remaining:' | cut -d: -f2)
        case "${_fixout:-}" in
          0) _ok "  Prefix keys verified in SQL — none stranded" ;;
          '') _warn "  Could not verify prefix keys. Check before trusting logins:" >&2
              _note "    wp-forensics.sh admins" ;;
          *)  _bad "  ${_fixout} key(s) still carry the source prefix."
              _note "    Users will have no roles. wp-forensics.sh admins" ;;
        esac
      fi
    else
      _bad "Database import FAILED. Files were copied; the database is unchanged"
      _bad "or partially loaded. The pre-import backup is the newest file in"
      _bad "/root/wp-db-backups."
      exit 1
    fi
    rm -f "$_sql"
  fi

  # ── Re-harden ────────────────────────────────────────────────────────────
  # An import undoes hardening: it carries the source site's URLs, users,
  # salts and scheduled tasks. Skipping this leaves a site configured for
  # somewhere else, with credentials someone else may know.
  _hdr "Re-hardening"
  # wp-cli runs in its OWN container: the official wordpress:*-apache image does
  # NOT ship wp-cli, so `podman exec wordpress wp ...` fails with "wp: not found".
  # This shares the running container's network and env-file so wp-config resolves
  # exactly as it does for the site itself.
  _wp() {
    podman run --rm \
      --network "container:wordpress" \
      --user 33:33 \
      --env-file "$WP_ENV_FILE" \
      -e WORDPRESS_DB_HOST=mariadb:3306 \
      -v /home/wpuser/wp/html:/var/www/html \
      "$(_wpcli_image)" wp --path=/var/www/html "$@" 2>/dev/null
  }

  _url="${WP_SCHEME:-https}://${WP_DOMAIN:-localhost}"
  _wp option update home "$_url"    >/dev/null && _ok "home    -> ${_url}"
  _wp option update siteurl "$_url" >/dev/null && _ok "siteurl -> ${_url}"

  # ── What a .wpress dump leaves out ───────────────────────────────────────
  # The plugin empties `template`, `stylesheet` and `active_plugins` in its dump
  # and records them in package.json, restoring them itself after an import.
  # Loaded as a plain dump, the site comes up with no theme and no plugins and
  # nothing reports a fault. These were validated by the reader against patterns
  # that exclude a leading dash, because `--exec=<php>` as a wp-cli argument is
  # code execution; they are checked again here because this file is being read
  # back. Written as options, as the plugin does, so no activation hook runs.
  _wmeta() { sed -n "s/^$1=//p" "${_st}/meta/wpress.meta" 2>/dev/null | head -1; }
  if [ -n "$_dump" ] && [ -f "${_st}/meta/wpress.meta" ]; then
    _hdr "Restoring what the .wpress dump left out"
    for _t in template stylesheet; do
      _tv=$(_wmeta "$_t")
      case "$_tv" in
        ''|-*|*[!A-Za-z0-9._-]*)
          # Older exports keep the theme in the dump instead. Believed only if
          # that theme is actually here.
          _tc=$(_wp option get "$_t" --skip-plugins --skip-themes 2>/dev/null)
          if [ -n "$_tc" ] && [ -d "${WP_ROOT}/wp-content/themes/${_tc}" ]; then
            _ok "${_t} kept from the dump: ${_tc}"
          else
            _bad "No usable ${_t} recorded — the site has NO THEME until you set one."
            _tm=$(_wmeta "${_t}_missing")
            [ -n "$_tm" ] && _note "The source used ${_tm}, which is not in this archive."
            _note "  wp-plugins.sh doctor, then activate a theme"
          fi ;;
        *)
          if _wp option update "$_t" "$_tv" --skip-plugins --skip-themes >/dev/null; then
            _ok "${_t} -> ${_tv}"
          else
            _bad "Could not set ${_t}. The site has NO THEME until this is done."
          fi ;;
      esac
    done

    _ap=$(_wmeta plugins_json)
    case "$_ap" in
      '['*']')
        if [ -n "$(printf '%s' "$_ap" | tr -d 'A-Za-z0-9._/,"[]-')" ]; then
          _bad "The active-plugin list is malformed. No plugins were activated."
        elif _wp option update active_plugins "$_ap" --format=json --skip-plugins --skip-themes >/dev/null; then
          _ok "Active plugins restored from the archive"
        else
          _bad "Could not restore active plugins. Forms, builders and shops will be missing."
        fi ;;
      '') _note "No plugin list in package.json — keeping the one in the dump." ;;
      *) _bad "The active-plugin list is malformed. No plugins were activated." ;;
    esac

    # home/siteurl above are not the only places the old address lives. Posts,
    # builder data and widgets carry it too, serialised and JSON-escaped, which
    # is why this is wp-cli's search-replace and not sed.
    for _su in "$(_wmeta site_url)" "$(_wmeta home_url)"; do
      case "$_su" in
        http://*|https://*) : ;;
        *) continue ;;
      esac
      case "$_su" in *[!A-Za-z0-9.:/_~%-]*) continue ;; esac
      _bare=${_su#*://}
      for _old in "https://${_bare}" "http://${_bare}"; do
        [ "$_old" = "$_url" ] && continue
        _oldj=$(printf '%s' "$_old" | sed 's|/|\\/|g')
        _urlj=$(printf '%s' "$_url" | sed 's|/|\\/|g')
        _wp search-replace "$_old" "$_url" --all-tables-with-prefix --skip-columns=guid \
          --skip-plugins --skip-themes >/dev/null \
          && _wp search-replace "$_oldj" "$_urlj" --all-tables-with-prefix --skip-columns=guid \
               --skip-plugins --skip-themes >/dev/null \
          || _warn "search-replace failed for ${_old}"
      done
      _ok "Rewrote ${_bare} -> ${_url}"
      [ "$(_wmeta home_url)" = "$(_wmeta site_url)" ] && break
    done
  fi

  # ── Two Factor, whatever the source format ───────────────────────────────
  # Any imported database replaces active_plugins, and the enforcement mu-plugin
  # no-ops unless the provider is loaded -- so an import that does not say
  # otherwise leaves admin login password-only while enforcement reads as
  # present. Verified after the attempt, because that gap was found once by
  # reading validator output on a live client site.
  _mfa_gap=0
  if [ "${MFA_ENFORCE:-0}" = "1" ] && [ -n "$_dump" ]; then
    _wp plugin activate two-factor --skip-plugins --skip-themes >/dev/null 2>&1 || true
    if _wp plugin is-active two-factor --skip-plugins --skip-themes >/dev/null 2>&1; then
      _ok "Two Factor active — MFA enforcement is armed"
    else
      _mfa_gap=1
      _bad "Two Factor is NOT active. Admin login is password-only."
      _note "  wp-plugins.sh install two-factor --activate"
    fi
  fi

  # The old salts may be known to whoever had the source site. Every existing
  # session is invalidated, which is the point.
  if _wp config shuffle-salts >/dev/null 2>&1; then
    _ok "Salts regenerated — all existing sessions invalidated"
  else
    _warn "Could not shuffle salts; wp-config may not be writable"
    _note "Old salts mean old session cookies still work. Rotate by hand."
  fi

  # Scheduled tasks are the persistence mechanism that survives a file clean.
  _wp option delete cron >/dev/null 2>&1 && _ok "Scheduled tasks cleared — WordPress will rebuild them"

  _wp cache flush >/dev/null 2>&1
  _wp rewrite flush >/dev/null 2>&1 && _ok "Permalinks flushed"

  # ── Automated remediation of the live, imported site ────────────────────
  # Now that the files and the database are in place: wordpress.org plugins
  # whose files differ from their published copy are reinstalled clean (the
  # modified copy quarantined), and accounts with two or more signs of being
  # planted are locked rather than deleted. The same pass `wp-malware-scan.sh
  # remediate` runs on a live site, here without asking, because an import of
  # a site to be cleaned is the case it exists for. --no-remediate skips it.
  if [ "$_remed" = 1 ] && [ -x /usr/local/bin/wp-malware-scan.sh ]; then
    _hdr "Automated remediation"
    /usr/local/bin/wp-malware-scan.sh remediate --apply --yes 2>&1 | sed 's/^/  /' 
  elif [ "$_remed" = 0 ]; then
    _warn "Automated remediation skipped (--no-remediate)."
    _note "  Run it when ready:  doas wp-malware-scan.sh remediate"
  fi

  echo ""
  _hdr "Administrators on the imported site"
  _wp user list --role=administrator --fields=ID,user_login,user_email,user_registered 2>/dev/null \
    | sed 's/^/  /' || _note "Could not list users — check by hand"
  echo ""
  _warn "Every account above can log in. Any you do not recognise is a backdoor."
  _note "  wp-forensics.sh admins"
  _note "Reset a password:  wp-plugins.sh doctor   then use wp-cli via the container (see SUPPORT-RUNBOOK.md)"

  # ── Record and verify ────────────────────────────────────────────────────
  {
    printf '%s  id=%s critical=%s high=%s force=%s quarantined=%s remediate=%s by=%s\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$_id" "${_c:-0}" "${_h:-0}" "$_force" "${_qp:-0}" "$_remed" \
      "${SUDO_USER:-${DOAS_USER:-${USER:-unknown}}}"
  } >> "${STAGING}/import-log.txt"
  chmod 600 "${STAGING}/import-log.txt" 2>/dev/null || true

  # ── Clean up ─────────────────────────────────────────────────────────────
  # The site is live; the staging copy and the archives it came from are now
  # only a second and third copy of a client's database. --keep-files skips it.
  _hdr "Cleaning up"
  if [ "$_keep" = 1 ]; then
    _note "Kept (--keep-files). Later:  wp-import.sh clean ${_id}"
  else
    _cleanup_set "$_id"
  fi

  _hdr "Verify"
  _note "  validate-wordpress.sh"
  _note "  wp-malware-scan.sh full        the live site, not the staging copy"
  _note "  wp-plugins.sh vulns            you have just installed someone else's plugins"
  echo ""
  [ "${_qp:-0}" -gt 0 ] && _note "Quarantined files kept at ${_q} — evidence, not rubbish."
  if [ "${_mfa_gap:-0}" = 1 ]; then
    _bad "Import finished with MFA NOT ACTIVE. Fix that before this site is public."
    exit 1
  fi
  _ok "Import complete. Recorded in ${STAGING}/import-log.txt"
  ;;

# ── Restore: the whole pipeline in one command ───────────────────────────────
# extract → scan → apply → clean up, stopping where a person has to decide.
# With nothing named, the one thing in the inbox is used: a single UpdraftPlus
# set (however many parts) or a single archive. Two or more, and it asks which.
restore)
  shift
  _tgt=""; _pass=""
  for _a in "$@"; do
    case "$_a" in
      --accept-findings|--force|--no-remediate|--keep-files) _pass="${_pass} ${_a}" ;;
      -*) _bad "Unknown option: ${_a}"; exit 1 ;;
      *) _tgt="$_a" ;;
    esac
  done
  if [ -z "$_tgt" ]; then
    _cands=$( { _updraft_sets "$INBOX"
                for _c in "$INBOX"/*; do
                  [ -f "$_c" ] || continue
                  [ -n "$(_updraft_prefix "$_c")" ] && continue
                  case "$_c" in *.zip|*.tar.gz|*.tgz|*.wpress|*.sql.gz|*.gz) basename "$_c" ;; esac
                done; } | grep . )
    _ncand=$(printf '%s\n' "$_cands" | grep -c .) || _ncand=0
    if [ "$_ncand" = 0 ]; then
      _bad "Nothing in ${INBOX} to restore."
      _note "  wp-import.sh where     how to get a backup here"
      exit 1
    elif [ "$_ncand" -gt 1 ]; then
      _bad "More than one backup in the inbox — name the one to restore:"
      printf '%s\n' "$_cands" | sed 's/^/       wp-import.sh restore /'
      exit 1
    fi
    _tgt="$_cands"
  fi

  _hdr "Restore: ${_tgt}"
  sh "$0" extract "$_tgt" || exit $?
  _id=$(cat "${STAGING}/.latest" 2>/dev/null)
  [ -n "$_id" ] || { _bad "Extract did not record a staging set."; exit 1; }

  _src=0; sh "$0" scan "$_id" || _src=$?
  case "$_src" in
    0) : ;;
    1)
      case "$_pass" in *--accept-findings*|*--force*) : ;; *)
        if [ -t 0 ]; then
          echo ""
          printf '  Import anyway, with these findings recorded as accepted? [y/N] : '
          read -r _yn || _yn=""
          case "$_yn" in y|Y|yes) _pass="${_pass} --accept-findings" ;;
            *) _note "Stopped. Nothing imported. Later:  wp-import.sh apply ${_id} --accept-findings"
               _note "Or discard it:  wp-import.sh clean ${_id}"; exit 1 ;;
          esac
        else
          _note "Stopped at findings. Re-run with --accept-findings, or: wp-import.sh apply ${_id} --accept-findings"
          exit 1
        fi ;;
      esac ;;
    2)
      case "$_pass" in *--force*) : ;; *)
        _bad "CRITICAL findings: not importing without a deliberate --force."
        _note "Importing a compromised site to clean it is legitimate; do it knowingly:"
        _note "  wp-import.sh apply ${_id} --force"
        _note "Or discard it:  wp-import.sh clean ${_id}"
        exit 2 ;;
      esac ;;
    *) _bad "The scan did not finish (exit ${_src}). Nothing imported."; exit "$_src" ;;
  esac
  # shellcheck disable=SC2086
  sh "$0" apply "$_id" $_pass
  ;;

# ── Clean: remove leftover copies of imported sites ──────────────────────────
clean)
  shift
  case "${1:-}" in
    '')
      echo "Usage: wp-import.sh clean <id> | --all [--yes] | --stale <days> [--yes]" >&2
      echo "       (wp-import.sh staged lists the ids)" >&2
      exit 1 ;;
    --all|--stale)
      _days=""
      if [ "$1" = --stale ]; then
        _days="${2:-}"
        case "$_days" in ''|*[!0-9]*) _bad "--stale takes a number of days"; exit 1 ;; esac
        [ "$_days" -ge 1 ] || { _bad "--stale needs at least 1 day"; exit 1; }
      fi
      _yes=0; for _a in "$@"; do [ "$_a" = --yes ] && _yes=1; done
      _old() { [ -z "$_days" ] || [ -n "$(find "$1" -maxdepth 0 -mtime +"$_days" 2>/dev/null)" ]; }
      # A set already cleaned after its import holds only evidence: not listed.
      _ids=""; for _d in "$STAGING"/*/; do
        [ -d "$_d" ] || continue
        [ -d "${_d}files" ] || [ -d "${_d}db" ] || continue
        _old "$_d" && _ids="${_ids} $(basename "$_d")"
      done
      _loose=""; for _c in "$INBOX"/*; do [ -f "$_c" ] && _old "$_c" && _loose="${_loose} $(basename "$_c")"; done
      if [ -z "${_ids}${_loose}" ]; then _ok "Nothing to clean${_days:+ older than ${_days} days}."; exit 0; fi
      _hdr "Clean up${_days:+ — older than ${_days} days}"
      [ -n "$_ids" ] && printf '  staging set  %s\n' $_ids
      [ -n "$_loose" ] && printf '  inbox file   %s\n' $_loose
      if [ "$_yes" != 1 ]; then
        printf '\n  Imported sets keep their quarantine and meta (evidence). Type CLEAN to proceed: '
        read -r _cf || { _bad "No input available. Use --yes to clean unattended."; exit 1; }
        [ "$_cf" = CLEAN ] || { echo "  Cancelled — nothing changed."; exit 0; }
      fi
      for _i in $_ids; do _cleanup_set "$_i"; done
      for _c in $_loose; do [ -f "${INBOX}/${_c}" ] && rm -f "${INBOX}/${_c}" && _ok "Removed ${_c}"; done
      logger -t wp-import "clean ${1}${_days:+ ${_days}}: staging [${_ids# }] inbox [${_loose# }]" 2>/dev/null || true
      ;;
    *)
      case "$1" in *[!A-Za-z0-9._-]*) _bad "Not a staging id: $1"; exit 1 ;; esac
      [ -d "${STAGING}/$1" ] || { _bad "No staging set $1"; _note "wp-import.sh staged"; exit 1; }
      _cleanup_set "$1"
      logger -t wp-import "clean $1" 2>/dev/null || true
      ;;
  esac
  ;;

*) sed -n '4,18p' "$0" ;;
esac
