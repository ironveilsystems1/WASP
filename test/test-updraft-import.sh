#!/usr/bin/env bash
# =============================================================================
# test-updraft-import.sh — an UpdraftPlus backup imports as one site, and
# what an import leaves behind is cleaned up
# =============================================================================
#
# Drives the real wp-import.sh (paths pointed at a temp tree; podman, the
# database backup and wp-cli stubbed) with a realistic UpdraftPlus set: a
# -db.gz and plugins, themes, uploads (in two parts), others and wpcore zips.
#
#   - list and inspect show the set as one, with what it holds and lacks
#   - extract, named by ANY part or by the prefix, stages ONE site: every
#     zip unpacked into one wp-content, the dump in db/, wpcore skipped
#   - a set with no database, an encrypted database, or one hostile zip is
#     refused whole, before anything is unpacked
#   - restore with nothing named uses the one backup in the inbox, refuses
#     to guess between two, and runs extract → scan → apply → clean up
#   - after the import: the archives and the staging copy are gone, the
#     record is kept; nothing outside the inbox is ever deleted
#   - clean <id>, clean --stale N
# Runs under BusyBox too (WASP_TEST_TOOLS / WASP_TEST_SH), with Info-ZIP's
# unzip as stage 08 installs it.
# =============================================================================
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
_p() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
_f() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n         %s\n' "$1" "${2:-}"; }
command -v unzip >/dev/null 2>&1 && unzip -Z1 /dev/null 2>&1 | grep -qv 'invalid option' \
  || { echo "  Info-ZIP unzip is required (as on the VM: apk add unzip)"; exit 1; }

echo ""
echo "UpdraftPlus import, and clean-up"

mkdir -p "$T/inbox" "$T/staging" "$T/html/wp-content" "$T/etc" "$T/bin" "$T/outside"
: > "$T/etc/vars.sh"
sed -e 's#^  if command -v doas.*##' \
    -e '/^if \[ "\$(id -u)" -ne 0 \]; then$/,/^fi$/d' \
    -e "s#/etc/wp-install/vars.sh#$T/etc/vars.sh#g" \
    -e "s#^INBOX=.*#INBOX=$T/inbox#" \
    -e "s#^STAGING=.*#STAGING=$T/staging#" \
    -e "s#^WP_ROOT=.*#WP_ROOT=$T/html#" \
    -e "s#^THREATS=.*#THREATS=$T/bin/none#" \
    -e "s#/usr/local/bin/wp-db-backup.sh#$T/bin/wp-db-backup.sh#g" \
    -e "s#/usr/local/bin/wp-plugins.sh#$T/bin/none#g" \
    -e "s#/usr/local/bin/wp-malware-scan.sh#$T/bin/none#g" \
    "$REPO/payload/bin/wp-import.sh" > "$T/wp-import.sh"
# The VM's own pieces, stubbed: the database backup succeeds, podman and
# wp-cli answer "done" to everything, logger records.
printf '#!/bin/sh\nexit 0\n' > "$T/bin/wp-db-backup.sh"
printf '#!/bin/sh\ncat >/dev/null 2>&1 &\nexit 0\n' > "$T/bin/podman"
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "%s/syslog"\n' "$T" > "$T/bin/logger"
ln -s "$(command -v unzip)" "$T/bin/unzip"
chmod +x "$T/bin/"*
_imp() { env PATH="$T/bin:${WASP_TEST_TOOLS:+$WASP_TEST_TOOLS:}$PATH" ${WASP_TEST_SH:-sh} "$T/wp-import.sh" "$@" 2>&1; }

P=backup_2026-11-01-0300_Example_Site_0a1b2c3d4e5f
_mkset() {   # _mkset <dir> <prefix> [nodb|crypt|hostile]
  python3 -I - "$1" "$2" "${3:-}" <<'PY'
import gzip, sys, zipfile
d, p, mode = sys.argv[1:4]
def z(name, members):
    with zipfile.ZipFile(f"{d}/{p}-{name}.zip", "w", zipfile.ZIP_DEFLATED) as f:
        for n, b in members: f.writestr(n, b)
z("plugins",  [("plugins/akismet/akismet.php", "<?php /* Plugin Name: Akismet */\n")])
z("themes",   [("themes/twentytwentyfive/style.css", "/* Theme Name: TT5 */\n")])
z("uploads",  [("uploads/2026/10/a.jpg", "jpg")])
z("uploads2", [("uploads/2026/11/b.jpg", "jpg")])
z("others",   [("languages/en_GB.mo", "mo"), ("index.php", "<?php // Silence is golden.\n")])
z("wpcore",   [("wp-includes/version.php", "<?php $wp_version = '6.8.3';\n")])
if mode == "hostile":
    z("uploads3", [("../../outside/planted.php", "<?php system($_GET['c']);")])
sql = b"CREATE TABLE `wp_options` (option_id int);\nINSERT INTO `wp_options` VALUES ('siteurl','https://old.example.com');\n"
if mode == "crypt":
    open(f"{d}/{p}-db.gz.crypt", "wb").write(b"encrypted")
elif mode != "nodb":
    with gzip.open(f"{d}/{p}-db.gz", "wb") as f: f.write(sql)
PY
}
_staged() { find "$T/staging" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' '; }
_reset() { rm -rf "$T/inbox"/* "$T/staging"/* "$T/staging/.latest" "$T/staging/import-log.txt" "$T/staging/scan-log.txt"; sleep 1; }

# ── list / inspect ──────────────────────────────────────────────────────────
_mkset "$T/inbox" "$P"
_o=$(_imp list)
{ printf '%s' "$_o" | grep -q "UpdraftPlus set: $P" && printf '%s' "$_o" | grep -q 'uploads    present (2 parts)'; } \
  && _p "list shows the set as one, uploads in two parts" || _f "list" "$(printf '%s' "$_o" | tail -12)"
_o=$(_imp inspect "$P-themes.zip")
printf '%s' "$_o" | grep -q 'This is one part of a set' && printf '%s' "$_o" | grep -q 'database   present' \
  && _p "inspecting one part reports the whole set" || _f "inspect" "$(printf '%s' "$_o" | head -20)"

# ── extract by a part, and by the prefix ────────────────────────────────────
_o=$(_imp extract "$P-uploads2.zip"); _rc=$?
_id=$(cat "$T/staging/.latest" 2>/dev/null); S="$T/staging/$_id"
{ [ "$_rc" = 0 ] && [ "$(_staged)" = 1 ] && [ -f "$S/files/wp-content/plugins/akismet/akismet.php" ] \
  && [ -f "$S/files/wp-content/themes/twentytwentyfive/style.css" ] && [ -f "$S/files/wp-content/uploads/2026/10/a.jpg" ] \
  && [ -f "$S/files/wp-content/uploads/2026/11/b.jpg" ] && [ -f "$S/files/wp-content/languages/en_GB.mo" ] \
  && [ -f "$S/db/$P-db.gz" ]; } \
  && _p "naming one part stages the whole set as ONE site (both uploads parts, dump in db/)" \
  || _f "set extract" "rc=$_rc $(printf '%s' "$_o" | tail -6)"
[ ! -e "$S/files/wp-content/wp-includes" ] && printf '%s' "$_o" | grep -q 'skipped .*-wpcore.zip' \
  && _p "the wpcore part is skipped, said so, and never lands in wp-content" || _f "wpcore" "$(ls "$S/files/wp-content")"
[ "$(grep -c . "$S/meta/sources.txt")" = 7 ] && _p "every part is recorded as a source of this set" || _f "sources" "$(cat "$S/meta/sources.txt")"
_reset; _mkset "$T/inbox" "$P"
_o=$(_imp extract "$P"); _rc=$?
[ "$_rc" = 0 ] && [ "$(_staged)" = 1 ] && _p "the set can be named by its prefix alone" || _f "prefix" "rc=$_rc $(printf '%s' "$_o" | tail -3)"

# ── refused sets ────────────────────────────────────────────────────────────
_reset; _mkset "$T/inbox" "$P" nodb
_o=$(_imp extract "$P-plugins.zip"); _rc=$?
{ [ "$_rc" = 3 ] && [ "$(_staged)" = 0 ] && printf '%s' "$_o" | grep -q 'database   MISSING'; } \
  && _p "a set with no database is refused, and says which file is missing" || _f "no db" "rc=$_rc $(printf '%s' "$_o" | tail -3)"
_reset; _mkset "$T/inbox" "$P" crypt
_o=$(_imp extract "$P-plugins.zip"); _rc=$?
{ [ "$_rc" = 3 ] && [ "$(_staged)" = 0 ] && printf '%s' "$_o" | grep -q 'Decrypt'; } \
  && _p "an encrypted database is refused, with how to decrypt it" || _f "crypt" "rc=$_rc $(printf '%s' "$_o" | tail -3)"
_reset; _mkset "$T/inbox" "$P" hostile
_o=$(_imp extract "$P-plugins.zip"); _rc=$?
{ [ "$_rc" = 2 ] && [ "$(_staged)" = 0 ] && [ ! -e "$T/outside/planted.php" ] && [ ! -e "$T/planted.php" ]; } \
  && _p "one hostile part refuses the whole set before anything is unpacked" || _f "hostile part" "rc=$_rc $(printf '%s' "$_o" | tail -3)"

# ── restore ─────────────────────────────────────────────────────────────────
_reset; _mkset "$T/inbox" "$P"; _mkset "$T/inbox" backup_2026-10-01-0300_Example_Site_ffffffffffff
_o=$(_imp restore </dev/null); _rc=$?
{ [ "$_rc" = 1 ] && [ "$(_staged)" = 0 ] && printf '%s' "$_o" | grep -q 'More than one backup'; } \
  && _p "restore with two backups in the inbox asks which, and touches nothing" || _f "two sets" "rc=$_rc $(printf '%s' "$_o" | tail -4)"
_reset; _mkset "$T/inbox" "$P"
printf 'keep me\n' > "$T/outside/precious.txt"
_o=$(printf 'IMPORT\n' | _imp restore); _rc=$?
_id=$(sed -n 's/.*id=\([^ ]*\) .*/\1/p' "$T/staging/import-log.txt" 2>/dev/null | tail -1); S="$T/staging/$_id"
if [ -n "$_id" ] && [ -f "$T/html/wp-content/plugins/akismet/akismet.php" ]; then
  _p "restore with nothing named runs extract → scan → apply on the one set"
else
  _f "restore did not import" "rc=$_rc $(printf '%s' "$_o" | tail -8)"
fi
[ -f "$T/html/wp-content/uploads/2026/11/b.jpg" ] && [ ! -e "$T/html/wp-content/languages" ] \
  && _p "plugins, themes and both uploads parts are imported; others are not" || _f "imported content" "$(ls "$T/html/wp-content")"
[ -z "$(ls -A "$T/inbox")" ] && _p "afterwards the archives are gone from the inbox" || _f "inbox not cleaned" "$(ls "$T/inbox")"
{ [ -n "$_id" ] && [ ! -d "$S/files" ] && [ ! -d "$S/db" ] && [ -f "$S/meta/sources.txt" ]; } \
  && _p "and the staging copy is gone; the record of what was imported is kept" || _f "staging not cleaned" "$(ls "$S" 2>&1)"
[ "$(cat "$T/outside/precious.txt" 2>/dev/null)" = "keep me" ] && _p "nothing outside the inbox was touched" || _f "outside file touched" ""

# --keep-files leaves everything for later; clean <id> then removes it.
_reset; _mkset "$T/inbox" "$P"
printf 'IMPORT\n' | _imp restore --keep-files >/dev/null 2>&1
_id=$(sed -n 's/.*id=\([^ ]*\) .*/\1/p' "$T/staging/import-log.txt" 2>/dev/null | tail -1); S="$T/staging/$_id"
{ [ -n "$_id" ] && [ -d "$S/files" ] && [ "$(ls "$T/inbox" | grep -c .)" = 7 ]; } \
  && _p "--keep-files keeps the archives and the staging copy" || _f "--keep-files" "$(ls "$T/inbox" "$S" 2>&1 | tail -5)"
# A source list that points outside the inbox is never followed.
printf '%s\n' "$T/outside/precious.txt" >> "$S/meta/sources.txt"
_o=$(_imp clean "$_id"); _rc=$?
{ [ "$_rc" = 0 ] && [ -z "$(ls -A "$T/inbox")" ] && [ ! -d "$S/files" ] && [ -f "$T/outside/precious.txt" ]; } \
  && _p "clean <id> removes them later, and ignores a source outside the inbox" || _f "clean id" "rc=$_rc $(printf '%s' "$_o" | tail -3)"

# A set extracted and abandoned is removed whole.
_reset; _mkset "$T/inbox" "$P"
_imp extract "$P-db.gz" >/dev/null; _id=$(cat "$T/staging/.latest")
_imp clean "$_id" >/dev/null
[ ! -e "$T/staging/$_id" ] && [ -z "$(ls -A "$T/inbox")" ] && _p "an abandoned (never imported) set is removed whole, with its archives" \
  || _f "abandoned set" "$(ls "$T/staging" "$T/inbox")"

# ── clean --stale ───────────────────────────────────────────────────────────
_reset; _mkset "$T/inbox" "$P"
touch -d '40 days ago' "$T/inbox/$P"-*.zip
printf 'new\n' > "$T/inbox/new-site.zip"
_o=$(_imp clean --stale 30 --yes); _rc=$?
{ [ "$_rc" = 0 ] && [ ! -e "$T/inbox/$P-plugins.zip" ] && [ -e "$T/inbox/new-site.zip" ] && [ -e "$T/inbox/$P-db.gz" ]; } \
  && _p "clean --stale 30 removes only what is older than 30 days" || _f "stale" "rc=$_rc $(ls "$T/inbox")"
grep -q 'clean --stale 30' "$T/syslog" && _p "and logs what it removed" || _f "stale not logged" "$(cat "$T/syslog" 2>/dev/null)"
_o=$(_imp clean --all </dev/null); _rc=$?
[ "$_rc" = 1 ] && [ -e "$T/inbox/new-site.zip" ] && _p "clean --all with no one to confirm changes nothing" || _f "clean --all unattended" "rc=$_rc"

echo ""
printf '  passed %d   failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
