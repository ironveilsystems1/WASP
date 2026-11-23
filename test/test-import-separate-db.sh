#!/usr/bin/env bash
# =============================================================================
# test-import-separate-db.sh — files and database in two files; plugins WASP
# replaces are not imported (10.30)
# =============================================================================
#
# Many hosts export a site as site.tar.gz (the files) and site.sql.gz (the
# database). Drives the real wp-import.sh (paths pointed at a temp tree;
# podman, wp-cli and the database backup stood in):
#
#   - extract with no dump says so and names add-db; add-db stages the dump,
#     and apply refuses until the set is scanned again
#   - restore <files> --db <dump>, and restore with just those two in the
#     inbox, import both; an archive's own dump is set aside for the named one
#   - a tar given as the dump, a gzip that is not SQL, a missing file: refused
#     before anything is staged
#   - Wordfence, WPS Hide Login and Limit Login Attempts Reloaded are set
#     aside at extract, not scanned, not copied, taken out of active_plugins,
#     and Wordfence's tables are dropped by name; --keep-plugin keeps one
# Runs under BusyBox too (WASP_TEST_TOOLS / WASP_TEST_SH).
# =============================================================================
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
_p() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
_f() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n         %s\n' "$1" "${2:-}"; }
echo ""
echo "Import: a separate database file, and plugins WASP replaces"

mkdir -p "$T/inbox" "$T/staging" "$T/html/wp-content" "$T/etc" "$T/bin" "$T/src"
: > "$T/etc/vars.sh"
sed -e 's#^  if command -v doas.*##' \
    -e '/^if \[ "\$(id -u)" -ne 0 \]; then$/,/^fi$/d' \
    -e "s#/etc/wp-install/vars.sh#$T/etc/vars.sh#g" \
    -e "s#^INBOX=.*#INBOX=$T/inbox#" \
    -e "s#^STAGING=.*#STAGING=$T/staging#" \
    -e "s#^WP_ROOT=.*#WP_ROOT=$T/html#" \
    -e "s#^THREATS=.*#THREATS=$REPO/payload/bin/wasp-threats.sh#" \
    -e "s#/usr/local/bin/wp-db-backup.sh#$T/bin/wp-db-backup.sh#g" \
    -e "s#/usr/local/bin/wp-plugins.sh#$T/bin/none#g" \
    -e "s#/usr/local/bin/wp-malware-scan.sh#$T/bin/none#g" \
    "$REPO/payload/bin/wp-import.sh" > "$T/wp-import.sh"
printf '#!/bin/sh\nexit 0\n' > "$T/bin/wp-db-backup.sh"
# podman: wp-cli answers for active_plugins, the database takes SQL on stdin.
cat > "$T/bin/podman" <<STUB
#!/bin/sh
case "\$*" in
  *"option get active_plugins"*) cat "$T/active.json" 2>/dev/null ;;
  *"option update active_plugins"*) printf '%s\n' "\$*" >> "$T/ap-updates" ;;
  *WORDPRESS_TABLE_PREFIX*) printf wp_ ;;
  *"exec -i mariadb"*) cat >> "$T/sql-in" ;;
  *) cat >/dev/null 2>&1 & ;;
esac
exit 0
STUB
printf '#!/bin/sh\nexit 0\n' > "$T/bin/logger"
chmod +x "$T/bin/"*
_imp() { env PATH="$T/bin:${WASP_TEST_TOOLS:+$WASP_TEST_TOOLS:}$PATH" ${WASP_TEST_SH:-sh} "$T/wp-import.sh" "$@" 2>&1; }
_latest() { cat "$T/staging/.latest" 2>/dev/null; }
_staged() { find "$T/staging" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' '; }
_reset() { rm -rf "$T/inbox"/* "$T/staging"/* "$T/staging/.latest" "$T/staging/import-log.txt" "$T/staging/scan-log.txt" \
             "$T/html/wp-content"/* "$T/ap-updates" "$T/sql-in"; sleep 1; }

# A host's two files: the account's public_html as a tar.gz, and a mysqldump.
_mk() {  # [with-own-dump]
  rm -rf "$T/src"; mkdir -p "$T/src/public_html/wp-includes" "$T/src/public_html/wp-content/uploads/2026/11"
  for p in akismet wordfence wps-hide-login limit-login-attempts-reloaded; do
    mkdir -p "$T/src/public_html/wp-content/plugins/$p"
    printf '<?php /* Plugin Name: %s */\n' "$p" > "$T/src/public_html/wp-content/plugins/$p/$p.php"
  done
  mkdir -p "$T/src/public_html/wp-content/themes/astra"; printf '/* Theme Name: Astra */\n' > "$T/src/public_html/wp-content/themes/astra/style.css"
  printf 'jpg' > "$T/src/public_html/wp-content/uploads/2026/11/a.jpg"
  printf '<?php $wp_version = "6.8.3";\n' > "$T/src/public_html/wp-includes/version.php"
  [ "${1:-}" = with-own-dump ] && printf 'CREATE TABLE `wp_options` (x int);\n-- OLD DUMP\n' > "$T/src/public_html/old-backup.sql"
  tar -czf "$T/inbox/site-files.tar.gz" -C "$T/src" public_html
  printf -- '-- MariaDB dump 10.19\nCREATE TABLE `wp_options` (option_id int, option_name varchar(191), option_value longtext, autoload varchar(20));\nINSERT INTO `wp_options` VALUES (1,%s,%s,%s);\n-- NEW DUMP\n-- Dump completed on 2026-11-20 10:00:00\n' \
    "'siteurl'" "'https://old.example.com'" "'yes'" | gzip > "$T/inbox/site-db.sql.gz"
}
printf '["akismet/akismet.php","wordfence/wordfence.php","wps-hide-login/wps-hide-login.php","limit-login-attempts-reloaded/limit-login-attempts-reloaded.php"]' > "$T/active.json"

echo ""
echo "── the files alone, then the database"
_reset; _mk
o=$(_imp extract site-files.tar.gz); rc=$?
ID=$(_latest); S="$T/staging/$ID"
[ "$rc" = 0 ] && printf '%s' "$o" | grep -q 'No database dump in this archive' && printf '%s' "$o" | grep -q "wp-import.sh add-db ${ID} <dump.sql.gz>" \
  && _p "a files-only archive: said, with the add-db command for this set" || _f "files only" "rc=$rc $o"
for p in wordfence wps-hide-login limit-login-attempts-reloaded; do
  [ -d "$S/withheld/plugins/$p" ] && [ ! -e "$S/files/public_html/wp-content/plugins/$p" ] && grep -q "^${p}|" "$S/meta/withheld-plugins.txt" \
    && _p "${p}: set aside at extract, with the reason" || _f "withheld $p" "$(ls "$S/files/public_html/wp-content/plugins" "$S/withheld/plugins" 2>&1)"
done
[ -d "$S/files/public_html/wp-content/plugins/akismet" ] && _p "other plugins stay" || _f "akismet" ""
printf '%s' "$o" | grep -q 'Not imported: plugins WASP replaces' && printf '%s' "$o" | grep -q "wordfence .*malware and vulnerability scans, CrowdSec" \
  && printf '%s' "$o" | grep -q 'wps-hide-login .*its own address' && printf '%s' "$o" | grep -q 'limit-login-attempts-reloaded .*login guard and CrowdSec' \
  && _p "and the extract says which, and why WASP covers each" || _f "withheld said" "$o"
o=$(_imp add-db "$ID" site-db.sql.gz); rc=$?
[ "$rc" = 0 ] && [ -f "$S/db/site-db.sql.gz" ] && printf '%s' "$o" | grep -q 'dumped 2026-11-20 10:00:00' \
  && _p "add-db stages the dump, and says when it was dumped" || _f "add-db" "rc=$rc $o"
grep -qx "$T/inbox/site-db.sql.gz" "$S/meta/sources.txt" && _p "the dump is recorded as a source of the set (clean-up removes it)" || _f "sources" "$(cat "$S/meta/sources.txt")"
o=$(printf 'IMPORT\n' | _imp apply "$ID"); rc=$?
[ "$rc" = 1 ] && printf '%s' "$o" | grep -q 'database dump was added after this set was scanned' && [ ! -s "$T/sql-in" ] \
  && _p "apply refuses until the set is scanned again" || _f "rescan gate" "rc=$rc $o"
o=$(_imp scan "$ID"); rc=$?
printf '%s' "$o" | grep -q 'Not imported, so not scanned: wordfence wps-hide-login limit-login-attempts-reloaded' \
  && printf '%s' "$o" | grep -q 'site-db.sql.gz' && _p "the scan reads the added dump and names what it does not scan" || _f "scan" "rc=$rc $o"
o=$(printf 'IMPORT\n' | _imp apply "$ID"); rc=$?
grep -q 'NEW DUMP' "$T/sql-in" 2>/dev/null && _p "apply loads the separate dump" || _f "apply db" "rc=$rc $(printf '%s' "$o" | tail -6)"
[ -f "$T/html/wp-content/plugins/akismet/akismet.php" ] && [ ! -e "$T/html/wp-content/plugins/wordfence" ] \
  && [ ! -e "$T/html/wp-content/plugins/wps-hide-login" ] && [ ! -e "$T/html/wp-content/plugins/limit-login-attempts-reloaded" ] \
  && _p "the withheld plugins never reach the site" || _f "copied" "$(ls "$T/html/wp-content/plugins")"
grep -q 'option update active_plugins \["akismet/akismet.php"\]' "$T/ap-updates" 2>/dev/null \
  && _p "and are taken out of the imported active_plugins" || _f "active_plugins" "$(cat "$T/ap-updates" 2>/dev/null) :: $o"
grep -q 'DROP TABLE IF EXISTS .*`wp_wfhits`.*`wp_wfconfig`\|DROP TABLE IF EXISTS .*`wp_wfconfig`.*`wp_wfhits`' "$T/sql-in" \
  && ! grep -q 'DROP TABLE IF EXISTS .*%' "$T/sql-in" && _p "Wordfence's tables dropped, by name" || _f "wf tables" "$(grep DROP "$T/sql-in")"

echo ""
echo "── both at once"
_reset; _mk
o=$(printf 'IMPORT\n' | _imp restore site-files.tar.gz --db site-db.sql.gz); rc=$?
[ "$rc" = 0 ] && grep -q 'NEW DUMP' "$T/sql-in" && [ -f "$T/html/wp-content/themes/astra/style.css" ] \
  && _p "restore <files> --db <dump> imports both" || _f "restore --db" "rc=$rc $(printf '%s' "$o" | tail -8)"
[ -z "$(ls -A "$T/inbox")" ] && _p "and both files leave the inbox afterwards" || _f "inbox" "$(ls "$T/inbox")"
_reset; _mk
o=$(printf 'IMPORT\n' | _imp restore); rc=$?
[ "$rc" = 0 ] && printf '%s' "$o" | grep -q "site-files.tar.gz (the site's files) and site-db.sql.gz (its database)" && grep -q 'NEW DUMP' "$T/sql-in" \
  && _p "restore with just those two in the inbox pairs them, and says so" || _f "pair" "rc=$rc $(printf '%s' "$o" | head -8)"
_reset; _mk with-own-dump
o=$(_imp extract site-files.tar.gz --db site-db.sql.gz); rc=$?
S="$T/staging/$(_latest)"
[ "$rc" = 0 ] && [ "$(ls "$S/db")" = site-db.sql.gz ] && [ -f "$S/meta/archive-dumps/old-backup.sql" ] \
  && printf '%s' "$o" | grep -q "archive's own dump set aside, not used: old-backup.sql" && ! printf '%s' "$o" | grep -q 'database dumps found' \
  && _p "an archive's own dump is set aside for the one named with --db" || _f "own dump" "rc=$rc $(ls "$S/db") $o"

echo ""
echo "── what is refused"
_reset; _mk; cp "$T/inbox/site-files.tar.gz" "$T/inbox/second.tar.gz"
o=$(_imp restore </dev/null); rc=$?
[ "$rc" = 1 ] && [ "$(_staged)" = 0 ] && printf '%s' "$o" | grep -q 'More than one backup' && printf '%s' "$o" | grep -q -- '--db <dump.sql.gz>' \
  && _p "two archives and a dump: no guess, and the --db form shown" || _f "ambiguous" "rc=$rc $o"
_reset; _mk
o=$(_imp extract site-files.tar.gz --db site-files.tar.gz); rc=$?
[ "$rc" = 1 ] && [ "$(_staged)" = 0 ] && printf '%s' "$o" | grep -q 'is a tar archive, not a database dump' \
  && _p "a tar given as the dump: refused, nothing staged" || _f "tar as dump" "rc=$rc $o"
printf 'just some text\n' | gzip > "$T/inbox/notes.sql.gz"
o=$(_imp extract site-files.tar.gz --db notes.sql.gz); rc=$?
[ "$rc" = 1 ] && [ "$(_staged)" = 0 ] && printf '%s' "$o" | grep -q 'does not read as a SQL dump' \
  && _p "a gzip that is not SQL: refused, nothing staged" || _f "not sql" "rc=$rc $o"
o=$(_imp extract site-files.tar.gz --db nope.sql.gz); rc=$?
[ "$rc" = 1 ] && [ "$(_staged)" = 0 ] && printf '%s' "$o" | grep -q 'Database dump not found: nope.sql.gz' \
  && _p "a dump that is not there: refused before extracting" || _f "missing" "rc=$rc $o"
o=$(_imp add-db no-such-set site-db.sql.gz); rc=$?
[ "$rc" = 1 ] && _p "add-db to a set that does not exist: refused" || _f "add-db none" "rc=$rc $o"

_reset; _mk
o=$(_imp extract site-db.sql.gz); rc=$?
S="$T/staging/$(_latest)"
[ "$rc" = 0 ] && [ -f "$S/db/site-db.sql.gz" ] && printf '%s' "$o" | grep -q 'Gzip input treated as a database dump' \
  && _p "a small dump on its own is a dump (GNU tar listed it as an empty archive)" || _f "lone dump" "rc=$rc $o"

echo ""
echo "── keeping one"
_reset; _mk
o=$(_imp extract site-files.tar.gz --keep-plugin wordfence); rc=$?
S="$T/staging/$(_latest)"
[ -d "$S/files/public_html/wp-content/plugins/wordfence" ] && ! grep -q '^wordfence|' "$S/meta/withheld-plugins.txt" \
  && [ -d "$S/withheld/plugins/wps-hide-login" ] && printf '%s' "$o" | grep -q 'Kept as asked (--keep-plugin): wordfence' \
  && _p "--keep-plugin wordfence imports it; the others are still set aside" || _f "keep" "rc=$rc $o"
o=$(_imp restore site-files.tar.gz --keep-plugin 'x;rm'); rc=$?
[ "$rc" = 1 ] && printf '%s' "$o" | grep -q 'Not a plugin slug' && _p "a --keep-plugin that is not a slug: refused" || _f "slug" "rc=$rc $o"

echo ""
printf '  passed %d   failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
