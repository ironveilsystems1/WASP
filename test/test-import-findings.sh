#!/usr/bin/env bash
# =============================================================================
# test-import-findings.sh — what inspect and scan say about a real-shaped site
# =============================================================================
#
# The first import of a real compromised site (10.10 field test) produced two
# false alarms at maximum confidence and missed the one piece of malware:
#
#   - six "<?php // Silence is golden." guards in uploads reported as "the
#     single strongest indicator that the source site was compromised";
#   - Composer's .../Installers/Installer.php reported as Duplicator;
#   - mu-plugins/<name>.php.bak (the real injector, disarmed by renaming)
#     reported as an mu-plugin "active on arrival", next to a count that
#     included the directory entry;
#   - scan printed "[ok] No PHP files in wp-content/uploads" because it was
#     pointed at the top of a nested cPanel tree and never found wp-content.
#
# This builds an archive with the same shape, and a second one with the true
# positives each fix must not lose: a real Duplicator package, a webshell in
# uploads, and a webshell NAMED index.php. Every assertion here fails against
# 10.10 except one, which guards behaviour 10.10 already had right
# (Duplicator's installer is still removed at extract).
#
# The scanner under test is the real wp-malware-scan.sh with its fixed paths
# moved into a temp tree. YARA is not required: these are structural checks.
# =============================================================================
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
_p() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
_f() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n         %s\n' "$1" "${2:-}"; }

mkdir -p "$T/bin" "$T/inbox" "$T/staging" "$T/html/wp-content" "$T/etc" "$T/log" "$T/scan-state" "$T/quar"
for s in chown stty; do printf '#!/bin/sh\nexit 0\n' > "$T/bin/$s"; done
cat > "$T/bin/podman" <<'STUB'
#!/bin/sh
case "$*" in
  *WORDPRESS_TABLE_PREFIX*) printf 'wp_' ;;
  *stranded*|*'-N -B'*) cat >/dev/null; echo 'stranded-remaining:0' ;;
  *'ps '*) echo wordpress ;;
  *) [ -t 0 ] || cat >/dev/null ;;
esac
exit 0
STUB
printf '#!/bin/sh\nexit 0\n' > "$T/wp-db-backup.sh"
printf '#!/bin/sh\nexit 0\n' > "$T/wp-plugins.sh"
chmod +x "$T/bin/"* "$T/wp-db-backup.sh" "$T/wp-plugins.sh"
printf 'WP_DOMAIN=new.example\nWP_SCHEME=https\n' > "$T/etc/vars.sh"
: > "$T/etc/pinned.env"

_noroot='/^if \[ "\$(id -u)" -ne 0 \]; then$/,/^fi$/d'
sed -e "$_noroot" \
    -e "s#/etc/wp-install/vars.sh#$T/etc/vars.sh#g" \
    -e "s#/etc/wp-install/pinned.env#$T/etc/pinned.env#g" \
    -e "s#^QUARANTINE=.*#QUARANTINE=$T/quar#" \
    -e "s#^STATE=.*#STATE=$T/scan-state#" \
    -e "s#/usr/local/bin/wp-plugins.sh#$T/wp-plugins.sh#g" \
    -e "s#/usr/local/bin/wp-forensics.sh#$T/nope#g" -e "s#/usr/local/bin/wp-notify.sh#$T/nope#g" \
    "$REPO/payload/bin/wp-malware-scan.sh" > "$T/wp-malware-scan.sh"
chmod +x "$T/wp-malware-scan.sh"
sed -e 's#^  if command -v doas.*##' \
    -e "$_noroot" \
    -e "s#/etc/wp-install/vars.sh#$T/etc/vars.sh#g" \
    -e "s#/etc/wp-install/pinned.env#$T/etc/pinned.env#g" \
    -e "s#^INBOX=.*#INBOX=$T/inbox#" \
    -e "s#^STAGING=.*#STAGING=$T/staging#" \
    -e "s#^WP_ROOT=.*#WP_ROOT=$T/html#" \
    -e "s#/usr/local/bin/wp-malware-scan.sh#$T/wp-malware-scan.sh#g" \
    -e "s#/usr/local/bin/wp-db-backup.sh#$T/wp-db-backup.sh#g" \
    -e "s#/usr/local/bin/wp-plugins.sh#$T/wp-plugins.sh#g" \
    -e "s#^THREATS=.*#THREATS=$REPO/payload/bin/wasp-threats.sh#" \
    "$REPO/payload/bin/wp-import.sh" > "$T/wp-import.sh"
export THREATS="$REPO/payload/bin/wasp-threats.sh"
_run() { PATH="$T/bin:${WASP_TEST_TOOLS:+$WASP_TEST_TOOLS:}$PATH" ${WASP_TEST_SH:-sh} "$@"; }
_imp() { _run "$T/wp-import.sh" "$@"; }

# ── Fixture 1: a cPanel home directory holding a site, as in the field test ──
B="$T/build1/acct"; S="$B/public_html"
mkdir -p "$S/wp-includes" "$S/wp-content/mu-plugins" "$S/wp-content/updraft" \
         "$S/wp-content/plugins/jobs/includes" \
         "$S/wp-content/plugins/jobs/vendor/composer/installers/src/Composer/Installers"
printf '<?php $wp_version = "6.8.3";\n' > "$S/wp-includes/version.php"
printf '<?php\n' > "$S/wp-config.php"
printf '<?php\n' > "$S/wp-content/plugins/jobs/jobs.php"
printf '<?php // the plugin\x27s own setup\n' > "$S/wp-content/plugins/jobs/includes/installer.php"
for c in Installer BaseInstaller WordPressInstaller; do
  printf '<?php class %s {}\n' "$c" \
    > "$S/wp-content/plugins/jobs/vendor/composer/installers/src/Composer/Installers/${c}.php"
done
for d in a b c d e f; do
  mkdir -p "$S/wp-content/uploads/jobs/$d"
  printf '<?php\n\n//Silence is golden.\n' > "$S/wp-content/uploads/jobs/$d/index.php"
done
printf 'GIF89a' > "$S/wp-content/uploads/jobs/a/logo.gif"
python3 - "$S/wp-content/mu-plugins/_x7Qe2k.php.bak" <<'PY'
import sys
e = lambda w: ''.join('\\x%02x' % ord(c) for c in w)
L = ['<?php', '/** Loads the WordPress environment and template. */', 'function P0x($f, ...$a) { return $f(...$a); }']
L += ['$t[] = P0x("%s", "inert");' % e(w) for w in ['strtoupper', 'strrev', 'md5', 'crc32', 'ucfirst', 'trim'] * 4]
open(sys.argv[1], 'w').write('\n'.join(L) + '\n')
PY
printf '<?php echo 1;\n' > "$S/wp-content/plugins/jobs/includes/old.php.suspected"
cat > "$S/wp-content/updraft/backup_db.sql" <<'SQL'
CREATE TABLE `wp_usermeta` (x int);
INSERT INTO `wp_options` VALUES (1,'siteurl','https://old.example','yes');
INSERT INTO `wp_users` VALUES (1,'owner','$P$a','owner','owner@example.com','','2020-12-04 15:22:01','',0,'Owner'),(3,'wpadminqxtvb','$P$b','wpadminqxtvb','wpadmin@example.ru','','2020-06-14 00:00:00','',0,'wpadminqxtvb');
INSERT INTO `wp_usermeta` VALUES (1,1,'wp_capabilities','a:1:{s:13:\"administrator\";b:1;}'),(9,3,'wp_capabilities','a:0:{}');
SQL
mkdir -p "$B/.trash"
printf 'ls\nwp plugin deactivate wordfence\nmv wp-content/mu-plugins/_x7Qe2k.php wp-content/mu-plugins/_x7Qe2k.php.bak\ncd /tmp\n' > "$B/.bash_history"
( cd "$T/build1" && tar -czf "$T/inbox/cpanel.tar.gz" acct )

# ── Fixture 2: the true positives ────────────────────────────────────────────
S2="$T/build2/site"
mkdir -p "$S2/wp-includes" "$S2/wp-content/uploads/2024/05" "$S2/wp-content/mu-plugins"
printf '<?php\n' > "$S2/wp-includes/version.php"
printf '<?php /* Duplicator installer */\n' > "$S2/installer.php"
printf 'PK' > "$S2/mysite_8a1f_20240101_archive.zip"
printf '<?php system($_GET[1]);\n' > "$S2/wp-content/uploads/2024/05/x.php"
printf '<?php\n//Silence is golden.\n@eval($_POST[1]);\n' > "$S2/wp-content/uploads/2024/index.php"
printf '<?php\n' > "$S2/wp-content/mu-plugins/loader.php"
( cd "$T/build2" && tar -czf "$T/inbox/positives.tar.gz" site )

echo ""
echo "Import findings on a real-shaped archive"
echo ""
echo "── inspect: the field-test shapes"
_o=$(_imp inspect cpanel.tar.gz 2>&1); _rc=$?
printf '%s' "$_o" | grep -q 'Duplicator' \
  && _f "Composer installers and a plugin's installer.php reported as Duplicator" "$(printf '%s' "$_o" | grep Duplicator)" \
  || _p "Composer's Installer.php and a plugin's installer.php are not Duplicator"
printf '%s' "$_o" | grep -q 'executable PHP file(s) inside uploads' \
  && _f "index guards reported as executable PHP in uploads" "" \
  || _p "directory-index guards are not reported as executable PHP"
printf '%s' "$_o" | grep -q 'beyond 6 directory-index guard(s)' \
  && _p "the six guards are counted and deferred to scan" || _f "guard count" "$_o"
printf '%s' "$_o" | grep -q 'renamed so they no longer run' \
  && printf '%s' "$_o" | grep -q '_x7Qe2k\.php\.bak' \
  && _p "the renamed injector is reported, by name" || _f "renamed PHP" "$_o"
printf '%s' "$_o" | grep -q 'on arrival' \
  && _f "a .php.bak described as loading on arrival" "$(printf '%s' "$_o" | grep 'on arrival')" \
  || _p "a .php.bak is not described as loading on arrival"
printf '%s' "$_o" | grep -q '1 other file(s) in mu-plugins' \
  && _p "mu-plugins counts its one file, not the directory entry too" || _f "mu-plugins count" "$_o"

printf '%s' "$_o" | grep -q 'Format : tar.gz, cPanel account export' \
  && _p "a cPanel account export is named, not 'unknown'" || _f "cPanel" "$(printf '%s' "$_o" | grep Format)"
printf '%s' "$_o" | grep -q 'Shell history is included' && _p "and its shell history is pointed out" || _f "history" ""

echo ""
echo "── inspect: the true positives still fire"
_o=$(_imp inspect positives.tar.gz 2>&1)
printf '%s' "$_o" | grep -q 'Duplicator package' \
  && _p "installer.php beside its archive.zip is Duplicator" || _f "duplicator" "$_o"
printf '%s' "$_o" | grep -q '1 executable PHP file(s) inside uploads' \
  && _p "a webshell in uploads is still the strongest finding" || _f "uploads webshell" "$_o"
printf '%s' "$_o" | grep -q '1 must-use plugin(s) would load on arrival' \
  && _p "a live mu-plugin is still reported as loading on arrival" || _f "live mu-plugin" "$_o"

echo ""
echo "── extract"
_o=$(_imp extract cpanel.tar.gz 2>&1) || _f "extract" "exit $?"
printf '%s' "$_o" | grep -q 'mv wp-content/mu-plugins/_x7Qe2k.php wp-content/mu-plugins/_x7Qe2k.php.bak' \
  && _p "extract prints the history lines that touched WordPress" || _f "history lines" "$_o"
printf '%s' "$_o" | grep -qE '^ *[0-9]+:(ls|cd /tmp)$' && _f "history" "printed unrelated lines" || _p "and only those"
_id1=$(cat "$T/staging/.latest"); _st="$T/staging/$_id1"
[ -f "$_st/files/acct/public_html/wp-content/plugins/jobs/includes/installer.php" ] \
  && _p "a plugin's own installer.php survives extract" || _f "plugin installer.php" "deleted"
sleep 1
_imp extract positives.tar.gz >/dev/null 2>&1 || _f "extract positives" "exit $?"
_id2=$(cat "$T/staging/.latest")
[ -e "$T/staging/$_id2/files/site/installer.php" ] \
  && _f "Duplicator installer" "still staged" || _p "Duplicator's installer.php is removed at extract"

echo ""
echo "── scan: pointed at the site root, guards decided by content"
_o=$(_imp scan "$_id1" 2>&1)
printf '%s' "$_o" | grep -q 'Site root: files/acct/public_html' \
  && _p "scan finds the nested site root" || _f "scan root" "$_o"
printf '%s' "$_o" | grep -q 'beyond 6 directory-index guard(s)' \
  && _p "the scanner itself saw the six guards and cleared them by content" || _f "scan guards" "$_o"
printf '%s' "$_o" | grep -qE 'No wp-content under|No PHP files in wp-content/uploads' \
  && _f "scan reported uploads without finding them" "$(printf '%s' "$_o" | grep -E 'No wp-content|No PHP files')" \
  || _p "scan does not call uploads clean without having looked"
printf '%s' "$_o" | grep -q 'Account looks planted: wpadminqxtvb <wpadmin@example.ru> id 3' \
  && _p "scan names the planted account from the dump, without loading it" || _f "planted" "$(printf '%s' "$_o" | grep -A3 'account(s)')"
printf '%s' "$_o" | grep -q 'id 1 .*owner' && _p "and lists the administrators by name" || _f "admins" ""
printf '%s' "$_o" | grep -q 'CRITICAL.*Obfuscated PHP.*_x7Qe2k.php.bak' && _p "scan reports the obfuscated injector CRITICAL" || _f "obf" ""
_o=$(_imp scan "$_id2" 2>&1)
printf '%s' "$_o" | grep -q 'CRITICAL.*uploads/2024/05/x.php' \
  && _p "a webshell in uploads is CRITICAL at scan" || _f "scan webshell" "$_o"
printf '%s' "$_o" | grep -q 'CRITICAL.*uploads/2024/index.php' \
  && _p "an index.php that is not a guard is CRITICAL — the name buys nothing" || _f "index.php webshell" "$_o"

echo ""
echo "── apply keeps what the scan named out of the site"
_o=$(printf 'IMPORT\n' | _imp apply "$_id1" --force 2>&1)
printf '%s' "$_o" | grep -q 'Kept out: wp-content/plugins/jobs/includes/old.php.suspected' \
  && [ ! -e "$T/html/wp-content/plugins/jobs/includes/old.php.suspected" ] \
  && _p "renamed PHP inside a plugin is kept out of the live site" || _f "renamed kept out" "$(printf '%s' "$_o" | tail -20)"
[ -f "$T/staging/$_id1/quarantined/remediated/wp-content/plugins/jobs/includes/old.php.suspected" ] \
  && _p "and set aside with its path" || _f "set aside" "$(find "$T/staging/$_id1/quarantined" | head)"
[ -f "$T/html/wp-content/plugins/jobs/includes/installer.php" ] && [ -f "$T/html/wp-content/plugins/jobs/jobs.php" ] \
  && _p "while the plugin's own files arrive" || _f "plugin files" ""
grep -q 'remediate=1' "$T/staging/import-log.txt" && _p "the import record says remediation ran" || _f "record" "$(cat "$T/staging/import-log.txt" 2>/dev/null)"

echo ""
echo "── the scanner on its own"
_o=$(_run "$T/wp-malware-scan.sh" --path "$T/staging/$_id1/files" structural 2>&1)
printf '%s' "$_o" | grep -q 'No wp-content under' \
  && _p "pointed at a tree with no wp-content, it says so instead of [ok]" || _f "no wp-content note" "$_o"

echo ""
printf '  passed %d   failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
