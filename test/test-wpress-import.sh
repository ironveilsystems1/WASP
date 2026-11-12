#!/usr/bin/env bash
# =============================================================================
# test-wpress-import.sh — the .wpress path through the real wp-import.sh
# =============================================================================
#
# test-wpress-reader.php proves the parser. This proves the wiring, which is
# where this feature can fail without anything reporting it. A .wpress dump is
# not a normal dump: its tables are named SERVMASK_PREFIX_*, and its theme and
# active plugins are blank. Handled wrongly, the option-row scan matches nothing
# and says "No code in option rows", and the import reports success on a site
# with no theme. Each of those is a passing run of a broken pipeline, so these
# assert on what reached the database and wp-cli, not on the exit status alone.
#
# The script under test is a copy with its fixed paths moved into a temp tree.
# podman is a stub: `run ... php` runs the real reader with the real mounts
# substituted, `exec mariadb` records the SQL, and `wp` is recorded. So the
# container's isolation flags are asserted as text; they are NOT exercised here.
# =============================================================================
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
command -v php >/dev/null 2>&1 || { echo "  SKIPPED — php not installed"; exit 0; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
_p() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
_f() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n         %s\n' "$1" "${2:-}"; }

mkdir -p "$T/bin" "$T/inbox" "$T/staging" "$T/html/wp-content" "$T/etc" "$T/log"
: > "$T/log/wp"; : > "$T/log/sql"; : > "$T/log/podman"

cat > "$T/bin/podman" <<STUB
#!/usr/bin/env bash
echo "\$*" >> "$T/log/podman"
case "\$1" in
  exec)
    case "\$*" in
      *WORDPRESS_TABLE_PREFIX*) printf 'wp_' ;;
      *stranded*|*-N\ -B*) cat >> "$T/log/sql"; echo 'stranded-remaining:0' ;;
      *) cat >> "$T/log/sql" ;;
    esac ;;
  run)
    if printf '%s' "\$*" | grep -q 'reader.php'; then
      shift; a=""; o=""; r=""; args=()
      while [ \$# -gt 0 ]; do
        case "\$1" in
          -v) case "\$2" in
                *:/wasp/reader.php:ro) r="\${2%%:*}" ;;
                *:/wasp/archive.wpress:ro) a="\${2%%:*}" ;;
                *:/wasp/out/files) o="\${2%%:*}"; o="\${o%/files}" ;;
              esac; shift ;;
          /wasp/reader.php) shift; for x in "\$@"; do
              x="\${x//\/wasp\/archive.wpress/\$a}"; x="\${x//\/wasp\/out/\$o}"; args+=("\$x"); done
            exec php "\$r" "\${args[@]}" ;;
        esac
        shift
      done
    fi
    printf '%s\n' "\$*" | sed 's/.* wp --path=[^ ]* //' >> "$T/log/wp"
    case "\$*" in *'plugin is-active two-factor'*) exit "\${WP_MFA_FAIL:-0}" ;; esac ;;
esac
exit 0
STUB
for s in chown stty; do printf '#!/bin/sh\nexit 0\n' > "$T/bin/$s"; done
printf '#!/bin/sh\nexit 0\n' > "$T/wp-db-backup.sh"
cat > "$T/wp-plugins.sh" <<STUB
#!/bin/sh
cp "\$3" "$T/log/inventory"
if grep -q '^plugin,oldplug,' "\$3"; then
  echo '  Sources: test'
  echo '  [HIGH] oldplug 1.2.3'
  echo '        Stored XSS'
fi
exit \${VULN_RC:-0}
STUB
chmod +x "$T/bin/"* "$T/wp-db-backup.sh" "$T/wp-plugins.sh"

cat > "$T/etc/vars.sh" <<VARS
MFA_ENFORCE=1
WP_DOMAIN=new.example
WP_SCHEME=https
VARS
: > "$T/etc/pinned.env"

sed -e 's#^  if command -v doas.*##' \
    -e '/^if \[ "\$(id -u)" -ne 0 \]; then$/,/^fi$/d' \
    -e "s#/etc/wp-install/vars.sh#$T/etc/vars.sh#g" \
    -e "s#/etc/wp-install/pinned.env#$T/etc/pinned.env#g" \
    -e "s#^INBOX=.*#INBOX=$T/inbox#" \
    -e "s#^STAGING=.*#STAGING=$T/staging#" \
    -e "s#^WP_ROOT=.*#WP_ROOT=$T/html#" \
    -e "s#^WPRESS_READER=.*#WPRESS_READER=$REPO/payload/lib/wasp-wpress-reader.php#" \
    -e "s#/usr/local/bin/wp-db-backup.sh#$T/wp-db-backup.sh#g" \
    -e "s#/usr/local/bin/wp-plugins.sh#$T/wp-plugins.sh#g" \
    "$REPO/payload/bin/wp-import.sh" > "$T/wp-import.sh"
_imp() { PATH="$T/bin:${WASP_TEST_TOOLS:+$WASP_TEST_TOOLS:}$PATH" ${WASP_TEST_SH:-sh} "$T/wp-import.sh" "$@"; }

cat > "$T/make.php" <<'PHP'
<?php
function e($p,$c){$d=dirname($p);return pack('a255a14a12a4088a8',basename($p),(string)strlen($c),'1700000000',$d,hash('crc32b',$c)).$c;}
function seal($b){return $b.pack('a255a14a4100a8','',(string)strlen($b),'',hash('crc32b',$b));}
$pkg=json_encode(['SiteURL'=>'https://old.example','HomeURL'=>'https://old.example','Plugin'=>['Version'=>'7.112'],
 'WordPress'=>['Version'=>'6.8.3'],'Database'=>['Prefix'=>'abc_'],'Plugins'=>['kept/kept.php'],'Template'=>'parent','Stylesheet'=>'child']);
$rows="INSERT INTO `SERVMASK_PREFIX_options` VALUES (1,'siteurl','https://old.example','yes');\n"
     ."INSERT INTO `SERVMASK_PREFIX_usermeta` VALUES (1,1,'SERVMASK_PREFIX_capabilities','a:0:{}');\n";
$bad =$rows."INSERT INTO `SERVMASK_PREFIX_options` VALUES (9,'x','<?php eval(base64_decode(\$_POST[1]));','yes');\n";
$files=e('package.json',$pkg).e('plugins/kept/kept.php','<?php').e('plugins/kept/schema.sql','CREATE TABLE y;')
      .e('themes/parent/style.css','/**/').e('themes/child/style.css','/**/').e('uploads/2024/a.jpg','jpeg')
      .e('mu-plugins/evil.php','<?php');
file_put_contents($argv[1].'/clean.wpress',seal($files.e('database.sql',$rows)));
file_put_contents($argv[1].'/dbbad.wpress',seal($files.e('database.sql',$bad)));
file_put_contents($argv[1].'/oldplug.wpress',seal($files.e('database.sql',$rows)
  .e('plugins/oldplug/oldplug.php',"<?php\n/**\n * Plugin Name: Old\n * Version: 1.2.3\n */\nfile_put_contents('/tmp/wasp-ran','x');\n")
  .e('plugins/nohdr/lib.php','<?php')
  .e('themes/oldtheme/style.css',"/*\nTheme Name: Old\nVersion: 9.8\n*/\n")));
file_put_contents($argv[1].'/shell.wpress',seal($files.e('database.sql',$rows).e('uploads/x.php','<?php system($_GET[1]);')));
file_put_contents($argv[1].'/hostile.wpress',seal($files.e('database.sql',$rows).pack('a255a14a12a4088a8','x.php','1','1','../../etc','').'y'));
PHP
php "$T/make.php" "$T/inbox"

echo ""
echo ".wpress through wp-import.sh"
echo ""
echo "── inspect"
_o=$(_imp inspect clean.wpress 2>&1); _rc=$?
[ "$_rc" = 0 ] && _p "a clean archive inspects" || _f "clean inspect" "exit $_rc: $_o"
printf '%s' "$_o" | grep -q 'https://old.example' && _p "the source site is shown" || _f "source site" "$_o"
printf '%s' "$_o" | grep -q 'must-use plugin' \
  && _p "the existing mu-plugin warning fires on a .wpress listing" || _f "mu-plugin warning" "$_o"
_o=$(_imp inspect shell.wpress 2>&1); _rc=$?
{ [ "$_rc" = 1 ] && printf '%s' "$_o" | grep -q 'PHP file(s) inside uploads'; } \
  && _p "PHP in uploads is flagged, as for any format" || _f "uploads php" "exit $_rc"
_imp inspect hostile.wpress >/dev/null 2>&1; [ $? = 2 ] \
  && _p "a hostile archive refuses at inspect" || _f "hostile inspect" ""

echo ""
echo "── extract"
_imp extract hostile.wpress >/dev/null 2>&1; _rc=$?
_left=$(find "$T/staging" -mindepth 1 -maxdepth 1 -type d | wc -l)
{ [ "$_rc" = 2 ] && [ "$_left" = 0 ]; } && _p "a hostile archive leaves no staging directory" \
  || _f "hostile extract" "exit $_rc, $_left dir(s)"

_imp extract clean.wpress >/dev/null 2>&1; _rc=$?
_st="$T/staging/$(cat "$T/staging/.latest")"
[ "$_rc" = 0 ] && _p "a clean archive extracts" || _f "extract" "exit $_rc"
[ -f "$_st/files/wp-content/uploads/2024/a.jpg" ] \
  && _p "the archive root becomes wp-content, so apply finds the site" || _f "site root" ""
[ "$(ls "$_st/db")" = "database.sql" ] \
  && _p "exactly one dump: a plugin's schema.sql stays in the plugin" || _f "dumps" "$(ls "$_st/db")"
grep -q 'SERVMASK_PREFIX_' "$_st/db/database.sql" \
  && _f "placeholder prefix" "still in the dump" || _p "the placeholder prefix is gone from the dump"
grep -q 'abc_capabilities' "$_st/db/database.sql" \
  && _p "user meta keys are restored, not only table names" || _f "meta keys" ""

echo ""
echo "── scan"
sleep 1
_imp extract dbbad.wpress >/dev/null 2>&1
_o=$(_imp scan 2>&1); _rc=$?
{ [ "$_rc" = 2 ] && printf '%s' "$_o" | grep -q 'option row(s) contain code'; } \
  && _p "code in an option row is found through the converted prefix" \
  || _f "option scan" "exit $_rc: $_o"
printf '%s' "$_o" | grep -q 'No code in option rows' \
  && _f "option scan" "reported clean" || _p "it does not report clean on the same run"

sleep 1
_imp extract oldplug.wpress >/dev/null 2>&1
_id=$(cat "$T/staging/.latest")
_o=$(_imp scan "$_id" 2>&1); _rc=$?
grep -qx 'plugin,oldplug,1.2.3' "$T/log/inventory" 2>/dev/null \
  && _p "a staged plugin's version is read from its header" || _f "plugin version" "$(cat "$T/log/inventory" 2>/dev/null)"
grep -qx 'theme,oldtheme,9.8' "$T/log/inventory" \
  && _p "and a staged theme's from style.css" || _f "theme version" ""
[ -e /tmp/wasp-ran ] && _f "staged code" "it ran" || _p "no staged code was executed to read them"
{ [ "$_rc" = 1 ] && printf '%s' "$_o" | grep -q 'high 1'; } \
  && _p "a HIGH vulnerability reaches the gate before import" || _f "gate" "exit $_rc: $_o"
_o=$(VULN_RC=3 _imp scan "$_id" 2>&1)
printf '%s' "$_o" | grep -q 'NOT fully checked' \
  && _p "an incomplete check says so at the verdict" || _f "incomplete" "$_o"

echo ""
echo "── apply"
sleep 1   # staging ids have one-second resolution
_imp extract clean.wpress >/dev/null 2>&1 || _f "re-extract" "exit $?"
_id=$(cat "$T/staging/.latest"); _imp scan "$_id" >/dev/null 2>&1
: > "$T/log/wp"; : > "$T/log/sql"
# --keep-files: the archive is extracted again below. (A plain apply deletes
# it once the site is live; test-updraft-import.sh covers that.)
_o=$(printf 'IMPORT\n' | _imp apply "$_id" --keep-files 2>&1); _rc=$?
[ "$_rc" = 0 ] && _p "apply completes" || _f "apply" "exit $_rc: $_o"
[ -f "$T/inbox/clean.wpress" ] && _p "--keep-files keeps the archive" || _f "--keep-files" "archive removed"
grep -q 'wp_options' "$T/log/sql" && _p "tables reach this VM's prefix" || _f "table prefix" "$(head -3 "$T/log/sql")"
# abc_ -> wp_. LIKE treats "_" as a wildcard, so "abc_%" also matched keys
# already carrying this VM's prefix whenever its 4th character differed only
# there; a second apply then mangled them. Exact LEFT() comparison only.
grep -qF 'WHERE LEFT(option_name, 4) = 0x6162635f' "$T/log/sql" \
  && grep -qF 'WHERE LEFT(meta_key, 4) = 0x6162635f' "$T/log/sql" \
  && _p "prefix keys are matched exactly, with no LIKE wildcard" || _f "prefix predicate" "$(grep -i stranded "$T/log/sql")"
grep -q 'LIKE 0x' "$T/log/sql" && _f "prefix predicate" "a LIKE pattern is still sent" || _p "no LIKE pattern reaches the prefix fix"
grep -q 'option update template parent ' "$T/log/wp" && _p "the theme is restored" || _f "template" "$(cat "$T/log/wp")"
grep -q 'option update stylesheet child ' "$T/log/wp" && _p "the child theme is restored" || _f "stylesheet" ""
grep -qF 'option update active_plugins ["kept/kept.php"] --format=json' "$T/log/wp" \
  && _p "active plugins are restored as data" || _f "plugins" "$(cat "$T/log/wp")"
grep -q 'search-replace https://old.example https://new.example' "$T/log/wp" \
  && _p "the old address is rewritten through the database" || _f "search-replace" ""
grep -qF 'search-replace https:\/\/old.example https:\/\/new.example' "$T/log/wp" \
  && _p "and in JSON-escaped builder data" || _f "escaped search-replace" ""
grep -q 'search-replace http://old.example' "$T/log/wp" \
  && _p "and its http form" || _f "http form" ""
grep -q 'plugin activate two-factor' "$T/log/wp" \
  && _p "Two Factor is reactivated after the import" || _f "two-factor" ""
[ -f "$T/html/wp-content/uploads/2024/a.jpg" ] && _p "uploads are in place" || _f "uploads" ""
[ -e "$T/html/wp-content/mu-plugins/evil.php" ] \
  && _f "mu-plugins" "imported" || _p "mu-plugins from the archive are withheld"
grep -E 'option update (template|stylesheet|active_plugins)' "$T/log/wp" | grep -qv -- '--skip-plugins' \
  && _f "skip-plugins" "archive-derived values ran with plugins loaded" \
  || _p "archive-derived values are written with plugins not loaded"

sleep 1
_imp extract clean.wpress >/dev/null 2>&1 || _f "re-extract" "exit $?"
_id=$(cat "$T/staging/.latest"); _imp scan "$_id" >/dev/null 2>&1
_o=$(printf 'IMPORT\n' | WP_MFA_FAIL=1 _imp apply "$_id" 2>&1); _rc=$?
{ [ "$_rc" = 1 ] && printf '%s' "$_o" | grep -q 'MFA NOT ACTIVE'; } \
  && _p "an import that leaves MFA inactive does not report success" || _f "mfa gate" "exit $_rc"
[ ! -e "$T/inbox/clean.wpress" ] && [ ! -d "$T/staging/$_id/files" ] \
  && _p "a plain apply removes the archive and the staging copy" || _f "clean-up after apply" "$(ls "$T/inbox")"

echo ""
echo "── the reader's container"
_r=$(grep -E 'reader.php' "$T/log/podman" | head -1)
for _flag in '--network none' '--read-only' '--cap-drop ALL' 'no-new-privileges' '--user 33:33'; do
  case "$_r" in *"$_flag"*) _p "runs with ${_flag}" ;; *) _f "container flag" "$_flag missing" ;; esac
done

echo ""
printf '  passed %d   failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
