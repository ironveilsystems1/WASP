#!/usr/bin/env bash
# =============================================================================
# test-threats.sh — detection and automated remediation of what we have seen
# =============================================================================
#
# The first real compromised import carried: a hex-obfuscated injector
# disarmed as mu-plugins/<x>.php.bak, a planted administrator (wpadmin<random>,
# registered at exactly midnight, dated before the owner although its ID came
# after, role stripped to a:0:{}), and the usual webshell-in-uploads risk.
# This builds those shapes -- inert stand-ins, not malware -- and checks that
#
#   wasp-threats.sh         finds each, and not WordPress's own look-alikes
#   wp-malware-scan.sh      reports each at the right severity
#   ... remediate           plans, changes nothing without --apply, then
#                           quarantines with paths kept, reinstalls modified
#                           plugins, and locks only privileged planted accounts
#   wp-plugins.sh           repair-modified / lock-user do what they say,
#                           and put a plugin back if no clean copy arrives
#
# podman, wp-cli and MariaDB are stubbed; every script under test is the real
# one with its fixed paths moved into a temp tree.
# =============================================================================
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
_p() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
_f() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n         %s\n' "$1" "${2:-}"; }
TH="$REPO/payload/bin/wasp-threats.sh"
_th() { PATH="${WASP_TEST_TOOLS:+$WASP_TEST_TOOLS:}$PATH" ${WASP_TEST_SH:-sh} "$TH" "$@"; }
TAB=$(printf '\t')

# An inert stand-in for the field-test injector: harmless function names
# hidden as \xNN escapes behind a dispatcher, the same shape and density.
_obf() {
  python3 - "$1" <<'PY'
import sys
def esc(w): return ''.join('\\x%02x' % ord(c) for c in w)
L = ['<?php', '/** Loads the WordPress environment and template. */',
     'function P0x($f, ...$a) { return $f(...$a); }']
for w in ['strtoupper','strtolower','str_repeat','ucfirst','strrev','trim','md5','crc32'] * 3:
    L.append('$t[] = P0x("%s", "inert");' % esc(w))
open(sys.argv[1], 'w').write('\n'.join(L) + '\n')
PY
}
# Real code's look-alikes: isolated escapes as separators (WordPress core's
# HTML5 entity table) and a dense-but-legitimate lookup table well under 20%.
_entity_table() {
  { printf '<?php\n$groups = "'
    for i in $(seq 1 400); do printf 'Ab\\x00'; done
    printf '";\n'; } > "$1"
}
_sbox() {
  { printf '<?php\nclass DES {\n'
    for i in $(seq 1 60); do
      printf '  protected $s%s = array(0x%s, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09);\n' "$i" "$i"
      printf '  protected $k%s = "\\x01\\x02\\x03\\x04";\n' "$i"
    done
    printf '}\n'; } > "$1"
}

echo ""
echo "Threat detection and automated remediation"
echo ""
echo "── wasp-threats.sh"
_have=$(cd "$REPO/payload/mu-plugins" && ls *.php | sort | tr '\n' ' ')
_list=$(sed -n 's/^WASP_MU="\(.*\)"$/\1/p' "$TH" | tr ' ' '\n' | sort | tr '\n' ' ')
[ "$_have" = "$_list" ] && _p "its list of WASP mu-plugins matches payload/mu-plugins" || _f "WASP_MU drift" "have: $_have list: $_list"

W="$T/site"; mkdir -p "$W/wp-content/mu-plugins" "$W/wp-content/plugins/good/lib" "$W/wp-content/plugins/odd" \
  "$W/wp-content/themes/t" "$W/wp-content/uploads/2024/05" "$W/wp-content/uploads/jobs/a" "$W/wp-includes"
printf '<?php\n' > "$W/wp-includes/version.php"
_obf "$W/wp-content/mu-plugins/_x7Qe2k.php.bak"
printf '<?php // ours\n' > "$W/wp-content/mu-plugins/01-wpvm-smtp.php"
printf '<?php // a hosting company helper\n' > "$W/wp-content/mu-plugins/host-cache.php"
_obf "$W/wp-content/plugins/odd/vendor-blob.php"
_entity_table "$W/wp-content/plugins/good/entities.php"
_sbox "$W/wp-content/plugins/good/lib/DES.php"
printf '<?php\n' > "$W/wp-content/plugins/good/good.php"
printf '<?php echo 1;\n' > "$W/wp-content/plugins/good/old.php.orig"
printf '<?php\n\n//Silence is golden.\n' > "$W/wp-content/uploads/jobs/a/index.php"
printf '<?php system($_GET[1]);\n' > "$W/wp-content/uploads/2024/05/x.php"
printf 'AddHandler application/x-httpd-php .jpg\n' > "$W/wp-content/uploads/.htaccess"
printf 'GIF89a' > "$W/wp-content/uploads/2024/05/a.gif"
printf 'notes\n' > "$W/wp-content/uploads/2024/05/readme.bak"
printf "<?php define('DB_PASSWORD','x');\n" > "$W/wp-config.php.bak"

_r=$(_th renamed "$W/wp-content")
printf '%s\n' "$_r" | grep -q '_x7Qe2k.php.bak$' && printf '%s\n' "$_r" | grep -q 'old.php.orig$' \
  && _p "renamed: finds .php.bak and .php.orig" || _f "renamed" "$_r"
printf '%s\n' "$_r" | grep -qE 'readme.bak$|good.php$' && _f "renamed" "matched a non-PHP .bak or a live .php" \
  || _p "renamed: not a plain .bak, not a working .php"
_o=$(_th obfuscated "$W/wp-content")
printf '%s\n' "$_o" | grep -q '_x7Qe2k.php.bak$' && _p "obfuscated: finds the injector shape, renamed or not" || _f "obfuscated" "$_o"
printf '%s\n' "$_o" | grep -qE 'entities.php|DES.php' && _f "obfuscated: false positive" "$_o" \
  || _p "obfuscated: not core's entity table (isolated escapes), not an S-box table"
_m=$(_th foreign-mu "$W/wp-content/mu-plugins")
[ "$_m" = "$W/wp-content/mu-plugins/host-cache.php" ] && _p "foreign-mu: only the one WASP did not install" || _f "foreign-mu" "$_m"

echo ""
echo "── accounts, from a dump that is never loaded"
cat > "$T/d1.sql" <<'EOF'
CREATE TABLE `wp_usermeta` (x int);
INSERT INTO `wp_users` VALUES (1,'owner','$P$a','owner','owner@example.com','','2020-12-04 15:22:01','',0,'Owner'),(2,'ed','$P$d','ed','ed@example.com','','2021-03-01 10:01:02','',0,'Ed, the \'editor\''),(3,'wpadminqxtvb','$wp$2y$10$x','wpadminqxtvb','wpadmin@example.ru','','2020-06-14 00:00:00','',0,'wpadminqxtvb');
INSERT INTO `wp_usermeta` VALUES (1,1,'wp_capabilities','a:1:{s:13:\"administrator\";b:1;}'),(2,1,'nickname','owner'),(5,2,'wp_capabilities','a:1:{s:6:\"editor\";b:1;}'),(9,3,'wp_capabilities','a:0:{}');
INSERT INTO `wp_bp_users` VALUES (9,'decoy','y','z','decoy@example.com','','2019-01-01 00:00:00','',0,'q');
EOF
cat > "$T/d2.sql" <<'EOF'
INSERT INTO "wp9_users" ("ID", "user_login", "user_pass", "user_nicename", "user_email", "user_url", "user_registered", "user_activation_key", "user_status", "display_name") VALUES
(1, "boss", "h", "boss", "boss@example.com", "", "2019-01-01 09:00:00", "", 0, "Boss"),
(7, "wp_support_k3x9", "h", "x", "x@example.net", "", "2018-05-05 00:00:00", "", 0, "x");
INSERT INTO "wp9_usermeta" ("umeta_id", "user_id", "meta_key", "meta_value") VALUES
(10, 1, "wp9_capabilities", "a:1:{s:13:\"administrator\";b:1;}"),
(70, 7, "wp9_capabilities", "a:1:{s:13:\"administrator\";b:1;}");
EOF
_u=$(_th dump-users wp_ < "$T/d1.sql")
[ "$(printf '%s\n' "$_u" | grep -c .)" = 3 ] && _p "dump-users: mysqldump style, escaped quotes, a plugin's *_users table ignored" || _f "dump-users d1" "$_u"
_u2=$(_th dump-users < "$T/d2.sql")
printf '%s\n' "$_u2" | grep -q "^7${TAB}wp_support_k3x9${TAB}x@example.net${TAB}2018-05-05 00:00:00$" \
  && _p "dump-users: phpMyAdmin style, column list, one row per line" || _f "dump-users d2" "$_u2"
_c=$(_th dump-caps wp_ < "$T/d1.sql")
printf '%s\n' "$_c" | grep -q "^3${TAB}a:0:{}$" && printf '%s\n' "$_c" | grep -q '^1.*"administrator"' \
  && _p "dump-caps: capabilities rows, unescaped" || _f "dump-caps" "$_c"
_join() { awk -F '\t' 'NR==FNR {c[$1]=$2; next} {print $0 "\t" c[$1]}' "$1" "$2"; }
_th dump-caps wp_ < "$T/d1.sql" > "$T/c1"; _th dump-users wp_ < "$T/d1.sql" > "$T/u1"
_s=$(_join "$T/c1" "$T/u1" | _th suspect-users)
printf '%s\n' "$_s" | grep -q "^3${TAB}wpadminqxtvb${TAB}.*midnight,backdated,login-pattern,role-stripped${TAB}none$" \
  && _p "the field-test account: all four signals" || _f "suspect field test" "$_s"
[ "$(printf '%s\n' "$_s" | grep -c .)" = 1 ] && _p "and nobody else" || _f "suspects" "$_s"
_th dump-caps < "$T/d2.sql" > "$T/c2"; _th dump-users < "$T/d2.sql" > "$T/u2"
_s=$(_join "$T/c2" "$T/u2" | _th suspect-users)
printf '%s\n' "$_s" | grep -q "^7${TAB}wp_support_k3x9.*login-pattern.*administrator$" \
  && _p "wp_support_<random>, midnight, backdated, administrator" || _f "suspect d2" "$_s"
# A customer import: every date midnight, but in ID order -- one signal each.
{ for i in 1 2 3 4 5 6; do printf '%s\tcust%s\tc%s@example.com\t2022-0%s-01 00:00:00\ta:1:{s:8:"customer";b:1;}\n' "$i" "$i" "$i" "$i"; done; } > "$T/cust"
[ -z "$(_th suspect-users < "$T/cust")" ] && _p "a bulk import with midnight dates in order is not flagged" || _f "bulk import" "$(_th suspect-users < "$T/cust")"

echo ""
echo "── wp-malware-scan.sh structural"
mkdir -p "$T/state" "$T/quar" "$T/bin" "$T/etc"
_noroot='/^if \[ "\$(id -u)" -ne 0 \]; then$/,/^fi$/d'
sed -e "$_noroot" -e "s#^STATE=.*#STATE=$T/state#" -e "s#^QUARANTINE=.*#QUARANTINE=$T/quar#" \
    -e "s#/etc/wp-install/vars.sh#$T/etc/vars.sh#g" -e "s#/etc/wp-install/pinned.env#$T/etc/pinned.env#g" \
    -e "s#^WP_ROOT=.*#WP_ROOT=$T/live#" \
    -e "s#/usr/local/bin/wp-plugins.sh#$T/wp-plugins.sh#g" \
    -e "s#/usr/local/bin/wp-forensics.sh#$T/nope#g" -e "s#/usr/local/bin/wp-notify.sh#$T/nope#g" \
    "$REPO/payload/bin/wp-malware-scan.sh" > "$T/scan.sh"
: > "$T/etc/vars.sh"; : > "$T/etc/pinned.env"
printf '#!/bin/sh\nexit 0\n' > "$T/bin/logger"; chmod +x "$T/bin/logger"
_scan() { THREATS="$TH" PATH="$T/bin:${WASP_TEST_TOOLS:+$WASP_TEST_TOOLS:}$PATH" ${WASP_TEST_SH:-sh} "$T/scan.sh" "$@" 2>&1; }
_o=$(_scan --path "$W" structural)
printf '%s\n' "$_o" | grep -q 'CRITICAL.*Obfuscated PHP.*mu-plugins/_x7Qe2k.php.bak' && _p "obfuscated outside plugins: CRITICAL" || _f "crit obf" "$_o"
printf '%s\n' "$_o" | grep -q 'HIGH.*Obfuscated PHP.*plugins/odd/vendor-blob.php' && _p "obfuscated inside a plugin: HIGH" || _f "high obf" ""
printf '%s\n' "$_o" | grep -q 'HIGH.*renamed so it no longer runs.*_x7Qe2k.php.bak' && _p "renamed PHP: HIGH, by name" || _f "renamed" ""
printf '%s\n' "$_o" | grep -q 'SUSPECT.*mu-plugin not installed by WASP.*host-cache.php' && _p "a foreign mu-plugin: SUSPECT" || _f "foreign mu" ""
printf '%s\n' "$_o" | grep -qE 'entities.php|DES.php|01-wpvm-smtp' && _f "false positive in scan" "$(printf '%s\n' "$_o" | grep -E 'entities|DES|01-wpvm')" \
  || _p "nothing said about the look-alikes or WASP's own mu-plugin"

echo ""
echo "── remediate, on a staged tree"
cp -a "$W" "$T/stage"; S="$T/stage"
_o=$(_scan --path "$S" remediate)
for _e in 'QUARANTINE.*uploads/2024/05/x.php' 'QUARANTINE.*_x7Qe2k.php.bak' 'QUARANTINE.*old.php.orig' \
          'QUARANTINE.*wp-config.php.bak' 'QUARANTINE.*uploads/.htaccess' 'FOR A HUMAN.*plugins/odd/vendor-blob.php'; do
  printf '%s\n' "$_o" | grep -q "$_e" && _p "plan: $(printf '%s' "$_e" | sed 's/\.\*/ … /')" || _f "plan $_e" "$_o"
done
[ "$(printf '%s\n' "$_o" | grep -c 'QUARANTINE.*_x7Qe2k')" = 1 ] && _p "a file matching two rules is planned once" || _f "dupe" ""
printf '%s\n' "$_o" | grep -qE 'QUARANTINE.*(jobs/a/index.php|host-cache|01-wpvm|entities|DES|a.gif|readme.bak)' \
  && _f "plan includes an innocent file" "$_o" || _p "plan leaves the guard, WASP's files, the look-alikes and media alone"
[ -f "$S/wp-content/uploads/2024/05/x.php" ] && [ -f "$S/wp-content/mu-plugins/_x7Qe2k.php.bak" ] \
  && _p "without --apply nothing moved" || _f "dry run moved files" ""
_o=$(_scan --path "$S" remediate --apply </dev/null); rc=$?
[ "$rc" = 1 ] && [ -f "$S/wp-content/uploads/2024/05/x.php" ] && _p "--apply with no one to ask and no --yes refuses" || _f "unattended apply" "rc=$rc"
_o=$(_scan --path "$S" remediate --apply --yes)
_rq=$(ls -d "$T/quar"/remediate-* 2>/dev/null | head -1)
[ -n "$_rq" ] && [ -f "$_rq/wp-content/uploads/2024/05/x.php" ] && [ -f "$_rq/wp-content/mu-plugins/_x7Qe2k.php.bak" ] \
  && [ -f "$_rq/wp-config.php.bak" ] && _p "--apply --yes quarantines them with their paths kept" || _f "apply" "$_o"
[ ! -e "$S/wp-content/uploads/2024/05/x.php" ] && [ ! -e "$S/wp-content/uploads/.htaccess" ] && _p "and they are gone from the tree" || _f "still there" ""
[ -f "$S/wp-content/uploads/jobs/a/index.php" ] && [ -f "$S/wp-content/plugins/odd/vendor-blob.php" ] && [ -f "$S/wp-content/mu-plugins/host-cache.php" ] \
  && _p "the guard, the plugin file left for a human, and the foreign mu-plugin are untouched" || _f "over-reach" ""
grep -q "${_rq}/wp-content/uploads/2024/05/x.php${TAB}${S}/wp-content/uploads/2024/05/x.php" "$T/quar/manifest.tsv" \
  && _p "each move is recorded with where it came from" || _f "manifest" "$(cat "$T/quar/manifest.tsv")"
_o=$(_scan --path "$S" remediate)
printf '%s\n' "$_o" | grep -q 'Nothing to remediate automatically' && _p "a second run finds nothing left to do" || _f "idempotent" "$_o"

echo ""
echo "── remediate, on the live site: plugins and accounts"
cp -a "$W" "$T/live"
# wp-plugins.sh stand-in: records what it is asked to do.
cat > "$T/wp-plugins.sh" <<STUB
#!/bin/sh
echo "\$*" >> "$T/plugins-calls"
case "\$1 \${2:-}" in
  'repair-modified --plan') [ -n "\${MODIFIED:-}" ] && echo "  REINSTALL  \$MODIFIED 1.2.3   (files differ from wordpress.org)" ;;
esac
exit 0
STUB
chmod +x "$T/wp-plugins.sh"
cat > "$T/bin/podman" <<STUB
#!/bin/sh
case "\$*" in
  *WORDPRESS_TABLE_PREFIX*) printf 'wp_' ;;
  *mariadb*) cat "$T/users.tsv" ;;
esac
exit 0
STUB
chmod +x "$T/bin/podman"
{ printf '1\towner\towner@example.com\t2020-12-04 15:22:01\ta:1:{s:13:"administrator";b:1;}\n'
  printf '3\twpadminqxtvb\twpadmin@example.ru\t2020-06-14 00:00:00\ta:0:{}\n'
  printf '4\tsub1\ts@example.com\t2019-01-01 00:00:00\ta:1:{s:10:"subscriber";b:1;}\n'; } > "$T/users.tsv"
: > "$T/plugins-calls"
_o=$(MODIFIED=akismet _scan remediate)
printf '%s\n' "$_o" | grep -q 'REINSTALL  akismet' && printf '%s\n' "$_o" | grep -q 'LOCK.*wpadminqxtvb' \
  && _p "plan: reinstall the modified plugin, lock the planted account" || _f "live plan" "$_o"
printf '%s\n' "$_o" | grep -A1 "FOR A HUMAN.*user 4 (sub1)" | grep -q "not privileged" && _p "a planted-looking subscriber goes to a human, not locked" || _f "subscriber" "$_o"
grep -qE 'repair-modified --yes|lock-user' "$T/plugins-calls" && _f "dry run acted" "$(cat "$T/plugins-calls")" || _p "and nothing acted on without --apply"
: > "$T/plugins-calls"
MODIFIED=akismet _scan remediate --apply --yes >/dev/null
grep -q '^repair-modified --yes$' "$T/plugins-calls" && _p "--apply reinstalls modified plugins" || _f "repair" "$(cat "$T/plugins-calls")"
grep -q '^lock-user 3 ' "$T/plugins-calls" && _p "--apply locks account 3" || _f "lock" "$(cat "$T/plugins-calls")"
grep -qE '^lock-user (1|4) ' "$T/plugins-calls" && _f "locked the wrong account" "$(cat "$T/plugins-calls")" || _p "and only account 3"
for i in 10 11 12 13 14 15; do printf '%s\twpadmin%sxyz\tx%s@example.com\t2010-01-01 00:00:00\ta:0:{}\n' "$i" "$i" "$i"; done >> "$T/users.tsv"
: > "$T/plugins-calls"
_o=$(_scan remediate --apply --yes)
grep -q '^lock-user' "$T/plugins-calls" && _f "a batch was locked" "$(cat "$T/plugins-calls")" \
  || _p "more than five at once: none locked automatically"
printf '%s\n' "$_o" | grep -q 'accounts match at once' && _p "and the batch is handed to a human" || _f "batch" "$_o"

echo ""
echo "── wp-plugins.sh repair-modified and lock-user"
H="$T/html"; mkdir -p "$H/wp-content/plugins/akismet" "$H/wp-content/plugins/gone"
printf '<?php // modified\n' > "$H/wp-content/plugins/akismet/akismet.php"
printf '<?php // backdoor\n' > "$H/wp-content/plugins/akismet/added.php"
printf '<?php\n' > "$H/wp-content/plugins/gone/gone.php"
sed -e "$_noroot" -e "s#^WP_HTML_DIR=.*#WP_HTML_DIR=$H#" -e "s#/etc/wp-install/vars.sh#$T/etc/vars.sh#g" \
    -e "s#^QUARANTINE=.*#QUARANTINE=$T/pq#" -e 's#^QUARANTINE="\${QUARANTINE:-/var/lib/wp-quarantine}"#QUARANTINE='"$T/pq"'#' \
    "$REPO/payload/bin/wp-plugins.sh" > "$T/plugins.sh"
grep -q "QUARANTINE=$T/pq" "$T/plugins.sh" || _f "harness" "could not redirect the quarantine"
# wp-cli stand-in, inside `podman run`: answers the commands repair and lock use.
cat > "$T/bin/podman" <<STUB
#!/bin/sh
case "\$*" in
  *"ps --filter"*) echo wordpress; exit 0 ;;
esac
a="\$*"; echo "\${a#*wp --path=/var/www/html }" >> "$T/wpcli-calls"
case "\$a" in
  *"plugin verify-checksums --all --format=csv"*)
     printf 'plugin_name,file,message\nakismet,akismet.php,"Checksum does not match"\nakismet,added.php,"File was added"\ngone,gone.php,"Checksum does not match"\n'; exit 1 ;;
  *"plugin list --fields=name,version"*) printf 'name,version\nakismet,5.3.1\ngone,2.0\n' ;;
  *"plugin install akismet"*) mkdir -p "$H/wp-content/plugins/akismet"; printf '<?php // clean\n' > "$H/wp-content/plugins/akismet/akismet.php" ;;
  *"plugin install gone"*) exit 1 ;;
  *"plugin verify-checksums akismet"*) exit 0 ;;
  *"user get 3 --field=user_login"*) echo wpadminqxtvb ;;
  *"user get 3 --field=user_email"*) echo wpadmin@example.ru ;;
  *"user get 3 --field=roles"*) echo "" ;;
esac
exit 0
STUB
chmod +x "$T/bin/podman"
_pl() { PATH="$T/bin:${WASP_TEST_TOOLS:+$WASP_TEST_TOOLS:}$PATH" ${WASP_TEST_SH:-sh} "$T/plugins.sh" "$@" 2>&1; }
_o=$(_pl repair-modified --plan)
printf '%s\n' "$_o" | grep -q 'REINSTALL  akismet 5.3.1' && printf '%s\n' "$_o" | grep -q 'REINSTALL  gone 2.0' \
  && _p "--plan lists each modified plugin once, with its version" || _f "plan" "$_o"
_o=$(_pl repair-modified --yes); rc=$?
grep -q '// clean' "$H/wp-content/plugins/akismet/akismet.php" && [ ! -e "$H/wp-content/plugins/akismet/added.php" ] \
  && _p "a modified plugin is replaced wholesale — the added file does not survive" || _f "repair" "$_o"
_aq=$(ls -d "$T/pq"/plugins-*/akismet 2>/dev/null | head -1)
[ -n "$_aq" ] && [ -f "$_aq/added.php" ] && _p "the modified copy is kept in quarantine" || _f "evidence" "$(ls -R "$T/pq" 2>&1 | head)"
grep -q 'plugin install akismet --version=5.3.1' "$T/wpcli-calls" && _p "reinstalled at the version it claimed" || _f "version" "$(cat "$T/wpcli-calls")"
[ -f "$H/wp-content/plugins/gone/gone.php" ] && _p "no clean copy available: the original is put back" || _f "restore" "$_o"
[ "$rc" != 0 ] && printf '%s\n' "$_o" | grep -q 'ORIGINAL is back' && _p "and that is reported as a failure" || _f "failure rc" "rc=$rc"
: > "$T/wpcli-calls"
_o=$(_pl lock-user 3 "signals: midnight,backdated")
grep -q '^user remove-role 3' "$T/wpcli-calls" && grep -q 'user update 3 --user_pass=[A-Za-z0-9]\{40\} --user_email=locked-3@wasp.invalid --skip-email' "$T/wpcli-calls" \
  && grep -q '^user session destroy 3 --all' "$T/wpcli-calls" && _p "lock-user: no role, new password, unreachable e-mail, sessions ended" || _f "lock" "$(cat "$T/wpcli-calls")"
grep -q '^user meta update 3 wasp_locked .*email=wpadmin@example.ru' "$T/wpcli-calls" && _p "and what it was is recorded on the account" || _f "lock record" ""
grep -q 'user delete' "$T/wpcli-calls" && _f "lock deleted the user" "" || _p "the account is not deleted"

echo ""
printf '  passed %d   failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
