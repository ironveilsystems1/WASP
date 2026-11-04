#!/usr/bin/env bash
# =============================================================================
# test-busybox-run.sh — the tools under the shell and applets the VM really has
# =============================================================================
#
# Every other test here runs on the build host, which means bash or dash, GNU
# tar and Info-ZIP. The VM is Alpine, where /bin/sh, tar, unzip, find, sed and
# awk are all BusyBox. That gap hid two critical bugs in wp-import.sh, and they
# passed every test in this repository:
#
#   - `unzip -Z1` does not exist in BusyBox, so the member list came back empty
#     and every hostile-archive check was skipped.
#   - BusyBox tar follows a hard-link target out of the extraction directory
#     (CVE-2026-26158), and GNU tar refuses, so the test host could not show it.
#
# So this runs the real tools with a PATH holding BusyBox applets and little
# else, plants the things they exist to catch, and asserts on the results. It
# then runs the import and scan suites again the same way.
#
# BusyBox is required, not optional. A skipped run here is the state those two
# bugs lived in. Set BUSYBOX=/path/to/busybox, or install busybox-static.
# WASP_TEST_REPO runs this against another tree, which is how to confirm it
# still fails on a build that has the bugs.
# =============================================================================
set -u
REPO="${WASP_TEST_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
HERE="$(cd "$(dirname "$0")" && pwd)"
BB="${BUSYBOX:-$(command -v busybox 2>/dev/null || true)}"
if [ -z "$BB" ] || ! "$BB" --list >/dev/null 2>&1; then
  echo "  FAILED — BusyBox not found, so nothing was tested. Install busybox-static,"
  echo "  or set BUSYBOX=/path/to/busybox."
  exit 1
fi
command -v python3 >/dev/null 2>&1 || { echo "  FAILED — python3 is needed to build the archives"; exit 1; }

T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
_p() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
_f() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n         %s\n' "$1" "${2:-}"; }

# ── The tool path: BusyBox applets, then only the stubs below ───────────────
mkdir -p "$T/bb" "$T/bin" "$T/inbox" "$T/staging" "$T/html/wp-content" "$T/etc" "$T/secret"
for _a in $("$BB" --list); do ln -sf "$BB" "$T/bb/$_a"; done
cat > "$T/bin/podman" <<STUB
#!$T/bb/sh
case "\$*" in
  *WORDPRESS_TABLE_PREFIX*) printf 'wp_' ;;
  *stranded*|*'-N -B'*) cat >/dev/null; echo 'stranded-remaining:0' ;;
  *'ps '*) echo wordpress ;;
  *) [ -t 0 ] || cat >/dev/null ;;
esac
exit 0
STUB
for s in chown stty; do printf '#!%s/bb/sh\nexit 0\n' "$T" > "$T/bin/$s"; done
printf '#!%s/bb/sh\nexit 0\n' "$T" > "$T/wp-db-backup.sh"
printf '#!%s/bb/sh\nexit 0\n' "$T" > "$T/wp-plugins.sh"
chmod +x "$T/bin/"* "$T/wp-db-backup.sh" "$T/wp-plugins.sh"
printf 'MFA_ENFORCE=1\nWP_DOMAIN=new.example\nWP_SCHEME=https\n' > "$T/etc/vars.sh"
: > "$T/etc/pinned.env"

sed -e 's#^  if command -v doas.*##' \
    -e '/^if \[ "\$(id -u)" -ne 0 \]; then$/,/^fi$/d' \
    -e "s#/etc/wp-install/vars.sh#$T/etc/vars.sh#g" \
    -e "s#/etc/wp-install/pinned.env#$T/etc/pinned.env#g" \
    -e "s#^INBOX=.*#INBOX=$T/inbox#" \
    -e "s#^STAGING=.*#STAGING=$T/staging#" \
    -e "s#^WP_ROOT=.*#WP_ROOT=$T/html#" \
    -e "s#/usr/local/bin/wp-db-backup.sh#$T/wp-db-backup.sh#g" \
    -e "s#/usr/local/bin/wp-plugins.sh#$T/wp-plugins.sh#g" \
    "$REPO/payload/bin/wp-import.sh" > "$T/wp-import.sh"

_imp() { env -i PATH="$T/bin:$T/bb" HOME=/root "$T/bb/sh" "$T/wp-import.sh" "$@" 2>&1; }

# ── Archives ────────────────────────────────────────────────────────────────
echo 'CANARY' > "$T/secret/env"; chmod 600 "$T/secret/env"
python3 -I - "$T/inbox" "$T/secret/env" <<'PY'
import io, stat, sys, tarfile, zipfile
inbox, target = sys.argv[1], sys.argv[2]
def tgz(name, extra):
    t = tarfile.open(f"{inbox}/{name}", "w:gz")
    for n, b in (("wp-content/uploads/ok.txt", b"hello"),
                 ("backup.sql", b"CREATE TABLE `wp_options` (a int);\n")):
        i = tarfile.TarInfo(n); i.size = len(b); t.addfile(i, io.BytesIO(b))
    extra(t); t.close()
def hard(link):
    def add(t):
        i = tarfile.TarInfo("wp-content/uploads/report.txt")
        i.type = tarfile.LNKTYPE; i.linkname = link; t.addfile(i)
    return add
def sym(t):
    i = tarfile.TarInfo("wp-content/uploads/leak.txt")
    i.type = tarfile.SYMTYPE; i.linkname = "../../wp-config.php"; t.addfile(i)
tgz("clean.tar.gz", lambda t: None)
tgz("hard-abs.tar.gz", hard(target))
tgz("hard-rel.tar.gz", hard("../../../secret/env"))
tgz("hard-inner.tar.gz", hard("wp-content/uploads/ok.txt"))
tgz("sym.tar.gz", sym)
def zipf(name, extra=None):
    z = zipfile.ZipFile(f"{inbox}/{name}", "w", zipfile.ZIP_DEFLATED)
    z.writestr("wp-content/uploads/ok.txt", "hello")
    if extra: extra(z)
    z.close()
def zsym(z):
    i = zipfile.ZipInfo("wp-content/uploads/leak.txt")
    i.create_system = 3; i.external_attr = (stat.S_IFLNK | 0o777) << 16
    z.writestr(i, "../../wp-config.php")
zipf("clean.zip"); zipf("sym.zip", zsym)
PY

_staged_count() { find "$T/staging" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' '; }
_clear() { rm -rf "$T/staging"/* "$T/staging"/.latest; sleep 1; }

echo ""
echo "wp-import.sh under BusyBox (BusyBox $("$BB" 2>&1 | head -1 | awk '{print $2}'))"
echo ""
echo "── hostile tar members"
for _a in hard-abs hard-rel hard-inner sym; do
  _o=$(_imp inspect "$_a.tar.gz"); _rc=$?
  [ "$_rc" = 2 ] && _p "inspect refuses $_a.tar.gz" || _f "inspect passed $_a.tar.gz" "exit $_rc: $(printf '%s' "$_o" | tail -3)"
  _clear
  _o=$(_imp extract "$_a.tar.gz"); _rc=$?
  { [ "$_rc" = 2 ] && [ "$(_staged_count)" = 0 ]; } \
    && _p "extract refuses $_a.tar.gz and leaves nothing staged" \
    || _f "extract accepted $_a.tar.gz" "exit $_rc, $(_staged_count) staged: $(printf '%s' "$_o" | tail -3)"
done
[ "$(stat -c %h "$T/secret/env")" = 1 ] \
  && _p "the file outside staging was never linked" \
  || _f "a hostile member reached a file outside staging" "$(stat -c '%h links, mode %a' "$T/secret/env")"
[ "$(stat -c %a "$T/secret/env")" = 600 ] \
  && _p "its mode is unchanged" || _f "its mode changed" "$(stat -c %a "$T/secret/env")"

echo ""
echo "── the check on what actually landed"
# Past the listing check, as with a tool whose listing does not show a link.
_clear
sed -e 's/^_tar_special() {.*/_tar_special() { echo 0; }/' "$T/wp-import.sh" > "$T/wp-import-blind.sh"
_o=$(env -i PATH="$T/bin:$T/bb" HOME=/root "$T/bb/sh" "$T/wp-import-blind.sh" extract hard-abs.tar.gz 2>&1); _rc=$?
{ [ "$_rc" = 2 ] && [ "$(_staged_count)" = 0 ]; } \
  && _p "a hard link that gets past the listing is still refused" \
  || _f "only the listing stood between that link and the docroot" "exit $_rc: $(printf '%s' "$_o" | tail -3)"
_clear
_imp extract clean.tar.gz >/dev/null
_id=$(cat "$T/staging/.latest")
_imp scan "$_id" >/dev/null
# A staging set that changed after it was scanned, or came from an older build.
ln "$T/secret/env" "$T/staging/$_id/files/wp-content/uploads/report.txt"
_o=$(printf 'IMPORT\n' | env -i PATH="$T/bin:$T/bb" HOME=/root "$T/bb/sh" "$T/wp-import.sh" apply "$_id" --force 2>&1); _rc=$?
if [ -e "$T/html/wp-content/uploads/report.txt" ]; then
  _f "apply copied a hard-linked file into the docroot" "$(printf '%s' "$_o" | tail -3)"
elif [ "$_rc" = 2 ] && printf '%s' "$_o" | grep -q 'link or special'; then
  _p "apply refuses a staging set holding a link"
else
  _f "apply stopped for some other reason, so the check was not reached" \
     "exit $_rc: $(printf '%s' "$_o" | tail -3)"
fi
rm -f "$T/staging/$_id/files/wp-content/uploads/report.txt"

echo ""
echo "── zips with the VM's own unzip"
_clear
_o=$(_imp inspect clean.zip); _rc=$?
{ [ "$_rc" = 2 ] && printf '%s' "$_o" | grep -q 'could not be read'; } \
  && _p "inspect says a zip it cannot list cannot be checked" \
  || _f "inspect passed a zip it could not list" "exit $_rc: $(printf '%s' "$_o" | tail -3)"
_o=$(_imp extract sym.zip); _rc=$?
{ [ "$_rc" = 2 ] && [ "$(_staged_count)" = 0 ]; } \
  && _p "extract refuses a zip it cannot list" \
  || _f "extract ran with no checks" "exit $_rc, $(_staged_count) staged: $(printf '%s' "$_o" | tail -3)"

if command -v unzip >/dev/null 2>&1 && unzip -Z1 "$T/inbox/clean.zip" >/dev/null 2>&1; then
  echo ""
  echo "── zips with Info-ZIP, as stage 08 installs it"
  ln -sf "$(command -v unzip)" "$T/bin/unzip"
  _clear
  _o=$(_imp inspect clean.zip); _rc=$?
  [ "$_rc" = 0 ] && _p "a clean zip inspects" || _f "clean zip refused" "exit $_rc: $(printf '%s' "$_o" | tail -3)"
  _o=$(_imp extract clean.zip); _rc=$?
  [ "$_rc" = 0 ] && _p "a clean zip extracts" || _f "clean zip did not extract" "exit $_rc: $(printf '%s' "$_o" | tail -3)"
  _clear
  _o=$(_imp inspect sym.zip); _rc=$?
  [ "$_rc" = 2 ] && _p "inspect refuses a zip symlink" || _f "inspect passed a zip symlink" "exit $_rc"
  _o=$(_imp extract sym.zip); _rc=$?
  { [ "$_rc" = 2 ] && [ "$(_staged_count)" = 0 ]; } \
    && _p "extract refuses a zip symlink" || _f "extract accepted a zip symlink" "exit $_rc"
  rm -f "$T/bin/unzip"
else
  echo ""
  echo "  [NOTE] no Info-ZIP on this host, so the zip acceptance path was not run"
fi

echo ""
echo "── a clean archive still goes through"
_clear
_o=$(_imp inspect clean.tar.gz); _rc=$?
[ "$_rc" = 0 ] && _p "a clean tar.gz inspects" || _f "clean tar.gz refused" "exit $_rc: $(printf '%s' "$_o" | tail -3)"
_o=$(_imp extract clean.tar.gz); _rc=$?
{ [ "$_rc" = 0 ] && [ "$(_staged_count)" = 1 ]; } \
  && _p "a clean tar.gz extracts" || _f "clean tar.gz did not extract" "exit $_rc: $(printf '%s' "$_o" | tail -3)"

echo ""
echo "── the inbox keeps its mode"
mkdir -p "$T/inbox2"; chmod 2770 "$T/inbox2"
sed -e "s#^INBOX=.*#INBOX=$T/inbox2#" "$T/wp-import.sh" > "$T/wp-import-inbox.sh"
printf 'ADMIN_USER=root\n' >> "$T/etc/vars.sh"
env -i PATH="$T/bin:$T/bb" HOME=/root "$T/bb/sh" "$T/wp-import-inbox.sh" list >/dev/null 2>&1
_m=$(stat -c %a "$T/inbox2")
[ "$_m" = 2770 ] && _p "running the tool leaves the inbox group-writable" \
  || _f "running the tool changed the inbox" "mode is now $_m, so scp as the admin user fails"

# ── The malware scanner ─────────────────────────────────────────────────────
echo ""
echo "wp-malware-scan.sh under BusyBox"
echo ""
M="$T/mal"; mkdir -p "$M/site/wp-content/uploads" "$M/state" "$M/quarantine"
sed -e '/^if \[ "\$(id -u)" -ne 0 \]; then$/,/^fi$/d' \
    -e "s#^STATE=.*#STATE=$M/state#" \
    -e "s#^QUARANTINE=.*#QUARANTINE=$M/quarantine#" \
    -e "s#/etc/wp-install/vars.sh#$T/etc/vars.sh#g" \
    -e "s#/etc/wp-install/pinned.env#$T/etc/pinned.env#g" \
    "$REPO/payload/bin/wp-malware-scan.sh" > "$M/scan.sh"
_scan() { env -i PATH="$T/bin:$T/bb" HOME=/root "$T/bb/sh" "$M/scan.sh" --path "$M/site" "$@" 2>&1; }

_o=$(_scan structural); _rc=$?
{ [ "$_rc" = 0 ] && printf '%s' "$_o" | grep -q 'critical 0'; } \
  && _p "a clean tree scans clean" || _f "clean tree" "exit $_rc: $(printf '%s' "$_o" | tail -4)"

U="$M/site/wp-content/uploads"
_expect() { # description, expected critical, expected high, expected suspicious
  _o=$(_scan structural); _rc=$?
  _line=$(printf '%s\n' "$_o" | sed 's/\x1b\[[0-9;]*m//g' | grep 'critical [0-9]' | tail -1)
  _want="critical $2   high $3   suspicious $4"
  if printf '%s' "$_line" | grep -q "$_want"; then
    _p "$1: $_want"
  else
    _f "$1" "wanted '$_want', summary said '$_line'"
  fi
  _xrc=0; [ "$3" -gt 0 ] && _xrc=1; [ "$2" -gt 0 ] && _xrc=2
  [ "$_rc" = "$_xrc" ] && _p "$1: exit $_xrc" || _f "$1: exit status" "wanted $_xrc, got $_rc"
}
printf '<?php system($_GET[1]);' > "$U/pic.jpg"
_expect "PHP in a .jpg" 1 0 0
rm -f "$U/pic.jpg"
printf '<?php system($_GET[1]);' > "$U/pic with space.jpeg"
_expect "PHP in a .jpeg with a space in its name" 1 0 0
rm -f "$U/pic with space.jpeg"
printf '<?php ?>' > "$U/shell.php"
_expect "PHP in uploads" 1 0 0
rm -f "$U/shell.php"
printf 'AddType application/x-httpd-php .jpg\n' > "$U/.htaccess"
_expect "a handler override in uploads" 1 0 0
printf 'AddType image/webp .webp\n' > "$U/.htaccess"
_expect "an image optimiser's AddType is left alone" 0 0 0
rm -f "$U/.htaccess"
ln -s ../../wp-config.php "$U/leak.txt"
_expect "a symlink in uploads" 0 1 0
rm -f "$U/leak.txt"
printf x > "$M/site/wp-content/w.txt"; chmod 666 "$M/site/wp-content/w.txt"
_expect "a world-writable file" 0 1 0
rm -f "$M/site/wp-content/w.txt"
printf '<?php' > "$M/site/wp-content/stray.php"
_expect "stray PHP at the top of wp-content" 0 0 1
rm -f "$M/site/wp-content/stray.php"
printf '<?php' > "$U/a.jpg"; ln -s x "$U/b"; printf '<?php' > "$M/site/wp-content/stray.php"
_expect "several findings add up" 1 1 1
rm -f "$U/a.jpg" "$U/b" "$M/site/wp-content/stray.php"

[ ! -e "$M/state/last-scan.tsv" ] \
  && _p "scanning a staged path leaves the site's last result alone" \
  || _f "a staged scan replaced the site's last result" ""

echo ""
echo "── database findings"
# Reaches the same _crit and _high as the file checks, through its own loops.
cat > "$T/bin/podman" <<STUB
#!$T/bb/sh
case "\$*" in
  *WORDPRESS_TABLE_PREFIX*) printf 'wp_'; exit 0 ;;
esac
for _a in "\$@"; do _sql="\$_a"; done
case "\$_sql" in
  *'SELECT 1'*)              echo 1 ;;
  *'autoload'*)              echo 'hacked_option' ;;
  *'user_registered'*)       printf 'newadmin\tn@example.test\t2026-01-01\n' ;;
  *'COUNT(*)'*)              echo 0 ;;
esac
exit 0
STUB
sed -e 's/^TARGET=.*/TARGET="${SCAN_PATH:-$WP_ROOT}"/' "$M/scan.sh" > "$M/scan-db.sh"
_o=$(env -i PATH="$T/bin:$T/bb" HOME=/root "$T/bb/sh" "$M/scan-db.sh" --path "$M/site" db 2>&1); _rc=$?
_line=$(printf '%s\n' "$_o" | sed 's/\x1b\[[0-9;]*m//g' | grep 'critical [0-9]' | tail -1)
{ printf '%s' "$_line" | grep -q 'critical 1   high 1' && [ "$_rc" = 2 ]; } \
  && _p "an autoloaded backdoor and a new admin are counted, exit 2" \
  || _f "database findings were lost" "exit $_rc, summary '$_line'"

# ── Rotating the database password ──────────────────────────────────────────
echo ""
echo "wp-rotate-secrets.sh db under BusyBox"
echo ""
Z="$T/rot"; mkdir -p "$Z/bin" "$Z/etc" "$Z/backup"
: > "$Z/calls"; : > "$Z/sql"
cat > "$Z/bin/podman" <<STUB
#!$T/bb/sh
echo "podman \$*" >> "$Z/calls"
case "\$*" in
  *'read -r p'*) cat >/dev/null; [ -e "$Z/bad-password" ] || echo OK ;;
  'exec -i mariadb'*) cat >> "$Z/sql" ;;
esac
exit 0
STUB
printf '#!%s/bb/sh\necho "rc-service $*" >> "%s/calls"\nexit 0\n' "$T" "$Z" > "$Z/bin/rc-service"
printf '#!%s/bb/sh\necho "health" >> "%s/calls"\n[ ! -e "%s/down" ]\n' "$T" "$Z" "$Z" > "$Z/health.sh"
chmod +x "$Z/bin/"* "$Z/health.sh"
sed -e '/^if \[ "\$(id -u)" -ne 0 \]; then$/,/^fi$/d' \
    -e "s#^ENVF=.*#ENVF=$Z/etc/env#" \
    -e "s#^WPENVF=.*#WPENVF=$Z/etc/wp.env#" \
    -e "s#^BACKUP_DIR=.*#BACKUP_DIR=$Z/backup#" \
    -e "s#^SECRETS=.*#SECRETS=$Z/secrets#" \
    -e "s#/etc/wp-install/vars.sh#$T/etc/vars.sh#g" \
    -e "s#/etc/wp-install/pinned.env#$T/etc/pinned.env#g" \
    -e "s#/usr/local/bin/wp-health-check.sh#$Z/health.sh#g" \
    -e 's/^    sleep 5$/    :/' \
    "$REPO/payload/bin/wp-rotate-secrets.sh" > "$Z/rotate.sh"
_env_reset() {
  cat > "$Z/etc/env" <<ENV
MARIADB_ROOT_PASSWORD=rootpw
MARIADB_PASSWORD=oldpw
WORDPRESS_DB_USER=wpdb
WORDPRESS_DB_PASSWORD=oldpw
WORDPRESS_DB_NAME=wordpress
ENV
  grep '^WORDPRESS_' "$Z/etc/env" > "$Z/etc/wp.env"
  : > "$Z/calls"; : > "$Z/sql"
}
_rot() { env -i PATH="$Z/bin:$T/bin:$T/bb" HOME=/root "$T/bb/sh" "$Z/rotate.sh" db 2>&1 </dev/null; }

_env_reset
_o=$(_rot); _rc=$?
[ "$_rc" = 0 ] && _p "a rotation completes" || _f "rotation failed" "exit $_rc: $(printf '%s' "$_o" | tail -3)"
_new=$(sed -n 's/^WORDPRESS_DB_PASSWORD=//p' "$Z/etc/env")
{ [ -n "$_new" ] && [ "$_new" != oldpw ]; } && _p "the password changed" || _f "the password did not change" ""
grep -q "^WORDPRESS_DB_PASSWORD=$_new\$" "$Z/etc/wp.env" \
  && _p "wp.env carries the new password" || _f "wp.env was left behind" "$(cat "$Z/etc/wp.env")"
grep -q MARIADB "$Z/etc/wp.env" \
  && _f "wp.env gained a MariaDB value" "$(cat "$Z/etc/wp.env")" || _p "wp.env still holds no root password"
[ "$(stat -c %a "$Z/etc/wp.env")" = 600 ] \
  && _p "wp.env stays private" || _f "wp.env mode" "$(stat -c %a "$Z/etc/wp.env")"
grep -qF "$_new" "$Z/calls" \
  && _f "the new password reached a process list" "$(grep -F "$_new" "$Z/calls" | head -2)" \
  || _p "the new password stayed off the process list"
grep -qF "$_new" "$Z/sql" && _p "the new password went to MariaDB over stdin" || _f "MariaDB never got it" "$(cat "$Z/sql")"
grep -q 'podman restart' "$Z/calls" \
  && _f "podman restart keeps the old environment" "$(cat "$Z/calls")" || _p "WordPress is not merely restarted"
_seq=$(grep -nE 'rc-service wp-container stop|podman rm -f wordpress|rc-service wp-container start|^health' "$Z/calls" | sed 's/^[0-9]*://' | head -4 | tr '\n' '|')
[ "$_seq" = "rc-service wp-container stop|podman rm -f wordpress|rc-service wp-container start|health|" ] \
  && _p "WordPress is recreated, then checked from inside" || _f "wrong order" "$_seq"

_env_reset; : > "$Z/bad-password"
_o=$(_rot); _rc=$?
rm -f "$Z/bad-password"
{ [ "$_rc" != 0 ] && grep -q '^WORDPRESS_DB_PASSWORD=oldpw$' "$Z/etc/env" && grep -q '^WORDPRESS_DB_PASSWORD=oldpw$' "$Z/etc/wp.env"; } \
  && _p "a new password that does not authenticate is rolled back in both files" \
  || _f "rollback" "exit $_rc: $(cat "$Z/etc/wp.env")"

_env_reset; : > "$Z/down"
_o=$(_rot); _rc=$?
rm -f "$Z/down"
[ "$_rc" != 0 ] && _p "a site that does not come back is an error, not a success" \
  || _f "reported success with the site down" "$(printf '%s' "$_o" | tail -3)"

# ── The suites again, with BusyBox underneath ───────────────────────────────
echo ""
echo "The import and scan suites with BusyBox underneath"
for _t in test-wpress-import.sh test-vuln-scan.sh test-import-source.sh; do
  [ -f "$HERE/$_t" ] || { _f "$_t is missing" ""; continue; }
  _o=$(WASP_TEST_TOOLS="$T/bb" WASP_TEST_SH="$T/bb/sh" bash "$HERE/$_t" 2>&1); _rc=$?
  if [ "$_rc" = 0 ]; then
    _p "$_t: $(printf '%s\n' "$_o" | grep 'passed [0-9]' | tail -1 | sed 's/^ *//')"
  else
    _f "$_t failed under BusyBox" "$(printf '%s\n' "$_o" | grep -A1 '\[FAIL\]' | head -12)"
  fi
done

echo ""
printf '  passed %s   failed %s\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
