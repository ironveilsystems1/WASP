#!/usr/bin/env bash
# =============================================================================
# test-links.sh — wp-links.sh: content spam and broken links
# =============================================================================
#
#   - the content scanner's analysis and report (test-links.php)
#   - `spam` runs the scanner in the wordpress container, passes its options,
#     keeps its exit code, and with --notify emails only when spam is found
#     and the content_spam alert is not turned off
#   - `broken` crawls a real local web server: a 404 page, a 404 image and a
#     500 are reported with the pages that link to them; the admin, login,
#     login-slug and API paths are never requested; other sites' links are
#     listed and never fetched; every request carries a browser identity (the
#     site refuses an empty one); --max-pages stops and says so
#
# Host shell and BusyBox (BUSYBOX=/path/to/busybox, required). Needs php and curl.
# =============================================================================
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
T=$(mktemp -d); SRV=""
trap '[ -n "$SRV" ] && kill "$SRV" 2>/dev/null; rm -rf "$T"' EXIT
PASS=0; FAIL=0
_p() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
_f() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n         %s\n' "$1" "${2:-}"; }
TOOL="$REPO/payload/bin/wp-links.sh"

echo ""
echo "wp-links.sh: content spam and broken links"
[ "$(id -u)" -eq 0 ] || { _f "must run as root" "the tool re-executes through doas otherwise"; exit 1; }
command -v php >/dev/null 2>&1 || { _f "php is required" ""; exit 1; }
command -v curl >/dev/null 2>&1 || { _f "curl is required" ""; exit 1; }
BB="${BUSYBOX:-$(command -v busybox 2>/dev/null || true)}"

_o=$(php "$REPO/test/test-links.php" 2>&1); _rc=$?
[ "$_rc" = 0 ] && _p "content scanner: $(printf '%s' "$_o" | sed -n 's/.*links (php): //p')" \
  || _f "content scanner scenarios failed" "$(printf '%s' "$_o" | grep -A2 FAIL | head -20)"
_o=$(php "$REPO/test/test-links-clean.php" 2>&1); _rc=$?
[ "$_rc" = 0 ] && _p "content clean-up: $(printf '%s' "$_o" | sed -n 's/.*links clean (php): //p')" \
  || _f "content clean-up scenarios failed" "$(printf '%s' "$_o" | grep -A2 FAIL | head -20)"

# The import scan reads the dump with the same word lists as the content
# scanner. Two copies of a list drift; this holds them together.
_php_host=$(sed -n "s/.*return '\/(\(casin[^)]*\))\/i';.*/\1/p" "$REPO/payload/php-tools/wasp-content-scan.php" | head -1)
_imp_host=$(sed -n "s/^ *_spamhost='(\(.*\))'\$/\1/p" "$REPO/payload/bin/wp-import.sh" | head -1)
_php_slug=$(sed -n "/function wcs_spam_slug_re/,/^}/s/.*return '\/(\(.*\))\/i';.*/\1/p" "$REPO/payload/php-tools/wasp-content-scan.php" | head -1)
_imp_slug=$(sed -n "s/^ *_spamslug='(\(.*\))'\$/\1/p" "$REPO/payload/bin/wp-import.sh" | head -1)
{ [ -n "$_php_host" ] && [ "$_php_host" = "$_imp_host" ] && [ -n "$_php_slug" ] && [ "$_php_slug" = "$_imp_slug" ]; } \
  && _p "the import scan and the content scanner use the same spam word lists" \
  || _f "spam word lists differ" "php host: $_php_host | import: $_imp_host | php slug: $_php_slug | import: $_imp_slug"
_mu_host=$(sed -n "/function wasp_alerts_spam_host_re/,/^}/s/.*return '\/(\(.*\))\/i';.*/\1/p" "$REPO/payload/mu-plugins/07-wasp-alerts.php" | head -1)
[ -n "$_mu_host" ] && [ "$_mu_host" = "$_php_host" ] \
  && _p "the save-time alert (07-wasp-alerts.php) uses the same spam host list" \
  || _f "save-time alert host list differs" "mu: $_mu_host | scanner: $_php_host"

# ── a small site to crawl ───────────────────────────────────────────────────
mkdir -p "$T/site"
cat > "$T/site/router.php" <<'PHP'
<?php
$u = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
file_put_contents(__DIR__ . '/requests.log', $_SERVER['REQUEST_METHOD'] . ' ' . $_SERVER['REQUEST_URI'] . "\t" . ($_SERVER['HTTP_USER_AGENT'] ?? '') . "\n", FILE_APPEND);
if (($_SERVER['HTTP_USER_AGENT'] ?? '') === '') { http_response_code(403); echo 'no agent'; return true; }
$page = function ($body) { header('Content-Type: text/html; charset=UTF-8'); echo "<html><body>{$body}</body></html>"; };
switch ($u) {
  case '/':
    $page('<a href="/about/">About</a> <a href="/missing/">gone</a> <a href="contact/">Contact</a>
           <img src="/img/logo.png"> <img src=\'/img/gone.jpg\'> <a href="https://supplier.invalid/catalog">Supplier</a>
           <a href="/wp-admin/">admin</a> <a href="/wp-login.php">login</a> <a href="/lighthouse/">slug</a>
           <a href="/wp-json/wp/v2/users">api</a> <a href="mailto:x@y.example">mail</a> <a href="#top">top</a>');
    return true;
  case '/about/':
    $page('<a href="/">Home</a> <a href="/missing/">gone again</a> <a href="/about/#team">team</a> <a href="/broken500/">err</a>
           <a href="https://supplier.invalid/other">Supplier 2</a> <a href="https://www.facebook.invalid/x">fb</a>');
    return true;
  case '/contact/':  $page('<p>Call us</p> <a href="/?s=services">search</a>'); return true;
  case '/img/logo.png': header('Content-Type: image/png'); echo "\x89PNG"; return true;
  case '/broken500/': http_response_code(500); echo 'fatal'; return true;
  default: http_response_code(404); echo 'not found'; return true;
}
PHP
PORT=$(( 20000 + RANDOM % 20000 ))
php -S "127.0.0.1:${PORT}" -t "$T/site" "$T/site/router.php" >/dev/null 2>&1 & SRV=$!
for _i in $(seq 1 50); do curl -s -o /dev/null -A t "http://127.0.0.1:${PORT}/" && break; sleep 0.1; done
BASE="http://127.0.0.1:${PORT}/"

_suite() { # label shell pathprefix
  L="$1"; SH="$2"; PP="$3"; W="$T/$L"; mkdir -p "$W/bin"
  : > "$T/site/requests.log"
  echo ""
  echo "  ── under ${L}"
  _b() { env PATH="$W/bin:$PP" WP_ADMIN_SLUG=lighthouse "$SH" "$TOOL" broken --url "$BASE" --delay 0 "$@" 2>&1; }
  out=$(_b); rc=$?
  plain=$(printf '%s\n' "$out" | sed 's/\x1b\[[0-9;]*m//g')
  [ "$rc" = 1 ] && printf '%s' "$plain" | grep -q '3 broken link(s)' \
    && _p "$L: three broken links found, exit 1" || _f "$L: count" "rc=$rc $plain"
  printf '%s\n' "$plain" | awk -v u="${BASE}missing/" '$1 == u { f = 1; next } f && /404/ { a = 1 } f && /linked from 2 page/ { b = 1 } END { exit !(a && b) }' \
    && _p "$L: a missing page: 404, linked from both pages that link to it" || _f "$L: missing page" "$plain"
  printf '%s' "$plain" | grep -q "${BASE}img/gone.jpg" && ! printf '%s' "$plain" | grep -q "${BASE}img/logo.png" \
    && _p "$L: a missing image is reported; the one that exists is not" || _f "$L: images" "$plain"
  printf '%s' "$plain" | grep -q '500 — the server failed on it' \
    && _p "$L: a server error is reported in words" || _f "$L: 500" "$plain"
  ! grep -qE ' /(wp-admin|wp-login\.php|lighthouse|wp-json)' "$T/site/requests.log" \
    && _p "$L: admin, login, login-slug and API paths are never requested" || _f "$L: crawled a forbidden path" "$(grep -E 'wp-|lighthouse' "$T/site/requests.log")"
  ! grep -q '/?s=' "$T/site/requests.log" && _p "$L: site search is not crawled" || _f "$L: crawled search" ""
  ! awk -F '\t' '$2 == ""' "$T/site/requests.log" | grep -q . && grep -q 'WASP-LinkCheck' "$T/site/requests.log" \
    && _p "$L: every request carries a browser identity" || _f "$L: user agent" "$(cat "$T/site/requests.log")"
  grep -q '^GET /contact/' "$T/site/requests.log" && _p "$L: a relative link (contact/) is resolved and crawled" || _f "$L: relative" ""
  [ "$(grep -c '^GET /about/' "$T/site/requests.log")" = 1 ] && _p "$L: a page is fetched once, fragments ignored" || _f "$L: refetch" "$(grep about "$T/site/requests.log")"
  { printf '%s' "$plain" | grep -q 'Links to other sites: 2 domain(s), NOT checked' \
    && printf '%s' "$plain" | grep -qE 'supplier\.invalid +2'; } \
    && _p "$L: other sites' links are listed by domain, never fetched" || _f "$L: externals" "$plain"
  printf '%s' "$plain" | grep -q "header 'User-Agent: Mozilla/5.0 (compatible; WASP-LinkCheck/1.0)'" \
    && _p "$L: and the workstation command to check them is printed" || _f "$L: workstation cmd" ""
  out=$(_b --max-pages 1 | sed 's/\x1b\[[0-9;]*m//g')
  printf '%s' "$out" | grep -q 'Stopped at 1 pages' && _p "$L: --max-pages stops and says so" || _f "$L: max" "$out"
  out=$(_b --max-pages x); [ $? = 1 ] && _p "$L: a bad --max-pages is refused" || _f "$L: bad max" ""

  # ── spam: plumbing only (the scanner itself is test-links.php) ──
  printf '#!%s\nprintf "%%s\\n" "$*" > "%s/podman.args"; cat > "%s/podman.stdin"; echo REPORT; exit "$(cat "%s/rc")"\n' \
    "$SH" "$W" "$W" "$W" > "$W/bin/podman"
  printf '#!%s\n{ echo "TAG=$1"; echo "SUBJECT=$2"; echo "TO=${NOTIFY_EMAIL:-}"; cat "$3"; } > "%s/mail"\n' "$SH" "$W" > "$W/bin/notify"
  printf '#!%s\nexit 0\n' "$SH" > "$W/bin/logger"
  chmod +x "$W/bin/"*
  printf '<?php echo 1;\n' > "$W/scanner.php"
  mkdir -p "$W/secrets"; printf 'to = ops@example.com\ncontent_spam = on\n' > "$W/secrets/alerts.ini"
  _s() { env PATH="$W/bin:$PP" WASP_CONTENT_SCANNER="$W/scanner.php" WASP_NOTIFY="$W/bin/notify" \
           WASP_SECRETS_DIR="$W/secrets" "$SH" "$TOOL" spam "$@" 2>&1; }
  echo 1 > "$W/rc"; rm -f "$W/mail"
  out=$(_s --json); rc=$?
  { [ "$rc" = 1 ] && [ "$out" = REPORT ] && grep -q 'exec -i --user www-data wordpress php' "$W/podman.args" \
    && grep -q -- '-- --json' "$W/podman.args" && cmp -s "$W/scanner.php" "$W/podman.stdin"; } \
    && _p "$L: spam runs the scanner in the container, as www-data, options passed, exit code kept" \
    || _f "$L: spam plumbing" "rc=$rc out=$out args=$(cat "$W/podman.args")"
  out=$(_s --notify); rc=$?
  { [ "$rc" = 1 ] && grep -q 'TAG=wp-content-spam' "$W/mail" && grep -q 'TO=ops@example.com' "$W/mail" && grep -q REPORT "$W/mail"; } \
    && _p "$L: --notify emails the report to the alert recipients when spam is found" || _f "$L: notify" "$(cat "$W/mail" 2>/dev/null)"
  echo 0 > "$W/rc"; rm -f "$W/mail"; _s --notify >/dev/null
  [ ! -f "$W/mail" ] && _p "$L: ...and stays silent when the site is clean" || _f "$L: mailed when clean" ""
  echo 1 > "$W/rc"; printf 'to = ops@example.com\ncontent_spam = off\n' > "$W/secrets/alerts.ini"; _s --notify >/dev/null
  [ ! -f "$W/mail" ] && _p "$L: ...and when content_spam is turned off" || _f "$L: ignored off" ""
  echo 2 > "$W/rc"; out=$(_s); rc=$?
  [ "$rc" = 2 ] && printf '%s' "$out" | grep -q 'did not run' && _p "$L: a scan that cannot run says so (exit 2), not \"clean\"" || _f "$L: error path" "$out"

  # ── clean: plumbing (the cleaner itself is test-links-clean.php) ──
  # wp-plugins.sh __wp stand-in: one line per call in calls, each argument on its own line in args.N.
  cat > "$W/bin/wp-plugins" <<EOF
#!$SH
[ "\$1" = __wp ] || exit 9; shift
if [ "\$1 \$2" = "user list" ]; then echo 1; exit 0; fi
n=\$(( \$(cat "$W/n" 2>/dev/null || echo 0) + 1 )); echo \$n > "$W/n"
printf '%s\n' "\$@" > "$W/args.\$n"; echo "wp \$*" >> "$W/calls"; echo "WPCLI_MOUNT=\$WPCLI_MOUNT" >> "$W/calls"
case " \$* " in *" export-indexnow "*) echo '{"log":1}'; exit 0 ;; esac
case " \$* " in *" apply "*) echo APPLIED; exit 0 ;; esac
echo PLAN; exit "\$(cat "$W/planrc" 2>/dev/null || echo 0)"
EOF
  printf '#!%s\necho backup >> "%s/calls"; exit "$(cat "%s/bkrc" 2>/dev/null || echo 0)"\n' "$SH" "$W" "$W" > "$W/bin/dbbackup"
  chmod +x "$W/bin/wp-plugins" "$W/bin/dbbackup"
  mkdir -p "$W/tools"; : > "$W/tools/wasp-content-clean.php"
  _c() { rm -f "$W/calls" "$W/n" "$W"/args.*; env PATH="$W/bin:$PP" WASP_CONTENT_SCANNER="$W/scanner.php" WASP_WP_PLUGINS="$W/bin/wp-plugins" \
           WASP_DB_BACKUP="$W/bin/dbbackup" WASP_PHP_TOOLS="$W/tools" WASP_EVIDENCE_DIR="$W/ev" WASP_SECRETS_DIR="$W/secrets" \
           "$SH" "$TOOL" clean "$@" < /dev/null > "$W/c.out" 2>&1; _crc=$?
         sed 's/\x1b\[[0-9;]*m//g' "$W/c.out"; return "$_crc"; }
  echo 0 > "$W/planrc"; echo 0 > "$W/bkrc"; echo 1 > "$W/rc"; rm -rf "$W/ev"
  out=$(_c)
  { grep -qx report "$W/args.1" && grep -q -- '--user=1 eval-file /tmp/wasp-php-tools/wasp-content-clean.php --use-include' "$W/calls" \
    && grep -q "WPCLI_MOUNT=-v $W/tools:/tmp/wasp-php-tools:ro" "$W/calls" && ! grep -qx apply "$W/args.1"; } \
    && _p "$L: clean with no names reports, through WP-CLI as an administrator, the tools mounted read-only" || _f "$L: clean report" "$(cat "$W/calls") $out"
  out=$(_c --widgets 'w1;rm'); rc=$?
  [ "$rc" = 1 ] && [ ! -f "$W/calls" ] && _p "$L: a malformed widget list is refused before WordPress is touched" || _f "$L: bad ids" "rc=$rc $out"
  out=$(_c --links 'Casino-Spam.example,casino-vegas.example')
  grep -qx 'links=casino-spam.example,casino-vegas.example' "$W/args.1" && _p "$L: --links passes the domains, lower-cased, to the cleaner" || _f "$L: links arg" "$(cat "$W/args.1" 2>/dev/null)"
  out=$(_c --links 'casino.example;rm -rf /'); rc=$?
  [ "$rc" = 1 ] && [ ! -f "$W/calls" ] && _p "$L: a malformed --links list is refused before WordPress is touched" || _f "$L: bad links" "rc=$rc $out"
  out=$(_c --title 'x=Foo'); rc=$?
  [ "$rc" = 1 ] && _p "$L: --title needs a post ID" || _f "$L: bad title" "$out"
  out=$(_c --widgets w1spam1,w2spam2 --title '327=Commercial Services & Repairs' --trash 512 --revisions --indexnow)
  { grep -qx 'widgets=w1spam1,w2spam2' "$W/args.1" && grep -qx 'title=327=Commercial Services & Repairs' "$W/args.1" \
    && grep -qx 'trash=512' "$W/args.1" && grep -qx revisions "$W/args.1" && grep -qx indexnow "$W/args.1" \
    && ! grep -qx apply "$W/args.1" && [ ! -d "$W/ev" ] && printf '%s' "$out" | grep -q 'Nothing was changed'; } \
    && _p "$L: without --apply: a preview, a title with spaces passed whole, no evidence written" || _f "$L: preview" "$(cat "$W/args.1" 2>/dev/null) $out"
  out=$(_c --widgets w1spam1 --apply); rc=$?
  [ "$rc" = 1 ] && ! grep -q ' apply' "$W/calls" && ! grep -q backup "$W/calls" && printf '%s' "$out" | grep -q 'add --yes' \
    && _p "$L: --apply off a terminal needs --yes; nothing applied" || _f "$L: no tty" "rc=$rc $out"
  out=$(_c --widgets w1spam1 --revisions --apply --yes); rc=$?
  _ev=$(ls -d "$W/ev"/content-spam-* 2>/dev/null | head -1)
  { [ -n "$_ev" ] && [ -s "$_ev/plan.txt" ] && [ -f "$_ev/scan-before.txt" ] && grep -q '"log"' "$_ev/indexnow-log.json" \
    && grep -q APPLIED "$_ev/applied.txt" && [ -f "$_ev/scan-after.txt" ] && [ "$(stat -c %a "$_ev")" = 700 ]; } \
    && _p "$L: --apply saves the plan, the scan before and after, and the IndexNow log (0700)" || _f "$L: evidence" "$(ls -la "$_ev" 2>&1) $out"
  { [ "$(grep -n backup "$W/calls" | cut -d: -f1)" -lt "$(grep -n ' apply' "$W/calls" | cut -d: -f1)" ] && grep -qx apply "$W/args.3"; } 2>/dev/null \
    && _p "$L: ...takes a database backup before the change" || _f "$L: order" "$(cat "$W/calls")"
  [ "$rc" = 1 ] && printf '%s' "$out" | grep -q 'still finds something' \
    && _p "$L: ...and says when the scan afterwards still finds spam (exit 1)" || _f "$L: after" "rc=$rc $out"
  echo 0 > "$W/rc"; out=$(_c --widgets w1spam1 --apply --yes); rc=$?
  [ "$rc" = 0 ] && printf '%s' "$out" | grep -q 'now finds no spam' && _p "$L: ...or that it is now clean (exit 0)" || _f "$L: clean after" "rc=$rc $out"
  echo 1 > "$W/bkrc"; out=$(_c --widgets w1spam1 --apply --yes); rc=$?
  [ "$rc" = 2 ] && ! grep -q ' apply' "$W/calls" && printf '%s' "$out" | grep -q 'backup failed' \
    && _p "$L: a failed database backup stops it before any change" || _f "$L: backup fail" "rc=$rc $(cat "$W/calls")"
  echo 0 > "$W/bkrc"; echo 1 > "$W/planrc"; out=$(_c --widgets nosuch --apply --yes); rc=$?
  [ "$rc" = 1 ] && ! grep -q ' apply' "$W/calls" && ! grep -q backup "$W/calls" \
    && _p "$L: when the cleaner refuses part of the plan, nothing is applied" || _f "$L: plan refused" "rc=$rc $(cat "$W/calls")"
}

_suite host /bin/sh "/usr/local/bin:/usr/bin:/bin"
if [ -n "$BB" ] && "$BB" --list >/dev/null 2>&1; then
  mkdir -p "$T/bb"; for _a in $("$BB" --list); do ln -sf "$BB" "$T/bb/$_a"; done
  ln -sf "$(command -v curl)" "$T/bb/curl"      # curl is a real package on the VM too
  _suite busybox "$T/bb/sh" "$T/bb"
else
  _f "BusyBox not found: the Alpine-shell pass did not run" "set BUSYBOX=/path/to/busybox"
fi

echo ""
echo "  links: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" = 0 ]
