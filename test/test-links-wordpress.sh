#!/usr/bin/env bash
# =============================================================================
# test-links-wordpress.sh — the content scan and clean-up against REAL WordPress
# =============================================================================
#
# test-links.php and test-links-clean.php drive the scanner and the cleaner
# with stand-ins for WordPress. This runs them for real: a WordPress core
# checkout and WP-CLI on a throwaway MariaDB, seeded with spam the way each
# builder and theme stores it, then:
#
#   - the scan (wasp-content-scan.php, straight from the database) finds every
#     place: classic HTML, block editor and a block plugin's settings, Divi and
#     WPBakery shortcodes (URL-encoded too), Beaver Builder's serialized layout
#     objects, Elementor data, a site-editor footer, the Customizer, a sidebar
#     widget, a menu item, a spam article
#   - a preview changes nothing (table checksums before and after)
#   - links= plus trash= then removes all of it, through WP-CLI as WordPress
#     runs it, and the scan afterwards finds nothing
#   - what must stay, stays: real paragraphs keep their words, the real Divi
#     module, the theme's other settings, the real menu item; Beaver's layout is
#     still objects; the block content still parses as blocks
#
# With WASP_TEST_ELEMENTOR (an Elementor plugin directory) the Elementor pages
# are cleaned through Elementor's own document save, and the page's HTML copy
# is checked to have been rebuilt by it: --widgets, and links= too.
#
# Needs: WASP_TEST_WP (a WordPress checkout), WASP_TEST_WPCLI (wp-cli.phar),
# mariadbd and mariadb, php with mysqli. Without them it says SKIPPED and why;
# run it before every release that touches the content tools.
# =============================================================================
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0; FAIL=0
_p() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
_f() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n         %s\n' "$1" "${2:-}"; }
echo ""
echo "Content scan and clean-up on real WordPress"
WPSRC="${WASP_TEST_WP:-}"; WPCLI="${WASP_TEST_WPCLI:-}"
if [ -z "$WPSRC" ] || [ ! -f "$WPSRC/wp-load.php" ] || [ -z "$WPCLI" ] || [ ! -f "$WPCLI" ] \
   || ! command -v mariadbd >/dev/null 2>&1 || ! php -m | grep -qi mysqli; then
  echo "  SKIPPED: set WASP_TEST_WP=<WordPress checkout> and WASP_TEST_WPCLI=<wp-cli.phar>; needs mariadbd and php-mysqli"
  exit 0
fi
T=$(mktemp -d); PORT=$((34000 + RANDOM % 2000))
cleanup() { [ -n "${DBPID:-}" ] && kill "$DBPID" 2>/dev/null; wait 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
mariadb-install-db --no-defaults --datadir="$T/db" --user=root --auth-root-authentication-method=normal >/dev/null 2>&1
mariadbd --no-defaults --datadir="$T/db" --socket="$T/m.sock" --port="$PORT" --bind-address=127.0.0.1 --user=root >"$T/m.log" 2>&1 &
DBPID=$!
for _ in $(seq 1 30); do mariadb --no-defaults -S "$T/m.sock" -u root -e 'SELECT 1' >/dev/null 2>&1 && break; sleep 1; done
mariadb --no-defaults -S "$T/m.sock" -u root -e "CREATE DATABASE wp; CREATE USER 'wp'@'127.0.0.1' IDENTIFIED BY 'wp'; GRANT ALL ON wp.* TO 'wp'@'127.0.0.1';"
cp -a "$WPSRC" "$T/wp"; rm -f "$T/wp/wp-config.php"
W() { php "$WPCLI" --allow-root --path="$T/wp" "$@"; }
W config create --dbname=wp --dbuser=wp --dbpass=wp --dbhost="127.0.0.1:$PORT" --skip-check >/dev/null 2>&1
W core install --url=https://shop.example --title=Shop --admin_user=owner --admin_password="pw$RANDOM$RANDOM" \
  --admin_email=owner@shop.example --skip-email >/dev/null 2>&1 || { _f "WordPress did not install" "$(tail -5 "$T/m.log")"; exit 1; }
mkdir -p "$T/tools"; cp "$REPO/payload/php-tools/"*.php "$T/tools/"
EL=0
if [ -n "${WASP_TEST_ELEMENTOR:-}" ] && [ -f "${WASP_TEST_ELEMENTOR}/elementor.php" ]; then
  cp -a "$WASP_TEST_ELEMENTOR" "$T/wp/wp-content/plugins/elementor"
  W plugin activate elementor >/dev/null 2>&1 && [ "$(W eval 'echo class_exists("\\Elementor\\Plugin") ? 1 : 0;' 2>/dev/null)" = 1 ] && EL=1
  [ "$EL" = 1 ] && _p "Elementor $(W eval 'echo ELEMENTOR_VERSION;' 2>/dev/null) is active: its pages are saved through Elementor" \
               || _f "WASP_TEST_ELEMENTOR given but Elementor did not activate" ""
else
  echo "  (no WASP_TEST_ELEMENTOR: Elementor pages are written directly, as on a site without the plugin)"
fi

# ── seed: spam the way each builder and theme stores it ──
cat > "$T/seed.php" <<'PHP'
<?php
$c = 'casino-spam.example'; $v = 'casino-vegas.example';
$id = function ($t, $content, $type = 'page', $name = '') {
    return wp_insert_post(wp_slash(array('post_title' => $t, 'post_name' => $name ?: sanitize_title($t), 'post_type' => $type,
                                         'post_status' => 'publish', 'post_content' => $content)));
};
$ids = array();
$ids['classic'] = $id('Classic', "<p>Our patios are made to order.</p>\n<p>Gioca al casino online con <a href=\"https://{$c}/\">bonus</a></p>\n<p>We install patios. <a href=\"https://www.{$c}/x\">more</a> Call us.</p>");
$ids['blocks'] = $id('Blocks', "<!-- wp:paragraph -->\n<p>Welcome.</p>\n<!-- /wp:paragraph -->\n\n<!-- wp:paragraph -->\n<p>Best casino bonus <a href=\"https://{$v}/\">here</a></p>\n<!-- /wp:paragraph -->\n\n"
    . "<!-- wp:buttons -->\n<div class=\"wp-block-buttons\"><!-- wp:button -->\n<div class=\"wp-block-button\"><a class=\"wp-block-button__link wp-element-button\" href=\"https://{$c}/\">Play</a></div>\n<!-- /wp:button --></div>\n<!-- /wp:buttons -->\n\n"
    . "<!-- wp:kadence/advancedbtn {\"url\":\"https://{$v}/go\"} /-->");
$ids['divi'] = $id('Divi', "[et_pb_section][et_pb_row][et_pb_column type=\"4_4\"][et_pb_text]<p>Our work</p>[/et_pb_text][et_pb_button button_url=\"https://{$c}/\" button_text=\"Play\"][/et_pb_button][/et_pb_column][/et_pb_row][/et_pb_section]");
$ids['wpb'] = $id('WPBakery', "[vc_row][vc_column][vc_column_text]Real text[/vc_column_text][vc_btn title=\"Bonus\" link=\"url:https%3A%2F%2F{$v}%2Fjoin|title:Join\"][/vc_column][/vc_row]");
$ids['beaver'] = $id('Beaver', '');
update_post_meta($ids['beaver'], '_fl_builder_data', array(
    'n1' => (object) array('node' => 'n1', 'type' => 'module', 'settings' => (object) array('text' => "<p>Online casino <a href=\"https://{$c}/\">x</a></p>")),
    'n2' => (object) array('node' => 'n2', 'type' => 'module', 'settings' => (object) array('text' => '<p>Our team</p>'))));
$ids['elementor'] = $id('Elementor', "<p>Commercial.</p><p><a href=\"https://{$v}/\">x</a> casino premi</p>");
update_post_meta($ids['elementor'], '_elementor_data', wp_slash(wp_json_encode(array(array('id' => 'c1', 'elType' => 'container', 'elements' => array(
    array('id' => 'a1clean', 'elType' => 'widget', 'widgetType' => 'text-editor', 'settings' => array('editor' => '<p>Commercial.</p>')),
    array('id' => 'w1spam1', 'elType' => 'widget', 'widgetType' => 'text-editor', 'settings' => array('editor' => "<p><a href=\"https://{$v}/\">x</a> casino premi</p>"))))))));
$ids['elementor2'] = $id('Elementor two', '<p>Our yard.</p><p>Gioca al casino online</p>');
update_post_meta($ids['elementor2'], '_elementor_edit_mode', 'builder');
update_post_meta($ids['elementor2'], '_elementor_template_type', 'wp-page');
update_post_meta($ids['elementor2'], '_elementor_data', wp_slash(wp_json_encode(array(array('id' => 'c2', 'elType' => 'container', 'settings' => array(), 'elements' => array(
    array('id' => 'b2real', 'elType' => 'widget', 'widgetType' => 'text-editor', 'settings' => array('editor' => '<p>Our yard.</p>'), 'elements' => array()),
    array('id' => 'w9spam9', 'elType' => 'widget', 'widgetType' => 'text-editor', 'settings' => array('editor' => "<p><span data-sheets-root=\"1\">Gioca al casino online <a class=\"in-cell-link\" href=\"https://{$c}/\">bonus</a></span></p>"), 'elements' => array())))))));
update_post_meta($ids['elementor'], '_elementor_edit_mode', 'builder');
update_post_meta($ids['elementor'], '_elementor_template_type', 'wp-page');
$ids['footer'] = $id('Footer', "<!-- wp:paragraph -->\n<p>Powered by casino partner <a href=\"https://{$c}/\">here</a></p>\n<!-- /wp:paragraph -->", 'wp_template_part', 'footer');
$ids['article'] = $id('Esimerkki', '<p>Pelaajat arvostavat.</p>', 'post', 'kasinon-esimerkki-artikkeli');
// Revisions. A Home page about "specialists" (which once counted as spam: "cialis"),
// edited twice, and a page that held a spam link for one save and was then fixed.
$ids['home'] = $id('Home', '<p>Patio specialists since 1985.</p>');
wp_update_post(wp_slash(array('ID' => $ids['home'], 'post_content' => '<p>Your patio specialists. Stone from <a href="https://www.stonespecialists.example/">our supplier</a>.</p>')));
wp_update_post(wp_slash(array('ID' => $ids['home'], 'post_content' => '<p>Your patio specialists since 1985.</p>')));
$ids['spamrev'] = $id('Decks', '<p>Decks to order.</p>');
wp_update_post(wp_slash(array('ID' => $ids['spamrev'], 'post_content' => "<p>Decks. Gioca al casino online <a href=\"https://{$c}/\">bonus</a></p>")));
wp_update_post(wp_slash(array('ID' => $ids['spamrev'], 'post_content' => '<p>Decks to order.</p>')));
set_theme_mod('footer_text', "Built by us · <a href=\"https://{$v}/\">partner</a>");
set_theme_mod('accent', '#336699');
update_option('widget_custom_html', array(3 => array('title' => '', 'content' => "<p>casino bonus <a href=\"https://{$c}/\">x</a></p>"), '_multiwidget' => 1));
$m = wp_create_nav_menu('Main');
wp_update_nav_menu_item($m, 0, array('menu-item-title' => 'Promo', 'menu-item-url' => "https://www.{$v}/", 'menu-item-status' => 'publish', 'menu-item-type' => 'custom'));
wp_update_nav_menu_item($m, 0, array('menu-item-title' => 'Contact', 'menu-item-url' => 'https://shop.example/contact/', 'menu-item-status' => 'publish', 'menu-item-type' => 'custom'));
echo json_encode($ids);
PHP
IDS=$(W eval-file "$T/seed.php" 2>&1 | tail -1)
_id() { printf '%s' "$IDS" | php -r '$j = json_decode(stream_get_contents(STDIN), true); echo $j[$argv[1]] ?? "";' "$1"; }
[ -n "$(_id classic)" ] && _p "seeded: classic, blocks, Divi, WPBakery, Beaver, Elementor, a site-editor footer, Customizer, widget, menu, an article" \
  || { _f "seeding failed" "$IDS"; exit 1; }

_scan() { env WORDPRESS_DB_HOST="127.0.0.1:$PORT" WORDPRESS_DB_USER=wp WORDPRESS_DB_PASSWORD=wp WORDPRESS_DB_NAME=wp \
            WORDPRESS_TABLE_PREFIX=wp_ php "$T/tools/wasp-content-scan.php" "$@" 2>&1; }
_clean() { W --user=1 eval-file "$T/tools/wasp-content-clean.php" --use-include "$@" 2>&1; }
_get_raw() { mariadb --no-defaults -S "$T/m.sock" -u root -N -e "SELECT post_content FROM wp.wp_posts WHERE ID=$1"; }
_sum() { mariadb --no-defaults -S "$T/m.sock" -u root -N -e 'CHECKSUM TABLE wp.wp_posts, wp.wp_postmeta, wp.wp_options' | awk '{print $2}' | tr '\n' ' '; }

# ── the scan finds every place ──
out=$(_scan); rc=$?
miss=""
for want in 'Classic  (page' 'Blocks  (page' 'Divi  (page' 'WPBakery  (page' 'Beaver Builder layout' 'Elementor widget w1spam1' \
            'site editor template part (header/footer)' 'Setting theme_mods_' 'Sidebar widget widget_custom_html' 'Menu item "Promo"' \
            'address is a spam article: /kasinon-esimerkki-artikkeli/' 'casino-vegas.example' 'casino-spam.example'; do
  printf '%s' "$out" | grep -qF -- "$want" || miss="${miss} [$want]"
done
[ "$rc" = 1 ] && [ -z "$miss" ] && _p "the scan, straight from the database, finds every place, each builder and theme named" \
  || _f "scan" "rc=$rc missing:${miss}
$out"
printf '%s' "$out" | grep -q 'Menu item "Contact"' && _f "a real menu item was reported" "" || _p "...and not the real menu item"
printf '%s' "$out" | grep -q 'clean --links casino-spam.example,casino-vegas.example\|clean --links casino-vegas.example,casino-spam.example' \
  && _p "...ending with the clean command that names both domains" || _f "scan next step" "$(printf '%s' "$out" | grep -A3 'What to do')"

# ── revisions: the scan's count and the cleaner's list are one test ──
# Until 10.23 the scan counted revisions by SQL LIKE '%cialis%': every revision
# of a page saying "specialists" was spam, while the cleaner (rightly) found none.
_hr=$(mariadb --no-defaults -S "$T/m.sock" -u root -N -e "SELECT COUNT(*) FROM wp.wp_posts WHERE post_type='revision' AND post_parent=$(_id home)")
_ns=$(_scan | sed -n 's/^ *\([0-9][0-9]*\) saved revision(s) also hold spam.*/\1/p'); _ns=${_ns:-0}
_rep=$(_clean report)
_nc=$(printf '%s\n' "$_rep" | sed -n 's/^ *page [0-9]*: \([0-9][0-9]*\) of its revisions hold spam.*/\1/p' | awk '{ t += $1 } END { print t + 0 }')
{ [ "${_hr:-0}" -ge 2 ] && [ "$_nc" -ge 1 ] && [ "$_ns" = "$_nc" ] && ! printf '%s' "$_rep" | grep -q "page $(_id home):" \
  && printf '%s' "$_rep" | grep -q "page $(_id spamrev):"; } \
  && _p "revisions: the scan counts what the cleaner would delete ($_nc); the specialists page's $_hr are not spam" \
  || _f "revision count" "home revisions=$_hr scan=$_ns cleaner=$_nc
$_rep"

# ── --widgets: one Elementor widget by ID ──
out=$(_clean "widgets=w9spam9" apply); wrc=$?
e2=$(W post meta get "$(_id elementor2)" _elementor_data 2>/dev/null); c2=$(_get_raw "$(_id elementor2)")
if [ "$EL" = 1 ]; then
  { [ "$wrc" = 0 ] && printf '%s' "$e2" | grep -q b2real && ! printf '%s' "$e2" | grep -q w9spam9 && ! printf '%s' "$out" | grep -q 'saved directly' \
    && ! printf '%s' "$c2" | grep -qi casino && printf '%s' "$c2" | grep -q 'Our yard'; } \
    && _p "--widgets: the widget is removed through Elementor's save, which rebuilt the page's HTML copy without it" \
    || _f "--widgets via Elementor" "rc=$wrc out=$out
data=$e2
content=$c2"
else
  { [ "$wrc" = 1 ] && printf '%s' "$out" | grep -q 'saved directly' && ! printf '%s' "$e2" | grep -q w9spam9 && printf '%s' "$out" | grep -q 'HTML copy still holds the spam wording'; } \
    && _p "--widgets without Elementor: the data is written, and the page's stale HTML copy is named (exit 1)" || _f "--widgets direct" "rc=$wrc $out"
fi

# ── report and preview change nothing ──
s0=$(_sum)
out=$(_clean report)
printf '%s' "$out" | grep -q 'remove them all, whichever builder holds them:  --links' && _p "report lists the spam domains and the --links command" || _f "report" "$out"
out=$(_clean "links=casino-spam.example,casino-vegas.example" "trash=$(_id article)")
s1=$(_sum)
{ [ "$s0" = "$s1" ] && printf '%s' "$out" | grep -q 'would remove' && printf '%s' "$out" | grep -q "would move post $(_id article)"; } \
  && _p "a preview names every change and the tables are byte-for-byte unchanged" || _f "preview" "$s0 / $s1
$out"

# ── apply, then the scan finds nothing ──
out=$(_clean "links=casino-spam.example,casino-vegas.example" "trash=$(_id article)" apply); crc=$?
[ "$crc" = 0 ] && _p "apply succeeds through WP-CLI" || _f "apply" "rc=$crc $out"
after=$(_scan); rc=$?
if [ "$EL" = 1 ]; then
  [ "$rc" = 0 ] && _p "the scan afterwards finds nothing, in any builder or setting" || _f "scan after" "$after
--- clean output:
$out"
else
  # Without the plugin, Elementor's HTML copy of a page cleaned by --widgets cannot be rebuilt;
  # the scan names that page, and only that page, for "Update" in Elementor.
  _left=$(printf '%s' "$after" | grep -E '^  [^ ].*\((page|post|setting|site editor)' | grep -v 'Elementor two' || true)
  { [ "$rc" = 1 ] && printf '%s' "$after" | grep -q 'Elementor two' && [ -z "$_left" ]; } \
    && _p "the scan afterwards finds nothing but the stale HTML copy of the --widgets page, which it names" || _f "scan after (no Elementor)" "$after"
fi

# ── what must stay, stays ──
_get() { W post get "$1" --field=content 2>/dev/null; }
c=$(_get "$(_id classic)")
{ printf '%s' "$c" | grep -q 'Our patios are made to order.' && printf '%s' "$c" | grep -q 'We install patios.  Call us.' \
  && ! printf '%s' "$c" | grep -qi 'casino\|gioca'; } && _p "classic: the spam paragraph is gone; the real ones keep their words" || _f "classic" "$c"
b=$(_get "$(_id blocks)")
nb=$(W eval "echo count(array_filter(parse_blocks(get_post($(_id blocks))->post_content), function (\$x) { return \$x['blockName']; }));" 2>/dev/null)
{ printf '%s' "$b" | grep -q '<p>Welcome.</p>' && ! printf '%s' "$b" | grep -qi 'casino\|kadence\|wp:button '; } \
  && [ "$nb" = 2 ] && _p "blocks: the spam block, the button and the block plugin's button are gone; it still parses (welcome + empty buttons group)" \
  || _f "blocks" "blocks=$nb
$b"
d=$(_get "$(_id divi)")
[ "$d" = '[et_pb_section][et_pb_row][et_pb_column type="4_4"][et_pb_text]<p>Our work</p>[/et_pb_text][/et_pb_column][/et_pb_row][/et_pb_section]' ] \
  && _p "Divi: the button module is gone, the layout and the real module untouched" || _f "divi" "$d"
w=$(_get "$(_id wpb)")
[ "$w" = '[vc_row][vc_column][vc_column_text]Real text[/vc_column_text][/vc_column][/vc_row]' ] && _p "WPBakery: the URL-encoded button is gone" || _f "wpb" "$w"
bv=$(W eval "\$d = get_post_meta($(_id beaver), '_fl_builder_data', true); echo is_object(\$d['n2']) ? get_class(\$d['n2']) . '|' . \$d['n2']->settings->text . '|' . (strpos(serialize(\$d), 'casino') === false ? 'clean' : 'dirty') : 'not-objects';" 2>/dev/null)
[ "$bv" = 'stdClass|<p>Our team</p>|clean' ] && _p "Beaver Builder: its layout is still objects, the real module kept, the spam gone" || _f "beaver" "$bv"
el=$(W post meta get "$(_id elementor)" _elementor_data 2>/dev/null); ec=$(_get_raw "$(_id elementor)")
{ printf '%s' "$el" | grep -q 'a1clean' && ! printf '%s' "$el" | grep -q 'w1spam1\|casino' && ! printf '%s' "$ec" | grep -qi 'casino'; } \
  && _p "Elementor via links=$( [ "$EL" = 1 ] && echo ' (through Elementor'"'"'s save)' || echo ' (written directly)'): the spam widget gone, the real one kept, the HTML copy clean" \
  || _f "elementor" "$el
$ec"
tm=$(W eval 'echo get_theme_mod("footer_text") . "|" . get_theme_mod("accent");' 2>/dev/null)
[ "$tm" = 'Built by us · |#336699' ] && _p "Customizer: the footer text loses the link and keeps its words; other theme settings untouched" || _f "theme mods" "$tm"
mi=$(W menu item list main --fields=title --format=csv 2>/dev/null | tail -n +2 | tr '\n' ' ')
[ "$mi" = 'Contact ' ] && _p "menu: the spam item is deleted, the real one kept" || _f "menu" "$mi"
[ "$(W post get "$(_id article)" --field=post_status 2>/dev/null)" = trash ] && _p "the spam article is in the Trash" || _f "article" ""

echo ""
echo "  links on WordPress: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
