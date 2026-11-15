<?php
/**
 * test-links-clean.php — the content clean-up (payload/php-tools/wasp-content-clean.php)
 *
 * The cleaner runs inside WordPress through WP-CLI. Here it runs against a small
 * stand-in for the WordPress functions it calls, holding a site with the shape
 * of a real import: pasted casino links in two Elementor text widgets, a casino
 * advert on a page title, a spam article, spam in some revisions and not others,
 * IndexNow entries for spam and for real pages. Each scenario is a fresh process.
 *
 *   - preview (no "apply") changes nothing, and report lists the IDs to name
 *   - only NAMED widgets that also test as spam are removed; a typo and a real
 *     widget are refused and the page is left alone
 *   - a title is changed only where the old one is spam and the new one is not
 *   - posts are trashed, not deleted, and only when they hold spam
 *   - revisions holding spam are deleted; clean ones stay
 *   - IndexNow: spam entries dropped, the rest kept
 *
 * Run: php test/test-links-clean.php
 */
if (($argv[1] ?? '') === '--run') {
    // ── one scenario: a stand-in WordPress, then the cleaner ──
    define('ABSPATH', '/');
    $GLOBALS['S'] = json_decode(file_get_contents($argv[2]), true);
    $GLOBALS['OUT'] = array();
    class WP_CLI {
        static function line($s) { $GLOBALS['OUT'][] = $s; }
        static function error($s) { $GLOBALS['OUT'][] = "Error: $s"; wcct_done(1); }
        static function halt($c) { wcct_done($c); }
    }
    class WP_Error { public $m; function __construct($m) { $this->m = $m; } function get_error_message() { return $this->m; } }
    function wcct_done($rc) {
        file_put_contents($GLOBALS['argv'][3], json_encode(array('rc' => $rc, 'out' => $GLOBALS['OUT'], 'S' => $GLOBALS['S'])));
        exit(0);
    }
    class FakeWpdb {
        public $posts = 'wp_posts'; public $postmeta = 'wp_postmeta'; public $options = 'wp_options';
        function update($t, $data, $where) { $GLOBALS['S']['db_updates'][] = array($t, $data, $where);
            if ($t === 'wp_posts') { $p = &wcct_post($where['ID']); foreach ($data as $k => $v) { $p[$k] = $v; } }
            if ($t === 'wp_postmeta') { foreach ($GLOBALS['S']['meta'] as $pid => $keys) { foreach ($keys as $k => $v) {
                if (wcct_mid($pid, $k) === $where['meta_id']) { $GLOBALS['S']['meta'][$pid][$k] = maybe_unserialize($data['meta_value']); } } } }
            return 1; }
        function delete($t, $where) { foreach ($GLOBALS['S']['meta'] as $pid => $keys) { foreach ($keys as $k => $v) {
                if (wcct_mid($pid, $k) === $where['meta_id']) { unset($GLOBALS['S']['meta'][$pid][$k]); } } } return 1; }
        function get_results($q) {
            $S = $GLOBALS['S']; $o = array();
            if (strpos($q, 'FROM wp_options') !== false) {
                foreach ($S['options'] as $k => $v) { $o[] = (object) array('option_name' => $k, 'option_value' => maybe_serialize($v)); }
                return $o;
            }
            if (strpos($q, 'FROM wp_postmeta m') !== false) {
                foreach ($S['meta'] as $pid => $keys) {
                    $p = wcct_post($pid);
                    if (!$p || $p['post_type'] === 'revision' || $p['post_status'] === 'trash') { continue; }
                    if (strpos($q, "'nav_menu_item'") !== false && strpos($q, "meta_key = '_menu_item_url'") === false && $p['post_type'] === 'nav_menu_item') { continue; }
                    foreach ($keys as $k => $v) {
                        if (strpos($q, "meta_key = '_menu_item_url'") !== false && $k !== '_menu_item_url') { continue; }
                        $o[] = (object) array('meta_id' => wcct_mid($pid, $k), 'post_id' => $pid, 'meta_key' => $k, 'meta_value' => maybe_serialize($v));
                    }
                }
                return $o;
            }
            foreach ($S['posts'] as $p) {
                $isrev = $p['post_type'] === 'revision';
                if (strpos($q, "post_type = 'revision'") !== false && !$isrev) { continue; }
                if (strpos($q, "NOT IN ('revision'") !== false && $isrev) { continue; }
                if (strpos($q, "post_type IN ('post','page')") !== false && !in_array($p['post_type'], array('post', 'page'), true)) { continue; }
                if (strpos($q, "'trash')") !== false && $p['post_status'] === 'trash') { continue; }
                $ed = $S['meta'][$p['ID']]['_elementor_data'] ?? null;
                if (strpos($q, "JOIN wp_postmeta m ON m.post_id = p.ID AND m.meta_key = '_elementor_data'") !== false
                    && strpos($q, 'LEFT JOIN') === false && $ed === null) { continue; }
                $r = (object) $p; $r->edata = $ed; $o[] = $r;
            }
            return $o;
        }
    }
    $GLOBALS['wpdb'] = new FakeWpdb();
    function &wcct_post($id) { foreach ($GLOBALS['S']['posts'] as $k => &$p) { if ($p['ID'] == $id) { return $p; } } $n = null; return $n; }
    function home_url() { return $GLOBALS['S']['home']; }
    function wcct_mid($pid, $k) { return (int) $pid * 1000 + crc32($k) % 1000; }
    function maybe_unserialize($v) { if (is_string($v) && preg_match('/^(a|O|s|i|b|d):/', $v)) { $u = @unserialize($v); if ($u !== false || $v === 'b:0;') { return $u; } } return $v; }
    function maybe_serialize($v) { return (is_array($v) || is_object($v)) ? serialize($v) : $v; }
    function wp_cache_delete($k, $g) {}
    function wp_delete_post($id, $f) { foreach ($GLOBALS['S']['posts'] as $k => $p) { if ($p['ID'] == $id) { unset($GLOBALS['S']['posts'][$k]); } }
        $GLOBALS['S']['posts'] = array_values($GLOBALS['S']['posts']); unset($GLOBALS['S']['meta'][$id]); return true; }
    function get_post($id) { $p = wcct_post($id); return $p ? (object) $p : null; }
    function get_post_field($f, $id) { $p = wcct_post($id); return $p ? (string) $p[$f] : ''; }
    function get_post_meta($id, $k, $single) { return $GLOBALS['S']['meta'][$id][$k] ?? ''; }
    function update_post_meta($id, $k, $v) { $GLOBALS['S']['meta'][$id][$k] = stripslashes($v); return true; }
    function delete_post_meta($id, $k) { unset($GLOBALS['S']['meta'][$id][$k]); }
    function wp_slash($v) { return is_array($v) ? array_map('wp_slash', $v) : (is_string($v) ? addslashes($v) : $v); }
    function wp_json_encode($v, $f = 0) { return json_encode($v, $f); }
    function clean_post_cache($id) {}
    function is_wp_error($x) { return $x instanceof WP_Error; }
    function wp_update_post($a, $e) { $p = &wcct_post($a['ID']); $p['post_title'] = stripslashes($a['post_title']); return $a['ID']; }
    function wp_trash_post($id) { $p = &wcct_post($id); $p['post_status'] = 'trash'; return true; }
    function wp_delete_post_revision($id) {
        foreach ($GLOBALS['S']['posts'] as $k => $p) { if ($p['ID'] == $id) { unset($GLOBALS['S']['posts'][$k]); } }
        $GLOBALS['S']['posts'] = array_values($GLOBALS['S']['posts']); unset($GLOBALS['S']['meta'][$id]); return true;
    }
    function get_option($k, $d = false) { return $GLOBALS['S']['options'][$k] ?? $d; }
    function update_option($k, $v, $a = null) { $GLOBALS['S']['options'][$k] = $v; return true; }
    function wp_cache_flush() { $GLOBALS['S']['flushed'] = true; }
    // Elementor's save: the stand-in records it, and rebuilds the HTML copy from the widgets.
    class FakeDoc { public $id; function __construct($id) { $this->id = $id; }
        function save($d) { $GLOBALS['S']['meta'][$this->id]['_elementor_data'] = json_encode($d['elements']);
            $html = ''; array_walk_recursive($d['elements'], function ($v, $k) use (&$html) { if ($k === 'editor') { $html .= $v; } });
            $p = &wcct_post($this->id); $p['post_content'] = $html; $GLOBALS['S']['elementor_saves'][] = $this->id; return true; } }
    class FakeDocs { function get($id, $c) { return new FakeDoc($id); } }
    class FakeFiles { function clear_cache() { $GLOBALS['S']['css_cleared'] = true; } }
    if (!empty($GLOBALS['S']['with_elementor'])) {
        eval('namespace Elementor; class Plugin { public static $instance; public $documents; public $files_manager; }');
        \Elementor\Plugin::$instance = new \Elementor\Plugin();
        \Elementor\Plugin::$instance->documents = new FakeDocs();
        \Elementor\Plugin::$instance->files_manager = new FakeFiles();
    }
    $args = json_decode($argv[4], true);
    include dirname(__DIR__) . '/payload/php-tools/wasp-content-clean.php';
    wcct_done(0);
}

// ── the scenarios ────────────────────────────────────────────────────────────
$pass = 0; $fail = 0;
function t($ok, $msg, $detail = '') {
    global $pass, $fail;
    if ($ok) { $pass++; echo "  [PASS] {$msg}\n"; } else { $fail++; echo "  [FAIL] {$msg}\n" . ($detail !== '' ? "         {$detail}\n" : ''); }
}
function el($id, $html) { return array('id' => $id, 'elType' => 'widget', 'widgetType' => 'text-editor', 'settings' => array('editor' => $html)); }
function sec($w) { return array(array('id' => 'c' . substr(md5(json_encode($w)), 0, 6), 'elType' => 'container', 'elements' => $w)); }
$spam1 = '<p><span data-sheets-root="1"><a class="in-cell-link" href="https://casino-spam.example/">slotsbonus</a> grandi premi</span></p>';
$spam2 = '<p><a href="https://www.casino-vegas.example/">vegasbonus</a></p>';
$clean = '<p>Commercial services, installed.</p>';
$site = array(
    'home' => 'https://shop.example',
    'with_elementor' => true,
    'posts' => array(
        array('ID' => 327, 'post_type' => 'page', 'post_status' => 'publish', 'post_title' => 'Commercial Gioca al grande casino online', 'post_name' => 'commercial', 'post_content' => $clean . $spam1, 'post_parent' => 0, 'post_date_gmt' => '2026-02-12 10:00:00'),
        array('ID' => 226, 'post_type' => 'page', 'post_status' => 'publish', 'post_title' => 'Services', 'post_name' => 'services', 'post_content' => $spam2, 'post_parent' => 0, 'post_date_gmt' => '2026-02-12 10:00:00'),
        array('ID' => 40, 'post_type' => 'page', 'post_status' => 'publish', 'post_title' => 'Residential', 'post_name' => 'residential', 'post_content' => 'Our slotted posts.', 'post_parent' => 0, 'post_date_gmt' => '2025-01-01 10:00:00'),
        array('ID' => 512, 'post_type' => 'post', 'post_status' => 'publish', 'post_title' => 'Esimerkki', 'post_name' => 'kasinon-esimerkki-artikkeli', 'post_content' => '<p>Pelaajat…</p>', 'post_parent' => 0, 'post_date_gmt' => '2026-02-10 15:10:00'),
        array('ID' => 901, 'post_type' => 'revision', 'post_status' => 'inherit', 'post_title' => 'Commercial', 'post_name' => '', 'post_content' => $clean . $spam1, 'post_parent' => 327, 'post_date_gmt' => '2026-02-12 10:00:00'),
        array('ID' => 902, 'post_type' => 'revision', 'post_status' => 'inherit', 'post_title' => 'Commercial', 'post_name' => '', 'post_content' => '', 'post_parent' => 327, 'post_date_gmt' => '2026-11-14 13:44:00'),
        array('ID' => 903, 'post_type' => 'revision', 'post_status' => 'inherit', 'post_title' => 'Residential', 'post_name' => '', 'post_content' => 'Our slotted posts.', 'post_parent' => 40, 'post_date_gmt' => '2025-01-01 10:00:00'),
    ),
    'meta' => array(
        327 => array('_elementor_data' => json_encode(sec(array(el('a1clean', $clean), el('w1spam1', $spam1)))), '_elementor_css' => 'x'),
        226 => array('_elementor_data' => json_encode(sec(array(el('w2spam2', $spam2))))),
        40  => array('_elementor_data' => json_encode(sec(array(el('r1real', '<p>Our slotted posts.</p>'))))),
        902 => array('_elementor_data' => json_encode(sec(array(el('w1spam1', $spam1))))),
    ),
    'options' => array('rank_math_indexnow_log' => array(
        array('url' => 'https://shop.example/kasinon-esimerkki-artikkeli/', 'status' => 200, 'time' => 1770000000),
        array('url' => 'https://shop.example/residential/', 'status' => 200, 'time' => 1770000100),
    )),
);
function run(array $S, array $args) {
    $in = tempnam(sys_get_temp_dir(), 'wcc'); $out = tempnam(sys_get_temp_dir(), 'wcc');
    file_put_contents($in, json_encode($S));
    exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__FILE__) . ' --run ' . escapeshellarg($in) . ' ' . escapeshellarg($out) . ' ' . escapeshellarg(json_encode($args)) . ' 2>&1', $o, $rc);
    $r = json_decode((string) file_get_contents($out), true);
    @unlink($in); @unlink($out);
    if (!is_array($r)) { return array('rc' => 99, 'out' => $o, 'S' => $S, 'text' => implode("\n", $o)); }
    $r['text'] = implode("\n", $r['out']);
    return $r;
}
function ids_in($S, $pid) {
    $ids = array(); $x = json_decode($S['meta'][$pid]['_elementor_data'] ?? '[]', true);
    array_walk_recursive($x, function ($v, $k) use (&$ids) { if ($k === 'id') { $ids[] = $v; } });
    return $ids;
}
function post($S, $id) { foreach ($S['posts'] as $p) { if ($p['ID'] == $id) { return $p; } } return null; }

echo "\nContent clean-up: report and preview\n";
$r = run($site, array('report'));
t($r['rc'] === 0 && strpos($r['text'], 'widget w1spam1 (text-editor) on page 327') !== false && strpos($r['text'], 'widget w2spam2') !== false
  && strpos($r['text'], 'a1clean') === false && strpos($r['text'], 'r1real') === false,
  'report lists the spam widgets by ID and page, not the clean ones', $r['text']);
t(strpos($r['text'], 'page 327: "Commercial Gioca') !== false && strpos($r['text'], 'post 512 (publish): /kasinon-esimerkki-artikkeli/') !== false,
  '...the spam title and the spam article', $r['text']);
t(strpos($r['text'], 'page 327: 2 of its revisions hold spam') !== false && strpos($r['text'], 'page 40') === false,
  '...revisions holding spam (by their content or their Elementor data), counted per page', $r['text']);
t(strpos($r['text'], 'kasinon-esimerkki-artikkeli/   2026-02-02 02:40 UTC') !== false && strpos($r['text'], '/residential/') === false,
  '...and the spam IndexNow entries', $r['text']);
t($r['S'] === json_decode(json_encode($site), true) || $r['S']['posts'] == $site['posts'] && $r['S']['meta'] == json_decode(json_encode($site['meta']), true),
  'report changes nothing');
$all = array('widgets=w1spam1,w2spam2', 'title=327=Commercial', 'trash=512', 'revisions', 'indexnow');
$r = run($site, $all);
t($r['rc'] === 0 && strpos($r['text'], 'would remove widget(s) w1spam1 from page 327') !== false
  && strpos($r['text'], 'would retitle 327') !== false && strpos($r['text'], 'would move post 512') !== false
  && strpos($r['text'], 'would delete these 2 revision(s)') !== false && strpos($r['text'], 'would remove these 1 entr') !== false,
  'preview says each change it would make', $r['text']);
t($r['S']['meta'] == json_decode(json_encode($site['meta']), true) && $r['S']['posts'] == $site['posts'] && empty($r['S']['flushed']),
  '...and makes none of them');

echo "\nContent clean-up: apply\n";
$r = run($site, array_merge($all, array('apply')));
t($r['rc'] === 0, 'apply succeeds', $r['text']);
t(ids_in($r['S'], 327) === array(ids_in($site, 327)[0], 'a1clean') && ids_in($r['S'], 226) === array(ids_in($site, 226)[0]),
  'the named spam widgets are gone; the clean widget beside one stays', json_encode(array(ids_in($r['S'], 327), ids_in($r['S'], 226))));
t(($r['S']['elementor_saves'] ?? array()) === array(327, 226) && strpos(post($r['S'], 327)['post_content'], 'casino-spam') === false,
  "saved through Elementor's own save, so the page's HTML copy is rebuilt without the link");
t(post($r['S'], 327)['post_title'] === 'Commercial', 'the page title is the real one');
t(post($r['S'], 512)['post_status'] === 'trash', 'the spam article is in the Trash, not deleted');
t(post($r['S'], 901) === null && post($r['S'], 902) === null && post($r['S'], 903) !== null,
  "revisions holding spam are deleted; another page's clean revision stays");
$log = $r['S']['options']['rank_math_indexnow_log'];
t(count($log) === 1 && strpos(json_encode($log), 'residential') !== false, 'IndexNow: the spam entry is dropped, the real page kept');
t(!empty($r['S']['flushed']) && !empty($r['S']['css_cleared']), 'caches and Elementor CSS are cleared afterwards');

echo "\nContent clean-up: what it refuses\n";
$r = run($site, array('widgets=w1spam1,nosuch,a1clean', 'apply'));
t($r['rc'] === 1 && strpos($r['text'], 'widget nosuch: not found') !== false && strpos($r['text'], "widget a1clean: holds no spam by the scanner's test") !== false,
  'a widget ID that does not exist, and a real widget named by mistake, are refused (exit 1)', $r['text']);
t(ids_in($r['S'], 327) === array(ids_in($site, 327)[0], 'a1clean'), '...while the named spam widget is still removed', json_encode(ids_in($r['S'], 327)));
$r = run($site, array('title=40=Something', 'title=327=Best casino deals', 'trash=40', 'apply'));
t($r['rc'] === 1 && post($r['S'], 40)['post_title'] === 'Residential' && post($r['S'], 327)['post_title'] === $site['posts'][0]['post_title']
  && post($r['S'], 40)['post_status'] === 'publish',
  'a clean title is not changed, a spam replacement title is refused, a clean page is not trashed', $r['text']);
$noel = $site; $noel['with_elementor'] = false;
$r = run($noel, array('widgets=w2spam2', 'apply'));
t(strpos($r['text'], 'saved directly: open it in Elementor and click Update') !== false && !isset($r['S']['meta'][226]['_elementor_css']),
  "without Elementor's save, the data is written directly and the operator is told to re-save", $r['text']);
t(strpos($r['text'], "HTML copy still links to casino-vegas.example") !== false && $r['rc'] === 1,
  "...and a page whose HTML copy still holds the link is named, not reported clean", $r['text']);
$r = run($site, array('widgets=w1spam1;rm', 'apply'));
t($r['rc'] === 1 && strpos($r['text'], 'Not understood') !== false && ids_in($r['S'], 327) === ids_in($site, 327),
  'a malformed argument is refused before anything changes', $r['text']);

echo "\nContent clean-up: links=, end to end through the stand-in WordPress\n";
$lk = $site;
$lk['posts'][] = array('ID' => 600, 'post_type' => 'page', 'post_status' => 'publish', 'post_title' => 'Divi page', 'post_name' => 'divi',
    'post_content' => '[et_pb_section][et_pb_text]<p>Our work</p>[/et_pb_text][et_pb_button button_url="https://casino-vegas.example/" button_text="Go"][/et_pb_button][/et_pb_section]',
    'post_parent' => 0, 'post_date_gmt' => '2026-02-12 10:00:00');
$lk['posts'][] = array('ID' => 601, 'post_type' => 'page', 'post_status' => 'publish', 'post_title' => 'Beaver page', 'post_name' => 'beaver', 'post_content' => '',
    'post_parent' => 0, 'post_date_gmt' => '2026-02-12 10:00:00');
$lk['posts'][] = array('ID' => 602, 'post_type' => 'nav_menu_item', 'post_status' => 'publish', 'post_title' => 'Promo', 'post_name' => 'promo', 'post_content' => '',
    'post_parent' => 0, 'post_date_gmt' => '2026-02-12 10:00:00');
$lk['meta'][601] = array('_fl_builder_data' => array('n1' => array('node' => 'n1', 'settings' => array('text' => '<p>Online casino <a href="https://casino-vegas.example/">x</a></p>'))),
                          '_thumbnail_id' => '5');
$lk['meta'][602] = array('_menu_item_url' => 'https://www.casino-vegas.example/');
$lk['options']['theme_mods_mytheme'] = array('footer_text' => 'Built by us · <a href="https://casino-vegas.example/">partner</a>', 'logo' => 12);
$lk['options']['widget_custom_html'] = array(3 => array('content' => '<p>casino bonus <a href="https://casino-vegas.example/">x</a></p>'), '_multiwidget' => 1);
$lk['options']['_transient_cache'] = 'https://casino-vegas.example/';
$r = run($lk, array('links=casino-vegas.example,supplier.example,shop.example', 'apply'));
t($r['rc'] === 1 && strpos($r['text'], "supplier.example does not read as a spam domain") !== false && strpos($r['text'], 'shop.example is this site') !== false,
  'a domain that is not spam, and the site itself, are refused (exit 1)', $r['text']);
$r = run($lk, array('links=casino-vegas.example'));
t($r['rc'] === 0 && strpos($r['text'], 'would remove') !== false && $r['S']['posts'] == $lk['posts'] && empty($r['S']['db_updates']),
  'preview names each place and changes nothing', $r['text']);
$r = run($lk, array('links=casino-vegas.example', 'apply'));
$S2 = $r['S'];
t($r['rc'] === 0 && post($S2, 600)['post_content'] === '[et_pb_section][et_pb_text]<p>Our work</p>[/et_pb_text][/et_pb_section]',
  'Divi content: the button module pointing there is gone, written to the database directly', $r['text']);
t(strpos(json_encode($S2['meta'][601]['_fl_builder_data']), 'casino') === false && $S2['meta'][601]['_thumbnail_id'] === '5',
  'Beaver Builder layout in post meta: the spam paragraph is gone; other meta untouched', json_encode($S2['meta'][601] ?? null));
t(post($S2, 602) === null, 'a menu item pointing there is deleted', $r['text']);
t($S2['options']['theme_mods_mytheme']['footer_text'] === 'Built by us · ' && $S2['options']['theme_mods_mytheme']['logo'] === 12,
  "the theme's footer text loses the link and keeps its words; other theme settings untouched", json_encode($S2['options']['theme_mods_mytheme']));
t(strpos(json_encode($S2['options']['widget_custom_html']), 'casino') === false && $S2['options']['_transient_cache'] === 'https://casino-vegas.example/',
  'a sidebar widget is cleaned; caches are not rewritten');
t(substr_count(json_encode($S2), 'casino-vegas') === 1,
  'nothing else links there any more, page 226 included (its HTML copy and its Elementor data); only the cache is left alone',
  (string) substr_count(json_encode($S2), 'casino-vegas'));

echo "\nContent clean-up: links= removal, for any builder (the functions)\n";
require_once dirname(__DIR__) . '/payload/php-tools/wasp-content-clean.php';
$hre = wcc_host_re(array('casino-spam.example', 'slots-vip.example'));
$sc = function ($s) use ($hre) { $n = 0; $u = 0; $r = wcc_scrub_text($s, $hre, $n, $u); return array($r, $n, $u); };
// Classic HTML: a paragraph that is all spam goes; a real paragraph keeps its words, loses the link.
list($r, $n, $u) = $sc('<p>Our patios.</p><p>Gioca al casino online con <a href="https://casino-spam.example/">bonus</a></p><p>We install patios. <a href="https://www.casino-spam.example/x">more</a> Call us.</p>');
t($r === '<p>Our patios.</p><p>We install patios.  Call us.</p>' && $n >= 2 && $u === 1, 'classic HTML: the spam paragraph goes whole; a real paragraph keeps its words and loses the link', $r);
list($r, $n, $u) = $sc('<p>Gioca al <a href="https://casino-spam.example/">casino</a> online</p>');
t($r === '<p>Gioca al  online</p>' && $u === 0, 'a paragraph whose only spam word was the link text keeps its other words: the link, the harm, is gone', $r);
list($r) = $sc('<p><span data-sheets-root="1">Il marchio <a href="https://casino-spam.example/">x</a> premi</span> and our real text</p>');
t($r === '<p> and our real text</p>', 'a pasted spreadsheet cell holding the link goes whole', $r);
// Block editor: a spam paragraph block goes; a block plugin's button pointing there goes; real blocks stay.
$g = "<!-- wp:paragraph -->\n<p>Welcome.</p>\n<!-- /wp:paragraph -->\n<!-- wp:paragraph -->\n<p>Best <a href=\"https://casino-spam.example/\">here</a> for casino bonus</p>\n<!-- /wp:paragraph -->\n"
   . "<!-- wp:kadence/advancedbtn {\"url\":\"https://slots-vip.example/go\"} /-->\n<!-- wp:buttons --><div class=\"wp-block-buttons\"><!-- wp:button {\"url\":\"https://casino-spam.example/\"} --><div class=\"wp-block-button\"><a class=\"wp-block-button__link\" href=\"https://casino-spam.example/\">Play</a></div><!-- /wp:button --></div><!-- /wp:buttons -->";
list($r, $n, $u) = $sc($g);
t(strpos($r, 'Welcome.') !== false && strpos($r, 'casino') === false && strpos($r, 'slots-vip') === false && strpos($r, 'wp:kadence') === false
  && strpos($r, '<!-- wp:button ') === false && strpos($r, '<!-- wp:buttons -->') !== false && $u === 3,
  'block editor: the spam paragraph block, a block plugin\'s button and a core button go; the real block and the container stay', $r);
// Divi: a spam text module and a button module go; WPBakery: a self-closing button with an encoded link goes.
$d = '[et_pb_section][et_pb_row][et_pb_column type="4_4"][et_pb_text]<p>Our work</p>[/et_pb_text][et_pb_text]<p>Casino bonus <a href="https://casino-spam.example/">here</a></p>[/et_pb_text][et_pb_button button_url="https://slots-vip.example/" button_text="Play"][/et_pb_button][/et_pb_column][/et_pb_row][/et_pb_section]';
list($r, $n, $u) = $sc($d);
t($r === '[et_pb_section][et_pb_row][et_pb_column type="4_4"][et_pb_text]<p>Our work</p>[/et_pb_text][/et_pb_column][/et_pb_row][/et_pb_section]' && $u === 2,
  'Divi: the spam text module and the button module go; the real module and the layout stay', $r);
list($r, $n, $u) = $sc('[vc_row][vc_column][vc_column_text]Real text[/vc_column_text][vc_btn title="Bonus" link="url:https%3A%2F%2Fslots-vip.example%2Fjoin|title:Join"][/vc_column][/vc_row]');
t($r === '[vc_row][vc_column][vc_column_text]Real text[/vc_column_text][/vc_column][/vc_row]' && $u === 1, 'WPBakery: a self-closing button with a URL-encoded link goes', $r);
// Builder data in meta: Beaver Builder objects, Bricks arrays, Oxygen JSON with escaped slashes.
$fl = array('a' => (object) array('node' => 'a', 'settings' => (object) array('text' => '<p>Online casino, <a href="https://casino-spam.example/">x</a></p>')),
            'b' => (object) array('node' => 'b', 'settings' => (object) array('text' => '<p>Our team</p>')));
$n = 0; $u = 0; $r = wcc_scrub($fl, $hre, $n, $u);
t(is_object($r['a']) && $r['a']->settings->text === '' && $r['b']->settings->text === '<p>Our team</p>' && $n >= 1,
  'Beaver Builder: the link is removed inside its layout objects; their shape is kept', json_encode($r));
$n = 0; $u = 0; $r = wcc_scrub(array(array('id' => 'x', 'settings' => array('link' => array('url' => 'https://slots-vip.example/'), 'text' => 'Bonus'))), $hre, $n, $u);
t($r[0]['settings']['link']['url'] === '' && $r[0]['settings']['text'] === 'Bonus' && $n === 1, 'Bricks: a link field is emptied', json_encode($r));
$n = 0; $u = 0; $r = wcc_scrub('{"children":[{"id":1,"options":{"url":"https:\\/\\/casino-spam.example\\/","text":"<p>ok<\\/p>"}}]}', $hre, $n, $u);
t(is_string($r) && json_decode($r, true)['children'][0]['options']['url'] === '' && json_decode($r, true)['children'][0]['options']['text'] === '<p>ok</p>',
  'Oxygen: JSON with escaped slashes is decoded, scrubbed and written back as JSON', $r);
// Elementor under links=: a widget that held only the spam goes; a real widget with a slipped-in link keeps its words.
$e = array(array('id' => 'c', 'elType' => 'container', 'elements' => array(
    array('id' => 'w1', 'elType' => 'widget', 'widgetType' => 'text-editor', 'settings' => array('editor' => '<p><a href="https://casino-spam.example/">x</a> casino premi</p>')),
    array('id' => 'w2', 'elType' => 'widget', 'widgetType' => 'text-editor', 'settings' => array('editor' => '<p>Our patios. <a href="https://casino-spam.example/">x</a></p>')),
    array('id' => 'w3', 'elType' => 'widget', 'widgetType' => 'button', 'settings' => array('text' => 'Go', 'link' => array('url' => 'https://slots-vip.example/'))))));
$n = 0; $u = 0; $gone = array(); $r = wcc_scrub_elementor($e, $hre, $n, $u, $gone);
$ids = array_map(function ($w) { return $w['id']; }, $r[0]['elements']);
t($ids === array('w2', 'w3') && $gone === array('w1') && strpos($r[0]['elements'][0]['settings']['editor'], 'Our patios.') !== false
  && strpos(json_encode($r), 'casino-spam') === false && $r[0]['elements'][1]['settings']['link']['url'] === '',
  'Elementor: the spam-only widget goes; a real widget keeps its words; a button keeps its label and loses the link', json_encode($r));
// Nothing else is touched.
list($r, $n) = $sc('<p>A <a href="https://supplier.example/casino-spam.example">link</a> and https://casino-spam.example.org/</p>');
t($n === 0 && strpos($r, 'supplier.example') !== false && strpos($r, 'casino-spam.example.org') !== false,
  'another host, a path that names the domain, and a longer domain that starts the same are left alone', $r);
t(wcc_option_skip('_transient_x') && wcc_option_skip('cron') && !wcc_option_skip('theme_mods_astra') && !wcc_option_skip('widget_text'),
  'caches and WordPress plumbing are never rewritten; theme settings and widgets are');

echo "\n  links clean (php): {$pass} passed, {$fail} failed\n";
exit($fail ? 1 : 0);
