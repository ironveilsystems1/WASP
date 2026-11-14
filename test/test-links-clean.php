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
        public $posts = 'wp_posts'; public $postmeta = 'wp_postmeta';
        function get_results($q) {
            $S = $GLOBALS['S']; $o = array();
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
    function get_post($id) { $p = wcct_post($id); return $p ? (object) $p : null; }
    function get_post_field($f, $id) { $p = wcct_post($id); return $p ? (string) $p[$f] : ''; }
    function get_post_meta($id, $k, $single) { return $GLOBALS['S']['meta'][$id][$k] ?? ''; }
    function update_post_meta($id, $k, $v) { $GLOBALS['S']['meta'][$id][$k] = stripslashes($v); return true; }
    function delete_post_meta($id, $k) { unset($GLOBALS['S']['meta'][$id][$k]); }
    function wp_slash($v) { return addslashes($v); }
    function wp_json_encode($v, $f = 0) { return json_encode($v, $f); }
    function clean_post_cache($id) {}
    function is_wp_error($x) { return $x instanceof WP_Error; }
    function wp_update_post($a, $e) { $p = &wcct_post($a['ID']); $p['post_title'] = $a['post_title']; return $a['ID']; }
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

echo "\n  links clean (php): {$pass} passed, {$fail} failed\n";
exit($fail ? 1 : 0);
