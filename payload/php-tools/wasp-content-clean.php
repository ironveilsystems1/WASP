<?php
/**
 * wasp-content-clean.php — remove what wasp-content-scan.php found.
 *
 * Run by `wp-links.sh clean`, through WP-CLI (`wp --user=<admin> eval-file`),
 * because the removal goes through WordPress and Elementor's own save: that
 * rebuilds the page's HTML copy and its CSS, which a database edit would leave
 * holding the spam. Arguments are words:
 *
 *   report                     what could be cleaned, with the IDs to name
 *   widgets=<id>,<id>          remove these Elementor widgets
 *   title=<post id>=<text>     set a page title (repeatable)
 *   trash=<post id>,<post id>  move these posts to the Trash
 *   revisions                  delete saved revisions that hold spam
 *   links=<domain>,<domain>    remove every link to these spam domains, whichever
 *                              builder, theme setting, widget or menu holds it
 *   indexnow                   drop the spam entries from Rank Math's IndexNow log
 *   export-indexnow            print the IndexNow log as JSON (evidence), change nothing
 *   apply                      do it; without this word nothing is changed
 *
 * WHAT IT REFUSES. Nothing is removed by pattern alone: a widget, post or title
 * is changed only when it is NAMED and the scanner's own test also finds spam in
 * it. A typo in an ID, or a real widget named by mistake, is reported and left.
 * Posts go to the Trash (WordPress keeps them 30 days), not straight to deletion.
 * Revisions are judged one by one with the same test, and only those holding
 * spam are deleted. The detection is wasp-content-scan.php's, included, so the
 * scan and the clean-up cannot disagree about what spam is.
 *
 * LINKS, ANY BUILDER (links=). A domain is accepted only when it reads as spam
 * by the scanner's own test and is not the site itself. Every link to it is
 * then removed wherever it is stored: the content (classic HTML, the block
 * editor and block plugins, Divi/WPBakery/Avada shortcodes, URL-encoded or
 * not), every builder's page data in post meta (Beaver Builder, Bricks, Oxygen,
 * Breakdance ... serialized, JSON or plain), Elementor widgets, theme and
 * Customizer settings, sidebar widgets; a menu item pointing there is deleted.
 * The SMALLEST UNIT around the link goes with it only when, once the link is
 * out, that unit holds nothing but spam: a pasted spreadsheet cell, a
 * paragraph, a block, a shortcode module, an Elementor widget. A real paragraph
 * that had a spam link slipped into it keeps its words and loses the link.
 * Content and builder data are written straight to the database, so no content
 * filter rewrites the rest of the page, then caches are cleared (Elementor,
 * Beaver Builder, Divi, and the common page-cache plugins).
 */
define('WCS_LIBRARY_ONLY', true);
require __DIR__ . '/wasp-content-scan.php';

/** Remove widgets whose id is in $ids from Elementor element data. */
function wcc_remove_widgets(array $els, array $ids, array &$removed) {
    $out = array();
    foreach ($els as $el) {
        if (!is_array($el)) { $out[] = $el; continue; }
        $id = isset($el['id']) ? (string) $el['id'] : '';
        if ($id !== '' && ($el['elType'] ?? '') === 'widget' && in_array($id, $ids, true)) {
            $removed[] = $id;
            continue;
        }
        if (!empty($el['elements']) && is_array($el['elements'])) {
            $el['elements'] = wcc_remove_widgets($el['elements'], $ids, $removed);
        }
        $out[] = $el;
    }
    return $out;
}

/** Every widget in Elementor data: id => [type, spam findings]. */
function wcc_widgets($data, array $site_hosts) {
    $out = array(); $ob = array();
    $walk = function ($els) use (&$walk, &$out, &$ob, $site_hosts) {
        foreach ((array) $els as $el) {
            if (!is_array($el)) { continue; }
            if (($el['elType'] ?? '') === 'widget') {
                $f = array_values(array_filter(wcs_html(wcs_widget_html($el), $site_hosts, $ob),
                    function ($x) { return in_array($x[0], array('spam_link', 'hidden_link', 'spam_text'), true); }));
                $out[(string) ($el['id'] ?? '')] = array((string) ($el['widgetType'] ?? 'widget'), $f);
            }
            if (!empty($el['elements'])) { $walk($el['elements']); }
        }
    };
    $walk(is_array($data) ? $data : array());
    return $out;
}

/** Does a post (or revision) hold spam? The scanner's own test, shared. */
function wcc_post_is_spam($title, $slug, $content, $edata, array $site_hosts) {
    return wcs_post_is_spam($title, $slug, $content, $edata, $site_hosts);
}

/** Split an IndexNow log into [kept, dropped]: an entry is spam when its address is. */
function wcc_indexnow_split($log) {
    $kept = array(); $dropped = array();
    foreach (is_array($log) ? $log : array() as $k => $e) {
        $path = (string) parse_url(is_array($e) ? (string) ($e['url'] ?? '') : '', PHP_URL_PATH);
        if ($path !== '' && preg_match(wcs_spam_slug_re(), $path)) { $dropped[$k] = $e; } else { $kept[$k] = $e; }
    }
    return array($kept, $dropped);
}

// ── links= : removal, for any builder ───────────────────────────────────────
/** The pattern for "a URL on one of these hosts", raw, JSON-escaped or URL-encoded. */
function wcc_host_re(array $hosts) {
    $alt = implode('|', array_map(function ($h) { return preg_quote($h, '#'); }, $hosts));
    return '(?:https?:(?:\\\\?/){2}|https?%3A%2F%2F)(?:www\.)?(?:' . $alt . ')(?![a-z0-9.-])';
}
function wcc_mentions($s, $hre) { return is_string($s) && $s !== '' && (bool) preg_match('#' . $hre . '#i', $s); }

/** Nothing left but spam (or nothing at all) once the link is out? */
function wcc_spam_only($html) {
    $t = html_entity_decode(strip_tags(preg_replace('#<!--.*?-->#s', '', (string) $html)), ENT_QUOTES, 'UTF-8');
    $t = trim(preg_replace('/[\s\x{00a0}]+/u', ' ', $t));
    return $t === '' || (bool) preg_match(wcs_spam_text_re(), $t);
}

/** The links themselves: an <a> to the host (with its text), then any URL left. */
function wcc_scrub_links($s, $hre, &$n) {
    $s = preg_replace('#<a\b[^>]*\bhref\s*=\s*\\\\?["\']?\s*' . $hre . '[^>]*>.*?<\\\\?/a>#is', '', (string) $s, -1, $c);
    $n += $c;
    $s = preg_replace('#' . $hre . '[^\s"\'<>\[\]|,)\\\\]*#i', '', $s, -1, $c);
    $n += $c;
    return $s;
}

/** HTML: a pasted spreadsheet cell holding the link goes whole; a paragraph, list item or heading too when nothing but spam is left. */
function wcc_scrub_html($s, $hre, &$n, &$units) {
    $s = preg_replace_callback('#<span\b[^>]*data-sheets-[^>]*>(?:(?!</span>).)*?</span>#is', function ($m) use ($hre, &$n, &$units) {
        if (!wcc_mentions($m[0], $hre)) { return $m[0]; }
        $n++; $units++; return '';
    }, (string) $s);
    $s = preg_replace_callback('#<(p|li|h[1-6])\b([^>]*)>((?:(?!</?\1\b).)*?)</\1>#is', function ($m) use ($hre, &$n, &$units) {
        if (!wcc_mentions($m[3], $hre)) { return $m[0]; }
        $k = 0; $inner = wcc_scrub_links($m[3], $hre, $k);
        if (wcc_spam_only($inner)) { $n += max(1, $k); $units++; return ''; }
        $n += $k; return '<' . $m[1] . $m[2] . '>' . $inner . '</' . $m[1] . '>';
    }, $s);
    return wcc_scrub_links($s, $hre, $n);
}

/** The block editor (and block plugins): a leaf block holding the link goes when nothing but spam is left in it. */
function wcc_scrub_blocks($s, $hre, &$n, &$units) {
    if (strpos((string) $s, '<!-- wp:') === false) { return $s; }
    $s = preg_replace_callback('#<!--\s+wp:([a-z0-9/_-]+)(\s+\{.*?\})?\s+/-->#s', function ($m) use ($hre, &$n, &$units) {
        if (!wcc_mentions($m[2] ?? '', $hre)) { return $m[0]; }
        $n++; $units++; return '';      // a self-closing block whose setting points there: a button, an embed
    }, (string) $s);
    return preg_replace_callback('#<!--\s+wp:([a-z0-9/_-]+)(\s+\{.*?\})?\s+-->((?:(?!<!--\s+/?wp:).)*?)<!--\s+/wp:\1\s+-->#s',
        function ($m) use ($hre, &$n, &$units) {
            $attrs = $m[2] ?? ''; $inner = $m[3];
            if (!wcc_mentions($attrs . $inner, $hre)) { return $m[0]; }
            $k = 0; $u = 0; $inner2 = wcc_scrub_html($inner, $hre, $k, $u); $attrs2 = wcc_scrub_links($attrs, $hre, $k);
            if (wcc_spam_only($inner2)) { $n += max(1, $k); $units++; return ''; }
            $n += $k; $units += $u; return '<!-- wp:' . $m[1] . $attrs2 . ' -->' . $inner2 . '<!-- /wp:' . $m[1] . ' -->';
        }, $s);
}

/** Shortcode builders (Divi, WPBakery, Avada ...): a module holding the link goes when nothing but spam is left in it. */
function wcc_scrub_shortcodes($s, $hre, &$n, &$units) {
    if (strpos((string) $s, '[') === false) { return $s; }
    // Self-closing modules ([vc_btn link="url:..."]): no closing tag anywhere after them.
    $s = preg_replace_callback('#\[([a-zA-Z][a-zA-Z0-9_-]*)(\s[^\]]*)\]#', function ($m) use ($hre, &$n, &$units, &$s) {
        if (!wcc_mentions($m[2], $hre) || strpos($s, '[/' . $m[1] . ']') !== false) { return $m[0]; }
        $n++; $units++; return '';
    }, (string) $s);
    return preg_replace_callback('#\[([a-zA-Z][a-zA-Z0-9_-]*)(\s[^\]]*)?\]((?:(?!\[).)*?)\[/\1\]#s', function ($m) use ($hre, &$n, &$units) {
        $attrs = $m[2] ?? ''; $inner = $m[3];
        if (!wcc_mentions($attrs . $inner, $hre)) { return $m[0]; }
        $k = 0; $u = 0; $inner2 = wcc_scrub_html($inner, $hre, $k, $u); $attrs2 = wcc_scrub_links($attrs, $hre, $k);
        if (wcc_spam_only($inner2)) { $n += max(1, $k); $units++; return ''; }
        $n += $k; $units += $u; return '[' . $m[1] . $attrs2 . ']' . $inner2 . '[/' . $m[1] . ']';
    }, $s);
}

/** One stored text, whatever wrote it. */
function wcc_scrub_text($s, $hre, &$n, &$units) {
    if (!wcc_mentions($s, $hre)) { return $s; }
    $s = wcc_scrub_blocks($s, $hre, $n, $units);
    $s = wcc_scrub_shortcodes($s, $hre, $n, $units);
    return wcc_scrub_html($s, $hre, $n, $units);
}

/** A stored value of any shape: strings (JSON inside them decoded and re-encoded), arrays, objects. */
function wcc_scrub($v, $hre, &$n, &$units) {
    if (is_string($v)) {
        if (!wcc_mentions($v, $hre)) { return $v; }
        $t = ltrim($v);
        if ($t !== '' && ($t[0] === '{' || $t[0] === '[')) {
            $j = json_decode($v, true);
            if (is_array($j)) {
                $k = 0; $j = wcc_scrub($j, $hre, $k, $units);
                $n += $k;
                return function_exists('wp_json_encode') ? wp_json_encode($j) : json_encode($j);
            }
        }
        return wcc_scrub_text($v, $hre, $n, $units);
    }
    if (is_array($v)) {
        foreach ($v as $k => $x) { $v[$k] = wcc_scrub($x, $hre, $n, $units); }
        return $v;
    }
    if (is_object($v)) {
        foreach (get_object_vars($v) as $k => $x) { $v->$k = wcc_scrub($x, $hre, $n, $units); }
        return $v;
    }
    return $v;
}

/** Elementor data under links=: scrub each widget; a widget left holding nothing but spam goes. */
function wcc_scrub_elementor(array $els, $hre, &$n, &$units, array &$gone) {
    $out = array();
    foreach ($els as $el) {
        if (!is_array($el)) { $out[] = $el; continue; }
        if (($el['elType'] ?? '') === 'widget' && isset($el['settings'])
            && wcc_mentions(json_encode($el['settings'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), $hre)) {
            $k = 0; $u = 0;
            $el['settings'] = wcc_scrub($el['settings'], $hre, $k, $u);
            if (wcc_spam_only(wcs_widget_html($el))) { $n += max(1, $k); $units++; $gone[] = (string) ($el['id'] ?? ''); continue; }
            $n += $k; $units += $u;
        }
        if (!empty($el['elements']) && is_array($el['elements'])) {
            $el['elements'] = wcc_scrub_elementor($el['elements'], $hre, $n, $units, $gone);
        }
        $out[] = $el;
    }
    return $out;
}

/** Spam domains linked from a stored value (for report). */
function wcc_spam_hosts_in($v, array $site_hosts) {
    $out = array();
    foreach (wcs_url_hosts(wcs_blob($v)) as $h) {
        if (!in_array($h, $site_hosts, true) && preg_match(wcs_spam_host_re(), $h)) { $out[] = $h; }
    }
    return $out;
}

/** Options never touched: caches, logs, and WordPress's own plumbing. */
function wcc_option_skip($name) {
    return strpos($name, '_transient') === 0 || strpos($name, '_site_transient') === 0
        || in_array($name, array('rank_math_indexnow_log', 'home', 'siteurl', 'cron', 'rewrite_rules', 'recently_edited',
                                 'active_plugins', 'uninstall_plugins', 'dashboard_widget_options'), true);
}

/** The words this tool takes. */
function wcc_args(array $args) {
    $o = array('apply' => false, 'report' => false, 'revisions' => false, 'indexnow' => false, 'export' => false,
               'widgets' => array(), 'titles' => array(), 'trash' => array(), 'links' => array(), 'bad' => array());
    foreach ($args as $a) {
        if ($a === 'apply') { $o['apply'] = true; }
        elseif ($a === 'report') { $o['report'] = true; }
        elseif ($a === 'revisions') { $o['revisions'] = true; }
        elseif ($a === 'indexnow') { $o['indexnow'] = true; }
        elseif ($a === 'export-indexnow') { $o['export'] = true; }
        elseif (strpos($a, 'widgets=') === 0 && preg_match('/^[a-z0-9]+(,[a-z0-9]+)*$/i', substr($a, 8))) {
            $o['widgets'] = array_values(array_unique(explode(',', substr($a, 8))));
        } elseif (strpos($a, 'trash=') === 0 && preg_match('/^\d+(,\d+)*$/', substr($a, 6))) {
            $o['trash'] = array_map('intval', array_unique(explode(',', substr($a, 6))));
        } elseif (strpos($a, 'links=') === 0 && preg_match('/^[a-z0-9.-]+(,[a-z0-9.-]+)*$/i', substr($a, 6))) {
            $o['links'] = array_values(array_unique(array_map(function ($h) { return wcs_bare($h); }, explode(',', substr($a, 6)))));
        } elseif (preg_match('/^title=(\d+)=(.+)$/s', $a, $m)) {
            $o['titles'][(int) $m[1]] = trim($m[2]);
        } else { $o['bad'][] = $a; }
    }
    return $o;
}

if (!defined('ABSPATH')) {
    return;   // included by the tests: the functions above, nothing run
}

// ── Inside WordPress (wp eval-file) ─────────────────────────────────────────
global $wpdb;
$o = wcc_args(isset($args) && is_array($args) ? $args : array());
if ($o['bad']) { WP_CLI::error('Not understood: ' . implode(' ', $o['bad'])); }
$site_hosts = array_values(array_filter(array(wcs_bare(wcs_host(home_url())))));
$apply = $o['apply'];
$say = function ($s) { WP_CLI::line($s); };

if ($o['export']) {
    $log = get_option('rank_math_indexnow_log', null);
    echo wp_json_encode($log, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
    return;
}
$say($apply ? 'Cleaning — changes are being saved.' : 'Preview — nothing is changed until you add --apply.');
$changed_posts = array(); $problems = 0;

// Pages and templates with Elementor data (not revisions).
$rows = $wpdb->get_results(
    "SELECT p.ID, p.post_type, p.post_status, p.post_title, m.meta_value AS edata
       FROM {$wpdb->posts} p JOIN {$wpdb->postmeta} m ON m.post_id = p.ID AND m.meta_key = '_elementor_data'
      WHERE p.post_type NOT IN ('revision') AND p.post_status NOT IN ('auto-draft','trash')");
$by_widget = array();   // widget id => [post id, type, findings]
$pages = array();
foreach ($rows as $r) {
    $data = json_decode((string) $r->edata, true);
    if (!is_array($data)) { continue; }
    $pages[(int) $r->ID] = array($r, $data);
    foreach (wcc_widgets($data, $site_hosts) as $wid => $w) {
        $by_widget[$wid] = array((int) $r->ID, $w[0], $w[1]);
    }
}

// ── widgets ──
if ($o['widgets'] || $o['report']) { $say(''); $say('Elementor widgets'); }
if ($o['report']) {
    $any = false;
    foreach ($by_widget as $wid => $w) {
        if (!$w[2]) { continue; }
        $any = true;
        $hosts = array();
        foreach ($w[2] as $x) { if (isset($x[1]) && $x[0] !== 'spam_text') { $hosts[] = $x[1]; } }
        $say(sprintf('  widget %s (%s) on %s %d "%s": %s', $wid, $w[1], $pages[$w[0]][0]->post_type, $w[0],
                     wcs_clip($pages[$w[0]][0]->post_title, 40), $hosts ? implode(', ', array_unique($hosts)) : 'spam wording'));
    }
    if (!$any) { $say('  none hold spam'); }
}
$remove_by_post = array();
foreach ($o['widgets'] as $wid) {
    if (!isset($by_widget[$wid])) { $say("  ✗ widget {$wid}: not found on any page — check the ID against the scan"); $problems++; continue; }
    if (!$by_widget[$wid][2]) { $say("  ✗ widget {$wid}: holds no spam by the scanner's test — not removed"); $problems++; continue; }
    $remove_by_post[$by_widget[$wid][0]][] = $wid;
}
foreach ($remove_by_post as $pid => $ids) {
    list($r, $data) = $pages[$pid];
    $removed = array();
    $new = wcc_remove_widgets($data, $ids, $removed);
    $label = sprintf('%s %d "%s"', $r->post_type, $pid, wcs_clip($r->post_title, 40));
    if (!$apply) { $say("  → would remove widget(s) " . implode(', ', $removed) . " from {$label}"); continue; }
    $saved = false;
    if (class_exists('\Elementor\Plugin') && isset(\Elementor\Plugin::$instance->documents)) {
        $doc = \Elementor\Plugin::$instance->documents->get($pid, false);
        if ($doc) { $saved = (bool) $doc->save(array('elements' => $new)); }
    }
    if (!$saved) {
        update_post_meta($pid, '_elementor_data', wp_slash(wp_json_encode($new)));
        delete_post_meta($pid, '_elementor_css');
    }
    clean_post_cache($pid);
    $changed_posts[$pid] = 1;
    $say("  ✔ removed widget(s) " . implode(', ', $removed) . " from {$label}" . ($saved ? '' : ' (saved directly: open it in Elementor and click Update)'));
    $after = (string) get_post_field('post_content', $pid);
    $ob = array();
    foreach (wcs_html($after, $site_hosts, $ob) as $x) {
        if ($x[0] === 'spam_link') { $say("  ! the page's HTML copy still links to {$x[1]}: open it in Elementor and click Update"); $problems++; break; }
        if ($x[0] === 'spam_text') { $say("  ! the page's HTML copy still holds the spam wording (\"{$x[1]}\"): open it in Elementor and click Update"); $problems++; break; }
    }
}

// ── titles ──
if ($o['titles'] || $o['report']) { $say(''); $say('Titles'); }
if ($o['report']) {
    $t = $wpdb->get_results("SELECT ID, post_type, post_title FROM {$wpdb->posts}
                              WHERE post_type NOT IN ('revision','nav_menu_item') AND post_status NOT IN ('auto-draft','trash')");
    $any = false;
    foreach ($t as $p) {
        if (preg_match(wcs_spam_text_re(), (string) $p->post_title)) {
            $any = true; $say(sprintf('  %s %d: "%s"', $p->post_type, $p->ID, wcs_clip($p->post_title, 70)));
        }
    }
    if (!$any) { $say('  none hold spam'); }
}
foreach ($o['titles'] as $pid => $text) {
    $old = get_post_field('post_title', $pid);
    if ($old === '' && !get_post($pid)) { $say("  ✗ post {$pid}: does not exist"); $problems++; continue; }
    if (!preg_match(wcs_spam_text_re(), (string) $old)) { $say("  ✗ post {$pid}: its title holds no spam (\"" . wcs_clip($old, 50) . "\") — not changed"); $problems++; continue; }
    if (preg_match(wcs_spam_text_re(), $text)) { $say("  ✗ post {$pid}: the new title itself reads as spam — not changed"); $problems++; continue; }
    if (!$apply) { $say("  → would retitle {$pid}: \"" . wcs_clip($old, 50) . "\" → \"{$text}\""); continue; }
    $rc = wp_update_post(wp_slash(array('ID' => $pid, 'post_title' => $text)), true);
    if (is_wp_error($rc)) { $say("  ✗ post {$pid}: " . $rc->get_error_message()); $problems++; continue; }
    $changed_posts[$pid] = 1;
    $say("  ✔ retitled {$pid}: \"{$text}\"");
}

// ── posts to the Trash ──
if ($o['trash'] || $o['report']) { $say(''); $say('Spam posts'); }
if ($o['report']) {
    $t = $wpdb->get_results("SELECT ID, post_type, post_status, post_title, post_name FROM {$wpdb->posts}
                              WHERE post_type IN ('post','page') AND post_status NOT IN ('auto-draft','trash')");
    $any = false;
    foreach ($t as $p) {
        if (preg_match(wcs_spam_slug_re(), (string) $p->post_name)) {
            $any = true; $say(sprintf('  %s %d (%s): /%s/', $p->post_type, $p->ID, $p->post_status, $p->post_name));
        }
    }
    if (!$any) { $say('  none found by address'); }
}
foreach ($o['trash'] as $pid) {
    $p = get_post($pid);
    if (!$p) { $say("  ✗ post {$pid}: does not exist"); $problems++; continue; }
    $ed = (string) get_post_meta($pid, '_elementor_data', true);
    $why = wcc_post_is_spam('', (string) $p->post_name, (string) $p->post_content, $ed, $site_hosts);
    if ($why === '' && preg_match(wcs_spam_text_re(), (string) $p->post_title)) { $why = 'title'; }
    if ($why === '') { $say("  ✗ post {$pid} \"" . wcs_clip($p->post_title, 40) . "\": holds no spam by the scanner's test — not moved"); $problems++; continue; }
    if (!$apply) { $say("  → would move {$p->post_type} {$pid} /{$p->post_name}/ to the Trash (spam in its {$why})"); continue; }
    if (wp_trash_post($pid)) { $say("  ✔ {$p->post_type} {$pid} /{$p->post_name}/ is in the Trash; its address now answers 404"); }
    else { $say("  ✗ could not trash {$pid}"); $problems++; }
}

// ── revisions ──
if ($o['revisions'] || $o['report']) {
    $say(''); $say('Saved revisions');
    $revs = $wpdb->get_results(
        "SELECT p.ID, p.post_parent, p.post_title, p.post_content, p.post_date_gmt, m.meta_value AS edata
           FROM {$wpdb->posts} p
           LEFT JOIN {$wpdb->postmeta} m ON m.post_id = p.ID AND m.meta_key = '_elementor_data'
          WHERE p.post_type = 'revision'");
    $spam = array();
    foreach ($revs as $v) {
        if (wcc_post_is_spam((string) $v->post_title, '', (string) $v->post_content, (string) $v->edata, $site_hosts) !== '') {
            $spam[(int) $v->post_parent][] = $v;
        }
    }
    $n = 0;
    foreach ($spam as $parent => $list) {
        $dates = array_map(function ($v) { return $v->post_date_gmt; }, $list); sort($dates);
        $say(sprintf('  page %d: %d of its revisions hold spam (%s to %s UTC)', $parent, count($list), substr(reset($dates), 0, 10), substr(end($dates), 0, 10)));
        $n += count($list);
    }
    if (!$spam) { $say('  none hold spam'); }
    if ($o['revisions'] && $spam) {
        if (!$apply) { $say("  → would delete these {$n} revision(s); the other revisions stay"); }
        else {
            $d = 0;
            foreach ($spam as $list) { foreach ($list as $v) { if (wp_delete_post_revision((int) $v->ID)) { $d++; } } }
            $say("  ✔ deleted {$d} revision(s) holding spam");
            if ($d < $n) { $problems++; }
        }
    }
}

// ── IndexNow log ──
if ($o['indexnow'] || $o['report']) {
    $say(''); $say("Rank Math's IndexNow log (what was announced to search engines)");
    $log = get_option('rank_math_indexnow_log', null);
    list($kept, $dropped) = wcc_indexnow_split($log);
    foreach ($dropped as $e) { $say('  ' . (string) ($e['url'] ?? '') . (isset($e['time']) ? '   ' . gmdate('Y-m-d H:i', (int) $e['time']) . ' UTC' : '')); }
    if (!$dropped) { $say('  no spam addresses in it'); }
    if ($o['indexnow'] && $dropped) {
        if (!$apply) { $say('  → would remove these ' . count($dropped) . ' entr(ies); ' . count($kept) . ' other(s) stay'); }
        else { update_option('rank_math_indexnow_log', $kept, false); $say('  ✔ removed ' . count($dropped) . ' spam entr(ies) from the log'); }
    }
}

// ── links= : every builder, theme setting, widget and menu ──
$content_types = "'revision','nav_menu_item','attachment','oembed_cache','customize_changeset','user_request'";
if ($o['report']) {
    $say(''); $say('Links to spam domains (any builder, theme setting, widget or menu)');
    $hosts = array();
    $add = function ($v, $where) use (&$hosts, $site_hosts) {
        foreach (wcc_spam_hosts_in($v, $site_hosts) as $h) { $hosts[$h][$where] = true; }
    };
    foreach ($wpdb->get_results("SELECT ID, post_type, post_content FROM {$wpdb->posts}
                                  WHERE post_type NOT IN ({$content_types}) AND post_status NOT IN ('auto-draft','trash')") as $p) {
        $add($p->post_content, wcs_type_label($p->post_type) . ' ' . $p->ID);
    }
    foreach ($wpdb->get_results("SELECT m.post_id, m.meta_key, m.meta_value FROM {$wpdb->postmeta} m JOIN {$wpdb->posts} p ON p.ID = m.post_id
                                  WHERE p.post_type NOT IN ({$content_types}) AND p.post_status NOT IN ('auto-draft','trash')
                                    AND m.meta_value LIKE '%http%'") as $m) {
        if ($m->meta_key === '_elementor_data' || !wcs_meta_skip($m->meta_key)) { $add(maybe_unserialize($m->meta_value), 'post ' . $m->post_id); }
    }
    foreach ($wpdb->get_results("SELECT m.post_id, m.meta_value FROM {$wpdb->postmeta} m WHERE m.meta_key = '_menu_item_url'") as $m) {
        $add($m->meta_value, 'menu item ' . $m->post_id);
    }
    foreach ($wpdb->get_results("SELECT option_name, option_value FROM {$wpdb->options} WHERE option_value LIKE '%http%'") as $op) {
        if (!wcc_option_skip($op->option_name)) { $add(maybe_unserialize($op->option_value), 'setting ' . $op->option_name); }
    }
    foreach ($hosts as $h => $w) {
        $say(sprintf('  %-34s %d place(s): %s', $h, count($w), implode(', ', array_slice(array_keys($w), 0, 5)) . (count($w) > 5 ? ', …' : '')));
    }
    if (!$hosts) { $say('  none'); }
    else { $say('  → remove them all, whichever builder holds them:  --links ' . implode(',', array_keys($hosts))); }
}
if ($o['links']) {
    $say(''); $say('Links to ' . implode(', ', $o['links']));
    $hosts = array();
    foreach ($o['links'] as $h) {
        if (in_array($h, $site_hosts, true)) { $say("  ✗ {$h} is this site — refused"); $problems++; continue; }
        if (!preg_match(wcs_spam_host_re(), $h)) { $say("  ✗ {$h} does not read as a spam domain by the scanner's test — refused"); $problems++; continue; }
        $hosts[] = $h;
    }
    if ($hosts) {
        $hre = wcc_host_re($hosts);
        $places = 0; $tot = 0; $tunits = 0;
        $tell = function ($where, $n, $units, $extra = '') use (&$places, &$tot, &$tunits, $apply, $say) {
            $places++; $tot += $n; $tunits += $units;
            $say(sprintf('  %s %s: %d link(s)%s%s', $apply ? '✔' : '→', $where, $n,
                $units ? sprintf(', %d spam-only unit(s) removed whole', $units) : '', $extra));
        };
        // Post content, as stored: no content filter runs over the rest of the page.
        foreach ($wpdb->get_results("SELECT ID, post_type, post_title, post_content FROM {$wpdb->posts}
                                      WHERE post_type NOT IN ({$content_types}) AND post_status NOT IN ('auto-draft','trash')") as $p) {
            if (!wcc_mentions($p->post_content, $hre)) { continue; }
            $n = 0; $u = 0; $new = wcc_scrub_text($p->post_content, $hre, $n, $u);
            if ($new === $p->post_content) { continue; }
            if ($apply) { $wpdb->update($wpdb->posts, array('post_content' => $new), array('ID' => (int) $p->ID)); clean_post_cache((int) $p->ID); $changed_posts[(int) $p->ID] = 1; }
            $tell(wcs_type_label($p->post_type) . ' ' . $p->ID . ' "' . wcs_clip($p->post_title, 40) . '" (content)', $n, $u);
        }
        // Builder data and every other post meta: Elementor widget by widget, the rest by value.
        foreach ($wpdb->get_results("SELECT m.meta_id, m.post_id, m.meta_key, m.meta_value FROM {$wpdb->postmeta} m
                                      JOIN {$wpdb->posts} p ON p.ID = m.post_id
                                      WHERE p.post_type NOT IN ({$content_types}) AND p.post_status NOT IN ('auto-draft','trash')
                                        AND m.meta_key NOT IN ('_menu_item_url','_edit_lock','_edit_last','_wp_attachment_metadata')") as $m) {
            if (in_array($m->meta_key, array('_menu_item_url', '_edit_lock', '_edit_last', '_wp_attachment_metadata'), true)) { continue; }
            if (!wcc_mentions(wcs_normalize($m->meta_value), $hre) && !wcc_mentions($m->meta_value, $hre)) { continue; }
            $n = 0; $u = 0; $pid = (int) $m->post_id;
            if ($m->meta_key === '_elementor_data') {
                $data = json_decode((string) $m->meta_value, true);
                if (!is_array($data)) { continue; }
                $gone = array(); $new = wcc_scrub_elementor($data, $hre, $n, $u, $gone);
                if (!$n) { continue; }
                $saved = false;
                if ($apply) {
                    if (class_exists('\Elementor\Plugin') && isset(\Elementor\Plugin::$instance->documents)) {
                        $doc = \Elementor\Plugin::$instance->documents->get($pid, false);
                        if ($doc) { $saved = (bool) $doc->save(array('elements' => $new)); }
                    }
                    if (!$saved) {
                        $wpdb->update($wpdb->postmeta, array('meta_value' => wp_json_encode($new)), array('meta_id' => (int) $m->meta_id));
                        delete_post_meta($pid, '_elementor_css'); delete_post_meta($pid, '_elementor_element_cache');
                        wp_cache_delete($pid, 'post_meta');
                    }
                    $changed_posts[$pid] = 1;
                }
                $tell("Elementor data of post {$pid}", $n, $u, ($gone ? '; widget(s) ' . implode(', ', $gone) : '')
                      . ($apply && !$saved ? ' (saved directly: open it in Elementor and click Update)' : ''));
                continue;
            }
            if (in_array($m->meta_key, array('_elementor_css', '_elementor_element_cache'), true)) {
                if ($apply) { $wpdb->delete($wpdb->postmeta, array('meta_id' => (int) $m->meta_id)); wp_cache_delete($pid, 'post_meta'); }
                continue;                     // caches: rebuilt by Elementor
            }
            $val = maybe_unserialize($m->meta_value);
            $new = wcc_scrub($val, $hre, $n, $u);
            if (!$n) { continue; }
            if ($apply) {
                $wpdb->update($wpdb->postmeta, array('meta_value' => maybe_serialize($new)), array('meta_id' => (int) $m->meta_id));
                wp_cache_delete($pid, 'post_meta'); $changed_posts[$pid] = 1;
            }
            $tell(wcs_meta_label($m->meta_key) . " of post {$pid}", $n, $u);
        }
        // Menu items pointing there go.
        foreach ($wpdb->get_results("SELECT m.post_id, m.meta_value FROM {$wpdb->postmeta} m WHERE m.meta_key = '_menu_item_url'") as $m) {
            if (!wcc_mentions($m->meta_value, $hre)) { continue; }
            if ($apply) { wp_delete_post((int) $m->post_id, true); }
            $tell('menu item ' . $m->post_id . ' (deleted)', 1, 1);
        }
        // Theme and Customizer settings, sidebar widgets, any other setting.
        foreach ($wpdb->get_results("SELECT option_name, option_value FROM {$wpdb->options}") as $op) {
            if (wcc_option_skip($op->option_name) || (!wcc_mentions($op->option_value, $hre) && !wcc_mentions(wcs_normalize($op->option_value), $hre))) { continue; }
            $n = 0; $u = 0; $new = wcc_scrub(maybe_unserialize($op->option_value), $hre, $n, $u);
            if (!$n) { continue; }
            if ($apply) { update_option($op->option_name, $new); }
            $tell(wcs_option_label($op->option_name), $n, $u);
        }
        if (!$places) { $say('  no links to ' . implode(', ', $hosts) . ' found'); }
        elseif (!$apply) { $say("  → would remove {$tot} link(s) in {$places} place(s)"); }
        else { $say("  ✔ removed {$tot} link(s) in {$places} place(s)"); }
    }
}

if ($apply && $changed_posts) {
    if (class_exists('\Elementor\Plugin') && isset(\Elementor\Plugin::$instance->files_manager)) {
        \Elementor\Plugin::$instance->files_manager->clear_cache();
    }
    // Builders that keep rendered copies, and page caches that would keep serving the old page.
    if (class_exists('FLBuilderModel') && method_exists('FLBuilderModel', 'delete_asset_cache_for_all_posts')) { FLBuilderModel::delete_asset_cache_for_all_posts(); }
    if (class_exists('ET_Core_PageResource') && method_exists('ET_Core_PageResource', 'remove_static_resources')) { ET_Core_PageResource::remove_static_resources('all', 'all'); }
    if (function_exists('rocket_clean_domain')) { rocket_clean_domain(); }
    if (function_exists('w3tc_flush_all')) { w3tc_flush_all(); }
    if (function_exists('wp_cache_clear_cache')) { wp_cache_clear_cache(); }
    if (function_exists('do_action')) { do_action('litespeed_purge_all'); }
    wp_cache_flush();
}
$say('');
if ($o['report'] && !$apply) {
    $say('To clean, name what to remove (each is checked again before anything changes):');
    $say('  wp-links.sh clean --links <domain>,<domain> --widgets <id>,<id> --title <post id>="<real title>" \\');
    $say('                    --trash <post id>,<post id> --revisions --indexnow');
    $say('  (a preview)   then the same with --apply');
}
if ($problems) { WP_CLI::halt(1); }
