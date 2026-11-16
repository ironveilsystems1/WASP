<?php
/**
 * wasp-content-scan.php — injected links and spam in a WordPress site's content
 *
 * Run by `wp-links.sh spam` inside the wordpress container, script on stdin:
 *
 *     podman exec -i --user www-data wordpress php -- [--json] < wasp-content-scan.php
 *
 * WHY
 *
 * A real import carried three casino paragraphs into the live pages, a casino
 * advert in a page title, spam articles in three languages, and a Rank Math
 * log of those articles being announced to search engines -- and every file
 * and signature check passed, because none of it is code. It is content,
 * typed into the editor through a valid session. Finding it took six hand-
 * written SQL queries. This does it in one pass and names each page, each
 * Elementor widget and each domain.
 *
 * HOW
 *
 * It reads the database DIRECTLY, with the container's own credentials, and
 * never loads WordPress: no plugin or theme code runs, so a compromised plugin
 * cannot hide its own content from the scan, and the scan works on a site too
 * broken to load. Read-only: nothing is changed.
 *
 * Looked at: every post, page, template and other content type except
 * revisions (counted, not listed: they are not public), whichever builder or
 * theme made it:
 *   - the content itself: classic HTML, the block editor and block plugins
 *     (links in block settings too), shortcode builders (Divi, WPBakery, Avada
 *     -- links in module settings, URL-encoded or not);
 *   - Elementor page data widget by widget, so the result names the widget;
 *   - every other builder's page data, kept as post meta (Beaver Builder,
 *     Bricks, Oxygen, Breakdance, SiteOrigin, Thrive, Brizy, Themify,
 *     Cornerstone -- serialized, JSON or base64), and SEO titles and
 *     descriptions;
 *   - site-editor templates and template parts (headers, footers), patterns
 *     and theme-builder layouts, named as such;
 *   - theme settings (Customizer, Divi, Avada, Astra, GeneratePress ...) and
 *     any other site option holding a spam link, menu links, sidebar widgets;
 *   - Rank Math's IndexNow log, which records what the site told search engines.
 *
 * What counts as spam is deliberately narrow: gambling, pharmacy, adult and
 * payday-loan words, in link targets, link text, titles and URL slugs. A small
 * business linking to a casino is never right; a word list wide enough to catch
 * "loan" would flag every bank. Links pasted from a Google Sheet and links
 * hidden with CSS are reported beside them, because that is how paid link
 * placement usually arrives.
 */

// ── Patterns ────────────────────────────────────────────────────────────────
// Domains: substring match on the host. "slot" is here and not in the text
// list: an ordinary site can say "slotted post", but has no reason to link to a
// host with "slot" in its name.
// Substrings, because domains and slugs run words together ("bestcasinoslots").
// Two are also inside ordinary words, found on a field site: "cialis" in
// speCIALISt / soCIALISm / speCIALISE, and "casin" in CASINg (window and door
// casing). (?![tme]) and (?!g) keep those out; "buycialisonline", "cialis20mg"
// and "casino" still match.
function wcs_spam_host_re() {
    return '/(casin(?!g)|kasin|kasyn|kaszin|cassin|slot|poker|roulette|blackjack|jackpot|betting|bet365|betway|1xbet|mostbet|melbet|sportsbet|bookmaker|gambl|scommess|apuest|viagra|cialis(?![tme])|levitra|kamagra|sildenafil|tadalafil|porn|xxx|escort|payday)/i';
}
// Words in link text, titles and visible text. Whole words, many languages.
function wcs_spam_text_re() {
    return '/\b(casino|casinos|casinò|kasino|kasinot|kasyno|kaszinó|cassino|scommess[a-z]*|apuestas?|gambling|gioco d\'azzardo|poker|roulette|blackjack|jackpot|sportsbook|bookmaker|viagra|cialis|levitra|kamagra|sildenafil|tadalafil|porn[a-z]*|escort service|payday loans?)\b/iu';
}
// URL slugs run words together ("onlinecasinoguide"): substring.
function wcs_spam_slug_re() {
    return '/(casino|kasino|kasyno|kaszino|cassino|scommess|apuesta|gambling|poker|roulette|blackjack|jackpot|bookmaker|viagra|cialis(?![tme])|levitra|kamagra|porn|payday)/i';
}
function wcs_hidden_style_re() {
    return '/(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(px|pt|em|rem)?\s*(;|$)|(left|top|text-indent)\s*:\s*-\d{3,}\s*px|height\s*:\s*0(px)?\s*;\s*overflow\s*:\s*hidden|opacity\s*:\s*0(\.0+)?\s*(;|$))/i';
}

function wcs_host($url) {
    $h = parse_url(trim(html_entity_decode((string) $url, ENT_QUOTES)), PHP_URL_HOST);
    return $h ? strtolower($h) : '';
}
function wcs_bare($host) { return preg_replace('/^www\./', '', strtolower((string) $host)); }
function wcs_clip($s, $n = 70) {
    $s = trim(preg_replace('/\s+/u', ' ', strip_tags(html_entity_decode((string) $s, ENT_QUOTES, 'UTF-8'))));
    return mb_strlen($s, 'UTF-8') > $n ? mb_substr($s, 0, $n, 'UTF-8') . '…' : $s;
}

/**
 * Look through one piece of HTML. Returns a list of findings:
 *   ['spam_link', host, anchor text, sheets?, hidden?]
 *   ['spam_text', snippet]
 * and adds every outbound host to $outbound.
 */
/** The substrings of wcs_spam_host_re(), for a cheap SQL pre-filter (LIKE). */
function wcs_spam_terms() {
    preg_match('/\((.*)\)/', wcs_spam_host_re(), $m);
    return array_map(function ($t) { return preg_replace('/\(\?![^)]*\)/', '', $t); }, explode('|', $m[1]));
}

/**
 * Builder data and settings hide URLs from an <a href> search: JSON escapes
 * the slashes ("https:\/\/"), WPBakery URL-encodes them ("url:https%3A%2F%2F"),
 * serialized PHP and block comments wrap them in quotes of their own. Undo
 * those so one search sees every link, whatever wrote it.
 */
function wcs_normalize($s) {
    $s = (string) $s;
    if (strpos($s, '\\') !== false) {
        $s = str_replace(array('\\/', '\\"', '\\u002F', '\\u002f', '\\u0026', '\\u003C', '\\u003E', '\\u003c', '\\u003e'),
                         array('/', '"', '/', '/', '&', '<', '>', '<', '>'), $s);
    }
    if (stripos($s, '%3A%2F%2F') !== false) {
        $s = preg_replace_callback('#https?%3A%2F%2F[^\s"\'|\]\[<>]+#i', function ($m) { return rawurldecode($m[0]); }, $s);
    }
    return $s;
}

/** Hosts of every http(s) URL in a string, in or out of a link. */
function wcs_url_hosts($s) {
    $out = array();
    if (preg_match_all('#https?://([a-z0-9][a-z0-9.-]*[a-z0-9])#i', (string) $s, $m)) {
        foreach ($m[1] as $h) { $out[wcs_bare($h)] = true; }
    }
    return array_keys($out);
}

/**
 * A stored value as text to search: serialized PHP and JSON are searched as
 * they are (normalized); a long base64 run (Brizy keeps its pages that way) is
 * decoded and searched too.
 */
function wcs_blob($v) {
    if (is_array($v) || is_object($v)) {
        $v = json_encode($v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR);
    }
    $v = (string) $v;
    if (strlen($v) > 200 && preg_match('#^[A-Za-z0-9+/=\s]+$#', $v)) {
        $d = base64_decode($v, true);
        if ($d !== false && preg_match('#[<"]#', $d)) { $v .= "\n" . $d; }
    } elseif (preg_match_all('#"[A-Za-z0-9+/]{300,}={0,2}"#', $v, $b)) {
        foreach ($b[0] as $chunk) {
            $d = base64_decode(trim($chunk, '"'), true);
            if ($d !== false) { $v .= "\n" . $d; }
        }
    }
    return wcs_normalize($v);
}

/** Where a post meta key's content is edited, in words. */
function wcs_meta_label($key) {
    static $map = array(
        '_fl_builder_data' => 'Beaver Builder layout', '_fl_builder_draft' => 'Beaver Builder draft',
        '_bricks_page_content_2' => 'Bricks layout', '_bricks_page_header_2' => 'Bricks header',
        '_bricks_page_footer_2' => 'Bricks footer', 'ct_builder_shortcodes' => 'Oxygen layout',
        '_ct_builder_shortcodes' => 'Oxygen layout', '_ct_builder_json' => 'Oxygen layout',
        '_breakdance_data' => 'Breakdance layout', 'panels_data' => 'SiteOrigin Page Builder layout',
        'tve_updated_post' => 'Thrive Architect content', 'tve_content_before_more' => 'Thrive Architect content',
        'brizy' => 'Brizy content', '_themify_builder_settings_json' => 'Themify Builder layout',
        '_cornerstone_data' => 'Cornerstone layout', '_et_pb_old_content' => 'Divi (content before the builder)',
        'rank_math_title' => 'SEO title (Rank Math)', 'rank_math_description' => 'SEO description (Rank Math)',
        '_yoast_wpseo_title' => 'SEO title (Yoast)', '_yoast_wpseo_metadesc' => 'SEO description (Yoast)',
        '_aioseo_title' => 'SEO title (AIOSEO)', '_aioseo_description' => 'SEO description (AIOSEO)',
    );
    return $map[$key] ?? "custom field {$key}";
}

/** Post meta that is not content, or is read elsewhere: never searched generically. */
function wcs_meta_skip($key) {
    return in_array($key, array('_elementor_data', '_menu_item_url', '_wp_attachment_metadata', '_wp_attached_file',
                                '_edit_lock', '_edit_last', '_elementor_css', '_elementor_element_cache',
                                '_elementor_page_assets', '_elementor_controls_usage', '_wp_trash_meta_status'), true)
        || strpos($key, '_oembed_') === 0 || strpos($key, '_transient') === 0;
}

/** Where a site option is edited, in words. */
function wcs_option_label($name) {
    if (strpos($name, 'theme_mods_') === 0) { return 'theme settings of "' . substr($name, 11) . '" (Appearance → Customize)'; }
    static $map = array(
        'et_divi' => 'Divi theme options (Divi → Theme Options)', 'fusion_options' => 'Avada options (Avada → Options)',
        'avada_theme_options' => 'Avada options (Avada → Options)', 'astra-settings' => 'Astra settings (Appearance → Customize)',
        'generate_settings' => 'GeneratePress settings (Appearance → Customize)', 'flatsome_settings' => 'Flatsome settings',
        'kadence_theme_options' => 'Kadence settings (Appearance → Customize)', 'blocksy_options' => 'Blocksy settings',
        'elementor_active_kit' => 'Elementor site settings',
    );
    return $map[$name] ?? "site setting {$name}";
}

/** Options that are caches, logs or read elsewhere: never searched generically. */
function wcs_option_skip($name) {
    return strpos($name, '_transient') === 0 || strpos($name, '_site_transient') === 0 || strpos($name, 'widget_') === 0
        || in_array($name, array('rank_math_indexnow_log', 'home', 'siteurl', 'cron', 'rewrite_rules', 'recently_edited',
                                 'active_plugins', 'uninstall_plugins', 'dashboard_widget_options'), true);
}

/** Content types the site editor and theme builders keep their parts in. */
function wcs_type_label($type) {
    static $map = array(
        'wp_template' => 'site editor template', 'wp_template_part' => 'site editor template part (header/footer)',
        'wp_block' => 'pattern (reusable block)', 'wp_navigation' => 'site editor menu',
        'et_template' => 'Divi Theme Builder template', 'et_header_layout' => 'Divi Theme Builder header',
        'et_body_layout' => 'Divi Theme Builder body', 'et_footer_layout' => 'Divi Theme Builder footer',
        'et_pb_layout' => 'Divi library layout', 'elementor_library' => 'Elementor template',
        'fl-builder-template' => 'Beaver Builder template', 'fl-theme-layout' => 'Beaver Themer layout',
        'bricks_template' => 'Bricks template', 'ct_template' => 'Oxygen template', 'breakdance_template' => 'Breakdance template',
        'vc_grid_item' => 'WPBakery grid template', 'fusion_template' => 'Avada layout', 'fusion_element' => 'Avada library element',
    );
    return $map[$type] ?? $type;
}

/**
 * Does a post or revision hold spam? The one test for both the scan's count of
 * spam revisions and the cleaner's choice of which to delete. Until 10.23 the
 * scan counted with SQL LIKE '%cialis%' and four other words, so every revision
 * of a page saying "specialists" was spam: 115 on a clean field site, after the
 * cleaner (using this test) had rightly deleted the real ones.
 */
function wcs_post_is_spam($title, $slug, $content, $edata, array $site_hosts) {
    $ob = array();
    if ($title !== '' && preg_match(wcs_spam_text_re(), $title)) { return 'title'; }
    if ($slug !== '' && preg_match(wcs_spam_slug_re(), $slug)) { return 'address'; }
    foreach (wcs_html((string) $content, $site_hosts, $ob) as $x) {
        if ($x[0] === 'spam_link' || $x[0] === 'spam_text') { return 'content'; }
    }
    if (is_string($edata) && $edata !== '') {
        foreach (wcs_elementor($edata, $site_hosts, $ob) as $w) {
            foreach ($w['findings'] as $x) {
                if ($x[0] === 'spam_link' || $x[0] === 'spam_text') { return 'Elementor widget ' . $w['widget']; }
            }
        }
    }
    return '';
}

function wcs_html(string $html, array $site_hosts, array &$outbound) {
    $found = array();
    if ($html === '' || stripos($html, '<a') === false && stripos($html, 'http') === false
        && stripos($html, '%3A%2F%2F') === false && !preg_match(wcs_spam_text_re(), $html)) {
        return $found;
    }
    $html = wcs_normalize($html);
    $sheets = (stripos($html, 'data-sheets-') !== false || stripos($html, 'in-cell-link') !== false);
    // Hidden containers: everything after an opening tag that hides itself
    // and before its close is treated as hidden. Approximate, deliberately --
    // a false "hidden" beside a real spam link costs nothing.
    $hidden_spans = array();
    if (preg_match_all('/<([a-z0-9]+)\b[^>]*\bstyle\s*=\s*(["\'])([^"\']*)\2[^>]*>/i', $html, $tm, PREG_OFFSET_CAPTURE | PREG_SET_ORDER)) {
        foreach ($tm as $t) {
            if (preg_match(wcs_hidden_style_re(), $t[3][0])) {
                $start = $t[0][1];
                $close = stripos($html, '</' . $t[1][0], $start + strlen($t[0][0]));
                $hidden_spans[] = array($start, $close === false ? strlen($html) : $close);
            }
        }
    }
    $spam_link_seen = false;
    if (preg_match_all('/<a\b[^>]*\bhref\s*=\s*(["\'])(.*?)\1[^>]*>(.*?)<\/a>/is', $html, $am, PREG_OFFSET_CAPTURE | PREG_SET_ORDER)) {
        foreach ($am as $a) {
            $href = $a[2][0];
            $host = wcs_host($href);
            if ($host === '') {
                continue;                       // relative, mailto:, tel:, #
            }
            $internal = in_array(wcs_bare($host), $site_hosts, true);
            if (!$internal) {
                $outbound[wcs_bare($host)] = ($outbound[wcs_bare($host)] ?? 0) + 1;
            }
            $text = wcs_clip($a[3][0], 50);
            $hidden = false;
            foreach ($hidden_spans as $sp) {
                if ($a[0][1] > $sp[0] && $a[0][1] < $sp[1]) { $hidden = true; break; }
            }
            if (!$internal && (preg_match(wcs_spam_host_re(), $host) || preg_match(wcs_spam_text_re(), $a[3][0]))) {
                $found[] = array('spam_link', wcs_bare($host), $text, $sheets, $hidden);
                $spam_link_seen = true;
            } elseif (!$internal && $hidden) {
                $found[] = array('hidden_link', wcs_bare($host), $text, $sheets, true);
            }
        }
    }
    // A spam URL outside any <a>: a button or menu setting in block JSON, a
    // shortcode attribute (Divi's button_url, WPBakery's link="url:..."), a
    // builder's own link field, or bare in the text. Once per domain.
    $linked = array();
    foreach ($found as $x) { if ($x[0] === 'spam_link') { $linked[$x[1]] = true; } }
    foreach (wcs_url_hosts($html) as $h) {
        if (isset($linked[$h]) || in_array($h, $site_hosts, true) || !preg_match(wcs_spam_host_re(), $h)) { continue; }
        $outbound[$h] = ($outbound[$h] ?? 0) + 1;
        $found[] = array('spam_link', $h, '(in a block, shortcode or builder setting)', $sheets, false);
        $spam_link_seen = true;
    }
    // Spam wording with no link of its own (text-only spam, or the link is in
    // another widget): reported once per block, only if no link said it already.
    if (!$spam_link_seen && preg_match(wcs_spam_text_re(), strip_tags($html), $wm)) {
        $plain = strip_tags(html_entity_decode($html, ENT_QUOTES, 'UTF-8'));
        $pos = mb_stripos($plain, $wm[0], 0, 'UTF-8');
        $found[] = array('spam_text', wcs_clip(mb_substr($plain, max(0, $pos - 30), 90, 'UTF-8'), 80));
    }
    return $found;
}

/**
 * Everything a widget shows or links to, as HTML: its text settings, plus each
 * link control ({"url": "..."}) wrapped as an <a> so a button pointing at a
 * casino is seen like a text link. The cleaner judges a widget by this too.
 */
function wcs_widget_html(array $el) {
    $html = '';
    if (!isset($el['settings']) || !is_array($el['settings'])) { return $html; }
    array_walk_recursive($el['settings'], function ($v) use (&$html) {
        if (is_string($v)) { $html .= ' ' . $v; }
    });
    array_walk_recursive($el['settings'], function ($v, $k) use (&$html) {
        if ($k === 'url' && is_string($v) && preg_match('#^https?://#i', $v)) {
            $html .= ' <a href="' . htmlspecialchars($v, ENT_QUOTES) . '">(button/link)</a>';
        }
    });
    return $html;
}

/** Walk Elementor page data; one result per widget with findings. */
function wcs_elementor($json, array $site_hosts, array &$outbound) {
    $out = array();
    $data = is_string($json) ? json_decode($json, true) : $json;
    if (!is_array($data)) {
        return $out;
    }
    $walk = function ($els) use (&$walk, &$out, $site_hosts, &$outbound) {
        foreach ((array) $els as $el) {
            if (!is_array($el)) { continue; }
            if (($el['elType'] ?? '') === 'widget' && isset($el['settings']) && is_array($el['settings'])) {
                $html = wcs_widget_html($el);
                $f = wcs_html($html, $site_hosts, $outbound);
                if ($f) {
                    $out[] = array('widget' => (string) ($el['id'] ?? '?'), 'type' => (string) ($el['widgetType'] ?? 'widget'), 'findings' => $f);
                }
            }
            if (!empty($el['elements'])) { $walk($el['elements']); }
        }
    };
    $walk($data);
    return $out;
}

/**
 * The analysis, on plain arrays -- what the tests drive.
 *
 * $d = [
 *   'siteurl' => 'https://example.com',
 *   'posts' => [[ID, post_type, post_status, post_title, post_name, post_content, author, modified_gmt], ...],
 *   'elementor' => [post_id => json, ...],
 *   'menus' => [[menu_item_id, url, title], ...],
 *   'widgets' => [option_name => unserialized value, ...],
 *   'indexnow' => unserialized rank_math_indexnow_log or null,
 *   'revisions_with_spam' => int,
 * ]
 */
function wcs_analyze(array $d) {
    $site_host = wcs_bare(wcs_host($d['siteurl'] ?? ''));
    $site_hosts = array_values(array_filter(array($site_host)));
    $outbound = array();
    $items = array();
    foreach ($d['posts'] ?? array() as $p) {
        list($id, $type, $status, $title, $slug, $content, $author, $modified) = array_pad(array_values($p), 8, '');
        $f = array();
        if ($title !== '' && preg_match(wcs_spam_text_re(), $title)) {
            $f[] = array('where' => 'title', 'what' => array('spam_title', wcs_clip($title, 80)));
        }
        if ($slug !== '' && preg_match(wcs_spam_slug_re(), $slug)) {
            $f[] = array('where' => 'URL', 'what' => array('spam_slug', '/' . $slug . '/'));
        }
        foreach (wcs_html((string) $content, $site_hosts, $outbound) as $x) {
            $f[] = array('where' => 'content', 'what' => $x);
        }
        if (isset($d['elementor'][$id])) {
            foreach (wcs_elementor($d['elementor'][$id], $site_hosts, $outbound) as $w) {
                foreach ($w['findings'] as $x) {
                    $f[] = array('where' => "Elementor widget {$w['widget']} ({$w['type']})", 'what' => $x);
                }
            }
        }
        // Every other builder's page data, and SEO fields: post meta.
        foreach ($d['meta'][$id] ?? array() as $mv) {
            list($key, $val) = array_pad(array_values($mv), 2, '');
            if (wcs_meta_skip((string) $key)) { continue; }
            foreach (wcs_html(wcs_blob($val), $site_hosts, $outbound) as $x) {
                $f[] = array('where' => wcs_meta_label((string) $key), 'what' => $x);
            }
        }
        if ($f) {
            $items[] = array('id' => (int) $id, 'type' => wcs_type_label($type), 'status' => $status,
                'title' => wcs_clip($title !== '' ? $title : '(no title)', 60),
                'author' => $author, 'modified' => $modified, 'findings' => $f);
        }
    }
    foreach ($d['menus'] ?? array() as $m) {
        list($mid, $url, $mt) = array_pad(array_values($m), 3, '');
        $h = wcs_host($url);
        if ($h === '' || in_array(wcs_bare($h), $site_hosts, true)) { continue; }
        $outbound[wcs_bare($h)] = ($outbound[wcs_bare($h)] ?? 0) + 1;
        if (preg_match(wcs_spam_host_re(), $h) || preg_match(wcs_spam_text_re(), (string) $mt)) {
            $items[] = array('id' => (int) $mid, 'type' => 'menu item', 'status' => 'publish', 'title' => wcs_clip($mt, 60),
                'author' => '', 'modified' => '',
                'findings' => array(array('where' => 'menu', 'what' => array('spam_link', wcs_bare($h), wcs_clip($mt, 50), false, false))));
        }
    }
    foreach ($d['widgets'] ?? array() as $name => $val) {
        $html = '';
        if (is_array($val)) {
            array_walk_recursive($val, function ($v) use (&$html) { if (is_string($v)) { $html .= ' ' . $v; } });
        } elseif (is_string($val)) {
            $html = $val;
        }
        $f = array();
        foreach (wcs_html($html, $site_hosts, $outbound) as $x) {
            $f[] = array('where' => 'sidebar widget', 'what' => $x);
        }
        if ($f) {
            $items[] = array('id' => 0, 'type' => 'widget', 'status' => 'publish', 'title' => (string) $name,
                'author' => '', 'modified' => '', 'findings' => $f);
        }
    }
    // Theme settings and every other site option holding a spam link.
    foreach ($d['options'] ?? array() as $name => $val) {
        if (wcs_option_skip((string) $name)) { continue; }
        $f = array();
        foreach (wcs_html(wcs_blob($val), $site_hosts, $outbound) as $x) {
            if ($x[0] === 'spam_text') { continue; }     // settings hold words of every kind; links only
            $f[] = array('where' => wcs_option_label((string) $name), 'what' => $x);
        }
        if ($f) {
            $items[] = array('id' => 0, 'type' => 'setting', 'status' => 'publish', 'title' => (string) $name,
                'author' => '', 'modified' => '', 'findings' => $f);
        }
    }
    $announced = array();
    if (is_array($d['indexnow'] ?? null)) {
        foreach ($d['indexnow'] as $e) {
            $u = is_array($e) ? (string) ($e['url'] ?? '') : '';
            $path = (string) parse_url($u, PHP_URL_PATH);
            if ($u !== '' && preg_match(wcs_spam_slug_re(), $path)) {
                $announced[$u] = isset($e['time']) ? gmdate('Y-m-d H:i', (int) $e['time']) . ' UTC' : '';
            }
        }
    }
    arsort($outbound);
    $nlinks = 0; $nhost = array(); $sheets = 0; $hidden = 0;
    foreach ($items as $it) {
        foreach ($it['findings'] as $x) {
            if (in_array($x['what'][0], array('spam_link', 'hidden_link'), true)) {
                $nlinks++; $nhost[$x['what'][1]] = 1;
                if (!empty($x['what'][3])) { $sheets++; }
                if (!empty($x['what'][4])) { $hidden++; }
            }
        }
    }
    return array(
        'site' => $site_host,
        'items' => $items,
        'announced' => $announced,
        'outbound' => $outbound,
        'revisions_with_spam' => (int) ($d['revisions_with_spam'] ?? 0),
        'counts' => array('places' => count($items), 'links' => $nlinks, 'domains' => count($nhost),
                          'sheets' => $sheets, 'hidden' => $hidden, 'announced' => count($announced)),
    );
}

function wcs_render_text(array $r, $all_domains = false) {
    $o = array();
    $c = $r['counts'];
    $bad = $r['items'] || $r['announced'];
    $o[] = '';
    $o[] = 'Content and links — ' . ($r['site'] !== '' ? $r['site'] : 'this site');
    $o[] = str_repeat('━', 34);
    if (!$bad) {
        $o[] = '  ✔  No spam links, spam titles or spam pages found in published or draft content.';
    } else {
        $o[] = sprintf('  ✗  Spam found in %d place(s): %d link(s) to %d spam domain(s)%s%s.',
            $c['places'], $c['links'], $c['domains'],
            $c['sheets'] ? ", {$c['sheets']} pasted from a Google Sheet" : '',
            $c['hidden'] ? ", {$c['hidden']} hidden with CSS" : '');
        if ($c['sheets']) {
            $o[] = '     Text pasted from a spreadsheet carrying a link is how paid link placement';
            $o[] = '     usually arrives: someone with an editor account pastes it in.';
        }
    }
    foreach ($r['items'] as $it) {
        $o[] = '';
        $head = $it['type'] === 'widget' ? "  Sidebar widget {$it['title']}  (Appearance → Widgets"
              : ($it['type'] === 'menu item' ? "  Menu item \"{$it['title']}\"  (Appearance → Menus, item {$it['id']}"
              : ($it['type'] === 'setting' ? "  Setting {$it['title']}  (" . wcs_option_label($it['title'])
              : "  {$it['title']}  ({$it['type']} {$it['id']}, {$it['status']}"));
        if ($it['author'] !== '') { $head .= ", last saved by {$it['author']}"; }
        if ($it['modified'] !== '') { $head .= " {$it['modified']} UTC"; }
        $o[] = $head . ')';
        foreach ($it['findings'] as $f) {
            $w = $f['what'];
            switch ($w[0]) {
                case 'spam_link':
                    $o[] = "     {$f['where']}: link to {$w[1]}" . ($w[2] !== '' ? " \"{$w[2]}\"" : '')
                        . ($w[3] ? '  [pasted from a Google Sheet]' : '') . ($w[4] ? '  [hidden with CSS]' : '');
                    break;
                case 'hidden_link':
                    $o[] = "     {$f['where']}: HIDDEN link to {$w[1]}" . ($w[2] !== '' ? " \"{$w[2]}\"" : '');
                    break;
                case 'spam_title':
                    $o[] = "     title contains spam: \"{$w[1]}\"";
                    break;
                case 'spam_slug':
                    $o[] = "     address is a spam article: {$w[1]}";
                    break;
                case 'spam_text':
                    $o[] = "     {$f['where']}: spam wording \"{$w[1]}\"";
                    break;
            }
        }
    }
    if ($r['announced']) {
        $o[] = '';
        $o[] = '  Announced to search engines (Rank Math IndexNow log) — ' . count($r['announced']) . ' spam URL(s):';
        $i = 0;
        foreach ($r['announced'] as $u => $t) {
            if (++$i > 10) { $o[] = '     … and ' . (count($r['announced']) - 10) . ' more (--json lists all)'; break; }
            $o[] = "     {$u}" . ($t !== '' ? "  ({$t})" : '');
        }
        $o[] = '     After cleaning: Bing Webmaster Tools → URL Removal, Google Search Console → Removals.';
    }
    if ($r['revisions_with_spam'] > 0) {
        $o[] = '';
        $o[] = "  {$r['revisions_with_spam']} saved revision(s) also hold spam. Not public, but one click restores";
        $o[] = '  them: delete revisions once the pages are clean (WP-Optimize, or Elementor → Tools).';
    }
    if ($bad) {
        $o[] = '';
        $o[] = '  What to do';
        $dom = array();
        foreach ($r['items'] as $it) { foreach ($it['findings'] as $f) {
            if ($f['what'][0] === 'spam_link' && preg_match(wcs_spam_host_re(), $f['what'][1])) { $dom[$f['what'][1]] = true; } } }
        $o[] = '    1. Remove the links, whichever builder or theme holds them (a preview first):';
        $o[] = $dom ? '         doas wp-links.sh clean --links ' . implode(',', array_keys($dom))
                    : '         doas wp-links.sh clean      (lists what can be cleaned)';
        $o[] = '       Elementor widgets named above can go whole: --widgets <id>. By hand instead:';
        $o[] = '       Elementor, delete the widget; block editor, the block; Divi or WPBakery, the';
        $o[] = '       module; a theme setting, Appearance → Customize. Fix any spam title.';
        $o[] = '    2. Spam articles: wp-links.sh clean --trash <id>.';
        $o[] = '    3. Run this again until it is clean; then  wp-links.sh clean --revisions.';
        $o[] = '    4. Find who placed it: the account that last saved each page is shown above;';
        $o[] = '       wp-forensics.sh admins, and change the passwords of every editor.';
    }
    $o[] = '';
    $n = count($r['outbound']);
    $o[] = "  Outbound links: {$n} other domain(s)" . ($n ? ' — the sites this one vouches for.' : '');
    $top = $all_domains ? $r['outbound'] : array_slice($r['outbound'], 0, 12, true);
    foreach ($top as $h => $cnt) {
        $o[] = sprintf('     %-40s %d', $h, $cnt) . (preg_match(wcs_spam_host_re(), $h) ? '   ← spam' : '');
    }
    if (!$all_domains && $n > 12) { $o[] = '     … ' . ($n - 12) . ' more:  wp-links.sh spam --all-domains'; }
    $o[] = '';
    return implode("\n", $o) . "\n";
}

// ── Database (only when run as a program, not when a test includes this) ────
if (defined('WCS_LIBRARY_ONLY')) {
    return;
}
$args = array_slice($argv ?? array(), 1);
$json = in_array('--json', $args, true);
$all  = in_array('--all-domains', $args, true);
mysqli_report(MYSQLI_REPORT_OFF);
$db = @mysqli_connect(getenv('WORDPRESS_DB_HOST'), getenv('WORDPRESS_DB_USER'),
                      getenv('WORDPRESS_DB_PASSWORD'), getenv('WORDPRESS_DB_NAME'));
if (!$db) {
    fwrite(STDERR, "Cannot connect to the WordPress database from the container.\n");
    exit(2);
}
mysqli_set_charset($db, 'utf8mb4');
$p = getenv('WORDPRESS_TABLE_PREFIX') ?: 'wp_';
if (!preg_match('/^[A-Za-z0-9_]+$/', $p)) { fwrite(STDERR, "Unexpected table prefix.\n"); exit(2); }
$q = function ($sql) use ($db) {
    $r = mysqli_query($db, $sql);
    if (!$r) { fwrite(STDERR, 'Query failed: ' . mysqli_error($db) . "\n"); exit(2); }
    return mysqli_fetch_all($r, MYSQLI_NUM);
};
$opt = function ($name) use ($q, $p, $db) {
    $r = $q("SELECT option_value FROM {$p}options WHERE option_name = '" . mysqli_real_escape_string($db, $name) . "' LIMIT 1");
    return $r ? $r[0][0] : null;
};
$users = array();
foreach ($q("SELECT ID, user_login FROM {$p}users") as $u) { $users[(int) $u[0]] = $u[1]; }
$posts = array();
foreach ($q("SELECT ID, post_type, post_status, post_title, post_name, post_content, post_author, post_modified_gmt
               FROM {$p}posts WHERE post_type NOT IN ('revision','nav_menu_item','attachment','oembed_cache','customize_changeset','user_request')
                AND post_status NOT IN ('auto-draft','trash')") as $r) {
    $r[6] = $users[(int) $r[6]] ?? ('user ' . $r[6]);
    $posts[] = $r;
}
$el = array();
foreach ($q("SELECT m.post_id, m.meta_value FROM {$p}postmeta m JOIN {$p}posts x ON x.ID = m.post_id
              WHERE m.meta_key = '_elementor_data' AND x.post_type <> 'revision'") as $r) {
    $el[(int) $r[0]] = $r[1];
}
// Post meta that may hold a link (a cheap LIKE pre-filter; PHP decides).
$like = array();
foreach (wcs_spam_terms() as $t) { $like[] = "m.meta_value LIKE '%" . mysqli_real_escape_string($db, $t) . "%'"; }
$meta = array();
foreach ($q("SELECT m.post_id, m.meta_key, m.meta_value FROM {$p}postmeta m JOIN {$p}posts x ON x.ID = m.post_id
              WHERE x.post_type NOT IN ('revision','nav_menu_item','attachment','oembed_cache','customize_changeset','user_request')
                AND x.post_status NOT IN ('auto-draft','trash')
                AND m.meta_key NOT IN ('_elementor_data','_menu_item_url','_wp_attachment_metadata','_elementor_css','_elementor_element_cache')
                AND (" . implode(' OR ', $like) . " OR m.meta_value REGEXP '[A-Za-z0-9+/]{300}')") as $r) {
    $v = @unserialize($r[2], array('allowed_classes' => false));
    $meta[(int) $r[0]][] = array($r[1], ($v === false && $r[2] !== 'b:0;') ? $r[2] : $v);
}
$olike = str_replace('m.meta_value', 'option_value', implode(' OR ', $like));
$options = array();
foreach ($q("SELECT option_name, option_value FROM {$p}options
              WHERE option_name NOT LIKE '\\_transient%' AND option_name NOT LIKE '\\_site\\_transient%'
                AND option_name NOT LIKE 'widget\\_%' AND ({$olike})") as $r) {
    $v = @unserialize($r[1], array('allowed_classes' => false));
    $options[$r[0]] = ($v === false && $r[1] !== 'b:0;') ? $r[1] : $v;
}
$menus = array();
foreach ($q("SELECT x.ID, m.meta_value, x.post_title FROM {$p}postmeta m JOIN {$p}posts x ON x.ID = m.post_id
              WHERE m.meta_key = '_menu_item_url' AND m.meta_value <> ''") as $r) {
    $menus[] = $r;
}
$widgets = array();
foreach ($q("SELECT option_name, option_value FROM {$p}options WHERE option_name LIKE 'widget\\_%'") as $r) {
    $v = @unserialize($r[1], array('allowed_classes' => false));
    $widgets[$r[0]] = ($v === false && $r[1] !== 'b:0;') ? $r[1] : $v;
}
$ix = $opt('rank_math_indexnow_log');
$ix = $ix !== null ? @unserialize($ix, array('allowed_classes' => false)) : null;
// Revisions: the SQL only narrows the candidates; wcs_post_is_spam() decides,
// the same test `wp-links.sh clean --revisions` deletes by.
$rlike = array();
foreach (array_merge(wcs_spam_terms(), array('casino', 'kasino', 'cialis', 'viagra', 'porn')) as $t) {
    $e = mysqli_real_escape_string($db, $t);
    $rlike[] = "r.post_content LIKE '%{$e}%' OR r.post_title LIKE '%{$e}%' OR m.meta_value LIKE '%{$e}%'";
}
$rev_hosts = array_values(array_filter(array(wcs_bare(wcs_host($opt('home') ?: $opt('siteurl') ?: '')))));
$rev_n = 0;
foreach ($q("SELECT r.post_title, r.post_content, m.meta_value FROM {$p}posts r
               LEFT JOIN {$p}postmeta m ON m.post_id = r.ID AND m.meta_key = '_elementor_data'
              WHERE r.post_type = 'revision' AND (" . implode(' OR ', array_unique($rlike)) . ")") as $r) {
    if (wcs_post_is_spam((string) $r[0], '', (string) $r[1], (string) $r[2], $rev_hosts) !== '') { $rev_n++; }
}
$rev = array(array($rev_n));
$report = wcs_analyze(array(
    'siteurl' => $opt('home') ?: $opt('siteurl'),
    'posts' => $posts, 'elementor' => $el, 'meta' => $meta, 'options' => $options, 'menus' => $menus, 'widgets' => $widgets,
    'indexnow' => is_array($ix) ? $ix : null,
    'revisions_with_spam' => (int) ($rev[0][0] ?? 0),
));
echo $json ? json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n"
           : wcs_render_text($report, $all);
exit(($report['items'] || $report['announced']) ? 1 : 0);
