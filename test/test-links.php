<?php
/**
 * test-links.php — the content scanner (payload/php-tools/wasp-content-scan.php)
 *
 * Fixtures are shaped on a real import: Italian casino paragraphs pasted from a
 * Google Sheet into Elementor text widgets, a casino advert appended to a page
 * title, spam articles in three languages announced through Rank Math's
 * IndexNow log. Beside them, the things an ordinary small-business site legitimately
 * has -- "slotted posts", a pasted pricing table, a supplier link, a footer
 * credit -- which must NOT be reported.
 *
 * Run: php test/test-links.php
 */
define('WCS_LIBRARY_ONLY', true);
require dirname(__DIR__) . '/payload/php-tools/wasp-content-scan.php';

$pass = 0; $fail = 0;
function t($ok, $msg, $detail = '') {
    global $pass, $fail;
    if ($ok) { $pass++; echo "  [PASS] {$msg}\n"; }
    else { $fail++; echo "  [FAIL] {$msg}\n" . ($detail !== '' ? "         {$detail}\n" : ''); }
}
function el_text($id, $html) {
    return array('id' => $id, 'elType' => 'widget', 'widgetType' => 'text-editor', 'settings' => array('editor' => $html));
}
function el_section(array $widgets) {
    return array('id' => 'c' . substr(md5(serialize($widgets)), 0, 6), 'elType' => 'container', 'elements' => $widgets);
}

$sheets_spam = '<p><span data-sheets-root="1">Il marchio <a class="in-cell-link" href="https://casino-spam.example/" target="_blank" rel="noopener">slotsbonus</a> è sinonimo di successo e grandi premi nel gioco d\'azzardo online.</span></p>';
$data = array(
    'siteurl' => 'https://shop.example',
    'posts' => array(
        array(327, 'page', 'publish', "Commercial Gioca e vinci ogni giorno al grande casino online", 'commercial', '', 'designer@example.com', '2026-11-14 13:44:51'),
        array(226, 'page', 'publish', 'Services', 'services', '', 'designer@example.com', '2026-02-12 13:05:04'),
        array(40, 'page', 'publish', 'Residential', 'residential', '<p>Our slotted posts and <a href="https://www.supplier.example/catalog">supplier catalog</a>.</p>', 'owner', '2025-08-01 10:00:00'),
        array(41, 'page', 'publish', 'Prices', 'prices', '<table><tr><td><span data-sheets-root="1">Cedar 6ft</span></td><td>$32</td></tr></table>', 'owner', '2025-08-01 10:00:00'),
        array(512, 'post', 'publish', 'Esimerkkiartikkeli', 'kasinon-luotettavuus-esimerkki-artikkeli', '<p>Pelaajat arvostavat…</p>', 'user 9', '2026-02-02 02:40:00'),
        array(513, 'post', 'draft', 'Hidden one', 'hidden-one', '<div style="position:absolute; left:-9999px"><a href="https://pills-shop.example/">cheap pills</a></div>', 'user 9', '2026-02-10 15:12:00'),
        array(600, 'elementor_library', 'publish', 'Footer', 'footer', '', 'owner', '2025-08-01 10:00:00'),
    ),
    'elementor' => array(
        327 => json_encode(array(el_section(array(el_text('a1b2c3d', '<p>Commercial services.</p>'), el_text('w1spam1', $sheets_spam))))),
        226 => json_encode(array(el_section(array(
            el_text('w2spam2', '<p><span data-sheets-root="1">Scegliere <a class="in-cell-link" href="https://casino-vegas.example/">vegasbonus</a> significa…</span></p>'),
            array('id' => 'b77btn', 'elType' => 'widget', 'widgetType' => 'button', 'settings' => array('text' => 'Bonus', 'link' => array('url' => 'https://www.mostbet-promo.example/go'))),
        )))),
        600 => json_encode(array(el_section(array(el_text('f00t3r', '<p>Website by <a href="https://agency.example/">Agency</a></p>'))))),
    ),
    'menus' => array(array(900, 'https://bet365-mirror.example/', 'Promo'), array(901, 'https://shop.example/contact/', 'Contact')),
    'widgets' => array('widget_text' => array(2 => array('text' => '<a href="https://www.cialis-online.example/">order</a>'), '_multiwidget' => 1)),
    'indexnow' => array(
        array('url' => 'https://shop.example/kasinon-luotettavuus-esimerkki-artikkeli/', 'status' => 200, 'time' => 1770000000),
        array('url' => 'https://shop.example/eksempel-artikkel-om-nettcasino/', 'status' => 200, 'time' => 1770000001),
        array('url' => 'https://shop.example/residential/', 'status' => 200, 'time' => 1770000100),
    ),
    'revisions_with_spam' => 103,
);
$r = wcs_analyze($data);
$byid = array();
foreach ($r['items'] as $it) { $byid[$it['type'] . ':' . $it['id']] = $it; }
$txt = wcs_render_text($r);

echo "\nContent scanner: spam links, titles, pages\n";
$c = $byid['page:327'] ?? null;
t($c && $c['findings'][0]['what'][0] === 'spam_title', 'a casino advert appended to a page title is reported');
$w = null; foreach (($c['findings'] ?? array()) as $f) { if ($f['what'][0] === 'spam_link') { $w = $f; } }
t($w && $w['where'] === 'Elementor widget w1spam1 (text-editor)' && $w['what'][1] === 'casino-spam.example',
  'the spam link names its Elementor widget id and the domain', json_encode($w));
t($w && $w['what'][3] === true, '...and says it was pasted from a Google Sheet');
t(!isset($byid['page:327']) || count(array_filter($c['findings'], function ($f) { return strpos($f['where'], 'a1b2c3d') !== false; })) === 0,
  'the clean widget on the same page is not reported');
$p = $byid['page:226'] ?? array('findings' => array());
$hosts = array_map(function ($f) { return $f['what'][1] ?? ''; }, $p['findings']);
t(in_array('casino-vegas.example', $hosts, true), 'a second page with a pasted casino link is reported');
t(in_array('mostbet-promo.example', $hosts, true), 'a button whose link control points at a betting site is reported (www. dropped)');
t(!isset($byid['page:40']), '"slotted posts" and a supplier link are not spam');
t(!isset($byid['page:41']), 'a pricing table pasted from Google Sheets, with no link, is not reported');
t(isset($byid['post:512']) && $byid['post:512']['findings'][0]['what'][0] === 'spam_slug', 'a spam article is found by its address (Finnish "kasino…")');
$h = $byid['post:513'] ?? null;
t($h && $h['status'] === 'draft' && $h['findings'][0]['what'][4] === true, 'a link hidden with CSS (left:-9999px) is reported, drafts included');
t(!isset($byid['elementor_library:600']), 'a footer credit link to a normal site is not spam');
t(isset($byid['menu item:900']) && !isset($byid['menu item:901']), 'a menu item pointing at a betting site is reported; an internal one is not');
t(isset($byid['widget:0']) && $byid['widget:0']['title'] === 'widget_text', 'a sidebar text widget with a pharmacy link is reported');
t(count($r['announced']) === 2 && isset($r['announced']['https://shop.example/eksempel-artikkel-om-nettcasino/']),
  'IndexNow: spam URLs announced to search engines are listed; the real page is not');
t(strpos($r['announced']['https://shop.example/kasinon-luotettavuus-esimerkki-artikkeli/'], '2026-02-02 02:40') === 0,
  '...with when they were announced (UTC)');
t($r['outbound']['agency.example'] === 1 && $r['outbound']['supplier.example'] === 1 && !isset($r['outbound']['shop.example']),
  'outbound domains are inventoried; the site itself is not outbound');
t($r['counts']['sheets'] === 2, 'two links pasted from a spreadsheet are counted', json_encode($r['counts']));

echo "\nContent scanner: the readable report\n";
t(strpos($txt, 'Spam found in') !== false && strpos($txt, 'pasted from a Google Sheet') !== false, 'opens with a one-line verdict and the Sheets explanation');
t(strpos($txt, '(page 327, publish, last saved by designer@example.com 2026-11-14 13:44:51 UTC)') !== false,
  'each place names the page, its id, status and who last saved it');
t(strpos($txt, 'Elementor widget w1spam1 (text-editor): link to casino-spam.example "slotsbonus"  [pasted from a Google Sheet]') !== false,
  'each link line says where to click and what to delete');
t(strpos($txt, '103 saved revision(s) also hold spam') !== false, 'revisions holding spam are counted, not listed');
t(strpos($txt, 'What to do') !== false && strpos($txt, 'Edit with Elementor') !== false, 'ends with what to do, in order');
t(preg_match('/casino-spam\.example\s+\d+\s+← spam/', $txt) === 1, 'the outbound list marks spam domains');

$clean = wcs_analyze(array('siteurl' => 'https://shop.example', 'posts' => array(array(40, 'page', 'publish', 'Residential', 'residential', '<a href="/contact/">Contact</a>', 'owner', '')), 'elementor' => array()));
t($clean['items'] === array() && strpos(wcs_render_text($clean), 'No spam links') !== false, 'a clean site says so in one line');

echo "\n  links (php): {$pass} passed, {$fail} failed\n";
exit($fail ? 1 : 0);
