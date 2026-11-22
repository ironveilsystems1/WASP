<?php
/**
 * test-csp-report.php — the browser's security-header reports (10.28)
 *
 * 08-wasp-csp-report.php takes unauthenticated reports from any visitor and
 * writes a line per report to the log people read. This checks it keeps only
 * what `wp-hardening.sh embeds report` needs -- the directive, the blocked
 * origin, the page's path -- from both formats browsers send, and that odd or
 * hostile input becomes nothing rather than a strange log line.
 */
define('ABSPATH', '/tmp/');
function add_action() {}
function status_header() {}
require __DIR__ . '/../payload/mu-plugins/08-wasp-csp-report.php';

$pass = 0; $fail = 0;
function t($ok, $what, $got = null) {
    global $pass, $fail;
    if ($ok) { $pass++; echo "  [PASS] $what\n"; }
    else { $fail++; echo "  [FAIL] $what\n         " . json_encode($got) . "\n"; }
}
echo "\nSecurity-header reports\n";

$r = wasp_csp_parse(json_encode(array('csp-report' => array(
    'document-uri' => 'https://shop.example/contact/?name=Pat&email=pat@home.example',
    'effective-directive' => 'frame-src', 'violated-directive' => 'frame-src',
    'blocked-uri' => 'https://www.google.com/maps/embed?pb=!1m18!1m12', 'script-sample' => 'secret'))));
t($r === array(array('frame-src', 'https://www.google.com', '/contact/')), 'report-uri format: directive, origin only, the page path without its query', $r);

$r = wasp_csp_parse(json_encode(array(
    array('type' => 'csp-violation', 'body' => array('documentURL' => 'https://shop.example/', 'effectiveDirective' => 'font-src', 'blockedURL' => 'https://fonts.gstatic.com/s/roboto.woff2')),
    array('type' => 'deprecation', 'body' => array('id' => 'x')),
    array('type' => 'csp-violation', 'body' => array('documentURL' => 'https://shop.example/a', 'effectiveDirective' => 'script-src-elem', 'blockedURL' => 'inline')))));
t($r === array(array('font-src', 'https://fonts.gstatic.com', '/'), array('script-src-elem', 'inline', '/a')), 'Reporting API list: CSP reports kept, other report types ignored', $r);

$r = wasp_csp_parse(json_encode(array('csp-report' => array('violated-directive' => 'script-src https://x', 'blocked-uri' => 'https://WWW.Example.NET:8443/a.js', 'document-uri' => 'https://shop.example/x'))));
t($r === array(array('script-src', 'https://www.example.net:8443', '/x')), 'older browsers: the directive from violated-directive; host lower-cased, port kept', $r);

$bad = array(
    'chrome extension' => array('effective-directive' => 'script-src', 'blocked-uri' => 'chrome-extension://abc/x.js', 'document-uri' => 'https://s/'),
    'newline in host'  => array('effective-directive' => 'img-src', 'blocked-uri' => "https://evil.example\n[wasp-csp] fake", 'document-uri' => 'https://s/'),
    'odd directive'    => array('effective-directive' => "frame-src\nfake", 'blocked-uri' => 'https://a.example', 'document-uri' => 'https://s/'),
    'empty blocked'    => array('effective-directive' => 'frame-src', 'blocked-uri' => '', 'document-uri' => 'https://s/'),
    'javascript:'      => array('effective-directive' => 'script-src', 'blocked-uri' => 'javascript:alert(1)', 'document-uri' => 'https://s/'),
);
foreach ($bad as $what => $rep) {
    $r = wasp_csp_parse(json_encode(array('csp-report' => $rep)));
    t($r === array() || ($what === 'newline in host' && $r === array()), "nothing logged for: $what", $r);
}
$r = wasp_csp_parse(json_encode(array('csp-report' => array('effective-directive' => 'frame-src', 'blocked-uri' => 'https://a.example', 'document-uri' => "https://s/p<script>/\n../x"))));
t(count($r) === 1 && !preg_match('/[<>\s]/', $r[0][2]), 'a page path keeps no markup, spaces or newlines', $r);
t(wasp_csp_parse('not json') === array() && wasp_csp_parse('') === array() && wasp_csp_parse('"x"') === array(), 'garbage is nothing');
$many = array(); for ($i = 0; $i < 50; $i++) { $many[] = array('type' => 'csp-violation', 'body' => array('effectiveDirective' => 'font-src', 'blockedURL' => "https://f$i.example", 'documentURL' => 'https://s/')); }
t(count(wasp_csp_parse(json_encode($many))) === 20, 'a batch is read to 20 reports at most');

// The hourly budget: counted in a file, stops at the limit.
$f = rtrim(sys_get_temp_dir(), '/') . '/wasp-csp-' . gmdate('YmdH'); @unlink($f);
$n = 0; for ($i = 0; $i < 7; $i++) { if (wasp_csp_budget(5)) { $n++; } }
@unlink($f);
t($n === 5, 'at most the hourly budget of lines are written', $n);

echo "\n  passed $pass   failed $fail\n";
exit($fail ? 1 : 0);
