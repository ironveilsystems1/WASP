<?php
/**
 * test-wpress-reader.php — does the .wpress reader refuse what it must?
 *
 * Builds archives byte by byte and runs the real reader in a subprocess, because
 * the exit status and what landed on disk are the contract. A clean case proves
 * nothing about a parser of hostile input, so most of these are refusals, and
 * every refusal also asserts that nothing was written.
 *
 * The clean fixtures here share an author with the reader. They were also
 * checked once against a third-party archive builder and a third-party Go
 * extractor when this was written. Neither is a substitute for a real 7.x export.
 */

$READER = dirname(__DIR__) . '/payload/lib/wasp-wpress-reader.php';
$WORK   = sys_get_temp_dir() . '/wasp-wpress-test-' . getmypid();
mkdir($WORK, 0700);
$pass = 0;
$fail = 0;

function ok($what) { global $pass; $pass++; echo "  [PASS] {$what}\n"; }
function no($what, $why) { global $fail; $fail++; echo "  [FAIL] {$what}\n         {$why}\n"; }

function hdr($name, $size, $dir, $crc = '', $mtime = '1700000000') {
	return pack('a255a14a12a4088a8', $name, (string) $size, $mtime, $dir, $crc);
}
function entry($path, $content, $crc = true, $stored = null) {
	$stored = null === $stored ? $content : $stored;
	$dir    = dirname($path);
	return hdr(basename($path), strlen($stored), $dir, $crc ? hash('crc32b', $content) : '') . $stored;
}
function eof_new($body) {
	return pack('a255a14a4100a8', '', (string) strlen($body), '', hash('crc32b', $body));
}
function eof_old() { return str_repeat("\0", 4377); }
function pkg($o = array()) {
	return json_encode(array_replace_recursive(array(
		'SiteURL' => 'https://old.example', 'HomeURL' => 'https://old.example',
		'Plugin' => array('Version' => '7.112'), 'WordPress' => array('Version' => '6.8.3'),
		'Database' => array('Prefix' => 'abc_'), 'Plugins' => array('kept/kept.php'),
		'Template' => 'parent', 'Stylesheet' => 'child',
	), $o));
}
function base($extra = '') {
	return entry('package.json', pkg())
		. entry('database.sql', "INSERT INTO `SERVMASK_PREFIX_options` VALUES (1,'a','b','yes');\n")
		. entry('plugins/kept/kept.php', '<?php // kept')
		. entry('themes/parent/style.css', '/**/') . entry('themes/child/style.css', '/**/')
		. entry('uploads/2024/a.jpg', 'jpegbytes') . $extra;
}
function sealed($extra = '') { $b = base($extra); return $b . eof_new($b); }

function run($bytes, $args = '', $stdin = '') {
	global $READER, $WORK;
	static $n = 0;
	$n++;
	$a = "{$WORK}/a{$n}.wpress";
	$o = "{$WORK}/o{$n}";
	file_put_contents($a, $bytes);
	mkdir("{$o}/files", 0700, true); mkdir("{$o}/db"); mkdir("{$o}/meta");
	$cmd = 'php ' . escapeshellarg($READER) . ' extract ' . escapeshellarg($a) . ' ' . escapeshellarg($o) . ' ' . $args;
	$p = proc_open($cmd, array(array('pipe', 'r'), array('pipe', 'w'), array('pipe', 'w')), $pipes);
	fwrite($pipes[0], $stdin); fclose($pipes[0]);
	$out = stream_get_contents($pipes[1]); $err = stream_get_contents($pipes[2]);
	$rc = proc_close($p);
	$written = array();
	$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($o, FilesystemIterator::SKIP_DOTS));
	foreach ($it as $f) { if ($f->isFile()) { $written[] = substr($f->getPathname(), strlen($o) + 1); } }
	sort($written);
	return array($rc, $err, $written, $o, $out);
}
function scan($bytes) {
	global $READER, $WORK;
	$a = "{$WORK}/s.wpress";
	file_put_contents($a, $bytes);
	exec('php ' . escapeshellarg($READER) . ' scan ' . escapeshellarg($a) . ' 2>/dev/null', $lines, $rc);
	return array($rc, $lines);
}
function refused($what, $bytes, $status = 2, $args = '', $stdin = '') {
	list($rc, $err, $written) = run($bytes, $args, $stdin);
	if ($rc !== $status) { no($what, "exit {$rc}, wanted {$status}: " . trim($err)); return; }
	if ($written)        { no($what, 'refused, but wrote: ' . implode(' ', $written)); return; }
	ok($what);
}

echo "\n.wpress reader\n";
echo "\n── Clean archives\n";

list($rc, $err, $w, $o) = run(sealed());
if (0 === $rc && in_array('files/wp-content/uploads/2024/a.jpg', $w, true) && in_array('db/database.sql', $w, true)
	&& in_array('meta/package.json', $w, true) && in_array('meta/wpress.meta', $w, true)) {
	ok('members land in wp-content, the dump in db/, the manifest in meta/');
} else { no('clean extract', "exit {$rc} " . trim($err) . ' ' . implode(' ', $w)); }

$b = base();
list($rc, $err, $w2) = run($b . eof_old());
0 === $rc ? ok('a pre-7.104 archive with an all-NUL end block reads') : no('legacy end block', trim($err));

$old = hdr('package.json', strlen(pkg()), '.', '') . pkg() . entry('database.sql', 'x', false) . eof_old();
list($rc) = run($old);
0 === $rc ? ok('headers with an empty checksum field read') : no('legacy headers', "exit {$rc}");

$win = entry('package.json', pkg()) . entry('database.sql', 'x') . hdr('w.jpg', 1, 'uploads\\2024') . 'y';
list($rc, $err, $w3) = run($win . eof_new($win));
(0 === $rc && in_array('files/wp-content/uploads/2024/w.jpg', $w3, true))
	? ok('backslash directories from a Windows export normalise') : no('windows paths', trim($err));

$plugin_sql = sealed(entry('plugins/kept/schema.sql', 'CREATE TABLE x;'));
list($rc, , $w4) = run($plugin_sql);
(0 === $rc && in_array('files/wp-content/plugins/kept/schema.sql', $w4, true))
	? ok('a .sql file inside a plugin stays in the plugin') : no('plugin sql', "exit {$rc}");

$gz = function ($c) { $z = gzcompress($c, 6); return pack('N', strlen($z)) . $z; };
$chunks = ''; $content = random_bytes(700000);
foreach (str_split($content, 512000) as $c) { $chunks .= $gz($c); }
$body = entry('package.json', pkg(array('Compression' => array('Enabled' => true, 'Type' => 'gzip'))))
	. entry('database.sql', 'sql', true, $gz('sql')) . entry('uploads/z.bin', $content, true, $chunks);
list($rc, $err, , $oz) = run($body . eof_new($body));
(0 === $rc && file_get_contents("{$oz}/files/wp-content/uploads/z.bin") === $content)
	? ok('gzip chunks decode to the original bytes') : no('gzip', trim($err));

$pw = 'correct horse'; $key = substr(sha1($pw, true), 0, 16);
$enc = function ($c) use ($key) { $iv = random_bytes(16); return $iv . openssl_encrypt($c, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv); };
$sign = '"How long do you want these messages to remain secret? I want them to remain secret for as long as men are capable of evil." - Neal Stephenson';
$estored = ''; foreach (str_split($content, 512000) as $c) { $estored .= $enc($c); }
$ebody = entry('package.json', pkg(array('Encrypted' => true, 'EncryptedSignature' => base64_encode($enc($sign)))))
	. entry('database.sql', 'sql', true, $enc('sql')) . entry('uploads/e.bin', $content, true, $estored);
$earch = $ebody . eof_new($ebody);
list($rc, $err, , $oe) = run($earch, '--password-stdin', "{$pw}\n");
(0 === $rc && file_get_contents("{$oe}/files/wp-content/uploads/e.bin") === $content)
	? ok('a password-protected archive decrypts') : no('encrypted', trim($err));

echo "\n── Hostile members: refused, and nothing written\n";

$h = function ($name, $dir) {
	$b = entry('package.json', pkg()) . entry('database.sql', 'x') . hdr($name, 1, $dir) . 'y';
	return $b . eof_new($b);
};
refused('../ in the directory field',     $h('x.php', '../../etc'));
refused('../ in the name field',          $h('../x.php', 'uploads'));
refused('..\\ with backslashes',          $h('x.php', '..\\..\\etc'));
refused('traversal mid-path',             $h('x.php', 'uploads/../../..'));
refused('absolute path',                  $h('x.php', '/etc/cron.d'));
refused('Windows drive path',             $h('x.php', 'C:\\Windows'));
refused('URL as a path',                  $h('x.php', 'php://filter'));
refused('escape sequence in a name',      $h("x\x1b[2J.php", 'uploads'));
refused('newline in a name',              $h("x\ny.php", 'uploads'));
$late = base(hdr('x', 1, '../..') . 'y');
refused('a hostile LAST member stops the FIRST write', $late . eof_new($late));

$nul = entry('package.json', pkg()) . entry('database.sql', 'x')
	. pack('a255a14a12a4088a8', "safe.jpg\0.php", '1', '1', 'uploads', '') . 'y';
refused('NUL inside a name', $nul . eof_new($nul));

$dup = base(entry('uploads/2024/a.jpg', 'second copy'));
list($rc, $err) = run($dup . eof_new($dup));
2 === $rc ? ok('a duplicate member cannot replace an earlier one') : no('duplicate', "exit {$rc}");

$fd = base(entry('uploads/f', 'file') . entry('uploads/f/x', 'under a file'));
list($rc) = run($fd . eof_new($fd));
2 === $rc ? ok('a file used as a directory is refused') : no('file as dir', "exit {$rc}");

echo "\n── Damaged archives\n";

$good = sealed();
refused('truncated mid-member',          substr($good, 0, 5000));
refused('truncated inside a header',     substr($good, 0, strlen($good) - 100));
refused('missing end block',             base());
refused('data after the end block',      $good . 'x');
refused('zero-filled gap after the end', $good . str_repeat("\0", 4377));
$flip = $good; $flip[4377 + 3] = 'X';
refused('a changed byte fails the archive checksum', $flip);
$ov = entry('package.json', pkg()) . hdr('big.bin', 99999999, 'uploads') . 'y';
refused('size past the end of the file', $ov . eof_new($ov));
$bad = entry('package.json', pkg()) . pack('a255a14a12a4088a8', 'a', '12x4', '1', 'uploads', '') . 'y';
refused('non-digit size field', $bad . eof_new($bad));
$wrong = pack('a255a14a4100a8', '', '1', '', 'deadbeef');
refused('end block with the wrong length', base() . $wrong);
refused('a zip renamed to .wpress',  "PK\x03\x04" . str_repeat('z', 9000));
refused('an HTML error page',        '<!doctype html><html>' . str_repeat(' ', 9000));
refused('empty file',                '');
$nopkg = entry('database.sql', 'x'); refused('no package.json', $nopkg . eof_new($nopkg));
$junk = entry('package.json', '{not json') . entry('database.sql', 'x');
refused('unreadable package.json', $junk . eof_new($junk));

echo "\n── Bounds\n";

$bomb_c = gzcompress(str_repeat("\0", 8 * 1048576), 9);
$bomb = entry('package.json', pkg(array('Compression' => array('Enabled' => true, 'Type' => 'gzip'))))
	. entry('database.sql', 'x', true, $gz('x'))
	. entry('uploads/bomb', '', false, pack('N', strlen($bomb_c)) . $bomb_c);
list($rc, , $bw) = run($bomb . eof_new($bomb));
(2 === $rc && !in_array('x', $bw, true)) ? ok('a decompression bomb hits the chunk limit') : no('bomb', "exit {$rc}");

$lie = entry('package.json', pkg(array('Compression' => array('Enabled' => true, 'Type' => 'gzip'))))
	. entry('database.sql', 'x', true, $gz('x')) . entry('uploads/l', '', false, pack('N', 0x7fffffff) . 'zz');
list($rc) = run($lie . eof_new($lie));
2 === $rc ? ok('a chunk length past its member is refused') : no('chunk length', "exit {$rc}");

list($rc, $err) = run(sealed(), '--max-bytes=64');
2 === $rc ? ok('the byte budget stops extraction') : no('budget', "exit {$rc}");
refused('the member limit stops the walk', sealed(), 2, '--max-entries=2');

echo "\n── Unsupported, and said so\n";

$m = entry('package.json', pkg()) . entry('database.sql', 'x') . entry('multisite.json', '{}');
refused('multisite export', $m . eof_new($m), 3);
$bz = entry('package.json', pkg(array('Compression' => array('Enabled' => true, 'Type' => 'bzip2')))) . entry('database.sql', 'x');
refused('bzip2 compression', $bz . eof_new($bz), 3);
$nodb = entry('package.json', pkg()) . entry('uploads/a', 'x');
refused('no database.sql', $nodb . eof_new($nodb), 3);
refused('encrypted, no password',    $earch, 3);
refused('encrypted, wrong password', $earch, 3, '--password-stdin', "nope\n");

echo "\n── package.json is attacker-controlled\n";

$inj = entry('package.json', pkg(array(
	'SiteURL' => "https://x.example\n--exec=system('id')",
	'Template' => '--exec=system("id")', 'Stylesheet' => '$(id)',
	'Database' => array('Prefix' => "wp_';DROP TABLE x;--"),
	'Plugins' => array('--exec=system("id");', '--require=/tmp/x.php', '../../x.php', "a/a.php\nb=c", 'kept/kept.php', 'absent/absent.php'),
))) . entry('database.sql', 'x') . entry('plugins/kept/kept.php', '<?php');
list($rc, $err, , $oi) = run($inj . eof_new($inj));
$meta = array();
foreach (file("{$oi}/meta/wpress.meta", FILE_IGNORE_NEW_LINES) as $l) { list($k, $v) = explode('=', $l, 2); $meta[$k] = $v; }
if (0 !== $rc) { no('injection archive', trim($err)); }
else {
	'' === $meta['site_url'] && false === strpos(file_get_contents("{$oi}/meta/wpress.meta"), 'exec')
		? ok('a URL carrying a second line is dropped, not repaired') : no('url', $meta['site_url']);
	('' === $meta['template'] && '' === $meta['stylesheet']) ? ok('option-shaped and $() theme names are dropped') : no('theme', $meta['template']);
	'' === $meta['db_prefix'] ? ok('a SQL-shaped prefix is dropped') : no('prefix', $meta['db_prefix']);
	'["kept/kept.php"]' === $meta['plugins_json'] ? ok('only plausible plugins that exist in the tree survive') : no('plugins', $meta['plugins_json']);
	'4' === $meta['plugins_rejected'] ? ok('rejected plugin names are counted') : no('rejected', $meta['plugins_rejected']);
}

echo "\n── Activation data\n";

$own = entry('package.json', pkg(array('Plugins' => array('all-in-one-wp-migration/all-in-one-wp-migration.php', 'kept/kept.php'))))
	. entry('database.sql', 'x') . entry('plugins/kept/kept.php', '<?php') . entry('plugins/all-in-one-wp-migration/all-in-one-wp-migration.php', '<?php');
list($rc, , , $oo) = run($own . eof_new($own));
false === strpos((string) file_get_contents("{$oo}/meta/wpress.meta"), 'all-in-one')
	? ok('the migration plugin itself is not reactivated') : no('own plugin', 'still listed');

$nt = entry('package.json', pkg()) . entry('database.sql', 'x');
list($rc, , , $on) = run($nt . eof_new($nt));
$mt = (string) file_get_contents("{$on}/meta/wpress.meta");
(false !== strpos($mt, "\ntemplate=\n") && false !== strpos($mt, "template_missing=parent"))
	? ok('a theme absent from the archive is reported, not recorded as active') : no('missing theme', $mt);

$np = json_decode(pkg(), true); unset($np['Plugins']);
$lg = entry('package.json', json_encode($np)) . entry('database.sql', 'x');
list($rc, , , $ol) = run($lg . eof_new($lg));
false !== strpos((string) file_get_contents("{$ol}/meta/wpress.meta"), "plugins_json=\n")
	? ok('no Plugins key stays empty, so the dump keeps its own list') : no('absent plugins', 'became a list');

list($rc, $lines) = scan(sealed());
(0 === $rc && in_array('F 9 wp-content/uploads/2024/a.jpg', $lines, true))
	? ok('scan lists under wp-content, so the existing inspect checks apply') : no('scan listing', implode('|', array_slice($lines, -3)));

exec('rm -rf ' . escapeshellarg($WORK));
echo "\n  passed {$pass}   failed {$fail}\n";
exit($fail ? 1 : 0);
