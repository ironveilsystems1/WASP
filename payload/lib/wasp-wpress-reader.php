<?php
/**
 * wasp-wpress-reader.php — read an All-in-One WP Migration .wpress archive.
 *
 *   php wasp-wpress-reader.php scan    <archive>
 *   php wasp-wpress-reader.php extract <archive> <out> [--max-bytes=N]
 *                                      [--max-entries=N] [--password-stdin]
 *
 * <out> must already hold files/, db/ and meta/.
 *
 * Exit:  0 done   2 refused (hostile or damaged)   3 unsupported   1 internal
 *
 * WHERE THIS RUNS
 *
 * Inside the pinned wp-cli image, started by wp-import.sh with no network, a
 * read-only root, no capabilities and an unprivileged uid. It parses a hostile
 * binary, so it does not run on the VM itself. The open question in
 * docs/IMPORT-DESIGN.md was "shell or Python": neither. PHP is already pinned on
 * every VM in that image, and this is the language the format was written in.
 *
 * THE FORMAT
 *
 * A flat run of entries, each a 4377-byte header followed by stored content:
 *
 *   offset  length  field
 *        0     255  name, NUL-padded, no directory
 *      255      14  stored size, decimal
 *      269      12  mtime, decimal
 *      281    4088  directory, relative to wp-content
 *     4369       8  CRC32 of the original content, hex (plugin 7.104+)
 *
 * Before 7.104 the directory field was 4096 bytes, so an old archive reads the
 * same with an empty CRC. The end block is all NUL (old), or an empty name, the
 * byte count of everything before it in the size field, and that span's CRC32
 * in the last eight bytes (7.104+).
 *
 * With compression, content is 512000-byte chunks, each zlib-compressed and then
 * prefixed with its stored length as a big-endian uint32. With a password, each
 * chunk is AES-256-CBC with a leading random IV, under the first 16 bytes of
 * sha1(password), after compression. package.json and multisite.json are always
 * plain.
 *
 * SOURCES, BECAUSE THIS IS NOT FROM THE PLUGIN'S CURRENT CODE
 *
 * wordpress.org was unreachable when this was written. The old header layout
 * comes from the plugin's own 4.5 source. The 7.x layout, the end block, the
 * chunking and the encryption come from two independent open implementations
 * that agree (turbopress-de/wpress, tonystechofficial/wpress-restore), plus
 * ServMask's published description of the CRC32 change. None of it has been run
 * against a real 7.x export. A format surprise fails closed here, as a refusal.
 *
 * bzip2 is refused: the wp-cli image has no bz2 extension.
 *
 * A CRC IS NOT A SECURITY CONTROL
 *
 * Anyone who can edit an archive can recompute it. It catches a truncated upload
 * and a damaged transfer, which is what it is for. The hostile-input checks below
 * are what stand against a crafted archive, and they do not rely on it.
 *
 * WHY scan WALKS THE WHOLE ARCHIVE BEFORE extract WRITES A BYTE
 *
 * A hostile member at the end of the archive has to refuse the import before the
 * first member exists on disk. So every extract is a full walk, then a write.
 */

declare(strict_types=1);

const HEADER_SIZE       = 4377;
const CHUNK_PLAIN       = 512000;
const CHUNK_DECODED_MAX = 1048576;   // decoded chunk ceiling: the bomb guard
const CHUNK_STORED_MAX  = 2097152;
const COPY_BUFFER       = 1048576;
const PACKAGE_MAX       = 1048576;
const DEFAULT_ENTRIES   = 500000;
const SIGN_TEXT         = '"How long do you want these messages to remain secret? I want them to remain secret for as long as men are capable of evil." - Neal Stephenson';

const EXIT_REFUSED     = 2;
const EXIT_UNSUPPORTED = 3;

final class Stop extends RuntimeException {
	/** @var int */
	public $status;
	public function __construct(int $status, string $message) {
		parent::__construct($message);
		$this->status = $status;
	}
}

function refuse(string $why): void { throw new Stop(EXIT_REFUSED, $why); }
function unsupported(string $why): void { throw new Stop(EXIT_UNSUPPORTED, $why); }

/** Safe to print, whatever the archive put in the name. */
function shown(string $s): string {
	$out = preg_replace_callback('/[^\x20-\x7e]/', static function ($m) {
		return sprintf('\\x%02x', ord($m[0]));
	}, substr($s, 0, 160));
	return (string) $out;
}

/** A NUL-padded field. A NUL with data after it is not padding. */
function field(string $raw, string $what, int $at): string {
	$v = rtrim($raw, "\0");
	if (strpos($v, "\0") !== false) {
		refuse("{$what} at offset {$at} has a NUL inside it");
	}
	return $v;
}

/**
 * A relative, "/"-separated path that stays below wp-content, or a refusal.
 *
 * Backslashes become slashes BEFORE the traversal test. An archive exported on
 * a Windows host carries them legitimately, and `..\..\x` must not pass because
 * it contains no forward slash.
 */
function safe_path(string $dir, string $name, int $at): string {
	$joined = str_replace('\\', '/', ('.' === $dir || '' === $dir) ? $name : $dir . '/' . $name);

	if (preg_match('/[\x00-\x1f\x7f]/', $joined)) {
		refuse('control character in a member name at offset ' . $at . ': ' . shown($joined));
	}
	if ('' === $joined || '/' === $joined[0] || preg_match('#^[A-Za-z]:#', $joined) || strpos($joined, '://') !== false) {
		refuse('absolute path at offset ' . $at . ': ' . shown($joined));
	}
	$parts = array();
	foreach (explode('/', $joined) as $p) {
		if ('..' === $p) {
			refuse('path traversal at offset ' . $at . ': ' . shown($joined));
		}
		if ('' !== $p && '.' !== $p) {
			if (strlen($p) > 255) {
				refuse('path component over 255 bytes at offset ' . $at);
			}
			$parts[] = $p;
		}
	}
	if (!$parts) {
		refuse('member with no usable name at offset ' . $at);
	}
	$clean = implode('/', $parts);
	if (strlen($clean) > 4096) {
		refuse('path over 4096 bytes at offset ' . $at);
	}
	return $clean;
}

function is_crc(string $v): bool { return 8 === strlen($v) && ctype_xdigit($v); }

/**
 * Header-only walk. Validates every member and the end block, returning what
 * the extract pass needs. Nothing is written.
 */
function walk($fh, int $total, int $max_entries): array {
	$r = array(
		'entries' => array(), 'eof_offset' => null, 'eof_crc' => '',
		'format' => 'legacy', 'stored' => 0, 'package' => null, 'database' => null,
		'multisite' => false,
	);
	$at = 0;
	while (true) {
		if ($at === $total) {
			refuse('no end-of-archive block: the file is truncated, usually an interrupted upload');
		}
		if ($total - $at < HEADER_SIZE) {
			refuse("archive ends inside a header at offset {$at}: the file is truncated");
		}
		if (fseek($fh, $at) !== 0) {
			throw new RuntimeException('seek failed');
		}
		$b = stream_get_contents($fh, HEADER_SIZE);
		if (!is_string($b) || strlen($b) !== HEADER_SIZE) {
			throw new RuntimeException('short read');
		}

		if (strspn($b, "\0") === HEADER_SIZE) {
			$r['eof_offset'] = $at;
			break;
		}

		$name  = field(substr($b, 0, 255), 'name', $at);
		$size  = trim(field(substr($b, 255, 14), 'size', $at), ' ');
		$mtime = trim(field(substr($b, 269, 12), 'mtime', $at), ' ');
		$dir   = field(substr($b, 281, 4088), 'path', $at);
		$crc   = trim(field(substr($b, 4369, 8), 'crc', $at), ' ');

		if ('' === $name) {
			// The 7.104+ end block: nothing but the span length and its CRC.
			if ('' !== $mtime || '' !== $dir || !ctype_digit($size) || !is_crc($crc)) {
				refuse("not a .wpress header at offset {$at}");
			}
			if ((int) $size !== $at) {
				refuse("end block says the archive is {$size} bytes, found {$at}: the file is damaged");
			}
			$r['eof_offset'] = $at;
			$r['eof_crc']    = strtolower($crc);
			$r['format']     = 'crc';
			break;
		}

		if (!ctype_digit($size) || strlen($size) > 14 || ('' !== $mtime && !ctype_digit($mtime))) {
			refuse("not a .wpress header at offset {$at}: this may not be a .wpress file");
		}
		if ('' !== $crc && !is_crc($crc)) {
			refuse("unreadable checksum field at offset {$at}");
		}
		$path   = safe_path($dir, $name, $at);
		$stored = (int) $size;
		$data   = $at + HEADER_SIZE;
		if ($stored > $total - $data) {
			refuse('member ' . shown($path) . " claims {$stored} bytes, more than the file holds");
		}
		if (count($r['entries']) >= $max_entries) {
			refuse("more than {$max_entries} members");
		}
		$r['entries'][] = array($path, $data, $stored, strtolower($crc));
		$r['stored']   += $stored;

		if ('package.json' === $path) {
			$r['package'] = array($data, $stored);
		} elseif ('database.sql' === $path) {
			$r['database'] = $stored;
		} elseif ('multisite.json' === $path) {
			$r['multisite'] = true;
		}
		$at = $data + $stored;
	}

	if ($r['eof_offset'] + HEADER_SIZE !== $total) {
		refuse(($total - $r['eof_offset'] - HEADER_SIZE) . ' bytes after the end block: the file is damaged');
	}
	return $r;
}

/** Archive-wide CRC over everything before the end block. */
function verify_archive_crc($fh, array $r): void {
	if ('' === $r['eof_crc']) {
		return;
	}
	fseek($fh, 0);
	$ctx  = hash_init('crc32b');
	$left = (int) $r['eof_offset'];
	while ($left > 0) {
		$chunk = fread($fh, min(COPY_BUFFER, $left));
		if (false === $chunk || '' === $chunk) {
			throw new RuntimeException('short read during checksum');
		}
		hash_update($ctx, $chunk);
		$left -= strlen($chunk);
	}
	$got = hash_final($ctx);
	if ($got !== $r['eof_crc']) {
		refuse("archive checksum mismatch: stored {$r['eof_crc']}, computed {$got}. The file was damaged in transfer");
	}
}

function read_package($fh, array $r): array {
	if (null === $r['package']) {
		refuse('no package.json at the archive root: this is not an All-in-One WP Migration backup');
	}
	list($offset, $size) = $r['package'];
	if ($size > PACKAGE_MAX) {
		refuse('package.json is implausibly large');
	}
	fseek($fh, $offset);
	$data = json_decode((string) stream_get_contents($fh, $size), true, 16);
	if (!is_array($data) || empty($data['SiteURL']) || !is_string($data['SiteURL'])) {
		refuse('package.json is unreadable: this is not an All-in-One WP Migration backup');
	}
	return $data;
}

/** A string from package.json, or '' unless it matches. Never trusted as given. */
function clean($v, string $pattern): string {
	return (is_string($v) && preg_match($pattern, $v)) ? $v : '';
}

const RE_URL     = '#^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~%/-]*)?$#D';
const RE_PREFIX  = '/^[A-Za-z0-9_]{1,32}$/D';
const RE_THEME   = '/^[A-Za-z0-9][A-Za-z0-9._-]{0,100}$/D';
const RE_PLUGIN  = '#^[A-Za-z0-9][A-Za-z0-9._-]{0,100}(/[A-Za-z0-9][A-Za-z0-9._-]{0,100})?\.php$#D';
const RE_VERSION = '/^[0-9A-Za-z.+-]{1,32}$/D';

/**
 * Everything the shell will read about this archive.
 *
 * package.json is attacker-controlled and these values reach wp-cli as
 * arguments, where `--exec=<php>` is code execution. So each one is held to a
 * pattern that a leading dash, a quote, whitespace or a newline cannot pass, and
 * a value that fails is dropped and reported rather than repaired.
 */
function describe(array $p, array $r): array {
	$prefix = clean($p['Database']['Prefix'] ?? null, RE_PREFIX);

	// Absent is not the same as empty. An old export has no Plugins key and left
	// the list in its dump, so an empty list here would deactivate everything.
	$has_list = isset($p['Plugins']) && is_array($p['Plugins']);
	$plugins  = array();
	$rejected = 0;
	foreach ((array) ($p['Plugins'] ?? array()) as $plugin) {
		$ok = clean($plugin, RE_PLUGIN);
		if ('' === $ok) {
			$rejected++;
		} elseif (0 !== strpos($ok, 'all-in-one-wp-migration')) {
			$plugins[] = $ok;
		}
	}

	$compression = '';
	if (!empty($p['Compression']['Enabled'])) {
		$compression = is_string($p['Compression']['Type'] ?? null) ? $p['Compression']['Type'] : 'unknown';
	}

	$site = rtrim(clean($p['SiteURL'] ?? null, RE_URL), '/');
	$home = rtrim(clean($p['HomeURL'] ?? null, RE_URL), '/');

	return array(
		'source'           => 'wpress',
		'format'           => $r['format'],
		'site_url'         => $site,
		'home_url'         => '' !== $home ? $home : $site,
		'wp_version'       => clean($p['WordPress']['Version'] ?? null, RE_VERSION),
		'plugin_version'   => clean($p['Plugin']['Version'] ?? ($p['Version'] ?? null), RE_VERSION),
		'db_prefix'        => $prefix,
		'template'         => clean($p['Template'] ?? null, RE_THEME),
		'stylesheet'       => clean($p['Stylesheet'] ?? null, RE_THEME),
		'plugins_json'     => $has_list ? (string) json_encode($plugins, JSON_UNESCAPED_SLASHES) : '',
		'plugins_rejected' => (string) $rejected,
		'compression'      => preg_match('/^[a-z0-9]{1,16}$/D', $compression) ? $compression : ('' === $compression ? '' : 'unknown'),
		'encrypted'        => (!empty($p['Encrypted']) && 'false' !== $p['Encrypted']) ? '1' : '0',
		'multisite'        => $r['multisite'] ? '1' : '0',
		'database'         => null === $r['database'] ? '0' : '1',
		'entries'          => (string) count($r['entries']),
		'stored_bytes'     => (string) $r['stored'],
		'archive_crc'      => $r['eof_crc'],
	);
}

function check_supported(array $d): void {
	if ('1' === $d['multisite']) {
		unsupported('this is a multisite export. WASP is single-site: export the one site instead');
	}
	if ('' !== $d['compression'] && 'gzip' !== $d['compression']) {
		unsupported("compressed with {$d['compression']}, which this reader cannot decode. Re-export uncompressed or with gzip");
	}
	if ('0' === $d['database']) {
		unsupported('no database.sql in this archive. It was exported with the database excluded');
	}
}

/** Where a member lands. The archive root is wp-content. */
function destination(string $out, string $path): string {
	switch ($path) {
		case 'database.sql':
			return "{$out}/db/database.sql";
		case 'package.json':
		case 'multisite.json':
			return "{$out}/meta/{$path}";
	}
	return "{$out}/files/wp-content/{$path}";
}

/**
 * Makes the directories for a target, from a known-good root downwards.
 *
 * is_link is belt and braces: this format cannot create a symlink, so one here
 * means something other than this code wrote to the tree.
 */
function make_parents(string $target, string $root): void {
	$rel   = substr(dirname($target), strlen($root));
	$cur   = $root;
	foreach (explode('/', trim($rel, '/')) as $seg) {
		if ('' === $seg) {
			continue;
		}
		$cur .= '/' . $seg;
		if (is_link($cur)) {
			refuse('symlink in the extraction tree: ' . shown($cur));
		}
		if (is_dir($cur)) {
			continue;
		}
		if (file_exists($cur)) {
			refuse('member uses a file as a directory: ' . shown(substr($cur, strlen($root))));
		}
		if (!mkdir($cur, 0700)) {
			throw new RuntimeException('mkdir failed');
		}
	}
}

function exactly($fh, int $n): string {
	$data = stream_get_contents($fh, $n);
	if (!is_string($data) || strlen($data) !== $n) {
		refuse('archive ended inside a member');
	}
	return $data;
}

function decode_chunk(string $stored, ?string $key, bool $gzip): string {
	if (null !== $key) {
		if (strlen($stored) <= 16) {
			refuse('encrypted chunk too short');
		}
		$plain = openssl_decrypt(substr($stored, 16), 'AES-256-CBC', $key, OPENSSL_RAW_DATA, substr($stored, 0, 16));
		if (false === $plain) {
			refuse('a chunk would not decrypt: damaged file');
		}
		$stored = $plain;
	}
	if ($gzip) {
		$plain = @gzuncompress($stored, CHUNK_DECODED_MAX);
		if (false === $plain) {
			refuse('a chunk would not decompress, or decompressed past the chunk limit');
		}
		$stored = $plain;
	}
	return $stored;
}

/** Writes one member. Returns [bytes written, crc32 of them]. */
function extract_member($fh, array $m, string $target, ?string $key, bool $gzip, int &$budget): array {
	list($path, $data, $stored) = $m;

	// 'x' refuses an existing file, so a duplicate member cannot silently replace
	// an earlier one, and O_EXCL does not follow a symlink.
	$out = @fopen($target, 'xb');
	if (false === $out) {
		refuse('duplicate or unwritable member: ' . shown($path));
	}
	fseek($fh, $data);
	$ctx     = hash_init('crc32b');
	$left    = $stored;
	$written = 0;

	$emit = static function (string $bytes) use (&$budget, &$written, $out, $ctx, $path): void {
		$n = strlen($bytes);
		if ($n > $budget) {
			refuse('extraction would exceed the size limit at ' . shown($path));
		}
		if (fwrite($out, $bytes) !== $n) {
			throw new RuntimeException('short write: disk full?');
		}
		hash_update($ctx, $bytes);
		$budget  -= $n;
		$written += $n;
	};

	while ($left > 0) {
		if ($gzip) {
			if ($left < 4) {
				refuse('compressed member ends inside a length prefix: ' . shown($path));
			}
			$len = unpack('N', exactly($fh, 4))[1];
			$left -= 4;
			if ($len > $left || $len > CHUNK_STORED_MAX) {
				refuse('compressed chunk overruns its member: ' . shown($path));
			}
			$emit(decode_chunk(exactly($fh, $len), $key, true));
			$left -= $len;
		} elseif (null !== $key) {
			// Length-prefixed only when compressed: a full encrypted chunk has
			// grown by its IV and one padding block.
			$len = $left > CHUNK_PLAIN ? min($left, CHUNK_PLAIN + 32) : $left;
			$emit(decode_chunk(exactly($fh, $len), $key, false));
			$left -= $len;
		} else {
			$n = min(COPY_BUFFER, $left);
			$emit(exactly($fh, $n));
			$left -= $n;
		}
	}
	fclose($out);
	return array($written, hash_final($ctx));
}

function password_opens(string $signature, string $key): bool {
	$raw = base64_decode($signature, true);
	if (false === $raw || strlen($raw) <= 16) {
		return false;
	}
	$plain = openssl_decrypt(substr($raw, 16), 'AES-256-CBC', $key, OPENSSL_RAW_DATA, substr($raw, 0, 16));
	return is_string($plain) && hash_equals(SIGN_TEXT, $plain);
}

function run_extract($fh, array $r, array $pkg, array &$d, string $out, int $budget, ?string $password): void {
	$gzip = 'gzip' === $d['compression'];
	$key  = null;

	if ('1' === $d['encrypted']) {
		if (null === $password || '' === $password) {
			unsupported('this archive is password-protected and no password was given');
		}
		$key = substr(sha1($password, true), 0, 16);
		$sig = $pkg['EncryptedSignature'] ?? '';
		if (is_string($sig) && '' !== $sig && !password_opens($sig, $key)) {
			unsupported('wrong password for this archive');
		}
	}

	foreach (array('files', 'db', 'meta') as $sub) {
		if (!is_dir("{$out}/{$sub}") || is_link("{$out}/{$sub}")) {
			throw new RuntimeException("missing output directory {$sub}");
		}
	}
	mkdir("{$out}/files/wp-content", 0700);

	$mismatch = 0;
	$written  = 0;
	foreach ($r['entries'] as $m) {
		$path   = $m[0];
		$plain  = 'package.json' === $path || 'multisite.json' === $path;
		$target = destination($out, $path);
		make_parents($target, $out);
		list($n, $crc) = extract_member($fh, $m, $target, $plain ? null : $key, $plain ? false : $gzip, $budget);
		$written += $n;
		if ('' !== $m[3] && $crc !== $m[3]) {
			$mismatch++;
		}
	}

	// Reported, not refused. The archive-wide CRC already covers every stored
	// byte. What a per-file CRC covers has only been read from third-party code,
	// and a wrong reading here must not refuse every real archive.
	$d['file_crc_mismatch'] = (string) $mismatch;
	$d['extracted_bytes']   = (string) $written;

	// Decided against the tree, so the import activates only what is there.
	$active  = array();
	$missing = array();
	foreach ((array) json_decode('' === $d['plugins_json'] ? '[]' : $d['plugins_json'], true) as $plugin) {
		if (is_file("{$out}/files/wp-content/plugins/{$plugin}")) {
			$active[] = $plugin;
		} else {
			$missing[] = $plugin;
		}
	}
	if ('' !== $d['plugins_json']) {
		$d['plugins_json'] = (string) json_encode($active, JSON_UNESCAPED_SLASHES);
	}
	$d['plugins_missing'] = (string) count($missing);
	foreach (array('template', 'stylesheet') as $t) {
		if ('' !== $d[$t] && !is_dir("{$out}/files/wp-content/themes/{$d[$t]}")) {
			$d["{$t}_missing"] = $d[$t];
			$d[$t] = '';
		}
	}

	$lines = '';
	foreach ($d as $k => $v) {
		$lines .= "{$k}={$v}\n";
	}
	file_put_contents("{$out}/meta/wpress.meta", $lines, LOCK_EX);
}

function main(array $argv): int {
	// PHP calls a handler even for a line marked @. Those lines check the result
	// themselves and refuse by name, which is what the exit status depends on.
	set_error_handler(static function (int $no, string $msg): bool {
		if (!(error_reporting() & $no)) {
			return false;
		}
		throw new RuntimeException($msg);
	}, E_WARNING | E_NOTICE | E_DEPRECATED);
	umask(0077);

	$mode    = $argv[1] ?? '';
	$archive = $argv[2] ?? '';
	if (!in_array($mode, array('scan', 'extract'), true) || '' === $archive) {
		fwrite(STDERR, "usage: scan <archive> | extract <archive> <out> [options]\n");
		return 1;
	}
	if (PHP_INT_SIZE < 8) {
		unsupported('a 64-bit PHP is required');
	}
	$out      = 'extract' === $mode ? rtrim($argv[3] ?? '', '/') : '';
	$budget   = PHP_INT_MAX;
	$entries  = DEFAULT_ENTRIES;
	$password = null;
	if ('extract' === $mode && '' === $out) {
		fwrite(STDERR, "extract needs an output directory\n");
		return 1;
	}
	foreach (array_slice($argv, 4) as $opt) {
		if (preg_match('/^--max-bytes=(\d+)$/D', $opt, $m)) {
			$budget = (int) $m[1];
		} elseif (preg_match('/^--max-entries=(\d+)$/D', $opt, $m)) {
			$entries = (int) $m[1];
		} elseif ('--password-stdin' === $opt) {
			$line     = fgets(STDIN);
			$password = false === $line ? '' : rtrim($line, "\r\n");
		} else {
			fwrite(STDERR, "unknown option\n");
			return 1;
		}
	}

	$fh = fopen($archive, 'rb');
	$st = fstat($fh);
	if (!is_array($st) || 0100000 !== ($st['mode'] & 0170000)) {
		refuse('not a regular file');
	}

	$r    = walk($fh, (int) $st['size'], $entries);
	verify_archive_crc($fh, $r);
	$pkg  = read_package($fh, $r);
	$desc = describe($pkg, $r);

	if ('scan' === $mode) {
		// A format this cannot import is still worth listing.
		foreach ($desc as $k => $v) {
			echo "M {$k} {$v}\n";
		}
		foreach ($r['entries'] as $m) {
			$shown = in_array($m[0], array('package.json', 'multisite.json', 'database.sql'), true)
				? $m[0] : 'wp-content/' . $m[0];
			echo 'F ', $m[2], ' ', $shown, "\n";
		}
		return 0;
	}

	check_supported($desc);
	run_extract($fh, $r, $pkg, $desc, $out, $budget, $password);
	return 0;
}

if (PHP_SAPI === 'cli' && realpath((string) ($_SERVER['SCRIPT_FILENAME'] ?? '')) === __FILE__) {
	try {
		exit(main($argv));
	} catch (Stop $e) {
		fwrite(STDERR, 'wpress: ' . $e->getMessage() . "\n");
		exit($e->status);
	} catch (Throwable $e) {
		fwrite(STDERR, 'wpress: internal error: ' . shown($e->getMessage()) . "\n");
		exit(1);
	}
}
