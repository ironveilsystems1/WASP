<?php
/**
 * WASP AppSec forwarder — CrowdSec WAF body inspection, opt-in.
 *
 * Loaded by auto_prepend_file (zz-wasp-appsec.ini) in front of every PHP
 * request, before WordPress or any plugin. Asks the CrowdSec AppSec component
 * whether the request may proceed, and answers 403 if a rule matched.
 *
 * Switched on and off by `wasp-appsec.sh on|off`, which writes
 * /var/www/private/appsec.ini (the host's secrets directory, mounted read-only).
 * With no such file, or enabled = 0, this returns at once.
 *
 * What it forwards, per the AppSec protocol (docs.crowdsec.net, AppSec
 * protocol): the original method, URI, Host, User-Agent, HTTP version and
 * client address in X-Crowdsec-Appsec-* headers, the original request headers,
 * and the body. Bodies larger than max_body are NOT forwarded: the URI,
 * arguments and headers are still inspected, the body is not, and the request
 * is counted as uninspected. multipart/form-data cannot be re-read once PHP
 * has parsed it, so its fields are forwarded url-encoded and the uploaded
 * files are not; PHP never runs from uploads on WASP, which is the control
 * that covers a file upload.
 *
 * Failure (timeout, 5xx, 401, connection refused) applies failure_action:
 * passthrough (default, fail-open) or ban (fail-closed). Failures are logged at
 * most once a minute.
 *
 * Only PHP requests pass through here. Static files never reach PHP, and on a
 * WordPress site every endpoint an attacker can exploit is PHP.
 */
(static function () {
    if (PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg') {
        return;
    }
    $cfg = @parse_ini_file(getenv('WASP_APPSEC_CONF') ?: '/var/www/private/appsec.ini', false, INI_SCANNER_RAW);
    if (!is_array($cfg) || empty($cfg['enabled']) || $cfg['enabled'] === '0' || empty($cfg['key'])) {
        return;
    }
    $url       = isset($cfg['url']) ? (string) $cfg['url'] : 'http://10.89.10.1:7422/';
    $timeoutMs = max(50, min(2000, (int) ($cfg['timeout_ms'] ?? 200)));
    $maxBody   = max(0, (int) ($cfg['max_body'] ?? 131072));
    $failBan   = (($cfg['failure_action'] ?? 'passthrough') === 'ban');

    $note = static function (string $msg): void {
        // Once a minute at most: a stopped CrowdSec must not fill the error
        // log that CrowdSec itself reads.
        $mark = sys_get_temp_dir() . '/wasp-appsec-' . md5($msg);
        $last = @filemtime($mark);
        if ($last === false || time() - $last >= 60) {
            @touch($mark);
            error_log('[wasp-appsec] ' . $msg);
        }
    };

    $verb = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    $ver  = $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.1';
    $ver  = preg_match('#HTTP/(\d)(?:\.(\d))?#', $ver, $m) ? $m[1] . ($m[2] ?? '0') : '11';

    $headers = [];
    $ctype   = '';
    foreach (function_exists('getallheaders') ? (getallheaders() ?: []) : [] as $name => $value) {
        $lname = strtolower((string) $name);
        if (in_array($lname, ['host', 'content-length', 'connection', 'transfer-encoding', 'expect',
                               'keep-alive', 'te', 'trailer', 'upgrade', 'proxy-authorization'], true)
            || strpos($lname, 'x-crowdsec-appsec-') === 0) {
            continue;   // hop-by-hop, recomputed, or ours to set
        }
        if ($lname === 'content-type') {
            $ctype = (string) $value;
        }
        $headers[] = $name . ': ' . str_replace(["\r", "\n"], ' ', (string) $value);
    }

    $body = '';
    $len  = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
    if ($len > 0 || !empty($_POST)) {
        if ($len > $maxBody) {
            $note('a body over max_body (' . $maxBody . ' bytes) was forwarded without its body');
        } elseif (stripos($ctype, 'multipart/form-data') === 0) {
            // php://input is empty once PHP has parsed multipart; send the
            // fields, not the files.
            $body = http_build_query($_POST);
            foreach ($headers as $i => $h) {
                if (stripos($h, 'content-type:') === 0) {
                    $headers[$i] = 'Content-Type: application/x-www-form-urlencoded';
                }
            }
        } else {
            $body = (string) file_get_contents('php://input');
        }
    }

    $headers[] = 'X-Crowdsec-Appsec-Ip: ' . ($_SERVER['REMOTE_ADDR'] ?? '');
    $headers[] = 'X-Crowdsec-Appsec-Uri: ' . ($_SERVER['REQUEST_URI'] ?? '/');
    $headers[] = 'X-Crowdsec-Appsec-Host: ' . ($_SERVER['HTTP_HOST'] ?? '');
    $headers[] = 'X-Crowdsec-Appsec-Verb: ' . $verb;
    $headers[] = 'X-Crowdsec-Appsec-Api-Key: ' . $cfg['key'];
    $headers[] = 'X-Crowdsec-Appsec-User-Agent: ' . ($_SERVER['HTTP_USER_AGENT'] ?? '');
    $headers[] = 'X-Crowdsec-Appsec-Http-Version: ' . $ver;
    $headers[] = 'Expect:';

    $ch = curl_init($url);
    $opts = [
        CURLOPT_HTTPHEADER        => $headers,
        CURLOPT_RETURNTRANSFER    => true,
        CURLOPT_CONNECTTIMEOUT_MS => min(100, $timeoutMs),
        CURLOPT_TIMEOUT_MS        => $timeoutMs,
        CURLOPT_NOSIGNAL          => true,
        // The container's egress proxy settings must not apply: this is a
        // local address, and through Squid it would be refused.
        CURLOPT_PROXY             => '',
        CURLOPT_NOPROXY           => '*',
        CURLOPT_FOLLOWLOCATION    => false,
    ];
    // GET unless there is a body, then POST: the protocol's rule.
    if ($body !== '') {
        $opts[CURLOPT_POST] = true;
        $opts[CURLOPT_POSTFIELDS] = $body;
    } else {
        $opts[CURLOPT_HTTPGET] = true;
    }
    curl_setopt_array($ch, $opts);
    $resp = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $err  = curl_error($ch);
    curl_close($ch);

    if ($code === 200) {
        return;
    }
    $block = false;
    $status = 403;
    if ($code === 403) {
        $d = json_decode((string) $resp, true);
        $action = is_array($d) ? (string) ($d['action'] ?? 'ban') : 'ban';
        if ($action !== 'allow') {
            $block = true;   // ban, captcha and challenge all end here: no captcha page on this path
            $status = (is_array($d) && isset($d['http_status']) && (int) $d['http_status'] >= 400) ? (int) $d['http_status'] : 403;
        }
    } else {
        $note('AppSec unavailable (' . ($code ?: 'no answer') . ($err !== '' ? ', ' . $err : '') . '): '
              . ($failBan ? 'refusing requests (failure_action = ban)' : 'requests pass uninspected'));
        $block = $failBan;
        $status = 503;
    }
    if (!$block) {
        return;
    }
    if (!headers_sent()) {
        http_response_code($status);
        header('Content-Type: text/plain; charset=utf-8');
        header('Cache-Control: no-store');
    }
    echo $status === 503 ? "Service temporarily unavailable.\n" : "Forbidden.\n";
    exit;
})();
