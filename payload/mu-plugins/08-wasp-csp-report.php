<?php
/**
 * Plugin Name: WASP — Security-header reports
 * Description: Receives the browser's Content-Security-Policy violation reports and logs which outside host was blocked, so `wp-hardening.sh embeds report` can say what a site needs before its header is tightened. Logs no visitor address, no query string, nothing a visitor typed.
 * Author: IronVeil Systems DevOps
 * Version: 1.0
 *
 * WHY (10.28)
 *
 * WASP's header lets the browser load scripts, frames, styles and fonts only
 * from the site itself. An imported site that embeds a Google map, reCAPTCHA
 * or Google Fonts then breaks without a word: on one field site the footer
 * map vanished and every enquiry failed with "The Captcha field cannot be
 * blank". The only way to know was to open each page with the browser's
 * console. The browser can say it itself: the header carries
 * `report-uri /?wasp_csp_report=1`, and every page view that hits a block
 * posts a small report here. In report-only mode (`wp-hardening.sh embeds
 * mode report`) nothing is blocked and everything is reported, which is how
 * a freshly imported site is surveyed before its header is enforced.
 *
 * WHAT IS LOGGED, AND WHAT IS NOT
 *
 * One line per report: the directive, the blocked origin (scheme and host,
 * no path), and the page's path. Not the visitor's address, not query
 * strings, not the sample of blocked code browsers may include: a report is
 * unauthenticated input from anyone, and the log is read by people.
 * At most 300 lines an hour, so a flood cannot fill the disk.
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Reports from a request body, in either format browsers send:
 * `application/csp-report` ({"csp-report": {...}}, report-uri) or the
 * Reporting API's list ([{"type": "csp-violation", "body": {...}}]).
 * Returns rows of array(directive, blocked origin, page path), cleaned.
 */
function wasp_csp_parse($raw) {
    $j = json_decode((string) $raw, true);
    if (!is_array($j)) {
        return array();
    }
    $reports = array();
    if (isset($j['csp-report']) && is_array($j['csp-report'])) {
        $reports[] = $j['csp-report'];
    } else {
        foreach (array_slice($j, 0, 20) as $r) {
            if (is_array($r) && isset($r['body']) && is_array($r['body'])
                && (!isset($r['type']) || $r['type'] === 'csp-violation')) {
                $reports[] = $r['body'];
            }
        }
    }
    $out = array();
    foreach ($reports as $r) {
        $dir = '';
        foreach (array('effective-directive', 'effectiveDirective', 'violated-directive', 'violatedDirective') as $k) {
            if (!empty($r[$k]) && is_string($r[$k])) {
                $dir = strtok(trim($r[$k]), ' ');
                break;
            }
        }
        if (!preg_match('/^[a-z-]{3,40}$/', $dir)) {
            continue;
        }
        $blocked = '';
        foreach (array('blocked-uri', 'blockedURL', 'blockedUri') as $k) {
            if (isset($r[$k]) && is_string($r[$k])) {
                $blocked = trim($r[$k]);
                break;
            }
        }
        if (preg_match('#^(https?|wss?)://([a-z0-9.-]{1,253})(:[0-9]{1,5})?(?:[/?\#]|$)#i', $blocked, $m)) {
            $origin = strtolower($m[1] . '://' . $m[2] . (isset($m[3]) ? $m[3] : ''));
        } elseif (preg_match('/^(inline|eval|data|blob|self|wasm-eval|trusted-types-policy)$/', strtolower($blocked))) {
            $origin = strtolower($blocked);
        } else {
            continue;   // an extension, an empty value, something odd: not a site's need
        }
        $doc = '';
        foreach (array('document-uri', 'documentURL', 'documentUri') as $k) {
            if (isset($r[$k]) && is_string($r[$k])) {
                $doc = (string) parse_url($r[$k], PHP_URL_PATH);
                break;
            }
        }
        $doc = substr(preg_replace('#[^A-Za-z0-9/._~%-]#', '', $doc), 0, 120);
        $out[] = array($dir, $origin, $doc === '' ? '/' : $doc);
    }
    return $out;
}

/** Up to $max lines an hour, counted in a file so a flood writes nothing else. */
function wasp_csp_budget($max = 300) {
    $f = rtrim(sys_get_temp_dir(), '/') . '/wasp-csp-' . gmdate('YmdH');
    $n = (int) @file_get_contents($f);
    if ($n >= $max) {
        return false;
    }
    @file_put_contents($f, (string) ($n + 1), LOCK_EX);
    return true;
}

add_action('init', function () {
    if (!isset($_GET['wasp_csp_report'])) {
        return;
    }
    if (!isset($_SERVER['REQUEST_METHOD']) || $_SERVER['REQUEST_METHOD'] !== 'POST') {
        status_header(405);
        exit;
    }
    $raw = file_get_contents('php://input', false, null, 0, 16384);
    foreach (wasp_csp_parse($raw) as $row) {
        if (!wasp_csp_budget()) {
            break;
        }
        error_log(sprintf('[wasp-csp] %s blocked %s on %s', $row[0], $row[1], $row[2]));
    }
    status_header(204);
    exit;
}, 0);
