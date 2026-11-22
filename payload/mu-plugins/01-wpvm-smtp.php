<?php
/**
 * Plugin Name: WASP — Mail Transport
 * Description: Sends WordPress mail through an authenticated relay with the credentials held outside the web root. WASP's own alerts always use the operator relay; the site's mail (contact forms, password resets, notifications) can go through the client's own Microsoft 365 or SMTP server instead. Without it WordPress hands mail to a local sendmail that does not exist, and everything fails silently.
 * Author: IronVeil Systems DevOps
 * Version: 2.0
 *
 * TWO MAIL PATHS (10.27)
 *
 *   operator  WASP's alerts and lockout notices: the relay set at install
 *             (/var/www/private/smtp.ini). The operator's server, so a
 *             client changing their mailbox can never silence an alert.
 *   client    everything else WordPress sends: contact forms, password
 *             resets, notifications. The client's own server when
 *             /var/www/private/client-mail.ini exists, else the relay.
 *
 * The client path speaks two transports:
 *
 *   m365  Microsoft Graph sendMail over HTTPS, signed in as an app the
 *         client's tenant registered (client credentials). No SMTP and no
 *         port 25: it leaves through the egress proxy like any other
 *         HTTPS call, to two named hosts. Microsoft turns password SMTP off
 *         by default from the end of December 2026; this does not use it.
 *   smtp  Authenticated submission on 587 (STARTTLS) or 465 (TLS), with a
 *         mailbox password or app password: Google Workspace, Microsoft 365
 *         while its tenant allows SMTP AUTH, or any other host.
 *
 * A message is the operator's when it carries `X-WASP-Alert` or
 * `X-WASP-Mail: operator`. `X-WASP-Mail: client` forces the client path
 * (wp-mail.sh client test). If the client path fails, the same message is
 * sent through the operator relay instead, with the visitor's Reply-To kept,
 * so an enquiry is never lost to an expired secret; the failure is logged
 * and `wp-mail.sh client status` shows it.
 *
 * WHY THE CREDENTIALS LIVE OUTSIDE THE DOCROOT
 *
 * The relay password is read from /var/www/private/smtp.ini, mounted
 * read-only from the host and deliberately NOT under /var/www/html. Two
 * distinct reasons:
 *
 *   1. If PHP execution ever breaks (a bad container update, a misapplied
 *      .htaccess, a mangled php.ini), Apache serves .php files as plain
 *      text. Anything holding secrets inside the docroot is then readable
 *      over HTTP. Outside the docroot there is no URL that maps to it.
 *   2. It is not passed as a container environment variable the way
 *      WORDPRESS_DB_PASSWORD is, because `podman inspect wordpress` prints
 *      the full environment -- so env vars are visible to anything that can
 *      talk to the Podman socket, and they leak into container logs and
 *      crash dumps more readily than a 0400 file does.
 *
 * mu-plugins (not a normal plugin) because these cannot be deactivated from
 * wp-admin, load before regular plugins, and survive core updates -- mail
 * transport should not be something an admin can switch off by accident.
 */

if (!defined('ABSPATH')) {
    exit;
}

/*
 * NON-EXECUTABLE CONFIG FORMAT
 *
 * This was previously a .php file returning an array, which meant the
 * credentials file was CODE: it was include()d, so any flaw in the escaping
 * that wrote it -- or any future write access to it -- became remote code
 * execution rather than a bad password. The escaping was careful, but
 * "careful escaping" is a mitigation and a data format is a fix.
 *
 * It is now an INI file parsed with INI_SCANNER_RAW, so a malformed value is
 * a malformed value and can never be a statement. The password is stored
 * base64-encoded purely so that quotes, semicolons and whitespace cannot
 * interact with INI parsing at all -- that is encoding for robustness, NOT
 * secrecy, and the file's permissions remain the thing protecting it.
 */
if (!defined('WPVM_SMTP_CONFIG')) {
    define('WPVM_SMTP_CONFIG', '/var/www/private/smtp.ini');
}
/* The client's own server, when they have one. Absent = the relay. */
if (!defined('WPVM_CLIENT_MAIL_CONFIG')) {
    define('WPVM_CLIENT_MAIL_CONFIG', '/var/www/private/client-mail.ini');
}
/* Legacy PHP config, still read if present so an existing VM keeps sending
 * mail after an update. Deliberately second: if both exist, the INI wins. */
if (!defined('WPVM_SMTP_CONFIG_LEGACY')) {
    define('WPVM_SMTP_CONFIG_LEGACY', '/var/www/private/smtp.php');
}

/**
 * Load and cache the relay config. Returns false when SMTP was never
 * configured, which is a supported state -- the site simply keeps
 * WordPress's default behavior rather than erroring.
 */
function wpvm_smtp_config() {
    static $cfg = null;
    if ($cfg !== null) {
        return $cfg;
    }
    $cfg = false;
    if (is_readable(WPVM_SMTP_CONFIG)) {
        // INI_SCANNER_RAW: values are taken literally, with no interpretation
        // of quotes, constants or type juggling. Nothing here can execute.
        $ini = @parse_ini_file(WPVM_SMTP_CONFIG, false, INI_SCANNER_RAW);
        if (is_array($ini) && !empty($ini['host']) && !empty($ini['user'])) {
            $ini['pass'] = isset($ini['pass_b64'])
                ? base64_decode($ini['pass_b64'], true)
                : '';
            if ($ini['pass'] !== false) {
                $cfg = $ini;
            }
        }
    }
    if ($cfg === false && is_readable(WPVM_SMTP_CONFIG_LEGACY)) {
        // Pre-INI installs. Logged so it is visible rather than silent, since
        // the whole point of the change is not to include() this file.
        $loaded = include WPVM_SMTP_CONFIG_LEGACY;
        if (is_array($loaded) && !empty($loaded['host']) && !empty($loaded['user'])) {
            $cfg = $loaded;
            error_log('[wpvm-smtp] using legacy smtp.php; re-run wp-mail.sh setup to migrate to the non-executable smtp.ini');
        }
    }
    return $cfg;
}

/**
 * The client's own mail server, or false. Read the same way as the relay's
 * (INI, raw, secrets base64), and checked as a whole: a half-written file is
 * logged and ignored, so mail keeps flowing through the relay rather than
 * failing on a typo.
 */
function wpvm_client_mail_config() {
    static $cfg = null;
    if ($cfg !== null) {
        return $cfg;
    }
    $cfg = false;
    if (!is_readable(WPVM_CLIENT_MAIL_CONFIG)) {
        return $cfg;
    }
    $ini = @parse_ini_file(WPVM_CLIENT_MAIL_CONFIG, false, INI_SCANNER_RAW);
    if (!is_array($ini)) {
        error_log('[wpvm-smtp] client-mail.ini does not parse; the site\'s mail goes through the operator relay');
        return $cfg;
    }
    $t = strtolower(trim(isset($ini['transport']) ? $ini['transport'] : 'smtp'));
    $from = trim(isset($ini['from']) ? $ini['from'] : '');
    if ($t === 'm365') {
        $secret = isset($ini['secret_b64']) ? base64_decode($ini['secret_b64'], true) : false;
        $ok = !empty($ini['tenant']) && preg_match('/^[A-Za-z0-9.-]{1,100}$/', $ini['tenant'])
            && !empty($ini['client_id']) && preg_match('/^[0-9a-fA-F-]{36}$/', $ini['client_id'])
            && $secret !== false && $secret !== ''
            && filter_var($from, FILTER_VALIDATE_EMAIL);
        if (!$ok) {
            error_log('[wpvm-smtp] client-mail.ini (m365) needs tenant, client_id, secret_b64 and from; the site\'s mail goes through the operator relay');
            return $cfg;
        }
        $ini['secret'] = $secret;
    } elseif ($t === 'smtp') {
        $pass = isset($ini['pass_b64']) ? base64_decode($ini['pass_b64'], true) : false;
        if (empty($ini['host']) || empty($ini['user']) || $pass === false || $pass === '') {
            error_log('[wpvm-smtp] client-mail.ini (smtp) needs host, user and pass_b64; the site\'s mail goes through the operator relay');
            return $cfg;
        }
        $ini['pass'] = $pass;
        if ($from === '') {
            $from = $ini['user'];
        }
    } else {
        error_log('[wpvm-smtp] client-mail.ini: unknown transport "' . preg_replace('/[^a-z0-9_-]/i', '', $t) . '"; the site\'s mail goes through the operator relay');
        return $cfg;
    }
    $ini['transport'] = $t;
    $ini['from'] = $from;
    $cfg = $ini;
    return $cfg;
}

/** One short line, for logs and errors: no newlines, no secrets' worth of text. */
function wpvm_mail_line($s, $max = 240) {
    $s = trim(preg_replace('/\s+/', ' ', (string) $s));
    return strlen($s) > $max ? substr($s, 0, $max - 3) . '...' : $s;
}

/**
 * Which path a message takes. Read from the message's own headers inside
 * phpmailer_init, so it holds for every sender, not only for calls this file
 * knows about.
 */
function wpvm_mail_route($phpmailer) {
    if (!empty($GLOBALS['wpvm_mail_force_operator'])) {
        return 'operator';
    }
    foreach ($phpmailer->getCustomHeaders() as $h) {
        $name = strtolower(trim($h[0]));
        if ($name === 'x-wasp-alert') {
            return 'operator';
        }
        if ($name === 'x-wasp-mail') {
            $v = strtolower(trim($h[1]));
            if ($v === 'operator') {
                return 'operator';
            }
            if ($v === 'client') {
                return wpvm_client_mail_config() ? 'client' : 'operator';
            }
        }
    }
    return wpvm_client_mail_config() ? 'client' : 'operator';
}

/** Point a mailer at an SMTP server: the relay, or the client's. */
function wpvm_apply_smtp($phpmailer, $cfg) {
    $phpmailer->isSMTP();
    $phpmailer->Host       = $cfg['host'];
    $phpmailer->Port       = (int) (isset($cfg['port']) && $cfg['port'] !== '' ? $cfg['port'] : 587);
    $phpmailer->SMTPAuth   = true;
    $phpmailer->Username   = $cfg['user'];
    $phpmailer->Password   = $cfg['pass'];

    // 'ssl' = implicit TLS, the whole session encrypted from connect (port
    // 465). 'tls' = STARTTLS, an explicit upgrade after a plaintext greeting
    // (port 587). Both are fine against a modern relay; 587/STARTTLS is the
    // submission standard and the default here. Port 25 is never used: it is
    // server-to-server delivery, not authenticated submission.
    $phpmailer->SMTPSecure  = (isset($cfg['encryption']) && $cfg['encryption'] === 'ssl') ? 'ssl' : 'tls';
    $phpmailer->SMTPAutoTLS = true;

    // Certificate verification is left at PHPMailer's default (ON). It is
    // deliberately not exposed as a config toggle: the usual reason people
    // reach for SMTPOptions/verify_peer=false is a self-signed or
    // mismatched cert, and silently accepting those turns an authenticated
    // TLS session into one an on-path attacker can read -- including the
    // relay password on every send. If the relay's certificate does not
    // validate, fix the certificate.

    // Bound how long a page load can block on an unreachable relay.
    // PHPMailer's default Timeout is 300 seconds: with the default, a mail
    // server that is down (or a dropped packet to it) hangs user-visible
    // requests like registration and password reset for five minutes each.
    $phpmailer->Timeout = isset($cfg['timeout']) ? (int) $cfg['timeout'] : 10;
    wpvm_apply_from($phpmailer, $cfg);
}

function wpvm_apply_from($phpmailer, $cfg) {
    if (!empty($cfg['from'])) {
        $phpmailer->From = $cfg['from'];
        // Envelope sender (Return-Path). SPF is evaluated against THIS, not
        // the visible From: header, so setting it is what keeps SPF aligned
        // when the relay checks the envelope domain.
        $phpmailer->Sender = $cfg['from'];
    }
    if (!empty($cfg['from_name'])) {
        $phpmailer->FromName = $cfg['from_name'];
    }
}

/**
 * The mailer WordPress uses when a client path is configured: WordPress's own
 * class with two additions. A `waspgraph` transport (PHPMailer calls
 * <Mailer>Send for a mailer it does not know), and a second try through the
 * operator relay when the client path fails. WordPress keeps it: wp_mail()
 * only builds its own when the global is not a PHPMailer already.
 */
function wpvm_mailer_class() {
    if (class_exists('WPVM_Mailer', false)) {
        return true;
    }
    if (!defined('ABSPATH') || !defined('WPINC')) {
        return false;
    }
    require_once ABSPATH . WPINC . '/PHPMailer/PHPMailer.php';
    require_once ABSPATH . WPINC . '/PHPMailer/SMTP.php';
    require_once ABSPATH . WPINC . '/PHPMailer/Exception.php';
    if (file_exists(ABSPATH . WPINC . '/class-wp-phpmailer.php')) {
        require_once ABSPATH . WPINC . '/class-wp-phpmailer.php';   // WordPress 6.8 and later
    }
    if (!class_exists('WPVM_Mailer_Base', false)) {
        class_alias(class_exists('WP_PHPMailer', false) ? 'WP_PHPMailer' : 'PHPMailer\\PHPMailer\\PHPMailer', 'WPVM_Mailer_Base');
    }

    class WPVM_Mailer extends WPVM_Mailer_Base {
        /** 'client' or 'operator', set per message in phpmailer_init. */
        public $wpvm_route = '';
        public $wpvm_fellback = false;

        public function postSend() {
            $err = null;
            try {
                $ok = parent::postSend();
            } catch (\PHPMailer\PHPMailer\Exception $e) {
                $err = $e;
                $ok = false;
            }
            if ($ok) {
                return true;
            }
            $relay = wpvm_smtp_config();
            if ($this->wpvm_route !== 'client' || $this->wpvm_fellback || !$relay) {
                if ($err) {
                    throw $err;
                }
                return false;
            }
            // The client path failed: the same message through the relay,
            // with the relay's own From (it would refuse the client's) and the
            // visitor's Reply-To untouched.
            $why = $err ? $err->getMessage() : $this->ErrorInfo;
            error_log('[wpvm-smtp] client mail failed (' . wpvm_mail_line($why) . '); sent through the operator relay instead');
            $this->wpvm_fellback = true;
            $this->wpvm_route = 'operator';
            $this->smtpClose();   // never reuse a connection to the client's server
            wpvm_apply_smtp($this, $relay);
            $this->addCustomHeader('X-WASP-Mail-Fallback', 'client mail failed');
            if (!$this->preSend()) {
                if ($err) {
                    throw $err;
                }
                return false;
            }
            return parent::postSend();
        }

        /**
         * Microsoft Graph: the whole MIME message, as PHPMailer built it,
         * base64 in the body of POST /users/{from}/sendMail. Attachments,
         * Reply-To and HTML go as they are. Graph takes 4 MB a request, so a
         * larger message goes to the relay instead.
         */
        protected function waspgraphSend($header, $body) {
            $cfg = wpvm_client_mail_config();
            if (!$cfg || $cfg['transport'] !== 'm365') {
                throw new \PHPMailer\PHPMailer\Exception('Microsoft 365 settings are missing');
            }
            $mime = $this->getSentMIMEMessage();
            if (!empty($this->bcc)) {
                $mime = $this->addrAppend('Bcc', $this->bcc) . $mime;
            }
            if (strlen($mime) > 2900000) {
                throw new \PHPMailer\PHPMailer\Exception(sprintf('message is %.1f MB, over what Microsoft Graph accepts in one request', strlen($mime) / 1048576));
            }
            $r = wpvm_graph_send($cfg, $mime);
            if (is_wp_error($r)) {
                throw new \PHPMailer\PHPMailer\Exception($r->get_error_message());
            }
            return true;
        }
    }
    return true;
}

/**
 * Sign in as the client's app and send. Both calls go out through
 * WP_PROXY_HOST, so the egress allowlist decides: login.microsoftonline.com
 * and graph.microsoft.com (wasp-egress reconcile adds them).
 */
function wpvm_graph_token($cfg) {
    $r = wp_remote_post('https://login.microsoftonline.com/' . rawurlencode($cfg['tenant']) . '/oauth2/v2.0/token', array(
        'timeout' => 10,
        'body'    => array(
            'client_id'     => $cfg['client_id'],
            'client_secret' => $cfg['secret'],
            'scope'         => 'https://graph.microsoft.com/.default',
            'grant_type'    => 'client_credentials',
        ),
    ));
    if (is_wp_error($r)) {
        return new WP_Error('wpvm_graph', 'could not reach Microsoft sign-in: ' . wpvm_mail_line($r->get_error_message()));
    }
    $code = (int) wp_remote_retrieve_response_code($r);
    $j = json_decode(wp_remote_retrieve_body($r), true);
    if ($code === 200 && is_array($j) && !empty($j['access_token'])) {
        return $j['access_token'];
    }
    $what = is_array($j) && !empty($j['error_description']) ? strtok($j['error_description'], "\r\n")
          : (is_array($j) && !empty($j['error']) ? $j['error'] : 'no reason given');
    return new WP_Error('wpvm_graph', sprintf('Microsoft sign-in refused (HTTP %d): %s', $code, wpvm_mail_line($what, 200)));
}

function wpvm_graph_send($cfg, $mime) {
    $token = wpvm_graph_token($cfg);
    if (is_wp_error($token)) {
        return $token;
    }
    $r = wp_remote_post('https://graph.microsoft.com/v1.0/users/' . rawurlencode($cfg['from']) . '/sendMail', array(
        'timeout' => 15,
        'headers' => array('Authorization' => 'Bearer ' . $token, 'Content-Type' => 'text/plain'),
        'body'    => base64_encode($mime),
    ));
    if (is_wp_error($r)) {
        return new WP_Error('wpvm_graph', 'could not reach Microsoft Graph: ' . wpvm_mail_line($r->get_error_message()));
    }
    $code = (int) wp_remote_retrieve_response_code($r);
    if ($code === 202) {
        return true;
    }
    $j = json_decode(wp_remote_retrieve_body($r), true);
    $gc = is_array($j) && isset($j['error']['code']) ? $j['error']['code'] : '';
    $gm = is_array($j) && isset($j['error']['message']) ? $j['error']['message'] : '';
    $hint = '';
    if ($code === 403 || $gc === 'ErrorAccessDenied') {
        $hint = ' (the app may not send as ' . $cfg['from'] . ': check Mail.Send and its Exchange scope)';
    } elseif ($code === 404) {
        $hint = ' (no mailbox ' . $cfg['from'] . ' in this tenant)';
    }
    return new WP_Error('wpvm_graph', sprintf('Microsoft Graph refused the message (HTTP %d %s): %s%s', $code, $gc, wpvm_mail_line($gm, 160), $hint));
}

/**
 * Before WordPress builds the message: when the client has a path, make sure
 * the mailer is ours, and start each message with no route decided.
 */
add_filter('wp_mail', function ($atts) {
    if (wpvm_client_mail_config() && wpvm_mailer_class()) {
        global $phpmailer;
        if (!($phpmailer instanceof WPVM_Mailer)) {
            $phpmailer = new WPVM_Mailer(true);
            $phpmailer::$validator = static function ($email) {
                return (bool) is_email($email);
            };
        }
        $phpmailer->wpvm_route = '';
        $phpmailer->wpvm_fellback = false;
    }
    return $atts;
}, PHP_INT_MAX);

add_action('phpmailer_init', function ($phpmailer) {
    $route = wpvm_mail_route($phpmailer);
    $ours = class_exists('WPVM_Mailer', false) && $phpmailer instanceof WPVM_Mailer;
    if ($route === 'client') {
        $c = wpvm_client_mail_config();
        if ($c['transport'] === 'm365' && $ours) {
            $phpmailer->Mailer = 'waspgraph';
            wpvm_apply_from($phpmailer, $c);
            $phpmailer->Sender = '';   // Graph sets the envelope itself
            $phpmailer->wpvm_route = 'client';
            return;
        }
        if ($c['transport'] === 'smtp') {
            wpvm_apply_smtp($phpmailer, $c);
            if ($ours) {
                $phpmailer->wpvm_route = 'client';
            }
            return;
        }
        error_log('[wpvm-smtp] Microsoft 365 mail needs WASP\'s mailer, and another plugin replaced it; sent through the operator relay');
    }
    if ($ours) {
        $phpmailer->wpvm_route = 'operator';
    }
    $cfg = wpvm_smtp_config();
    if (!$cfg) {
        return;
    }
    wpvm_apply_smtp($phpmailer, $cfg);
}, 10, 1);

/**
 * WordPress defaults the sender to wordpress@<site-domain>, which frequently
 * is not a real mailbox and frequently is not a sender the relay's SPF
 * record authorizes. Under a DMARC policy of quarantine or reject that
 * mismatch means silent non-delivery -- the same invisible failure this
 * plugin exists to fix. Both filters run at priority 99 so a site-specific
 * plugin can still deliberately override them; phpmailer_init then sets the
 * sender of whichever path the message takes.
 */
add_filter('wp_mail_from', function ($email) {
    $cfg = wpvm_smtp_config();
    return ($cfg && !empty($cfg['from'])) ? $cfg['from'] : $email;
}, 99);

add_filter('wp_mail_from_name', function ($name) {
    $cfg = wpvm_smtp_config();
    return ($cfg && !empty($cfg['from_name'])) ? $cfg['from_name'] : $name;
}, 99);

/**
 * Make failures visible. Silent failure is the entire problem being solved
 * here, so a send that fails is written to the PHP error log (which this VM
 * ships to /home/wpuser/wp/logs and rotates hourly). wp-mail.sh reads these.
 */
add_action('wp_mail_failed', function ($error) {
    if (is_wp_error($error)) {
        error_log('[wpvm-smtp] wp_mail failed: ' . $error->get_error_message());
    }
});
