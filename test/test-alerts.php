<?php
/**
 * test-alerts.php — the WordPress half of the security alerts (07-wasp-alerts.php)
 *
 * Drives the real mu-plugin against a small stand-in for WordPress: hooks,
 * users, options, transients, user meta and wp_mail are recorded rather than
 * real. Each scenario runs in its own PHP process, because the plugin reads
 * its settings once per request and defines constants, exactly as on a VM.
 *
 * What it holds:
 *   - unconfigured, nothing is hooked; an event turned off sends nothing
 *   - the recipient comes from alerts.ini, never from the admin_email option
 *   - every event class produces its email; several in one request are ONE
 *   - no password, reset key or application password value is ever included
 *   - administrator sign-ins are emailed for a new address only (or all)
 *   - identical events are de-duplicated; the hourly ceiling sends one notice
 *   - a hostile user_login cannot inject a mail header
 *
 * Run: php test/test-alerts.php
 */

$PLUGIN = dirname(__DIR__) . '/payload/mu-plugins/07-wasp-alerts.php';

if ($argc < 2) {
    $pass = 0; $fail = 0;
    echo "\nSecurity alerts: the WordPress mu-plugin\n";
    foreach (array_keys(scenarios()) as $name) {
        $out = array(); $rc = 0;
        exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__FILE__) . ' ' . escapeshellarg($name) . ' 2>&1', $out, $rc);
        $text = implode("\n", $out);
        if ($rc === 0 && strpos($text, 'OK') !== false) {
            $pass++; echo "  [PASS] {$name}: " . substr($text, strpos($text, 'OK') + 3) . "\n";
        } else {
            $fail++; echo "  [FAIL] {$name}\n         " . str_replace("\n", "\n         ", $text) . "\n";
        }
    }
    echo "\n  alerts (php): {$pass} passed, {$fail} failed\n";
    exit($fail ? 1 : 0);
}

// ── A small WordPress ───────────────────────────────────────────────────────
define('ABSPATH', sys_get_temp_dir() . '/');
define('HOUR_IN_SECONDS', 3600);
define('DAY_IN_SECONDS', 86400);

class WP_User {
    public $ID; public $user_login; public $user_email; public $roles; public $user_pass;
    function __construct($id, $login = '', $email = '', $roles = array(), $pass = 'hash1') {
        $this->ID = $id; $this->user_login = $login; $this->user_email = $email;
        $this->roles = $roles; $this->user_pass = $pass;
    }
    function exists() { return $this->ID > 0; }
}
class WP_Post {
    public $ID; public $post_type; public $post_status; public $post_title; public $post_content;
    function __construct($id, $type, $status, $title, $content) {
        $this->ID = $id; $this->post_type = $type; $this->post_status = $status; $this->post_title = $title; $this->post_content = $content;
    }
}
function get_post($id) { return $GLOBALS['_posts'][(int) $id] ?? null; }
class WP_Theme { private $n; function __construct($n) { $this->n = $n; } function get($k) { return $this->n; } }

$GLOBALS['_hooks'] = array(); $GLOBALS['_mail'] = array(); $GLOBALS['_tr'] = array();
$GLOBALS['_meta'] = array(); $GLOBALS['_opts'] = array('admin_email' => 'attacker@evil.example', 'default_role' => 'subscriber');
$GLOBALS['_users'] = array(
    1 => new WP_User(1, 'owner', 'owner@example.com', array('administrator')),
    5 => new WP_User(5, 'dev', 'dev@example.com', array('subscriber')),
    7 => new WP_User(7, 'editor1', 'ed@example.com', array('editor')),
);
function add_action($h, $cb, $p = 10, $n = 1) { $GLOBALS['_hooks'][$h][$p][] = array($cb, $n); }
function do_action($h, ...$args) {
    if (empty($GLOBALS['_hooks'][$h])) { return; }
    ksort($GLOBALS['_hooks'][$h]);
    foreach ($GLOBALS['_hooks'][$h] as $cbs) {
        foreach ($cbs as $c) { call_user_func_array($c[0], array_slice($args, 0, $c[1])); }
    }
}
function get_userdata($id) { return $GLOBALS['_users'][(int) $id] ?? false; }
function get_user_by($f, $v) { foreach ($GLOBALS['_users'] as $u) { if ($u->user_login === $v) { return $u; } } return false; }
function is_email($a) { return (bool) filter_var($a, FILTER_VALIDATE_EMAIL); }
function wp_parse_url($u, $c = -1) { return parse_url($u, $c); }
function home_url() { return 'https://site.example.com'; }
function get_transient($k) { return $GLOBALS['_tr'][$k] ?? false; }
function set_transient($k, $v, $t = 0) { $GLOBALS['_tr'][$k] = $v; return true; }
function get_user_meta($id, $k, $s = false) { return $GLOBALS['_meta']["$id:$k"] ?? ''; }
function update_user_meta($id, $k, $v) { $GLOBALS['_meta']["$id:$k"] = $v; return true; }
function maybe_unserialize($v) { if (is_string($v)) { $u = @unserialize($v); return $u !== false ? $u : $v; } return $v; }
function get_option($k) { return $GLOBALS['_opts'][$k] ?? ''; }
function get_bloginfo($k) { return '7.1.4'; }
function wp_get_current_user() { return $GLOBALS['_current'] ?? new WP_User(0); }
function clean_user_cache($id) {}
function wp_doing_cron() { return false; }
function wp_mail($to, $subject, $body, $headers = array()) {
    $GLOBALS['_mail'][] = array('to' => $to, 'subject' => $subject, 'body' => $body, 'headers' => $headers);
    return true;
}

function ini($extra = '') {
    $f = tempnam(sys_get_temp_dir(), 'alerts');
    file_put_contents($f, "to = ops@example.com, owner@example.com\n" . $extra);
    return $f;
}
function load($ini) {
    define('WASP_ALERTS_CONFIG', $ini);
    $_SERVER['REMOTE_ADDR'] = '198.51.100.20';
    $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 test';
    require $GLOBALS['PLUGIN'];
}
function request_end() { do_action('shutdown'); }
function mails() { return $GLOBALS['_mail']; }
function check($cond, $msg) { if (!$cond) { fwrite(STDOUT, "FAILED: {$msg}\n" . print_r(mails(), true)); exit(1); } }
function ok($msg) { echo "OK {$msg}\n"; exit(0); }

function scenarios() {
    return array(
        'unconfigured' => function () {
            load('/nonexistent/alerts.ini');
            check(empty($GLOBALS['_hooks']), 'hooks were added with no settings file');
            ok('with no alerts.ini, nothing is hooked');
        },
        'admin_added' => function () {
            load(ini());
            do_action('set_user_role', 5, 'administrator', array('subscriber'));
            request_end();
            $m = mails();
            check(count($m) === 1, 'expected one mail');
            check(strpos($m[0]['subject'], 'Administrator added: dev') !== false, 'subject');
            check($m[0]['to'] === array('ops@example.com', 'owner@example.com'), 'recipients from alerts.ini');
            check(!in_array('attacker@evil.example', (array) $m[0]['to'], true), 'admin_email option used as recipient');
            check(strpos($m[0]['body'], 'From       : 198.51.100.20') !== false, 'source address in body');
            ok('promotion to administrator is emailed, to alerts.ini recipients only');
        },
        'event_off' => function () {
            load(ini("admin_role = off\n"));
            do_action('set_user_role', 5, 'administrator', array('subscriber'));
            request_end();
            check(count(mails()) === 0, 'an event turned off still sent');
            ok('an event turned off sends nothing');
        },
        'demoted_deleted' => function () {
            load(ini());
            do_action('set_user_role', 1, 'subscriber', array('administrator'));
            request_end();
            do_action('delete_user', 1, null, $GLOBALS['_users'][1]);
            request_end();
            $m = mails();
            check(count($m) === 2, 'expected two mails');
            check(strpos($m[0]['subject'], 'Administrator rights removed: owner') !== false, 'demotion');
            check(strpos($m[1]['subject'], 'Administrator deleted: owner') !== false, 'deletion');
            ok('demoting or deleting an administrator is emailed');
        },
        'bulk_is_one' => function () {
            load(ini());
            do_action('activated_plugin', 'a/a.php');
            do_action('activated_plugin', 'b/b.php');
            do_action('deactivated_plugin', 'c/c.php');
            do_action('switch_theme', 'Twenty', null, new WP_Theme('Old'));
            request_end();
            $m = mails();
            check(count($m) === 1, 'bulk changes were not one email');
            check(strpos($m[0]['subject'], '4 security changes') !== false, 'bulk subject');
            check(strpos($m[0]['body'], 'Plugin deactivated: c/c.php') !== false, 'item listed');
            ok('several changes in one request arrive as one email');
        },
        'login_new_ip' => function () {
            load(ini());
            $owner = $GLOBALS['_users'][1];
            do_action('wp_login', 'owner', $owner); request_end();
            $GLOBALS['_tr'] = array();           // a later request, outside the de-dup window
            do_action('wp_login', 'owner', $owner); request_end();
            $_SERVER['REMOTE_ADDR'] = '203.0.113.77';
            do_action('wp_login', 'owner', $owner); request_end();
            do_action('wp_login', 'editor1', $GLOBALS['_users'][7]); request_end();
            $m = mails();
            check(count($m) === 2, 'expected exactly two sign-in mails, got ' . count($m));
            check(strpos($m[1]['body'], '203.0.113.77') !== false, 'new address named');
            check(strpos($m[0]['body'], 'Two-factor, where enrolled, is checked after') !== false, '2FA note');
            ok('admin sign-in: first and new addresses emailed, a known one and non-admins not');
        },
        'login_all' => function () {
            load(ini("admin_login_mode = all\n"));
            $owner = $GLOBALS['_users'][1];
            do_action('wp_login', 'owner', $owner); request_end();
            $GLOBALS['_tr'] = array();
            do_action('wp_login', 'owner', $owner); request_end();
            check(count(mails()) === 2, 'mode all did not email every sign-in');
            ok('admin_login_mode = all emails every administrator sign-in');
        },
        'secrets_never_sent' => function () {
            load(ini());
            do_action('wp_set_password', 'Sup3rS3cretPW', 1, null);
            do_action('retrieve_password_key', 'owner', 'RESETKEY123');
            do_action('wp_create_application_password', 5, array('name' => 'Zapier'), 'APPPASS999', array());
            request_end();
            $all = '';
            foreach (mails() as $m) { $all .= $m['subject'] . $m['body']; }
            check(strpos($all, 'Administrator password changed: owner') !== false, 'password change');
            check(strpos($all, 'Password reset requested for administrator: owner') !== false, 'reset request');
            check(strpos($all, 'Application password created for dev') !== false && strpos($all, 'Zapier') !== false, 'app password');
            foreach (array('Sup3rS3cretPW', 'RESETKEY123', 'APPPASS999') as $secret) {
                check(strpos($all, $secret) === false, "secret {$secret} appeared in an email");
            }
            ok('password, reset and app-password events emailed; no secret value ever included');
        },
        'email_change' => function () {
            load(ini());
            $old = clone $GLOBALS['_users'][1];
            $GLOBALS['_users'][1]->user_email = 'new@evil.example';
            do_action('profile_update', 1, $old, array());
            request_end();
            $m = mails();
            check(count($m) === 1 && strpos($m[0]['subject'], 'Administrator email changed: owner') !== false, 'email change');
            check(strpos($m[0]['body'], 'new@evil.example') !== false, 'new address shown');
            ok('an administrator email change is emailed, old and new');
        },
        'mfa_off' => function () {
            load(ini());
            do_action('deleted_user_meta', array(9), 1, '_two_factor_enabled_providers', '');
            request_end();
            do_action('updated_user_meta', 9, 1, '_two_factor_enabled_providers', serialize(array('Two_Factor_Totp')));
            request_end();
            do_action('updated_user_meta', 9, 7, '_two_factor_enabled_providers', serialize(array()));
            request_end();
            $m = mails();
            check(count($m) === 2, 'expected two (the editor is not an administrator)');
            check(strpos($m[0]['subject'], 'Two-factor turned OFF for administrator: owner') !== false, 'off');
            check(strpos($m[1]['body'], 'Totp') !== false, 'methods listed');
            ok('two-factor turned off or changed for an administrator is emailed');
        },
        'settings' => function () {
            load(ini());
            do_action('update_option_default_role', 'subscriber', 'administrator', 'default_role');
            do_action('update_option_users_can_register', '0', '1', 'users_can_register');
            do_action('update_option_siteurl', 'https://site.example.com', 'https://evil.example', 'siteurl');
            request_end();
            $m = mails();
            check(count($m) === 1, 'one email for one request');
            check(strpos($m[0]['body'], 'DANGER: new accounts now become administrators') !== false, 'default role');
            check(strpos($m[0]['body'], 'Public registration turned ON') !== false, 'registration');
            check(strpos($m[0]['body'], 'https://evil.example') !== false, 'site address');
            ok('default role, open registration and site address changes are emailed');
        },
        'dedupe' => function () {
            load(ini());
            do_action('activated_plugin', 'a/a.php'); request_end();
            do_action('activated_plugin', 'a/a.php'); request_end();
            check(count(mails()) === 1, 'identical event within the window sent twice');
            ok('an identical event inside its quiet window is not sent twice');
        },
        'ceiling' => function () {
            load(ini("max_per_hour = 2\n"));
            foreach (array('a', 'b', 'c', 'd') as $p) { do_action('activated_plugin', "{$p}/{$p}.php"); request_end(); }
            $m = mails();
            check(count($m) === 3, 'expected 2 alerts + 1 ceiling notice, got ' . count($m));
            check(strpos($m[2]['subject'], 'Alert limit reached') !== false, 'ceiling notice');
            ok('the hourly ceiling holds, with exactly one notice when reached');
        },
        'header_injection' => function () {
            $GLOBALS['_users'][5]->user_login = "dev\r\nBcc: victim@example.com";
            load(ini());
            do_action('set_user_role', 5, 'administrator', array());
            request_end();
            $m = mails();
            check(count($m) === 1, 'no mail');
            check(strpbrk($m[0]['subject'], "\r\n") === false, 'CR/LF reached the subject');
            ok('a hostile account name cannot inject a mail header');
        },
        'send_test' => function () {
            load(ini("code_change = off\n"));
            check(wasp_alerts_send_test() === true, 'test send returned false');
            $m = mails();
            check(strpos($m[0]['subject'], 'Test security alert') !== false, 'subject');
            check(preg_match('/off\s+Plugins and themes/', $m[0]['body']) === 1, 'off events listed as off');
            ok('wasp-alerts.sh test path sends, listing what is on and off');
        },
        'content_spam_elementor' => function () {
            load(ini());
            $spam = '<p><span data-sheets-root="1"><a class="in-cell-link" href="https://www.casino-spam.example/">x</a></span></p>';
            $GLOBALS['_posts'][327] = new WP_Post(327, 'page', 'publish', 'Commercial', '<p>Commercial.</p>' . $spam);
            $data = array(array('id' => 'c1', 'elType' => 'container', 'elements' => array(
                array('id' => 'a1clean', 'elType' => 'widget', 'widgetType' => 'text-editor', 'settings' => array('editor' => '<p>Commercial.</p> <a href="https://www.supplier.example/">s</a>')),
                array('id' => 'w1spam1', 'elType' => 'widget', 'widgetType' => 'text-editor', 'settings' => array('editor' => $spam)),
                array('id' => 'b2btn', 'elType' => 'widget', 'widgetType' => 'button', 'settings' => array('link' => array('url' => 'https://mostbet-promo.example/go'))),
            )));
            // Elementor writes its data (JSON, slashes escaped) and then the post: two hooks, one alert.
            do_action('updated_post_meta', 11, 327, '_elementor_data', json_encode($data));
            do_action('save_post', 327, $GLOBALS['_posts'][327], true);
            request_end();
            $m = mails();
            check(count($m) === 1, 'expected exactly one mail for one save seen by two hooks');
            check(strpos($m[0]['subject'], 'Spam link saved on page 327: "Commercial"') !== false, 'subject names the page');
            check(strpos($m[0]['body'], 'Links to   : casino-spam.example, mostbet-promo.example') !== false, 'both spam hosts, www. dropped');
            check(strpos($m[0]['body'], 'Elementor widget w1spam1 (text-editor)') !== false && strpos($m[0]['body'], 'Elementor widget b2btn (button)') !== false, 'widgets named');
            check(strpos($m[0]['body'], 'a1clean') === false && strpos($m[0]['body'], 'supplier') === false, 'the clean widget and supplier link not reported');
            check(strpos($m[0]['body'], 'doas wp-links.sh clean --widgets w1spam1,b2btn') !== false, 'the command that removes them');
            check(strpos($m[0]['body'], 'Pasted from a Google Sheet') !== false, 'the Sheets paste is named');
            check(strpos($m[0]['body'], 'Done by') !== false, 'who saved it');
            ok('a spam link saved through Elementor is emailed once, naming the page, widgets and the clean command');
        },
        'content_spam_quiet' => function () {
            load(ini());
            $GLOBALS['_posts'][40] = new WP_Post(40, 'page', 'publish', 'Residential', '<p>Our slotted posts and <a href="https://supplier.example/">catalog</a>, <a href="https://site.example.com/casino-night/">event</a>. Casino night!</p>');
            do_action('save_post', 40, $GLOBALS['_posts'][40], true);
            $GLOBALS['_posts'][41] = new WP_Post(41, 'revision', 'inherit', 'Old', '<a href="https://casino-spam.example/">x</a>');
            do_action('save_post', 41, $GLOBALS['_posts'][41], true);
            do_action('updated_post_meta', 12, 41, '_elementor_data', '[{"id":"z","elType":"widget","settings":{"editor":"<a href=\\"https:\\/\\/casino-spam.example\\/\\">x<\\/a>"}}]');
            $GLOBALS['_posts'][42] = new WP_Post(42, 'page', 'trash', 'Gone', '<a href="https://casino-spam.example/">x</a>');
            do_action('save_post', 42, $GLOBALS['_posts'][42], true);
            request_end();
            check(count(mails()) === 0, 'a clean page, spam words without a spam link, a link to the site itself, a revision or a trashed page alerted');
            ok('clean pages, revisions and trashed posts send nothing; wording alone is not judged');
        },
        'content_spam_off_and_dedupe' => function () {
            load(ini("content_spam = off\n"));
            $GLOBALS['_posts'][5] = new WP_Post(5, 'post', 'publish', 'Hi', '<a href="https://casino-spam.example/">x</a>');
            do_action('save_post', 5, $GLOBALS['_posts'][5], true);
            request_end();
            check(count(mails()) === 0, 'content_spam = off still sent');
            ok('content_spam = off sends nothing');
        },
        'content_spam_menu_widget_repeat' => function () {
            load(ini());
            $GLOBALS['_posts'][900] = new WP_Post(900, 'nav_menu_item', 'publish', 'Promo', '');
            do_action('updated_post_meta', 13, 900, '_menu_item_url', 'https://bet365-mirror.example/');
            do_action('updated_option', 'widget_text', array(), array(2 => array('text' => '<a href="https://www.cialis-online.example/">order</a>'), '_multiwidget' => 1));
            request_end();
            $m = mails();
            check(count($m) === 1 && strpos($m[0]['body'], 'menu item 900') !== false && strpos($m[0]['body'], 'sidebar widget widget_text') !== false,
                  'menu item and sidebar widget in one email');
            $GLOBALS['_posts'][6] = new WP_Post(6, 'post', 'publish', 'Hi', '<a href="https://casino-spam.example/">x</a>');
            do_action('save_post', 6, $GLOBALS['_posts'][6], true); request_end();
            do_action('save_post', 6, $GLOBALS['_posts'][6], true); request_end();
            check(count(mails()) === 2, 'the same spam on the same page, saved twice, alerted twice');
            ok('menus and sidebar widgets are watched; the same spam on a page alerts once a day');
        },
    );
}

$s = scenarios();
if (!isset($s[$argv[1]])) { echo "unknown scenario\n"; exit(2); }
$s[$argv[1]]();
