<?php
/**
 * Plugin Name: WASP Security Alerts
 * Description: Emails the operator when something security-relevant changes inside WordPress: administrators added, removed or signing in from a new address, administrator passwords and email addresses, application passwords, two-factor, plugins and themes, and the settings attackers change first. Configured by wasp-alerts.sh on the VM, not from wp-admin.
 * Version: 1.0
 *
 * WHY THIS EXISTS
 *
 * Every other WASP alert comes from the host: scans, backups, disk, TLS. They
 * see files and logs. What they cannot see is a change made THROUGH WordPress
 * by someone holding a valid session -- a stolen administrator password, a
 * developer's reused credential, a plugin flaw that grants a role. Those look
 * exactly like normal use, leave no file behind, and are the usual first step
 * of everything that follows. The one person who can tell normal use from an
 * intrusion is the operator, so the operator is told, at the moment it
 * happens.
 *
 * WHAT IT DOES NOT DO
 *
 * It is not configurable from wp-admin, deliberately. The settings live in
 * /var/www/private/alerts.ini, mounted read-only from the VM, so an attacker
 * with an administrator session cannot turn the alerts off or redirect them
 * -- the first two things one would try. The recipient is never taken from
 * the admin_email option for the same reason: changing that option is one of
 * the events reported here.
 *
 * Changes made with WASP's own tools on the VM run in a wp-cli container that
 * does not mount the private directory, so they are not emailed: that is the
 * operator at the console. Changes made directly in the database bypass every
 * WordPress hook; `wasp-alerts.sh watch-admins` covers the one that matters,
 * a planted administrator.
 *
 * Nothing secret is ever included: no password, reset key or application
 * password value -- only that the event happened, to which account, from
 * which address.
 */

if (!defined('ABSPATH')) {
    exit;
}
if (!defined('WASP_ALERTS_CONFIG')) {
    define('WASP_ALERTS_CONFIG', '/var/www/private/alerts.ini');
}

/** The events, their alerts.ini keys, and what each one means. */
function wasp_alerts_events() {
    return array(
        'admin_role'        => 'Administrator added, promoted, demoted or deleted',
        'admin_login'       => 'Administrator sign-in from a new address',
        'admin_credentials' => 'Administrator password or email changed, or a password reset requested',
        'app_password'      => 'Application password created (API access without the login page or 2FA)',
        'mfa_change'        => 'Two-factor turned off or changed for an administrator',
        'code_change'       => 'Plugins and themes installed, updated, activated, deactivated, deleted or switched; core updated',
        'settings_change'   => 'Site address, admin email, open registration or default role changed',
        'content_spam'      => 'Spam links saved into a page, widget or menu (as saved; the weekly scan too)',
    );
}

/**
 * Read alerts.ini once per request. INI_SCANNER_RAW, as for smtp.ini: data,
 * never code. Returns false -- alerts off, silently -- when the file is
 * missing or names no valid recipient.
 */
function wasp_alerts_config() {
    static $cfg = null;
    if ($cfg !== null) {
        return $cfg;
    }
    $cfg = false;
    if (!is_readable(WASP_ALERTS_CONFIG)) {
        return $cfg;
    }
    $ini = @parse_ini_file(WASP_ALERTS_CONFIG, false, INI_SCANNER_RAW);
    if (!is_array($ini)) {
        return $cfg;
    }
    $to = array();
    foreach (explode(',', (string) ($ini['to'] ?? '')) as $addr) {
        $addr = trim($addr);
        if ($addr !== '' && is_email($addr)) {
            $to[] = $addr;
        }
    }
    if (!$to) {
        return $cfg;
    }
    $events = array();
    foreach (wasp_alerts_events() as $key => $label) {
        $v = strtolower(trim((string) ($ini[$key] ?? 'on')));
        $events[$key] = !in_array($v, array('off', '0', 'no', 'false'), true);
    }
    $mode = strtolower(trim((string) ($ini['admin_login_mode'] ?? 'new_ip')));
    $cfg = array(
        'to'           => $to,
        'events'       => $events,
        'login_mode'   => $mode === 'all' ? 'all' : 'new_ip',
        'ip_days'      => max(1, min(3650, (int) ($ini['login_ip_days'] ?? 90))),
        'max_per_hour' => max(1, min(500, (int) ($ini['max_per_hour'] ?? 20))),
    );
    return $cfg;
}

function wasp_alerts_enabled($event) {
    $cfg = wasp_alerts_config();
    return $cfg && !empty($cfg['events'][$event]);
}

/** One line, no control characters: these values reach a mail header or body. */
function wasp_alerts_clean($s, $max = 300) {
    $s = preg_replace('/[\x00-\x1F\x7F]+/', ' ', (string) $s);
    return strlen($s) > $max ? substr($s, 0, $max) . '…' : $s;
}

function wasp_alerts_is_admin_user($user) {
    if (is_numeric($user)) {
        $user = get_userdata((int) $user);
    }
    return ($user instanceof WP_User) && in_array('administrator', (array) $user->roles, true);
}

function wasp_alerts_user_label($user) {
    if (is_numeric($user)) {
        $user = get_userdata((int) $user);
    }
    if (!($user instanceof WP_User)) {
        return 'unknown account';
    }
    return wasp_alerts_clean(sprintf('%s <%s> (user %d)', $user->user_login, $user->user_email, $user->ID));
}

/** Who did it. REMOTE_ADDR is the real client: mod_remoteip substitutes it from the proxy. */
function wasp_alerts_context() {
    if (defined('WP_CLI') && WP_CLI) {
        $who = 'WP-CLI on the server';
    } elseif (function_exists('wp_doing_cron') && wp_doing_cron()) {
        $who = 'WordPress scheduled task';
    } else {
        $u = function_exists('wp_get_current_user') ? wp_get_current_user() : null;
        $who = ($u instanceof WP_User && $u->exists()) ? wasp_alerts_user_label($u) : 'not signed in';
    }
    $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
    return array(
        'Done by    : ' . $who,
        'From       : ' . (filter_var($ip, FILTER_VALIDATE_IP) ? $ip : 'unknown'),
        'Browser    : ' . wasp_alerts_clean($_SERVER['HTTP_USER_AGENT'] ?? 'none', 160),
    );
}

/**
 * Queue an alert. Sent once, at the end of the request, so a bulk action --
 * ten plugins updated at once -- is one email, not ten. $key identifies the
 * event for de-duplication; $ttl is how long an identical event stays quiet.
 */
function wasp_alerts_add($event, $title, array $lines, $key = '', $ttl = 600) {
    if (!wasp_alerts_enabled($event)) {
        return;
    }
    $key = $key !== '' ? $key : $event . ':' . md5($title . "\n" . implode("\n", $lines));
    if (!isset($GLOBALS['wasp_alerts_queue'])) {
        $GLOBALS['wasp_alerts_queue'] = array();
    }
    if (isset($GLOBALS['wasp_alerts_queue'][$key])) {
        return;
    }
    $GLOBALS['wasp_alerts_queue'][$key] = array(
        'event' => $event,
        'title' => wasp_alerts_clean($title, 200),
        'lines' => array_map('wasp_alerts_clean', $lines),
        'ttl'   => (int) $ttl,
        'ctx'   => wasp_alerts_context(),
    );
}

function wasp_alerts_site() {
    $host = wp_parse_url(home_url(), PHP_URL_HOST);
    return wasp_alerts_clean($host ? $host : 'WordPress');
}

/** Send whatever this request queued. */
function wasp_alerts_flush() {
    $queue = $GLOBALS['wasp_alerts_queue'] ?? array();
    $GLOBALS['wasp_alerts_queue'] = array();
    $cfg = wasp_alerts_config();
    if (!$queue || !$cfg) {
        return;
    }
    $items = array();
    foreach ($queue as $key => $item) {
        $t = 'wasp_alert_' . md5($key);
        if (get_transient($t)) {
            continue;
        }
        set_transient($t, 1, max(60, $item['ttl']));
        $items[] = $item;
    }
    if (!$items) {
        return;
    }

    // A ceiling, so a script hammering an endpoint cannot turn this into a
    // mail flood -- or burn the relay's sending quota and get the address
    // blocklisted. One notice says the ceiling was reached; then silence until
    // the hour is up. The window is fixed from its first message, so steady
    // activity cannot keep extending it.
    $now = time();
    $win = get_transient('wasp_alerts_window');
    if (!is_array($win) || ($now - (int) $win['start']) >= HOUR_IN_SECONDS) {
        $win = array('start' => $now, 'count' => 0, 'capped' => 0);
    }
    $left = HOUR_IN_SECONDS - ($now - (int) $win['start']);
    if ((int) $win['count'] >= $cfg['max_per_hour']) {
        if (empty($win['capped'])) {
            $win['capped'] = 1;
            set_transient('wasp_alerts_window', $win, $left);
            wasp_alerts_mail($cfg, 'Alert limit reached — further alerts held for up to an hour',
                "More than {$cfg['max_per_hour']} security alerts were raised on " . wasp_alerts_site() .
                " in under an hour. Further alerts are suppressed until the hour is up.\n\n" .
                "A burst like this is itself worth looking at. On the VM:\n" .
                "  doas wp-forensics.sh timeline\n  doas wp-forensics.sh admins\n");
        }
        return;
    }
    $win['count'] = (int) $win['count'] + 1;
    set_transient('wasp_alerts_window', $win, $left);

    $site = wasp_alerts_site();
    $subject = count($items) === 1 ? $items[0]['title'] : count($items) . ' security changes';
    $body  = "Site   : {$site}\n";
    $body .= 'Time   : ' . gmdate('Y-m-d H:i:s') . " UTC\n\n";
    foreach ($items as $i => $it) {
        $body .= (count($items) > 1 ? ($i + 1) . '. ' : '') . $it['title'] . "\n";
        foreach ($it['lines'] as $l) {
            $body .= '   ' . $l . "\n";
        }
        foreach ($it['ctx'] as $l) {
            $body .= '   ' . $l . "\n";
        }
        $body .= "\n";
    }
    $body .= "If you, or someone you work with, did not do this:\n";
    $body .= "  - Sign in and check Users, Plugins and Settings → General.\n";
    $body .= "  - On the VM:  doas wp-forensics.sh admins\n";
    $body .= "                doas wp-malware-scan.sh full\n";
    $body .= "  - Change the passwords of every administrator, then sign everyone\n";
    $body .= "    out:        doas wp-rotate-secrets.sh salts\n\n";
    $body .= "Which events are emailed:  doas wasp-alerts.sh status\n";
    wasp_alerts_mail($cfg, $subject, $body, array_unique(array_map(function ($i) { return $i['event']; }, $items)));
}

function wasp_alerts_mail($cfg, $subject, $body, $events = array('notice')) {
    $subject = '[' . wasp_alerts_site() . '] ' . wasp_alerts_clean($subject, 180);
    $headers = array(
        'Content-Type: text/plain; charset=UTF-8',
        'X-WASP-Alert: ' . preg_replace('/[^a-z_,]/', '', implode(',', (array) $events)),
    );
    return wp_mail($cfg['to'], $subject, $body, $headers);
}

/** Used by `wasp-alerts.sh test`: the real send path, rate limit aside. */
function wasp_alerts_send_test() {
    $cfg = wasp_alerts_config();
    if (!$cfg) {
        return false;
    }
    $on = array();
    foreach (wasp_alerts_events() as $k => $label) {
        $on[] = (empty($cfg['events'][$k]) ? '  off  ' : '  ON   ') . $label;
    }
    return wasp_alerts_mail($cfg, 'Test security alert',
        'This is a test from WASP Security Alerts on ' . wasp_alerts_site() . ".\n\n" .
        "If you are reading it, WordPress can tell you when something security-relevant\n" .
        "changes. Emailed events:\n\n" . implode("\n", $on) . "\n\n" .
        "Administrator sign-ins: " . ($cfg['login_mode'] === 'all' ? 'every one' :
            "from an address not seen for that account in {$cfg['ip_days']} days") . "\n" .
        'Sent: ' . gmdate('c') . "\n", array('test'));
}

if (!wasp_alerts_config()) {
    return;   // Not configured: nothing is hooked, nothing costs anything.
}
add_action('shutdown', 'wasp_alerts_flush', 1);

// ── Administrators: added, promoted, demoted, deleted ──────────────────────
add_action('set_user_role', function ($user_id, $role, $old_roles) {
    $was = in_array('administrator', (array) $old_roles, true);
    $is  = ($role === 'administrator');
    if ($is && !$was) {
        wasp_alerts_add('admin_role', 'Administrator added: ' . wasp_alerts_user_label($user_id),
            array('The account now has full control of the site.'), 'admin_added:' . $user_id, 3600);
    } elseif ($was && !$is) {
        wasp_alerts_add('admin_role', 'Administrator rights removed: ' . wasp_alerts_user_label($user_id),
            array('New role: ' . ($role !== '' ? $role : 'none'),
                  'Removing the real administrators is how an intruder locks the owner out.'),
            'admin_removed:' . $user_id, 3600);
    }
}, 10, 3);
add_action('add_user_role', function ($user_id, $role) {
    if ($role === 'administrator') {
        wasp_alerts_add('admin_role', 'Administrator added: ' . wasp_alerts_user_label($user_id),
            array('The account now has full control of the site.'), 'admin_added:' . $user_id, 3600);
    }
}, 10, 2);
add_action('remove_user_role', function ($user_id, $role) {
    if ($role === 'administrator') {
        wasp_alerts_add('admin_role', 'Administrator rights removed: ' . wasp_alerts_user_label($user_id),
            array('Removing the real administrators is how an intruder locks the owner out.'),
            'admin_removed:' . $user_id, 3600);
    }
}, 10, 2);
// Backstop for an account created with the role already set.
add_action('user_register', function ($user_id) {
    $GLOBALS['wasp_alerts_new_users'][] = (int) $user_id;
}, 10, 1);
add_action('shutdown', function () {
    foreach ((array) ($GLOBALS['wasp_alerts_new_users'] ?? array()) as $id) {
        clean_user_cache($id);
        if (wasp_alerts_is_admin_user($id)) {
            wasp_alerts_add('admin_role', 'Administrator added: ' . wasp_alerts_user_label($id),
                array('A new account was created with full control of the site.'), 'admin_added:' . $id, 3600);
        }
    }
}, 0);
add_action('delete_user', function ($id, $reassign = null, $user = null) {
    $user = ($user instanceof WP_User) ? $user : get_userdata($id);
    if (wasp_alerts_is_admin_user($user)) {
        wasp_alerts_add('admin_role', 'Administrator deleted: ' . wasp_alerts_user_label($user),
            array($reassign ? 'Content reassigned to user ' . (int) $reassign : 'Content not reassigned'),
            'admin_deleted:' . $id, 3600);
    }
}, 10, 3);

// ── Administrator sign-in from a new address ────────────────────────────────
// wp_login fires when the PASSWORD is accepted. With two-factor enrolled the
// second step comes after this -- so an alert here with no sign-in of your
// own means someone has the password, whether or not they got further.
add_action('wp_login', function ($login, $user) {
    if (!wasp_alerts_is_admin_user($user)) {
        return;
    }
    $cfg = wasp_alerts_config();
    $ip  = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
    $ip  = filter_var($ip, FILTER_VALIDATE_IP) ? $ip : 'unknown';
    $now = time();
    $known = get_user_meta($user->ID, 'wasp_alerts_known_ips', true);
    $known = is_array($known) ? $known : array();
    foreach ($known as $k => $t) {
        if ($now - (int) $t > $cfg['ip_days'] * DAY_IN_SECONDS) {
            unset($known[$k]);
        }
    }
    $new = !isset($known[$ip]);
    $known[$ip] = $now;
    if (count($known) > 50) {
        arsort($known);
        $known = array_slice($known, 0, 50, true);
    }
    update_user_meta($user->ID, 'wasp_alerts_known_ips', $known);
    if ($new || $cfg['login_mode'] === 'all') {
        wasp_alerts_add('admin_login',
            ($new ? 'Administrator sign-in from a new address: ' : 'Administrator signed in: ') . wasp_alerts_user_label($user),
            array(
                $new ? "This account has not signed in from {$ip} in the last {$cfg['ip_days']} days."
                     : 'Every administrator sign-in is emailed (admin_login_mode = all).',
                'The password was accepted. Two-factor, where enrolled, is checked after this step.',
            ),
            'login:' . $user->ID . ':' . $ip, 300);
    }
}, 10, 2);

// ── Administrator password, email, reset requests ──────────────────────────
function wasp_alerts_password_changed($user_id) {
    if (wasp_alerts_is_admin_user($user_id)) {
        wasp_alerts_add('admin_credentials', 'Administrator password changed: ' . wasp_alerts_user_label($user_id),
            array('Whoever set it can now sign in as this account.'), 'pass:' . $user_id, 600);
    }
}
add_action('profile_update', function ($user_id, $old = null) {
    $u = get_userdata($user_id);
    if (!($old instanceof WP_User) || !$u || (!wasp_alerts_is_admin_user($u) && !wasp_alerts_is_admin_user($old))) {
        return;
    }
    if (strtolower($old->user_email) !== strtolower($u->user_email)) {
        wasp_alerts_add('admin_credentials', 'Administrator email changed: ' . wasp_alerts_clean($u->user_login),
            array('From : ' . wasp_alerts_clean($old->user_email), 'To   : ' . wasp_alerts_clean($u->user_email),
                  'Password-reset links for this account now go to the new address.'),
            'email:' . $user_id . ':' . md5($u->user_email), 3600);
    }
    if ($old->user_pass !== $u->user_pass) {
        wasp_alerts_password_changed($user_id);
    }
}, 10, 2);
// WordPress 6.2+: fires for every password set, including resets, which do
// not pass through profile_update. The password itself is never read.
add_action('wp_set_password', function ($password, $user_id = 0) {
    wasp_alerts_password_changed((int) $user_id);
}, 10, 2);
add_action('after_password_reset', function ($user) {
    if ($user instanceof WP_User) {
        wasp_alerts_password_changed($user->ID);
    }
}, 10, 1);
add_action('retrieve_password_key', function ($user_login) {
    $u = get_user_by('login', $user_login);
    if ($u && wasp_alerts_is_admin_user($u)) {
        wasp_alerts_add('admin_credentials', 'Password reset requested for administrator: ' . wasp_alerts_clean($user_login),
            array('A reset link was emailed to ' . wasp_alerts_clean($u->user_email) . '.',
                  'Harmless if it was you. If not, someone knows this account name and is trying it.'),
            'reset:' . $u->ID, 6 * HOUR_IN_SECONDS);
    }
}, 10, 1);

// ── Application passwords ───────────────────────────────────────────────────
add_action('wp_create_application_password', function ($user_id, $item = array()) {
    $name = is_array($item) && isset($item['name']) ? $item['name'] : '(unnamed)';
    wasp_alerts_add('app_password', 'Application password created for ' . wasp_alerts_user_label($user_id),
        array('Name : ' . wasp_alerts_clean($name),
              'Role : ' . implode(', ', (array) (get_userdata($user_id)->roles ?? array())),
              'An application password signs in to the REST API and XML-RPC without the',
              'login page or two-factor. If nobody on your team made it, revoke it now:',
              'Users → that user → Application Passwords.'),
        'app:' . $user_id . ':' . md5((string) $name), 600);
}, 10, 2);

// ── Two-factor (the Two Factor plugin WASP installs) ───────────────────────
foreach (array('added_user_meta', 'updated_user_meta', 'deleted_user_meta') as $wasp_alerts_hook) {
    add_action($wasp_alerts_hook, function ($meta_id, $user_id, $meta_key, $value = null) use ($wasp_alerts_hook) {
        if ($meta_key !== '_two_factor_enabled_providers' || !wasp_alerts_is_admin_user($user_id)) {
            return;
        }
        $prov = $wasp_alerts_hook === 'deleted_user_meta' ? array() : array_filter((array) maybe_unserialize($value));
        if (!$prov) {
            wasp_alerts_add('mfa_change', 'Two-factor turned OFF for administrator: ' . wasp_alerts_user_label($user_id),
                array('The account now signs in with a password alone.'), 'mfa:' . $user_id . ':off', 600);
        } else {
            $names = array_map(function ($p) { return preg_replace('/^Two_Factor_/', '', (string) $p); }, array_values($prov));
            wasp_alerts_add('mfa_change',
                ($wasp_alerts_hook === 'added_user_meta' ? 'Two-factor set up for administrator: ' : 'Two-factor methods changed for administrator: ')
                . wasp_alerts_user_label($user_id),
                array('Methods now enabled: ' . implode(', ', $names)), 'mfa:' . $user_id . ':' . md5(implode(',', $names)), 600);
        }
    }, 10, 4);
}
unset($wasp_alerts_hook);

// ── Plugins, themes, core ───────────────────────────────────────────────────
add_action('activated_plugin', function ($plugin) {
    wasp_alerts_add('code_change', 'Plugin activated: ' . $plugin, array(), 'pa:' . $plugin);
}, 10, 1);
add_action('deactivated_plugin', function ($plugin) {
    wasp_alerts_add('code_change', 'Plugin deactivated: ' . $plugin, array(), 'pd:' . $plugin);
}, 10, 1);
add_action('deleted_plugin', function ($plugin, $deleted = true) {
    if ($deleted) {
        wasp_alerts_add('code_change', 'Plugin deleted: ' . $plugin, array(), 'px:' . $plugin);
    }
}, 10, 2);
add_action('upgrader_process_complete', function ($upgrader, $extra = array()) {
    $type   = $extra['type'] ?? '';
    $action = $extra['action'] ?? '';
    if (!in_array($type, array('plugin', 'theme', 'core'), true)) {
        return;
    }
    if ($type === 'core') {
        wasp_alerts_add('code_change', 'WordPress core updated to ' . get_bloginfo('version'), array(), 'core:' . get_bloginfo('version'));
        return;
    }
    $names = array();
    if ($action === 'install') {
        $r = is_object($upgrader) && isset($upgrader->result) && is_array($upgrader->result) ? $upgrader->result : array();
        $names[] = $r['destination_name'] ?? '(unknown)';
    } else {
        $names = (array) ($extra[$type . 's'] ?? ($extra[$type] ?? array()));
    }
    foreach ($names as $n) {
        $verb = $action === 'install' ? 'installed' : 'updated';
        wasp_alerts_add('code_change', ucfirst($type) . " {$verb}: " . $n,
            $action === 'install' ? array('New code on the site. Installed from a zip upload or the directory.') : array(),
            "up:{$type}:{$action}:" . $n);
    }
}, 10, 2);
add_action('switch_theme', function ($new_name, $new_theme = null, $old_theme = null) {
    wasp_alerts_add('code_change', 'Theme switched to ' . $new_name,
        array('Previous theme: ' . (($old_theme instanceof WP_Theme) ? $old_theme->get('Name') : 'unknown')),
        'theme:' . $new_name);
}, 10, 3);

// ── Settings an intruder changes first ─────────────────────────────────────
foreach (array('siteurl', 'home', 'admin_email', 'new_admin_email', 'users_can_register', 'default_role') as $wasp_alerts_opt) {
    add_action('update_option_' . $wasp_alerts_opt, function ($old, $new, $option) {
        $lines = array('From : ' . wasp_alerts_clean(is_scalar($old) ? (string) $old : json_encode($old)),
                       'To   : ' . wasp_alerts_clean(is_scalar($new) ? (string) $new : json_encode($new)));
        switch ($option) {
            case 'siteurl':
            case 'home':
                $title = "Site address changed ({$option})";
                $lines[] = 'Changing this redirects every visitor, and the login page, elsewhere.';
                break;
            case 'admin_email':
                $title = 'Site admin email changed';
                $lines[] = 'WordPress sends its own security notices to this address.';
                break;
            case 'new_admin_email':
                $title = 'Change of site admin email requested';
                $lines[] = 'WordPress mails a confirmation link to the new address; until it is';
                $lines[] = 'clicked the old address stays in force.';
                break;
            case 'users_can_register':
                if ((string) $new === '1') {
                    $title = 'Public registration turned ON';
                    $lines[] = 'Anyone can now create an account, with the default role ('
                        . wasp_alerts_clean((string) get_option('default_role')) . ').';
                } else {
                    $title = 'Public registration turned off';
                }
                break;
            default:
                $title = 'Default role for new accounts changed';
                if ($new === 'administrator') {
                    $title = 'DANGER: new accounts now become administrators';
                }
                break;
        }
        wasp_alerts_add('settings_change', $title, $lines, 'opt:' . $option . ':' . md5(serialize($new)), 600);
    }, 10, 3);
}
unset($wasp_alerts_opt);

// ── Spam links saved into the content (10.18) ──────────────────────────────
// The weekly scan (wp-links.sh spam) finds injected links days after they go
// in; this sees them as they are saved -- through any editor or builder, a
// stolen session or the REST API -- and names the page, the Elementor widget
// and the command that removes it. Since 10.19 whichever builder or theme
// stores it: post content (blocks, shortcodes, classic), any builder's page
// data in post meta (Beaver, Bricks, Oxygen, Breakdance ...), theme and
// Customizer settings, widgets and menus. Only LINKS are judged here, never wording
// alone: a false alarm on every save would be ignored by the second week.
// The word list is the content scanner's (test-links.sh holds the copies
// together). One email per page per day while the spam stays.
function wasp_alerts_spam_host_re() {
    return '/(casin(?!g)|kasin|kasyn|kaszin|cassin|slot|poker|roulette|blackjack|jackpot|betting|bet365|betway|1xbet|mostbet|melbet|sportsbet|bookmaker|gambl|scommess|apuest|viagra|cialis(?![tme])|levitra|kamagra|sildenafil|tadalafil|porn|xxx|escort|payday)/i';
}

/**
 * Outside hosts with a spam name that a saved value links to, however it is
 * stored: HTML, JSON with escaped slashes, a URL-encoded shortcode attribute
 * (WPBakery), serialized arrays and objects (Beaver Builder, theme settings).
 */
function wasp_alerts_spam_hosts($v) {
    if (is_array($v) || is_object($v)) {
        $v = json_encode($v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR);
    }
    $s = (string) $v;
    if (stripos($s, 'http') === false) { return array(); }
    $s = str_replace(array('\\/', '\\u002F', '\\u002f'), '/', $s);                 // JSON escaping
    if (stripos($s, '%3A%2F%2F') !== false) {                                    // URL-encoded
        $s = preg_replace_callback('#https?%3A%2F%2F[^\s"\'|\]\[<>]+#i', function ($m) { return rawurldecode($m[0]); }, $s);
    }
    $site = strtolower(preg_replace('/^www\./', '', (string) wp_parse_url(home_url(), PHP_URL_HOST)));
    $out = array();
    if (preg_match_all('#https?://([a-z0-9][a-z0-9.-]*[a-z0-9])#i', $s, $m)) {
        foreach ($m[1] as $h) {
            $h = strtolower(preg_replace('/^www\./', '', $h));
            if ($h !== $site && preg_match(wasp_alerts_spam_host_re(), $h)) {
                $out[$h] = true;
            }
        }
    }
    return array_keys($out);
}

/** Post meta that is not content: never judged. */
function wasp_alerts_spam_meta_skip($key) {
    return in_array($key, array('_menu_item_url', '_edit_lock', '_edit_last', '_wp_attachment_metadata', '_wp_attached_file',
                                '_elementor_css', '_elementor_element_cache', '_elementor_page_assets', '_wp_old_slug'), true)
        || strpos($key, '_oembed_') === 0 || strpos($key, '_transient') === 0;
}

/** Options that are caches, logs or plumbing: never judged (transients are most writes). */
function wasp_alerts_spam_option_skip($name) {
    return strpos($name, '_transient') === 0 || strpos($name, '_site_transient') === 0
        || in_array($name, array('cron', 'rewrite_rules', 'rank_math_indexnow_log', 'active_plugins', 'recently_edited',
                                 'wasp_alerts_state', 'dashboard_widget_options', 'uninstall_plugins'), true);
}

/** Note spam found in one saved thing; the emails are written at the end of the request. */
function wasp_alerts_spam_note($id, $kind, array $hosts, $where = '', $sheets = false) {
    if (!$hosts || !wasp_alerts_enabled('content_spam')) {
        return;
    }
    $k = $kind . ':' . (int) $id;
    if (!isset($GLOBALS['wasp_alerts_spam'][$k])) {
        $GLOBALS['wasp_alerts_spam'][$k] = array('id' => (int) $id, 'kind' => $kind, 'hosts' => array(), 'where' => array(), 'sheets' => false);
    }
    $e = &$GLOBALS['wasp_alerts_spam'][$k];
    $e['hosts'] = array_values(array_unique(array_merge($e['hosts'], $hosts)));
    if ($where !== '') { $e['where'][$where] = true; }
    $e['sheets'] = $e['sheets'] || $sheets;
}

function wasp_alerts_spam_is_content($post) {
    return $post && !in_array($post->post_type, array('revision', 'nav_menu_item', 'attachment', 'customize_changeset', 'oembed_cache'), true)
        && !in_array($post->post_status, array('auto-draft', 'trash', 'inherit'), true);
}

add_action('save_post', function ($post_id, $post = null) {
    if (!($post instanceof WP_Post)) { $post = get_post($post_id); }
    if (!wasp_alerts_spam_is_content($post)) { return; }
    $hosts = wasp_alerts_spam_hosts($post->post_content);
    wasp_alerts_spam_note($post->ID, 'post', $hosts, '', stripos($post->post_content, 'data-sheets-') !== false);
}, 20, 2);

foreach (array('added_post_meta', 'updated_post_meta') as $wasp_alerts_hook) {
    add_action($wasp_alerts_hook, function ($meta_id, $object_id, $meta_key, $value = null) {
        $meta_key = (string) $meta_key;
        if ($meta_key !== '_elementor_data' && $meta_key !== '_menu_item_url') {
            // Any other builder's page data (and SEO fields): judged by value.
            if (wasp_alerts_spam_meta_skip($meta_key)) { return; }
            $hosts = wasp_alerts_spam_hosts($value);
            if (!$hosts) { return; }
            $post = get_post($object_id);
            if (!wasp_alerts_spam_is_content($post)) { return; }
            wasp_alerts_spam_note($object_id, 'post', $hosts, 'meta|' . preg_replace('/[^a-z0-9_-]/i', '', $meta_key),
                                  is_string($value) ? stripos($value, 'data-sheets-') !== false : false);
            return;
        }
        $post = get_post($object_id);
        if ($meta_key === '_menu_item_url') {
            if ($post && $post->post_type === 'nav_menu_item') {
                wasp_alerts_spam_note($object_id, 'menu', wasp_alerts_spam_hosts('href="' . (string) $value . '"'));
            }
            return;
        }
        if (!wasp_alerts_spam_is_content($post)) { return; }
        $data = is_array($value) ? $value : json_decode((string) $value, true);
        if (!is_array($data)) { return; }
        $walk = function ($els) use (&$walk, $object_id) {
            foreach ((array) $els as $el) {
                if (!is_array($el)) { continue; }
                if (($el['elType'] ?? '') === 'widget' && isset($el['settings'])) {
                    $j = json_encode($el['settings'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
                    $h = wasp_alerts_spam_hosts($j);
                    if ($h) {
                        $id = preg_replace('/[^a-z0-9]/i', '', (string) ($el['id'] ?? ''));
                        wasp_alerts_spam_note($object_id, 'post', $h,
                            $id . '|' . preg_replace('/[^a-z0-9_-]/i', '', (string) ($el['widgetType'] ?? 'widget')),
                            stripos($j, 'data-sheets-') !== false);
                    }
                }
                if (!empty($el['elements'])) { $walk($el['elements']); }
            }
        };
        $walk($data);
    }, 10, 4);
}
unset($wasp_alerts_hook);

// Sidebar widgets, theme and Customizer settings, any other setting.
$wasp_alerts_option = function ($option, $new) {
    $option = (string) $option;
    if (wasp_alerts_spam_option_skip($option)) { return; }
    $hosts = wasp_alerts_spam_hosts($new);
    if (!$hosts) { return; }
    $kind = strpos($option, 'widget_') === 0 ? 'widget:' : 'setting:';
    wasp_alerts_spam_note(0, $kind . preg_replace('/[^a-z0-9_.-]/i', '', $option), $hosts);
};
add_action('updated_option', function ($option, $old = null, $new = null) use ($wasp_alerts_option) { $wasp_alerts_option($option, $new); }, 10, 3);
add_action('added_option', function ($option, $value = null) use ($wasp_alerts_option) { $wasp_alerts_option($option, $value); }, 10, 2);
unset($wasp_alerts_option);

// Before wasp_alerts_flush (priority 1): one alert per page, however many hooks saw it.
add_action('shutdown', function () {
    foreach ($GLOBALS['wasp_alerts_spam'] ?? array() as $e) {
        $hosts = $e['hosts']; sort($hosts);
        $widgets = array(); $wlines = array();
        foreach (array_keys($e['where']) as $w) {
            list($wid, $wtype) = array_pad(explode('|', $w, 2), 2, 'widget');
            if ($wid === 'meta') { $wlines[] = "page data: {$wtype}"; continue; }
            $widgets[] = $wid; $wlines[] = "Elementor widget {$wid} ({$wtype})";
        }
        if ($e['kind'] === 'post') {
            $post = get_post($e['id']);
            $what = $post ? $post->post_type . ' ' . $post->ID . ' "' . wasp_alerts_clean($post->post_title, 80) . '" (' . $post->post_status . ')' : 'post ' . $e['id'];
            $title = 'Spam link saved on ' . ($post ? $post->post_type : 'post') . ' ' . $e['id'] . ($post ? ': "' . wasp_alerts_clean($post->post_title, 60) . '"' : '');
        } elseif ($e['kind'] === 'menu') {
            $what = 'menu item ' . $e['id'] . ' (Appearance → Menus)';
            $title = 'Spam link saved in a menu';
        } elseif (strpos($e['kind'], 'setting:') === 0) {
            $name = substr($e['kind'], 8);
            $what = 'setting ' . $name . (strpos($name, 'theme_mods_') === 0 ? ' (the theme\'s settings: Appearance → Customize)' : '');
            $title = strpos($name, 'theme_mods_') === 0 ? 'Spam link saved in the theme settings' : 'Spam link saved in a site setting';
        } else {
            $what = 'sidebar widget ' . substr($e['kind'], 7) . ' (Appearance → Widgets)';
            $title = 'Spam link saved in a sidebar widget';
        }
        $lines = array(
            'Where      : ' . $what,
            'Links to   : ' . implode(', ', $hosts),
        );
        foreach ($wlines as $l) { $lines[] = '             ' . $l; }
        if ($e['sheets']) { $lines[] = 'Pasted from a Google Sheet (the paste markers are still in the page).'; }
        $lines[] = '';
        $lines[] = 'A business site linking to casino, pharmacy or adult sites is how paid link';
        $lines[] = 'spam looks. If nobody here added it, the account that saved it may be in';
        $lines[] = "someone else's hands: see who it was below, and check it first.";
        $lines[] = '';
        $lines[] = 'Remove it : doas wp-links.sh clean --links ' . implode(',', $hosts) . '   (a preview; then the same with --apply)';
        if ($widgets) { $lines[] = '            or the whole widget: doas wp-links.sh clean --widgets ' . implode(',', $widgets); }
        $lines[] = 'See all   : doas wp-links.sh spam';
        wasp_alerts_add('content_spam', $title, $lines, 'spam:' . $e['kind'] . ':' . $e['id'] . ':' . md5(implode(',', $hosts)), DAY_IN_SECONDS);
    }
    $GLOBALS['wasp_alerts_spam'] = array();
}, 0);

