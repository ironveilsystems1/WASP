<?php
/**
 * Plugin Name:  WASP — Username Privacy
 * Description:  Closes the routes that hand an attacker a valid username.
 * Version:      1.1
 *
 * =========================================================================
 * WHY THIS MATTERS MORE HERE THAN ON A TYPICAL SITE
 * =========================================================================
 *
 * WordPress leaks usernames through five separate routes, and on most sites
 * that is treated as low severity: knowing a username still leaves the
 * password.
 *
 * On a VM running WASP it is worse than that, because the login guard locks
 * accounts BY USERNAME. An attacker who learns a real administrator's login
 * name can lock that administrator out repeatedly — five wrong passwords every
 * twenty minutes, escalating to a twenty-four hour lockout — without ever
 * coming close to guessing the password.
 *
 * That turns a protective control into a denial-of-service against the client,
 * and the client cannot tell the difference from the outside. Closing the
 * enumeration routes is what stops brute-force protection being weaponised.
 *
 * =========================================================================
 * THE FIVE ROUTES
 * =========================================================================
 *
 *   1. REST:    /wp-json/wp/v2/users  returns every author's slug and name to
 *               an unauthenticated caller.
 *   2. Author:  /?author=1  redirects to /author/<username>/, which is the
 *               login name unless the slug was changed by hand.
 *   3. Errors:  the login form distinguishes "unknown username" from
 *               "incorrect password", which confirms a guess in one request.
 *   4. Sitemap: /wp-sitemap-users-1.xml lists every author archive URL, and
 *               WordPress pings search engines with it on publish.
 *   5. oEmbed:  /wp-json/oembed/1.0/embed returns author_url UNAUTHENTICATED.
 *
 * All five are closed below. None of this is obscurity for its own sake —
 * each one converts a single request into a confirmed username.
 *
 * -------------------------------------------------------------------------
 * ROUTES 4 AND 5 WERE MISSED, AND THIS IS WHAT THAT COST
 * -------------------------------------------------------------------------
 *
 * Version 1.0 of this file closed routes 1-3 and asserted, in a comment, that
 * oEmbed "exposes the display name rather than the login name". That was
 * wrong. oEmbed returns author_url, which is built from user_nicename, and
 * user_nicename DEFAULTS TO user_login. It was never tested.
 *
 * Route 4 was not considered at all. WordPress has generated a users sitemap
 * by default since 5.5, and it is submitted to search engines automatically.
 *
 * On a live client site this published the administrator login name in a
 * crawlable, indexed file for the lifetime of the install. A credential
 * attack against that exact account followed, and the username was initially
 * assumed to have come from a prior compromise of the client's old host — it
 * had not. This file published it.
 *
 * The lesson is in the shape of the failure, not the detail: routes 1-3 are
 * the ones security guidance names, closing them made the control read as
 * present, and enumeration kept working through the two nobody checked.
 *
 * -------------------------------------------------------------------------
 * ROUTE 6 DOES NOT EXIST, BECAUSE user_nicename IS THE REAL FIX
 * -------------------------------------------------------------------------
 *
 * Every public surface — author archives, the sitemap, oEmbed, theme bylines,
 * feeds, comment links — prints user_nicename, not user_login. Blocking each
 * surface one at a time is a losing game against a plugin or theme that adds
 * a sixth. Decoupling nicename from login closes all of them at once and
 * keeps closing them.
 *
 * So section 4 below is the control. Sections 5 and 6 are defence in depth
 * for accounts this plugin did not create — an imported database, a user made
 * before this file was installed, a slug reset by hand.
 *
 * =========================================================================
 * WHAT IS DELIBERATELY LEFT ALONE
 * =========================================================================
 *
 * The users endpoint is restricted, not removed. An authenticated user with
 * `list_users` still gets it, because the block editor and several legitimate
 * tools need it — breaking wp-admin to hide a username would be a poor trade.
 *
 * Author archives still resolve. They are a published URL that themes link
 * to, and 404ing them breaks navigation on sites that use them. With section
 * 4 in force the slug in that URL is not the login name, so the archive
 * working costs nothing.
 */

if (!defined('ABSPATH')) { exit; }

/**
 * 1. The REST users endpoint.
 *
 * Restricted to callers who can already list users. `rest_endpoints` is used
 * rather than unregistering the route, so an authenticated editor keeps the
 * functionality wp-admin depends on.
 */
add_filter('rest_endpoints', function ($endpoints) {

    $guard = function ($request) {
        if (current_user_can('list_users')) {
            return true;
        }
        return new WP_Error(
            'rest_user_cannot_view',
            __('Sorry, you are not allowed to list users.'),
            array('status' => rest_authorization_required_code())
        );
    };

    foreach (array('/wp/v2/users', '/wp/v2/users/(?P<id>[\d]+)') as $route) {
        if (!isset($endpoints[$route])) {
            continue;
        }
        foreach ($endpoints[$route] as $i => $handler) {
            // Only GET. Leave write methods to core's own capability checks —
            // they are already correct, and overriding them here would be
            // second-guessing a control that works.
            if (isset($handler['methods'])
                && strpos(strtoupper($handler['methods']), 'GET') !== false) {
                $endpoints[$route][$i]['permission_callback'] = $guard;
            }
        }
    }
    return $endpoints;
}, 20);

/**
 * 2. Author archive enumeration.
 *
 * /?author=1 is answered by a redirect to /author/<username>/, so a single
 * request over a range of IDs maps the whole user table. 404 instead.
 *
 * Runs on `parse_request` rather than `template_redirect` because WordPress
 * resolves the author and issues the canonical redirect early — by
 * template_redirect the Location header is already decided.
 */
add_action('parse_request', function ($wp) {
    if (is_admin() || !isset($wp->query_vars['author'])) {
        return;
    }
    // A numeric author var means ?author=N. A named author archive
    // (/author/jane/) arrives as author_name and is left working, since that
    // is a deliberate published URL rather than an enumeration probe.
    if (is_numeric($wp->query_vars['author'])) {
        unset($wp->query_vars['author']);
        $wp->query_vars['error'] = '404';
    }
});

/**
 * 3. Login error messages.
 *
 * WordPress distinguishes "unknown username" from "incorrect password", which
 * confirms a valid username in one request without any rate limit being
 * involved — the attacker is not guessing passwords yet.
 *
 * One identical message for every failure. This is the change most likely to
 * be noticed by a legitimate user, and the trade is deliberate: a person who
 * mistypes their username sees the same message as one who mistypes their
 * password, which is marginally less helpful and removes a free oracle.
 */
add_filter('login_errors', function ($error) {
    global $errors;
    if (!is_wp_error($errors)) {
        return $error;
    }
    $codes = $errors->get_error_codes();
    $leaky = array(
        'invalid_username', 'invalidcombo', 'incorrect_password',
        'invalid_email', 'empty_password', 'empty_username',
    );
    foreach ($codes as $code) {
        if (in_array($code, $leaky, true)) {
            return __('The username or password you entered is not correct.');
        }
    }
    return $error;
});

/**
 * The same oracle exists on password reset: "There is no account with that
 * username or email address" confirms which addresses are registered.
 * Core has a filter for exactly this; turn it on.
 */
add_filter('allow_password_reset', '__return_true');
add_filter('lostpassword_errors', function ($errors) {
    if (is_wp_error($errors) && $errors->get_error_codes()) {
        $clean = new WP_Error();
        $clean->add('confirm', __('If that account exists, a reset link has been sent.'), 'message');
        return $clean;
    }
    return $errors;
});

/* =========================================================================
 * 4. user_nicename — the control every other section leans on.
 * =========================================================================
 *
 * WordPress sets user_nicename to sanitize_title(user_login) when a user is
 * created. Every public surface prints the nicename, so by default every
 * public surface prints the login name. Decoupling them is what actually
 * closes enumeration; sections 5 and 6 only close the two surfaces that are
 * reachable without a theme rendering a byline.
 *
 * Opt out with  define('WPVM_NICENAME_PRIVACY', false);  in wp-config.php —
 * for a site that genuinely publishes author archives under human-readable
 * slugs AND whose logins differ from them.
 */
if (!defined('WPVM_NICENAME_PRIVACY')) {
    define('WPVM_NICENAME_PRIVACY', true);
}

/**
 * An opaque slug with nothing derived from the account.
 *
 * Deliberately not built from the login, display name or email: a slug
 * derived from any of them leaks what it was derived from, which is the bug
 * this function exists to avoid repeating.
 */
function wpvm_private_nicename() {
    return sanitize_title(strtolower(wp_generate_password(12, false, false)));
}

/**
 * Would this nicename publish the login name?
 *
 * True only when the slug is exactly what WordPress would have generated from
 * the login. Anything else was set on purpose and is left alone.
 */
function wpvm_nicename_leaks($user_login, $user_nicename) {
    return $user_nicename === sanitize_title($user_login);
}

/**
 * New users: replace the generated slug before anything can publish it.
 *
 * Priority 5 so this lands ahead of anything that reads the slug on
 * registration. $wpdb->update rather than wp_update_user, which fires
 * profile_update and would re-enter hooks mid-registration.
 */
add_action('user_register', function ($user_id) {
    if (!WPVM_NICENAME_PRIVACY) {
        return;
    }
    global $wpdb;
    $user = get_userdata($user_id);
    if (!$user || !wpvm_nicename_leaks($user->user_login, $user->user_nicename)) {
        return;
    }
    $wpdb->update(
        $wpdb->users,
        array('user_nicename' => wpvm_private_nicename()),
        array('ID' => (int) $user_id)
    );
    clean_user_cache($user_id);
}, 5);

/**
 * Existing users: a one-time pass for accounts this plugin did not create.
 *
 * An imported database is the case that matters. A dump from another host
 * brings its own users table, with its own nicenames, and the user_register
 * hook above never fires for any of them — which is exactly how a site can
 * pass every check here and still publish a login name.
 *
 * Runs in wp-admin or cron only, never on a front-end request: this reads the
 * whole users table, and a visitor should not pay for a migration. The option
 * is autoloaded 'no' because it is read once and then never again on a normal
 * request path.
 */
add_action('init', function () {
    if (!WPVM_NICENAME_PRIVACY || get_option('wpvm_nicename_migrated')) {
        return;
    }
    if (!is_admin() && !wp_doing_cron()) {
        return;
    }
    global $wpdb;
    $rows = $wpdb->get_results("SELECT ID, user_login, user_nicename FROM {$wpdb->users}");
    if (!is_array($rows)) {
        // Do not mark the migration done on a failed read — it would never be
        // retried, and the failure is silent. Leave the flag unset and try on
        // the next admin request.
        return;
    }
    foreach ($rows as $row) {
        if (!wpvm_nicename_leaks($row->user_login, $row->user_nicename)) {
            continue;
        }
        $wpdb->update(
            $wpdb->users,
            array('user_nicename' => wpvm_private_nicename()),
            array('ID' => (int) $row->ID)
        );
        clean_user_cache((int) $row->ID);
    }
    update_option('wpvm_nicename_migrated', 1, false);
});

/* =========================================================================
 * 5. The users sitemap.
 * =========================================================================
 *
 * Core has published /wp-sitemap-users-1.xml since WordPress 5.5, listing one
 * author archive URL per user, and pings search engines with it on publish.
 * With the default nicename that file is a machine-readable roster of valid
 * logins, delivered to crawlers without anyone asking.
 *
 * Dropped rather than filtered: there is no version of a public user sitemap
 * that helps this site, and an empty one still advertises that users exist.
 */
add_filter('wp_sitemaps_add_provider', function ($provider, $name) {
    return 'users' === $name ? false : $provider;
}, 10, 2);

/* =========================================================================
 * 6. oEmbed author data.
 * =========================================================================
 *
 * /wp-json/oembed/1.0/embed answers unauthenticated and returns author_url,
 * which is built from the nicename. It is the standard way around a
 * restricted REST user listing — section 1 can be perfect and this still
 * hands the slug over.
 *
 * author_name (the display name) goes too. On its own it is harmless, but
 * leaving it while removing author_url produces a response that looks
 * sanitised and still narrows a guess.
 *
 * What this costs: a site embedding one of these posts shows the post title
 * and site name without an author byline. That is the whole impact.
 */
add_filter('oembed_response_data', function ($data) {
    unset($data['author_url'], $data['author_name']);
    return $data;
}, 10, 1);
