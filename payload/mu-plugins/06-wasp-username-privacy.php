<?php
/**
 * Plugin Name:  WASP — Username Privacy
 * Description:  Closes the routes that hand an attacker a valid username.
 * Version:      1.0
 *
 * =========================================================================
 * WHY THIS MATTERS MORE HERE THAN ON A TYPICAL SITE
 * =========================================================================
 *
 * WordPress leaks usernames through three separate routes, and on most sites
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
 * THE THREE ROUTES
 * =========================================================================
 *
 *   1. REST:    /wp-json/wp/v2/users  returns every author's slug and name to
 *               an unauthenticated caller.
 *   2. Author:  /?author=1  redirects to /author/<username>/, which is the
 *               login name unless the slug was changed by hand.
 *   3. Errors:  the login form distinguishes "unknown username" from
 *               "incorrect password", which confirms a guess in one request.
 *
 * All three are closed below. None of this is obscurity for its own sake —
 * each one converts a single request into a confirmed username.
 *
 * =========================================================================
 * WHAT IS DELIBERATELY LEFT ALONE
 * =========================================================================
 *
 * The users endpoint is restricted, not removed. An authenticated user with
 * `list_users` still gets it, because the block editor and several legitimate
 * tools need it — breaking wp-admin to hide a username would be a poor trade.
 *
 * oEmbed author data is left alone for the same reason: it is used by other
 * sites embedding your posts, and it exposes the display name rather than the
 * login name.
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
