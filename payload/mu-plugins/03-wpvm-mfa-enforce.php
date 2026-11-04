<?php
/**
 * Plugin Name: WASP — MFA Enforcement
 * Description: Requires administrators to hold a configured second factor via the Two Factor plugin, and closes the REST and application-password routes that would otherwise let an admin skip it. Built around recovery: a grace window before blocking, backup codes count, and a console reset if every factor is lost. Deleting this file disables the requirement — it does not lock anyone out.
 * Author: IronVeil Systems DevOps
 * Version: 1.0
 * WHY THIS EXISTS AS A SEPARATE PIECE
 *
 * The Two Factor plugin (maintained by the WordPress core contributors) provides
 * the actual TOTP / backup-code / WebAuthn machinery, but deliberately has NO
 * enforcement: every user opts in from their own profile. For an MSP that is the
 * wrong default — an administrator who never visits their profile page has no
 * second factor, which is exactly the account that most needs one. This adds the
 * enforcement WITHOUT modifying the plugin, so the plugin can update freely.
 *
 * THE THING THIS MUST NOT DO IS STRAND ANYONE
 *
 * Enforcement that has no escape hatch is how a lost phone becomes a rebuild.
 * So this is built around recovery, not just around blocking. Past the grace
 * window an unenrolled administrator hits a wall from the network, on purpose
 * (see "The wall" below), and the escape hatch is the console:
 *
 *   1. A GRACE WINDOW. A newly-created or newly-promoted admin is not blocked
 *      immediately; they are steered to set up 2FA and given a configurable
 *      number of days to do it. Blocking someone before they have had any
 *      chance to enrol is the fastest way to manufacture a lockout.
 *
 *   2. BACKUP CODES ARE PART OF "ENROLLED". The Two Factor plugin's backup-code
 *      provider counts. An admin with TOTP + printed backup codes can always get
 *      back in from any device, which is the property that makes enforcement
 *      safe to turn on.
 *
 *   3. A CONSOLE RECOVERY PATH. If every factor is lost, 2FA for a single user
 *      can be reset from the VM console with wp-cli — documented in
 *      SUPPORT-RUNBOOK.md — because the console is the one entry point WASP
 *      keeps working when everything else is locked. That is a deliberate,
 *      audited override, not a bypass reachable from the network.
 *
 * HOW IT COMPOSES WITH THE REST OF THE LOGIN PATH
 *
 * WASP already has three things on this path: the custom login slug
 * (00-wpvm-login-slug), the SMTP transport (01), and the brute-force login guard
 * (02). This is 03 and is ordered AFTER them on purpose:
 *
 *   - The slug rewrite decides WHERE the login form lives; 2FA happens after the
 *     form is reached, so they do not interact.
 *   - The login guard runs on the `authenticate` filter and the wp_login_failed
 *     action, gating the FIRST factor (password). Two Factor runs its second
 *     factor AFTER a successful password on the `wp_login`/interim-login flow.
 *     They are sequential stages of the same login, not competitors for the same
 *     hook, so both apply cleanly: guard throttles password guessing, 2FA blocks
 *     a guessed-or-phished password from being enough.
 *   - The IP restriction is enforced at Apache, before PHP runs at all, so it is
 *     strictly outside this — a request that reaches here has already passed it.
 *
 * The one real interaction risk is REST and XML-RPC: a second factor on the
 * interactive login does nothing if an attacker can authenticate via an API that
 * bypasses it. WASP already disables XML-RPC. This additionally blocks
 * application-password and basic REST authentication for administrators unless
 * they have 2FA enrolled, so the enforcement cannot be walked around the side.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/*
 * Configuration, substituted at provisioning time. Kept as constants rather than
 * options so they cannot be changed from a compromised admin session — an
 * attacker who could set the grace window to 3650 days could defeat the whole
 * control.
 */
if ( ! defined( 'WPVM_MFA_ENFORCE' ) ) {
    // 1 = enforce for administrators, 0 = plugin present but enforcement off.
    define( 'WPVM_MFA_ENFORCE', WPVM_MFA_ENFORCE_PLACEHOLDER );
}
if ( ! defined( 'WPVM_MFA_GRACE_DAYS' ) ) {
    // Days a new/promoted admin has to enrol before they are blocked.
    define( 'WPVM_MFA_GRACE_DAYS', WPVM_MFA_GRACE_PLACEHOLDER );
}

/**
 * Is the Two Factor plugin actually present and providing its API?
 *
 * Everything here is a no-op if it is not — enforcing "you must use a plugin that
 * is not installed" would lock out every admin with no way to comply, which is
 * the exact failure this file exists to avoid. So absence disables enforcement
 * and surfaces an admin notice instead.
 */
function wpvm_mfa_available() {
    return class_exists( 'Two_Factor_Core' );
}

/**
 * Has this user enrolled at least one REAL second factor?
 *
 * "Real" excludes the email fallback deliberately for administrators: the email
 * account is usually also the password-reset channel, so email-as-2FA collapses
 * both factors into one inbox. TOTP, backup codes and WebAuthn all count.
 */
function wpvm_mfa_user_enrolled( $user_id ) {
    if ( ! wpvm_mfa_available() ) {
        return true; // cannot require what is not available
    }
    // AVAILABLE, not merely ENABLED. The plugin distinguishes a provider the
    // user ticked (enabled) from one they actually finished setting up
    // (available = enabled AND configured). This matters for lockout safety: a
    // user can enable TOTP and never scan the QR, leaving no secret. If we
    // counted that as enrolled we would stop nudging them and then block them at
    // their next fresh login with no factor that actually works. Requiring a
    // *configured* provider means "enrolled" means "can really pass 2FA".
    if ( method_exists( 'Two_Factor_Core', 'get_available_providers_for_user' ) ) {
        $providers = Two_Factor_Core::get_available_providers_for_user( $user_id );
        // Keyed by provider classname => instance; the keys are what we test.
        $providers = is_array( $providers ) ? array_keys( $providers ) : array();
    } else {
        // Defensive fallback for an unexpected plugin version.
        $providers = Two_Factor_Core::get_enabled_providers_for_user( $user_id );
        $providers = is_array( $providers ) ? $providers : array();
    }
    if ( empty( $providers ) ) {
        return false;
    }
    // Any configured provider other than plain email satisfies enforcement.
    // Email is excluded for admins because the inbox is usually also the
    // password-reset channel, which would collapse both factors into one.
    foreach ( $providers as $provider ) {
        if ( 'Two_Factor_Email' !== $provider ) {
            return true;
        }
    }
    // Only email is configured — for an admin that is not sufficient on its own.
    return false;
}

/**
 * Does this user fall under enforcement? Administrators (manage_options) do.
 */
function wpvm_mfa_user_in_scope( $user ) {
    if ( ! ( $user instanceof WP_User ) ) {
        return false;
    }
    return user_can( $user, 'manage_options' );
}

/**
 * When did this user's grace window start? First seen under enforcement anchors
 * it, so a pre-existing admin at rollout also gets a fair window rather than
 * being blocked the instant enforcement turns on.
 */
function wpvm_mfa_grace_expired( $user_id ) {
    $started = get_user_meta( $user_id, 'wpvm_mfa_grace_start', true );
    if ( empty( $started ) ) {
        $started = time();
        update_user_meta( $user_id, 'wpvm_mfa_grace_start', $started );
    }
    $deadline = (int) $started + ( WPVM_MFA_GRACE_DAYS * DAY_IN_SECONDS );
    return time() > $deadline;
}

/*
 * ── The wall ─────────────────────────────────────────────────────────────────
 *
 * Past the grace window an unenrolled administrator gets nothing: no session, no
 * wp-admin, no admin-ajax, no admin-post, no REST. That is a decision, not a side
 * effect. The grace window is when they enrol, and after it the recovery path is
 * the console (SUPPORT-RUNBOOK.md, "An admin hit the two-factor wall"), which
 * clears wpvm_mfa_grace_start and so gives that one account a fresh window.
 *
 * There is deliberately no list of pages that stay open. This used to allow
 * profile.php, user-edit.php, admin-ajax.php, admin-post.php and any request with
 * action=logout, so that someone past grace could finish enrolling. Reproduced
 * against real WordPress with only a stolen password: `plugins.php?action=logout`
 * rendered, user-edit.php promoted another account to administrator, and that
 * account then had a fresh grace window and the whole of wp-admin. Enrolment
 * did not even work there, because TOTP setup goes through the REST API, which is
 * closed below. A list that opened the door without serving its purpose is worse
 * than no list.
 */
function wpvm_mfa_is_walled( $user ) {
    if ( ! WPVM_MFA_ENFORCE || ! wpvm_mfa_available() ) {
        return false;
    }
    if ( ! wpvm_mfa_user_in_scope( $user ) || wpvm_mfa_user_enrolled( $user->ID ) ) {
        return false;
    }
    return wpvm_mfa_grace_expired( $user->ID );
}

function wpvm_mfa_wall_message() {
    return '<strong>Two-factor authentication is required.</strong> Administrator accounts '
        . 'on this site must have it set up, and the time allowed to do that has ended. '
        . 'Contact your support team: they can reopen the setup window for this account.';
}

/**
 * End every session this user has.
 *
 * wp_destroy_current_session() is no use here. It reads the token from $_COOKIE,
 * which is empty during a login, so it destroyed nothing and the cookies issued
 * moments earlier in the same response stayed valid. destroy_all() works from
 * the user, not the request.
 */
function wpvm_mfa_end_sessions( $user_id ) {
    WP_Session_Tokens::get_instance( $user_id )->destroy_all();
    wp_clear_auth_cookie();
}

/*
 * Refuse before a session exists, so there are no cookies to clean up.
 *
 * Priority 100 is after core's password check (20) and spam check (99). The
 * tempting hook, wp_authenticate_user, runs BEFORE the password is checked, so it
 * would tell anyone who typed an administrator's username that the account has
 * no second factor, and start that account's grace clock for them.
 */
add_filter( 'authenticate', function ( $user ) {
    if ( $user instanceof WP_User && wpvm_mfa_is_walled( $user ) ) {
        return new WP_Error( 'wpvm_mfa_required', wpvm_mfa_wall_message() );
    }
    return $user;
}, 100 );

/*
 * Sessions that already exist. An admin logged in when the window closed never
 * fires authenticate or wp_login again until their cookie expires, up to 14 days
 * later. Priority 0, so it runs before other plugins' admin_init work, and it
 * fires for admin-ajax.php and admin-post.php as well as every wp-admin screen.
 */
add_action( 'admin_init', function () {
    $user = wp_get_current_user();
    if ( ! $user || ! $user->ID || ! wpvm_mfa_is_walled( $user ) ) {
        return;
    }
    wpvm_mfa_end_sessions( $user->ID );
    wp_die(
        wp_kses_post( wpvm_mfa_wall_message() ),
        'Two-factor authentication required',
        array( 'response' => 403 )
    );
}, 0 );

/*
 * ── Login-moment enforcement, kept as a second layer ─────────────────────────
 *
 * The authenticate filter above is the control. This catches anything that logs
 * a user in without going through it, such as a single sign-on plugin calling
 * wp_set_auth_cookie() and firing wp_login itself. Within grace it sets the nudge.
 */
add_action( 'wp_login', function ( $user_login, $user ) {
    if ( ! WPVM_MFA_ENFORCE || ! wpvm_mfa_available() ) {
        return;
    }
    if ( ! wpvm_mfa_user_in_scope( $user ) || wpvm_mfa_user_enrolled( $user->ID ) ) {
        return;
    }
    if ( wpvm_mfa_grace_expired( $user->ID ) ) {
        wpvm_mfa_end_sessions( $user->ID );
        wp_die(
            wp_kses_post( wpvm_mfa_wall_message() ),
            'Two-factor authentication required',
            array( 'response' => 403 )
        );
    }
    // Within grace: set a transient so an admin notice nudges them.
    set_transient( 'wpvm_mfa_nudge_' . $user->ID, 1, HOUR_IN_SECONDS );
}, 20, 2 );

/*
 * Admin notice within the grace window: a persistent, dismissible reminder with
 * the days remaining, so enrolment is a prompt rather than a surprise wall.
 */
add_action( 'admin_notices', function () {
    if ( ! WPVM_MFA_ENFORCE ) {
        return;
    }
    $user = wp_get_current_user();
    if ( ! wpvm_mfa_user_in_scope( $user ) || wpvm_mfa_user_enrolled( $user->ID ) ) {
        return;
    }
    if ( ! wpvm_mfa_available() ) {
        echo '<div class="notice notice-error"><p><strong>Two-factor enforcement is on, but the Two Factor plugin is not active.</strong> Administrators cannot enrol until it is activated. Activate it under Plugins.</p></div>';
        return;
    }
    $started  = (int) get_user_meta( $user->ID, 'wpvm_mfa_grace_start', true );
    $deadline = $started + ( WPVM_MFA_GRACE_DAYS * DAY_IN_SECONDS );
    $days     = max( 0, (int) ceil( ( $deadline - time() ) / DAY_IN_SECONDS ) );
    $url      = esc_url( admin_url( 'profile.php#two-factor-options' ) );
    printf(
        '<div class="notice notice-warning"><p><strong>Set up two-factor authentication.</strong> This administrator account will be required to use it in %d day%s. <a href="%s">Set it up now</a> — you will need an authenticator app, and you should print the backup codes.</p></div>',
        (int) $days,
        1 === $days ? '' : 's',
        $url
    );
} );

/*
 * ── Close the API side doors ─────────────────────────────────────────────────
 *
 * A second factor on the browser login is meaningless if an administrator can
 * authenticate through an API that skips it. XML-RPC is already disabled by
 * WASP. Here we refuse REST authentication and application-password auth for an
 * in-scope admin who has not enrolled — so the enforcement cannot be sidestepped
 * by switching channels. A non-admin, or an enrolled admin, is unaffected.
 */
add_filter( 'rest_authentication_errors', function ( $result ) {
    if ( ! WPVM_MFA_ENFORCE || ! wpvm_mfa_available() ) {
        return $result;
    }
    // Defer ONLY to a prior ERROR, never to a prior ALLOW. WordPress core's
    // convention for this filter is that null = no opinion and true = "already
    // authenticated, allow it". If we treated a prior `true` as "someone decided,
    // stop here" we would skip enforcement exactly when another handler had
    // authenticated an unenrolled admin — the opposite of what we want. So we
    // pass an existing WP_Error straight through (do not override another
    // control's denial) but we do NOT stop on a prior allow.
    if ( is_wp_error( $result ) ) {
        return $result;
    }
    $user = wp_get_current_user();
    if ( $user && $user->ID && wpvm_mfa_user_in_scope( $user )
         && ! wpvm_mfa_user_enrolled( $user->ID )
         && wpvm_mfa_grace_expired( $user->ID ) ) {
        return new WP_Error(
            'wpvm_mfa_required',
            'Two-factor authentication must be enabled on this administrator account before using the REST API.',
            array( 'status' => 403 )
        );
    }
    return $result;
} );

/*
 * Application passwords are a REST-auth bypass by design (they exist to skip
 * interactive login for automation). For an unenrolled in-scope admin past
 * grace, refuse to let them be USED for authentication — issuance is separately
 * a profile action, but an un-2FA'd admin should not have a working app password
 * standing in for the second factor.
 */
add_filter( 'wp_is_application_passwords_available_for_user', function ( $available, $user ) {
    if ( ! WPVM_MFA_ENFORCE || ! wpvm_mfa_available() ) {
        return $available;
    }
    if ( wpvm_mfa_user_in_scope( $user )
         && ! wpvm_mfa_user_enrolled( $user->ID )
         && wpvm_mfa_grace_expired( $user->ID ) ) {
        return false;
    }
    return $available;
}, 10, 2 );
