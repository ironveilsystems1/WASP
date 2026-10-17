<?php
/**
 * Plugin Name:  WASP Contact Handler
 * Description:  Receives a contact form POST and emails it through the site's
 *               own relay. No third-party service, no stored submissions.
 * Version:      1.0
 *
 * =========================================================================
 * WHY THIS EXISTS
 * =========================================================================
 *
 * Every WordPress site needs a contact form, and the usual answer is a plugin
 * — Contact Form 7, WPForms, Gravity Forms. Each is tens of thousands of lines
 * of code, an admin UI, a database table of submissions, and a supply-chain
 * dependency, to accomplish "take three fields and email them".
 *
 * Contact form plugins are also disproportionately represented in WordPress
 * vulnerability disclosures, because they accept unauthenticated input by
 * definition and are installed on millions of sites.
 *
 * This is the same job in ninety lines, using wp_mail() and therefore whatever
 * relay the VM already has configured. It has no admin screen, stores nothing,
 * and cannot be deactivated from wp-admin because it is a mu-plugin.
 *
 * =========================================================================
 * THE ONE RULE THAT MAKES THIS SAFE
 * =========================================================================
 *
 * THE RECIPIENT IS DECIDED SERVER-SIDE AND NEVER READ FROM THE REQUEST.
 *
 * A handler that emails whatever address the form supplies is an open relay:
 * anyone can POST to it and have your server send mail to anybody, with your
 * domain's reputation attached. That is how a contact form becomes a spam
 * cannon and a domain ends up on a blocklist.
 *
 * The recipient here is get_option('admin_email'), overridable only by a
 * constant in wp-config.php or a PHP filter — both of which require access to
 * the server. Nothing in $_POST can change where mail goes.
 *
 * =========================================================================
 * USING IT WITH ANY FORM
 * =========================================================================
 *
 * Your form needs three things:
 *
 *   1. action="/wp-admin/admin-post.php"  and  method="post"
 *   2. <input type="hidden" name="action" value="wasp_contact">
 *   3. A honeypot field named "website", visually hidden
 *
 * Field names default to name / email / message. To use different ones — a
 * form you did not write, or a translated theme — filter them:
 *
 *   add_filter('wasp_contact_fields', function ($f) {
 *       return array('name' => 'your_name',
 *                    'email' => 'your_email',
 *                    'message' => 'enquiry');
 *   });
 *
 * Any additional fields are included in the email automatically, so a form
 * with "company" or "budget" needs no code change at all.
 *
 * To send somewhere other than the admin address, in wp-config.php:
 *
 *   define('WASP_CONTACT_TO', 'sales@example.com');
 *
 * =========================================================================
 * WHAT THIS DELIBERATELY DOES NOT DO
 * =========================================================================
 *
 * NO CSRF NONCE. A nonce must be generated in PHP when the form renders, and
 * these forms frequently live in page-builder HTML modules that do not execute
 * PHP. The realistic threat to a contact form is spam, not forgery — an
 * attacker gains nothing by causing you to email yourself. The honeypot and
 * rate limit are the proportionate controls.
 *
 * If your form IS rendered by PHP, add wp_nonce_field('wasp_contact') to it and
 * this handler will verify it. It checks for a nonce and requires one when
 * present, so adding it strengthens the form without any change here.
 *
 * NO STORAGE. Submissions are emailed, never written to the database. Nothing
 * to breach, nothing to export under a subject access request, no admin screen
 * to secure. Your mailbox is the record.
 *
 * NO FILE UPLOADS. An unauthenticated upload endpoint is a materially
 * different risk from an unauthenticated text endpoint, and is not worth it
 * for a contact form.
 */

if (!defined('ABSPATH')) { exit; }

add_action('admin_post_nopriv_wasp_contact', 'wasp_contact_handle');
add_action('admin_post_wasp_contact',        'wasp_contact_handle');

function wasp_contact_handle() {

    $back = apply_filters('wasp_contact_redirect', home_url('/'));

    // ── Honeypot ────────────────────────────────────────────────────────────
    // Bots fill every field they find; a person never sees this one. Redirect
    // as though it succeeded rather than erroring — telling a bot it was
    // caught only teaches whoever wrote it to skip the field next time.
    if (!empty($_POST['website'])) {
        wp_safe_redirect($back . '?sent=1');
        exit;
    }

    // ── Nonce, if the form supplied one ─────────────────────────────────────
    // Optional by design: a form in a page-builder HTML module cannot generate
    // one. But if it IS present it must be valid, so a PHP-rendered form gets
    // full CSRF protection without any change here.
    if (isset($_POST['_wpnonce'])
        && !wp_verify_nonce($_POST['_wpnonce'], 'wasp_contact')) {
        wp_safe_redirect($back . '?sent=invalid');
        exit;
    }

    // ── Rate limit ──────────────────────────────────────────────────────────
    // Courtesy to your own inbox more than security: without it, one script
    // fills it in an afternoon. Five minutes stops a loop and does not lock out
    // someone correcting a typo.
    //
    // Keyed on REMOTE_ADDR, which behind a reverse proxy is only the real
    // client if mod_remoteip is working. On a WASP VM it is — see
    // `wp-hardening.sh proxy-check` — but on a misconfigured proxy every
    // visitor shares one bucket and one submission blocks everyone for five
    // minutes. That is the failure this note exists to make findable.
    $ip  = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
    $key = 'waspc_' . md5($ip);
    if (get_transient($key)) {
        wp_safe_redirect($back . '?sent=slow');
        exit;
    }
    set_transient($key, 1, 5 * MINUTE_IN_SECONDS);

    // ── Fields ──────────────────────────────────────────────────────────────
    $map = apply_filters('wasp_contact_fields', array(
        'name'    => 'name',
        'email'   => 'email',
        'message' => 'message',
    ));

    $name    = isset($_POST[$map['name']])    ? sanitize_text_field(wp_unslash($_POST[$map['name']]))       : '';
    $email   = isset($_POST[$map['email']])   ? sanitize_email(wp_unslash($_POST[$map['email']]))           : '';
    $message = isset($_POST[$map['message']]) ? sanitize_textarea_field(wp_unslash($_POST[$map['message']])) : '';

    if ($name === '' || !is_email($email) || $message === '') {
        wp_safe_redirect($back . '?sent=invalid');
        exit;
    }

    // ── Recipient: SERVER-SIDE ONLY. Never from the request. ────────────────
    $to = defined('WASP_CONTACT_TO') ? WASP_CONTACT_TO : get_option('admin_email');
    $to = apply_filters('wasp_contact_to', $to);
    if (!is_email($to)) {
        error_log('[wasp-contact] no valid recipient configured — not sending');
        wp_safe_redirect($back . '?sent=error');
        exit;
    }

    $host    = wp_parse_url(home_url(), PHP_URL_HOST);
    $subject = sprintf('[%s] Enquiry from %s', $host, $name);

    $body  = "Name:    {$name}\n";
    $body .= "Email:   {$email}\n";
    $body .= "Address: {$ip}\n";
    $body .= "Time:    " . gmdate('Y-m-d H:i:s') . " UTC\n";

    // Any field the form sent that is not one of the three known ones. This is
    // what lets the handler work with a form it has never seen — add "company"
    // or "budget" to the markup and it appears here with no code change.
    $known = array_merge(array_values($map), array('action', 'website', '_wpnonce', '_wp_http_referer'));
    $extra = '';
    foreach ($_POST as $k => $v) {
        if (in_array($k, $known, true) || !is_string($v) || $v === '') { continue; }
        $extra .= sprintf("%-8s %s\n", sanitize_key($k) . ':', sanitize_textarea_field(wp_unslash($v)));
    }
    if ($extra !== '') { $body .= $extra; }

    $body .= "\n{$message}\n";

    // Reply-To, NOT From. Setting From to the visitor's address makes the
    // message fail SPF at the receiving end and land in spam — the relay is
    // authorised to send as your domain, not as theirs. Reply still goes to
    // the visitor when you hit reply.
    $headers = array('Reply-To: ' . $name . ' <' . $email . '>');

    $ok = wp_mail($to, $subject, $body, $headers);

    // Log both outcomes. A contact form that quietly stops delivering is the
    // kind of failure nobody notices for a month, and the ABSENCE of these
    // lines is itself the signal. CrowdSec reads this log on a WASP VM.
    error_log(sprintf('[wasp-contact] %s to=%s from=%s ip=%s',
        $ok ? 'sent' : 'FAILED', $to, $email, $ip));

    wp_safe_redirect($back . ($ok ? '?sent=1' : '?sent=error'));
    exit;
}
