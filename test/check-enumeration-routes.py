#!/usr/bin/env python3
"""
check-enumeration-routes.py — are all five username-disclosure routes closed,
and does the generated proxy config keep the public front end working?

WHY THIS EXISTS
---------------

On 2026-10-25 a credential attack hit a live client site using a randomly
generated ten-character administrator login. The username had not come from
the prior compromise of that client's old host, which was the first theory.
WASP published it.

06-wasp-username-privacy.php closed the three enumeration routes that security
guidance names — the REST user listing, ?author=N, and the login error oracle
— and stated in a comment that oEmbed "exposes the display name rather than
the login name". That was never tested and was wrong: oEmbed returns
author_url, which is built from user_nicename, and user_nicename defaults to
user_login. The users sitemap, which WordPress has generated and submitted to
search engines by default since 5.5, was not considered at all.

So the control read as present, three of five doors were shut, and the
administrator login name sat in a crawlable indexed file for the life of the
install.

The test below is deliberately shaped around that failure: it asserts every
route individually, including the two that were missed, so closing most of
them can never again read as closing them.

It also covers a second defect found the same day. `wp-hardening.sh
nginx-snippet` emitted a single regex location matching ^/(wp-admin/|...),
which matches /wp-admin/admin-ajax.php — the endpoint the PUBLIC front end
calls for Elementor, contact forms and most interactive plugins. Applied as
generated, it would IP-restrict the site's front end while every admin page
kept working, so the breakage points nowhere near its cause.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MU = ROOT / "payload" / "mu-plugins" / "06-wasp-username-privacy.php"
HARDENING = ROOT / "payload" / "bin" / "wp-hardening.sh"

passed = 0
failed = 0


def check(name, condition, why):
    global passed, failed
    if condition:
        print(f"  [PASS] {name}")
        passed += 1
    else:
        print(f"  [FAIL] {name}")
        print(f"         {why}")
        failed += 1


def main():
    mu = MU.read_text(encoding="utf-8")
    hard = HARDENING.read_text(encoding="utf-8")

    print("\n── Username disclosure: all five routes")

    check(
        "route 1 — the REST user listing is gated",
        "rest_endpoints" in mu and "list_users" in mu,
        "/wp-json/wp/v2/users returns every author's slug to anyone.",
    )
    check(
        "route 2 — ?author=N does not redirect to the login name",
        "parse_request" in mu and "is_numeric" in mu,
        "A single request over a range of IDs maps the whole user table.",
    )
    check(
        "route 3 — the login form does not confirm a valid username",
        "login_errors" in mu and "invalid_username" in mu,
        "'Unknown username' vs 'incorrect password' confirms a guess in one "
        "request, before any rate limit is involved.",
    )
    check(
        "route 4 — the users sitemap provider is dropped",
        "wp_sitemaps_add_provider" in mu,
        "Core publishes /wp-sitemap-users-1.xml by default and pings search "
        "engines with it. With the default nicename that file is a "
        "machine-readable roster of valid logins. THIS IS THE ROUTE THAT WAS "
        "USED against a live client site.",
    )
    check(
        "route 5 — oEmbed carries no author identity",
        "oembed_response_data" in mu,
        "/wp-json/oembed/1.0/embed answers unauthenticated and returns "
        "author_url, built from user_nicename. It is the standard way around "
        "a restricted REST user listing, so route 1 being perfect does not "
        "cover this.",
    )

    print("\n── The control the routes lean on")

    check(
        "new users get a nicename unrelated to their login",
        "user_register" in mu and "user_nicename" in mu,
        "Every public surface prints user_nicename, which defaults to "
        "user_login. Blocking surfaces one at a time loses to the next plugin "
        "that adds one; decoupling the slug closes all of them at once.",
    )
    check(
        "imported users are migrated too",
        "wpvm_nicename_migrated" in mu,
        "A dump from another host brings its own users table and the "
        "user_register hook never fires for those rows — which is exactly how "
        "a site passes every other check here and still publishes a login "
        "name.",
    )
    check(
        "the generated slug is not derived from the account",
        "wp_generate_password" in mu,
        "A slug built from the login, display name or email leaks what it was "
        "derived from, which is the bug being fixed.",
    )
    check(
        "the migration does not run on front-end requests",
        "wp_doing_cron" in mu and "is_admin" in mu,
        "It reads the whole users table; a visitor should not pay for it.",
    )

    print("\n── Generated proxy config keeps the front end working")

    # The exact-match location must be emitted. '=' outranks a regex location
    # whatever the file order, which is what keeps this one path open without
    # widening the admin restriction.
    check(
        "nginx-snippet emits an exact-match admin-ajax location",
        re.search(r"location = /wp-admin/admin-ajax\.php", hard) is not None,
        "The admin regex location matches /wp-admin/admin-ajax.php, which the "
        "PUBLIC front end calls (Elementor, contact forms). Without an exact "
        "match to outrank it, applying the generated config IP-restricts the "
        "site for ordinary visitors while every admin page keeps working.",
    )
    # .find(), not .index(): a missing string must report as a failed check,
    # not raise and abandon every assertion after it. Found by running this
    # file against the unfixed source, which is the only way that gets found.
    _ajax_at = hard.find("location = /wp-admin/admin-ajax.php")
    _regex_at = hard.find("location ~* ^/(wp-admin/")
    check(
        "admin-ajax is emitted before the admin regex location",
        _ajax_at != -1 and _regex_at != -1 and _ajax_at < _regex_at,
        "Order does not change nginx's matching, but a reader checking this "
        "config should meet the exception before the rule it excepts.",
    )
    check(
        "nginx-snippet denies xmlrpc.php",
        "location = /xmlrpc.php { deny all; }" in hard,
        "xmlrpc.php supports system.multicall, which tests hundreds of "
        "passwords per request. The live attack used POST //xmlrpc.php.",
    )
    check(
        "nginx-snippet blocks executable uploads",
        "wp-content/uploads" in hard and "phtml" in hard,
        "The web shell found in a client import sat in wp-content/uploads for "
        "two years behind a plugin directory name.",
    )
    check(
        "nginx-snippet denies the version-disclosing files",
        "readme" in hard and "license.txt" in hard,
        "readme.html and license.txt publish the exact core version, which is "
        "the first thing a scanner reads to choose an exploit.",
    )
    check(
        "nginx-snippet keeps .well-known reachable",
        "/.well-known/" in hard,
        "The dotfile deny rule would otherwise block ACME challenges, and a "
        "blocked challenge means certificate renewal fails silently, weeks "
        "later, with nothing connecting it to this config.",
    )
    check(
        "no placeholder slug leaks into customer-facing output",
        "/boob" not in hard,
        "This string was being printed in the config WASP hands an operator "
        "to paste into their reverse proxy.",
    )

    print(f"\n  passed {passed}   failed {failed}\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
