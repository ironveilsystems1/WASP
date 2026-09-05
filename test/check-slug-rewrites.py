#!/usr/bin/env python3
"""
check-slug-rewrites.py — the two slug-rewrite generators must agree.

WHY THIS EXISTS

The custom login slug is generated in TWO places, because it lands in two
files:

    lib/03-dynamic-configs.sh          -> wp-security.conf (Apache config)
    payload/stages/04-apache-hardening -> .htaccess

They drifted, and the result was a site nobody could log into. On a live VM:

    lib/03    :  ^<slug>/?$  ->  /wp-login.php
    stage 04  :  ^<slug>/?$  ->  /wp-admin/index.php     <-- disagreed

Whichever ruleset won, a request to /<slug> reached wp-admin unauthenticated;
WordPress redirected to the login page; the login-slug mu-plugin rewrote that
URL back to /<slug>; the browser looped until it gave up with "The page isn't
redirecting properly". Nothing failed, nothing logged an error, and the
installer cheerfully printed the login URL. The only symptom was a browser that
would not settle.

Worse, stage 04 also carried a rule for `^<slug>-login`, a suffix the mu-plugin
had stopped using — a dead rule that made the block LOOK like it handled the
login entry point when the live rule sent it somewhere else entirely.

WHAT IT CHECKS

1. Both generators map the bare slug to the SAME target.
2. Both map the sub-path the same way.
3. Neither still references the removed `-login` suffix.

The right long-term fix is one generator feeding both files. Until that
refactor happens, this check makes the duplication safe by making divergence
loud.
"""

import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONF_GEN = os.path.join(REPO, "lib", "03-dynamic-configs.sh")
HTACCESS_GEN = os.path.join(REPO, "payload", "stages", "04-apache-hardening.sh")

# RewriteRule ^${WP_ADMIN_SLUG}<rest>$ <target> [flags]
RULE_RE = re.compile(
    r"RewriteRule\s+\^\$\{WP_ADMIN_SLUG\}(?P<pat>[^\s]*?)\\?\$\s+(?P<target>\S+)"
)


def rules_in(path):
    """Map of slug-pattern -> rewrite target, normalised for comparison."""
    out = {}
    if not os.path.exists(path):
        return out
    for m in RULE_RE.finditer(open(path, encoding="utf-8", errors="replace").read()):
        pat = m.group("pat").replace("\\", "")
        target = m.group("target").replace("\\", "")
        out[pat] = target
    return out


def scan(conf_rules, ht_rules):
    problems = []

    # 1 + 2: every pattern present in both must map to the same target.
    for pat in sorted(set(conf_rules) | set(ht_rules)):
        a = conf_rules.get(pat)
        b = ht_rules.get(pat)
        if a and b and a != b:
            shown = pat if pat else "(bare slug)"
            problems.append(
                f"slug pattern '{shown}' maps to '{a}' in the Apache config but "
                f"'{b}' in .htaccess — a request will loop or land on the wrong page"
            )

    # 3: the removed suffix must not reappear in either generator.
    for label, rules in (("Apache config", conf_rules), (".htaccess", ht_rules)):
        for pat in rules:
            if "-login" in pat:
                problems.append(
                    f"{label} still has a '<slug>-login' rule. That suffix was "
                    f"removed from the mu-plugin, so the rule is dead and "
                    f"misleading — the real entry point is the bare slug"
                )
    return problems


def self_test():
    # Divergence must be caught.
    bad = scan({"": "/wp-login.php"}, {"": "/wp-admin/index.php"})
    assert bad and "loop" in bad[0], "self-test: divergent targets not detected"

    # Agreement must pass.
    good = scan(
        {"": "/wp-login.php", "/(.+)": "/wp-admin/$1"},
        {"": "/wp-login.php", "/(.+)": "/wp-admin/$1"},
    )
    assert not good, f"self-test: agreeing rules flagged: {good}"

    # The dead suffix must be caught.
    dead = scan({"": "/wp-login.php"}, {"": "/wp-login.php", "-login": "/wp-login.php"})
    assert dead and "-login" in dead[0], "self-test: dead -login rule not detected"

    # A rule present in only one file is not, by itself, a mismatch.
    partial = scan({"": "/wp-login.php", "/(.+)": "/wp-admin/$1"}, {"": "/wp-login.php"})
    assert not partial, "self-test: a one-sided rule was wrongly flagged"
    return True


def check_single_source():
    """Both consumers must READ the shared template, not carry a copy.

    The rules now live in payload/templates/slug-rewrite.rules and both
    generators sed the slug into it. This check changed shape with that: it
    used to compare two hand-maintained copies for agreement, which was the
    best available guarantee while they were separate. Verifying they both read
    one file is stronger -- there is nothing left to diverge.
    """
    problems = []
    tmpl = os.path.join(REPO, "payload", "templates", "slug-rewrite.rules")
    if not os.path.exists(tmpl):
        return ["payload/templates/slug-rewrite.rules is missing — "
                "both generators depend on it"]
    body = open(tmpl, encoding="utf-8", errors="replace").read()
    if "@@SLUG@@" not in body:
        problems.append("the template has no @@SLUG@@ placeholder to substitute")
    if "/wp-login.php" not in body:
        problems.append("the template does not route the bare slug to "
                        "/wp-login.php — that is the redirect loop again")
    for f in ("lib/03-dynamic-configs.sh",
              "payload/stages/04-apache-hardening.sh"):
        p = os.path.join(REPO, f)
        if not os.path.exists(p):
            continue
        t = open(p, encoding="utf-8", errors="replace").read()
        if "slug-rewrite.rules" not in t:
            problems.append(f"{f} does not read the shared template — "
                            f"it is carrying its own copy again")
        # A literal RewriteRule for the slug means a copy has crept back.
        if re.search(r'RewriteRule\s+\^\$\{WP_ADMIN_SLUG\}', t):
            problems.append(f"{f} contains a hand-written slug RewriteRule; "
                            f"the template is the single source of truth")
    return problems


def main():
    self_test()
    single = check_single_source()
    if single:
        print(f"FOUND {len(single)} single-source problem(s):")
        for p in single:
            print(f"  {p}")
        print()
        print("  Two copies of these rules drifted once and produced a login")
        print("  redirect loop that no individual check could see.")
        return 1

    conf_rules = rules_in(CONF_GEN)
    ht_rules = rules_in(HTACCESS_GEN)

    if not conf_rules and not ht_rules:
        # This is now the EXPECTED state: neither generator carries literal
        # rules any more, because both read the shared template. The
        # single-source check above has already verified that, so an absence
        # of inline rules is success rather than a reason to skip.
        print("Slug rewrites: CLEAN — single source of truth, no inline copies")
        return 0

    problems = scan(conf_rules, ht_rules)
    if problems:
        print(f"FOUND {len(problems)} slug-rewrite problem(s):")
        for p in problems:
            print(f"  {p}")
        print()
        print("  A slug mismatch produces a redirect loop, not an error. The")
        print("  install reports success and the login page never settles.")
        return 1

    shared = len(set(conf_rules) & set(ht_rules))
    print(f"Slug rewrites: CLEAN — {shared} shared rule(s), both generators agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
