#!/usr/bin/env python3
"""
check-trusted-proxy.py — the TRUST-COUNT contract.

WHY THIS EXISTS

`RemoteIPTrustedProxy` must name exactly ONE literal address.

mod_remoteip walks `X-Forwarded-For` from the RIGHT, popping entries for as
long as they match a trusted proxy, and takes the first address it does not
trust as the client. Name a range instead of one address and every host inside
that range can prepend whatever client address it likes and have Apache accept
it as genuine.

That forged address is not cosmetic. It is:

  * the address CrowdSec parses out of the access log and bans,
  * the address the wp-admin `Require ip` restriction is evaluated against,
  * the address the login guard counts failed attempts against, and
  * the address the contact-form rate limit keys on.

So a widened trusted-proxy declaration turns one compromised neighbour on the
same segment into an authentication bypass, a way to get any chosen third party
banned, and a way to never be rate-limited.

The same reasoning rules out `RemoteIPInternalProxy`, which the upstream
WordPress image ships pre-populated with every RFC1918 range in
`/etc/apache2/conf-enabled/remoteip.conf` — this install disables that file for
exactly this reason, and a re-enable would undo the whole contract quietly.

This is enforced at three points: install.sh's contract preflight (before
anything is built), and again in lib/03 and lib/06 where the directive is
actually written. This check is the fourth: it stops the constraint being
loosened in the source tree, which is the one failure the runtime assertions
cannot catch — they would faithfully assert whatever weaker rule replaced them.

WHAT IT CHECKS

1. Every `RemoteIPTrustedProxy` emitted anywhere in the tree substitutes a
   single variable and nothing else — no CIDR literal, no second value.
2. `RemoteIPInternalProxy` is never emitted.
3. Both of the places that write the directive guard their input first, so
   neither path can write a range.
4. The installer's preflight still refuses a CIDR.

Documentation and comments are exempt: explaining the rule requires writing
down the wrong form next to the right one, and a check that cannot tell those
apart would force the explanation out of the docs.
"""

import glob
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Files that WRITE the directive and must therefore guard their input.
WRITERS = ["lib/03-dynamic-configs.sh", "lib/06-vars-and-payload-inject.sh"]

# A guard is any of these shapes rejecting a slash, a comma or whitespace in
# the value. Matched loosely on purpose: the point is that a guard exists and
# names the right characters, not that it is spelled one particular way.
GUARD = re.compile(r"\*/\*\|\*,\*\|\*\[\[:space:\]\]\*|\[/,\[:space:\]\]")

TRUSTED = re.compile(r"^\s*RemoteIPTrustedProxy\s+(.+?)\s*$")
INTERNAL = re.compile(r"^\s*RemoteIPInternalProxy\s+\S")

# One variable reference, alone: ${PROXY_IP} or $PROXY_IP.
SINGLE_VAR = re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*\}$|^\$[A-Za-z_][A-Za-z0-9_]*$")

CODE_EXT = (".sh", ".conf", ".tmpl", ".yaml", ".php")


def is_comment(line):
    return line.lstrip().startswith("#")


def scan_text(text):
    """Return a list of (lineno, kind, detail) problems for one file's text."""
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        if is_comment(line):
            continue
        m = TRUSTED.match(line)
        if m:
            value = m.group(1)
            if not SINGLE_VAR.match(value):
                out.append((n, "literal-or-multi", value))
        if INTERNAL.match(line):
            out.append((n, "internal-proxy", line.strip()))
    return out


def self_test():
    assert scan_text("RemoteIPTrustedProxy 10.20.10.0/24\n"), \
        "self-test: a CIDR literal was not flagged"
    assert scan_text("RemoteIPTrustedProxy ${PROXY_IP} ${OTHER}\n"), \
        "self-test: two values were not flagged"
    assert scan_text("RemoteIPInternalProxy 10.0.0.0/8\n"), \
        "self-test: RemoteIPInternalProxy was not flagged"
    assert not scan_text("RemoteIPTrustedProxy ${PROXY_IP}\n"), \
        "self-test: the correct form was flagged"
    assert not scan_text("# RemoteIPTrustedProxy 10.0.0.0/8 would be wrong\n"), \
        "self-test: a comment was flagged"
    return True


def main():
    self_test()
    problems = []

    files = []
    for ext in CODE_EXT:
        files += glob.glob(os.path.join(REPO, "**", "*" + ext), recursive=True)
    files = sorted(set(files))

    emitters = 0
    for path in files:
        rel = os.path.relpath(path, REPO)
        text = open(path, encoding="utf-8", errors="replace").read()
        if "RemoteIPTrustedProxy" in text:
            emitters += 1
        for n, kind, detail in scan_text(text):
            if kind == "literal-or-multi":
                problems.append(
                    f"{rel}:{n}: RemoteIPTrustedProxy takes ONE variable; found '{detail}'"
                )
            else:
                problems.append(
                    f"{rel}:{n}: RemoteIPInternalProxy must never be emitted — "
                    f"it widens XFF trust to whole ranges"
                )

    # Each writer guards its input before writing.
    for rel in WRITERS:
        path = os.path.join(REPO, rel)
        if not os.path.exists(path):
            problems.append(f"{rel}: expected to exist and write RemoteIPTrustedProxy")
            continue
        text = open(path, encoding="utf-8", errors="replace").read()
        if "RemoteIPTrustedProxy" not in text:
            continue
        if not GUARD.search(text):
            problems.append(
                f"{rel}: writes RemoteIPTrustedProxy with no guard rejecting a "
                f"range or list in PROXY_IP"
            )

    # The installer's own preflight.
    inst = os.path.join(REPO, "install.sh")
    itext = open(inst, encoding="utf-8", errors="replace").read()
    if "WASP_PROXY_IP" in itext and not GUARD.search(itext):
        problems.append(
            "install.sh: accepts WASP_PROXY_IP but its contract preflight no "
            "longer rejects a range or list"
        )

    if problems:
        print(f"FOUND {len(problems)} trusted-proxy problem(s):")
        for p in problems:
            print(f"  {p}")
        print()
        print("  TRUST-COUNT: RemoteIPTrustedProxy must be a single literal")
        print("  address. mod_remoteip pops trusted entries off the right of")
        print("  X-Forwarded-For, so a range lets any host inside it forge the")
        print("  client IP — the address CrowdSec bans, wp-admin allows, and")
        print("  the login guard counts against.")
        return 1

    print(f"Trusted proxy: CLEAN — {emitters} file(s) emit RemoteIPTrustedProxy, "
          f"single-literal contract held at every write site")
    return 0


if __name__ == "__main__":
    sys.exit(main())
