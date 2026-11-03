#!/usr/bin/env python3
"""
check-version-claims.py — documented versions must match the shipped ones.

WHY THIS EXISTS

An external evaluation found README.md advertising
`wordpress:6.9.4-php8.3-apache` while the installer pinned 7.0.3 -- three
security releases apart, including a login-page XSS and an Author+ RCE. The
version was corrected in code each time and the documentation was not.

That is worse than an out-of-date number. A reader deciding whether this
platform is current reads the README, not install-wordpress.sh. Stating a
version that is neither the implemented default nor a supported release makes
the whole document untrustworthy, and it is invisible to every other check here:
the markdown is valid and the code is correct.
"""

import glob
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The authoritative value, read from the code that actually pins it.
def shipped_wp():
    p = os.path.join(REPO, "payload", "install-wordpress.sh")
    if not os.path.exists(p):
        return None
    m = re.search(r'WP_IMAGE="docker\.io/wordpress:([^"]+)"',
                  open(p, encoding="utf-8", errors="replace").read())
    return m.group(1) if m else None


TAG_RE = re.compile(r"\b(\d+\.\d+(?:\.\d+)?-php\d+\.\d+-apache)\b")


def scan(shipped):
    problems = []
    docs = (glob.glob(os.path.join(REPO, "*.md"))
            + glob.glob(os.path.join(REPO, "docs", "*.md")))
    for path in docs:
        name = os.path.relpath(path, REPO)
        # The changelog is append-only history; old entries SHOULD name old
        # versions, and rewriting them would falsify the record.
        if name == "CHANGELOG.md":
            continue
        text = open(path, encoding="utf-8", errors="replace").read()
        for tag in set(TAG_RE.findall(text)):
            if tag != shipped:
                problems.append((name, tag))
    return problems


def installer_versions(text):
    """(WASP_RELEASE, WASP_VERSION) as install.sh assigns them."""
    rel = re.search(r'^WASP_RELEASE="([^"]*)"', text, re.M)
    ver = re.search(r'^WASP_VERSION="([^"]*)"', text, re.M)
    return (rel.group(1) if rel else None, ver.group(1) if ver else None)


def self_test():
    assert scan("9.9.9-php9.9-apache"), "self-test: mismatch not detected"
    r, v = installer_versions('WASP_RELEASE="1.0"\nWASP_VERSION="1.1"\n')
    assert r != v, "self-test: version split not detected"
    r, v = installer_versions('WASP_RELEASE="1.1"\nWASP_VERSION="1.1"\n')
    assert r == v, "self-test: matching versions misread"
    return True


def main():
    shipped = shipped_wp()
    if not shipped:
        print("check-version-claims: could not read the shipped tag — skipping")
        return 0
    self_test()
    # There is one version. 10.5 shipped WASP_VERSION=10.5 beside
    # WASP_RELEASE=10.4, and the signing tool reads WASP_RELEASE, so the
    # release's signed trusted comment would have named the wrong build.
    rel, ver = installer_versions(
        open(os.path.join(REPO, "install.sh"), encoding="utf-8", errors="replace").read())
    if not rel or rel != ver:
        print(f"WASP_RELEASE ({rel}) and WASP_VERSION ({ver}) disagree in install.sh.")
        print("  The signing tool reads one and the VM records the other.")
        return 1
    problems = scan(shipped)
    if problems:
        print(f"FOUND {len(problems)} stale version claim(s). Shipped: {shipped}")
        for name, tag in sorted(set(problems)):
            print(f"  {name}: states {tag}")
        print()
        print("  A reader judging whether this platform is current reads the")
        print("  docs, not the installer. Update them together.")
        return 1
    print(f"Version claims: CLEAN — docs agree with the shipped tag ({shipped})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
