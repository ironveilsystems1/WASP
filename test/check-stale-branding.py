#!/usr/bin/env python3
"""
check-stale-branding.py — no superseded org or domain may reach a user.

WHY THIS EXISTS

The repository moved to the IronVeil Systems organisation. A first pass
replaced two exact strings and looked complete. It was not: fifteen files still
carried the old name, including install.sh's fallback owner — so a standalone
install printed

    fetching RothITguy-jitsi/alpine-vm-wordpress@main...

and fetched from an org the project had left. The DNS record for release
signing was stale in the same way, which fails closed under production and
gives an operator nothing to work from.

Cosmetic references are untidy. A stale owner in a download path or a stale DNS
name in a signature check is a functional defect that only shows at install
time, on someone else's machine.

WHAT IT CHECKS

Any superseded identifier anywhere in the tree. CHANGELOG.md is exempt: it is
append-only history, and rewriting it would falsify the record of what was
true when each entry was written.
"""

import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Substring, and why it must not appear.
STALE = {
    "rothitguy":              "superseded organisation / domain",
    "RothITguy-jitsi":        "superseded GitHub owner",
    "alpine-vm-wordpress":    "superseded repository name",
    "_wasp.rothitguy":        "superseded signing DNS record",
}

EXEMPT_FILES = {"CHANGELOG.md"}

# Lines that legitimately NAME the old identifier in order to explain the move.
# Documenting "it was previously X" is the opposite of a stale reference — it
# tells a reader with an old clone what happened. Matched as substrings so the
# surrounding prose can be edited without breaking the exemption.
EXEMPT_CONTEXT = (
    "was previously",
    "superseded",
    "redirects the old",
    "renamed from",
)
SKIP_DIRS = {".git", "node_modules", "__pycache__"}


def main():
    problems = []
    for root, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in files:
            if fn in EXEMPT_FILES or fn == os.path.basename(__file__):
                continue
            path = os.path.join(root, fn)
            try:
                text = open(path, encoding="utf-8", errors="replace").read()
            except (OSError, UnicodeDecodeError):
                continue
            for n, line in enumerate(text.split("\n"), 1):
                low = line.lower()
                # A line that explains the move is documentation, not drift.
                if any(c in low for c in EXEMPT_CONTEXT):
                    continue
                for needle, why in STALE.items():
                    if needle.lower() in low:
                        problems.append(
                            f"{os.path.relpath(path, REPO)}:{n}: '{needle}' — {why}")
                        break

    if problems:
        print(f"FOUND {len(problems)} stale branding reference(s):")
        for p in sorted(set(problems)):
            print(f"  {p}")
        print()
        print("  A stale owner in a download path, or a stale DNS name in a")
        print("  signature check, only fails at install time on someone else's")
        print("  machine. CHANGELOG.md is exempt as append-only history.")
        return 1

    print("Branding: CLEAN — no superseded org, repo or DNS name in the tree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
