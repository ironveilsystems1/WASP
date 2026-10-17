#!/usr/bin/env python3
"""
check-no-client-material.py — no client-specific material in the platform repo.

WHY THIS EXISTS

Two documents were written into docs/ during a working session: call notes for
a named prospect, and a sales brochure. Both were useful. Neither belongs in a
repository that gets cloned, forked, published, and shipped to other clients.

The call notes in particular contained a named individual, their employer,
their phone number, their hosting provider, and an assessment of unpatched
vulnerabilities on their live website. Shipping that inside a platform tarball
would be a privacy problem and a professional one, and it would have gone
wherever the tarball went.

This is not a hypothetical risk that was avoided. Both files were committed and
packaged into several releases before anyone noticed.

WHAT IT CHECKS

Filenames that indicate sales, prospect or client-specific material anywhere in
the tree, plus a small set of content markers for the same. Deliberately
filename-led: content scanning for personal data is a different and much larger
problem, and a check that tries to do it badly is worse than one with a clear
scope.

Client-facing documents belong in whatever the business uses for client
documents. This repository is the platform.
"""

import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Filename fragments that indicate the file is about a customer, not the code.
# NOTE the absence of a bare "quote". It matched check-embedded-quotes.py,
# where the word means shell quoting — a false positive on the first run, and
# a reminder that a check firing on a correct file trains people to ignore it.
# Markers must be specific enough that a hit is almost certainly real.
NAME_MARKERS = (
    "call-notes", "callnotes", "brochure", "prospect", "proposal",
    "sales-quote", "pitch-deck", "sales-", "-client-", "client-notes",
)

# Content markers, kept narrow. These indicate a specific named engagement
# rather than documentation about the platform.
CONTENT_MARKERS = (
    re.compile(r"(?i)\bcall notes\b.*\b(client|prospect)\b"),
    re.compile(r"(?i)^\s*\*\*noon tomorrow", re.M),
    re.compile(r"(?i)questions to ask him\b"),
)

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".github"}
EXEMPT_FILES = {"CHANGELOG.md", os.path.basename(__file__)}


def main():
    problems = []
    for root, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in files:
            if fn in EXEMPT_FILES:
                continue
            rel = os.path.relpath(os.path.join(root, fn), REPO)
            low = fn.lower()
            if any(m in low for m in NAME_MARKERS):
                problems.append(f"{rel}: filename indicates client or sales material")
                continue
            if not fn.endswith((".md", ".txt")):
                continue
            try:
                text = open(os.path.join(root, fn), encoding="utf-8",
                            errors="replace").read()
            except OSError:
                continue
            for pat in CONTENT_MARKERS:
                if pat.search(text):
                    problems.append(f"{rel}: content reads as notes on a specific engagement")
                    break

    if problems:
        print(f"FOUND {len(problems)} file(s) that should not be in this repository:")
        for p in sorted(set(problems)):
            print(f"  {p}")
        print()
        print("  This repository is cloned, forked, published and shipped to")
        print("  clients. Anything naming a specific customer travels with it.")
        print("  Client-facing documents belong wherever the business keeps")
        print("  client documents — not here.")
        return 1

    print("Client material: CLEAN — nothing customer-specific in the tree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
