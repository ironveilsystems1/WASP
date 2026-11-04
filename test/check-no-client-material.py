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

# ── Routable addresses ───────────────────────────────────────────────────────
#
# ADDED 2026-10-25, after this check reported CLEAN on a tree that contained a
# client's name in twenty places, their public IP as a live allowlist entry in
# the test data, and their Proxmox node name. All of it was about to be pushed
# to a public GitHub org.
#
# The check was not broken. It is filename-led BY DESIGN and says so, and its
# content markers only ever ran on .md and .txt — so a .sh file naming a
# client was never examined. A control that is correct, documented, and blind
# to the thing it is named for is this project's characteristic defect, and it
# turned up here in the check written to prevent exactly this.
#
# This addition stays inside the original scope rule: it is not a PII scanner.
# It asks one precisely answerable question — does this repository contain an
# IPv4 address that routes on the public internet? A platform repo has no
# legitimate need for one. Every example belongs in a documentation range.
#
# Scanned across ALL text files, not just prose, because the leak was in a
# shell script.
_ALLOWED_V4 = (
    (0, 0),            # 0.0.0.0/8      this network
    (10, 0),           # 10.0.0.0/8     private
    (127, 0),          # 127.0.0.0/8    loopback
    (169, 254),        # 169.254/16     link-local
    (172, 16), (172, 17), (172, 18), (172, 19), (172, 20), (172, 21),
    (172, 22), (172, 23), (172, 24), (172, 25), (172, 26), (172, 27),
    (172, 28), (172, 29), (172, 30), (172, 31),          # private
    (192, 168),        # private
    (192, 0),          # 192.0.0/24 IETF, 192.0.2/24 TEST-NET-1
    (198, 18), (198, 19),   # benchmarking
    (198, 51),         # 198.51.100/24 TEST-NET-2
    (203, 0),          # 203.0.113/24  TEST-NET-3
    (255, 255),        # broadcast
)

# Public infrastructure constants, not client data. The installer offers these
# as resolver choices and must ship their real addresses — a documentation
# range would make the feature not work.
#
# This list is the difference between a check people act on and one they learn
# to skip. The first run flagged 46 files, 40 of them public resolvers, and
# buried three genuine leaks (a web developer's two personal addresses and a
# past operator's) in the noise. The original author's note on NAME_MARKERS
# applies exactly: "a check firing on a correct file trains people to ignore
# it."
#
# Add to this only for an address that is genuinely public infrastructure.
# An address belonging to a client, a contractor or an operator never
# qualifies, however convenient the example.
_PUBLIC_INFRA = {
    "9.9.9.9", "149.112.112.112",                  # Quad9
    "149.112.121.10", "149.112.122.10",            # CIRA Canadian Shield
    "1.1.1.1", "1.0.0.1",                          # Cloudflare
    "8.8.8.8", "8.8.4.4",                          # Google
    "94.140.14.14", "94.140.15.15",                # AdGuard
    "76.76.2.0", "76.76.10.0",                     # Control D
    "185.222.222.222", "45.11.45.11",              # DNS.SB
    "89.233.43.71", "91.239.100.100",              # UncensoredDNS
    "5.1.66.255", "185.150.99.255",                # FDN / Freifunk
    "86.54.11.100", "86.54.11.200",                # DNS4EU
    "45.148.10.62",                                # CrowdSec CTI demo lookup
}

_IPV4 = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?![\w.])")

_TEXT_SUFFIXES = (".sh", ".php", ".py", ".md", ".txt", ".conf", ".cron",
                  ".yar", ".xml", ".json", ".service", ".yaml", ".yml")


# ADDED 2026-11-03. A comment quoting a real download link put a client's share
# id, archive name and access token into a public repository, past every check
# here: the name was not on any list, and nothing looked for link shapes. The
# host was absent, so this was one guess from a working link to a full backup.
#
# Same scope rule as above: not a PII scanner, one answerable question. Does this
# tree hold something shaped like a live share link? Examples use <id> and <token>.
_SHARE_LINK = (
    re.compile(r"/share/\d{3,}/"),
    re.compile(r"\.(?:zip|wpress|tar\.gz|tgz|sql)/[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_.-])"),
)


def _routable_v4(text):
    """Public IPv4 literals in this text, deduplicated and in order."""
    found = []
    for m in _IPV4.finditer(text):
        raw = m.group(1)
        try:
            octets = [int(o) for o in raw.split(".")]
        except ValueError:
            continue
        if len(octets) != 4 or any(o > 255 for o in octets):
            continue          # a version string, not an address
        if raw in _PUBLIC_INFRA:
            continue
        a, b = octets[0], octets[1]
        if a >= 240:
            continue          # 240.0.0.0/4 reserved
        if (a, b) in _ALLOWED_V4 or (a, 0) in _ALLOWED_V4:
            continue
        if 100 <= a <= 100 and 64 <= b <= 127:
            continue          # 100.64.0.0/10 CGNAT — NetBird, Tailscale
        if 224 <= a <= 239:
            continue          # multicast
        if raw not in found:
            found.append(raw)
    return found


def main():
    # Built by concatenation so this file does not flag itself.
    _sample = "x/share/" + "331999" + "/backup/a.zip/" + "AbCdEfGh1"
    assert any(p.search(_sample) for p in _SHARE_LINK), \
        "self-test: a share link was not caught"
    assert not any(p.search("x/share/<id>/backup/a.zip/<token>") for p in _SHARE_LINK), \
        "self-test: the placeholder form was flagged"
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
            if not fn.endswith(_TEXT_SUFFIXES):
                continue
            try:
                text = open(os.path.join(root, fn), encoding="utf-8",
                            errors="replace").read()
            except OSError:
                continue
            if fn.endswith((".md", ".txt")):
                for pat in CONTENT_MARKERS:
                    if pat.search(text):
                        problems.append(
                            f"{rel}: content reads as notes on a specific engagement")
                        break
            for pat in _SHARE_LINK:
                if pat.search(text):
                    problems.append(
                        f"{rel}: looks like a real share link — use <id> and <token>")
                    break
            for addr in _routable_v4(text):
                problems.append(
                    f"{rel}: routable IPv4 address {addr} — use a documentation "
                    f"range (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)")

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
