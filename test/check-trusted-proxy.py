#!/usr/bin/env python3
"""
check-trusted-proxy.py — the TRUST-COUNT contract, and where it is declared.

WHY THIS EXISTS

The reverse proxy must be declared to mod_remoteip as exactly ONE literal
address, in exactly ONE file, with `RemoteIPInternalProxy`.

ONE ADDRESS. mod_remoteip walks `X-Forwarded-For` from the RIGHT, popping
entries for as long as they match a declared proxy, and takes the first address
it does not trust as the client. Declare a range instead of one address and
every host inside that range can prepend whatever client address it likes and
have Apache accept it as genuine. That forged address is:

  * the address CrowdSec parses out of the access log and bans,
  * the address the wp-admin `Require ip` restriction is evaluated against,
  * the address the login guard counts failed attempts against, and
  * the address the contact-form rate limit keys on.

So a widened declaration turns one compromised neighbour on the same segment
into an authentication bypass. The upstream WordPress image ships exactly that
— every RFC1918 range — in conf-enabled/remoteip.conf, which this install
masks (check-remoteip-mask.py holds that).

INTERNAL, NOT TRUSTED (since 10.15). `RemoteIPTrustedProxy` treats the values a
proxy reports as EXTERNAL addresses and discards private ones ("appears to be a
private IP or nonsensical. Ignored"). On this platform administrators reach the
proxy from the LAN or over an overlay (NetBird masquerades onto the LAN), so
their address is always private: Apache kept the proxy as the client, the
`Require not ip <proxy>` guard denied it, and wp-admin returned 403 to the
operator on every tenant while internet visitors were substituted correctly.
`RemoteIPInternalProxy` with ONE address accepts private client values without
widening who may set the header: only a connection from that address has its
X-Forwarded-For read at all. The danger in the image's file was the ranges,
not the directive.

ONE FILE. mod_remoteip's proxy lists APPEND across files. Through 10.14 the
directive was written both into wp-security.conf and into a second file mounted
over mods-enabled/remoteip.conf, so correcting one changed nothing: the field
fix "did not work" until the second was masked too. lib/06 now stages that
second file as a directive-free mask.

WHAT IT CHECKS

1. Every `RemoteIPInternalProxy` emitted anywhere substitutes a single variable
   and nothing else — no CIDR literal, no second value.
2. `RemoteIPTrustedProxy` is never emitted.
3. Exactly one file in the tree emits the declaration (lib/03), and it guards
   its input against a range or list before writing.
4. lib/06's mods-enabled mask carries no RemoteIP directive, and lib/06 still
   asserts the single-address contract before staging the mask.
5. The installer's preflight still refuses a CIDR.

Documentation and comments are exempt: explaining the rule requires writing
down the wrong form next to the right one. So is test/, whose fixtures have to
be shaped like the VMs the repair exists for; nothing under test/ ships to a VM.
"""

import glob
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DECLARER = "lib/03-dynamic-configs.sh"
MASKER = "lib/06-vars-and-payload-inject.sh"

# A guard is any of these shapes rejecting a slash, a comma or whitespace in
# the value. Matched loosely on purpose: the point is that a guard exists and
# names the right characters, not that it is spelled one particular way.
GUARD = re.compile(r"\*/\*\|\*,\*\|\*\[\[:space:\]\]\*|\[/,\[:space:\]\]")

INTERNAL = re.compile(r"^\s*RemoteIPInternalProxy\s+(.+?)\s*$")
TRUSTED = re.compile(r"^\s*RemoteIPTrustedProxy\s+\S")

# One variable reference, alone: ${PROXY_IP} or $PROXY_IP.
SINGLE_VAR = re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*\}$|^\$[A-Za-z_][A-Za-z0-9_]*$")

CODE_EXT = (".sh", ".conf", ".tmpl", ".yaml", ".php")


def is_comment(line):
    return line.lstrip().startswith("#")


def scan_text(text):
    """(lineno, kind, detail) problems, plus the count of declarations."""
    out = []
    decls = 0
    for n, line in enumerate(text.splitlines(), 1):
        if is_comment(line):
            continue
        m = INTERNAL.match(line)
        if m:
            decls += 1
            if not SINGLE_VAR.match(m.group(1)):
                out.append((n, "literal-or-multi", m.group(1)))
        if TRUSTED.match(line):
            out.append((n, "trusted-proxy", line.strip()))
    return out, decls


def mask_heredoc(text):
    """Body of the heredoc that writes wp-remoteip.conf, or None."""
    m = re.search(r'cat > "\$MNT/root/wp-remoteip\.conf" << \'?(\w+)\'?\n(.*?)\n\1\n',
                  text, re.S)
    return m.group(2) if m else None


def self_test():
    assert scan_text("RemoteIPInternalProxy 10.20.10.0/24\n")[0], \
        "self-test: a CIDR literal was not flagged"
    assert scan_text("RemoteIPInternalProxy ${PROXY_IP} ${OTHER}\n")[0], \
        "self-test: two values were not flagged"
    assert scan_text("RemoteIPInternalProxy 10.0.0.0/8\n")[0], \
        "self-test: the image's range was not flagged"
    assert scan_text("RemoteIPTrustedProxy ${PROXY_IP}\n")[0], \
        "self-test: RemoteIPTrustedProxy was not flagged"
    p, d = scan_text("RemoteIPInternalProxy ${PROXY_IP}\n")
    assert not p and d == 1, "self-test: the correct form was flagged or not counted"
    assert not scan_text("# RemoteIPTrustedProxy 10.0.0.0/8 would be wrong\n")[0], \
        "self-test: a comment was flagged"
    good = ("  cat > \"$MNT/root/wp-remoteip.conf\" << 'RICONF'\n"
            "# masked\nRICONF\n")
    bad = ("  cat > \"$MNT/root/wp-remoteip.conf\" << RICONF\n"
           "RemoteIPHeader X-Forwarded-For\nRICONF\n")
    assert mask_heredoc(good) == "# masked", "self-test: mask heredoc not parsed"
    assert "RemoteIP" in mask_heredoc(bad), "self-test: directive in mask not seen"
    return True


def main():
    self_test()
    problems = []

    files = []
    for ext in CODE_EXT:
        files += glob.glob(os.path.join(REPO, "**", "*" + ext), recursive=True)
    files = sorted(f for f in set(files)
                   if not os.path.relpath(f, REPO).startswith("test" + os.sep))

    declarers = []
    for path in files:
        rel = os.path.relpath(path, REPO)
        text = open(path, encoding="utf-8", errors="replace").read()
        found, decls = scan_text(text)
        if decls:
            declarers.append(rel)
        for n, kind, detail in found:
            if kind == "literal-or-multi":
                problems.append(
                    f"{rel}:{n}: RemoteIPInternalProxy takes ONE variable; found '{detail}'")
            else:
                problems.append(
                    f"{rel}:{n}: RemoteIPTrustedProxy must not be emitted — it discards "
                    f"private client addresses and locks LAN/overlay administrators "
                    f"out of wp-admin; use RemoteIPInternalProxy ${{PROXY_IP}}")

    if declarers != [DECLARER]:
        problems.append(
            f"the proxy must be declared in exactly one file ({DECLARER}); "
            f"found: {', '.join(declarers) or 'none'} — mod_remoteip's lists append "
            f"across files, so a second declaration silently stays in force")

    dtext = open(os.path.join(REPO, DECLARER), encoding="utf-8", errors="replace").read()
    if not GUARD.search(dtext):
        problems.append(f"{DECLARER}: declares the proxy with no guard rejecting "
                        f"a range or list in PROXY_IP")

    mpath = os.path.join(REPO, MASKER)
    if not os.path.exists(mpath):
        problems.append(f"{MASKER}: expected to exist and stage the remoteip mask")
    else:
        mtext = open(mpath, encoding="utf-8", errors="replace").read()
        body = mask_heredoc(mtext)
        if body is None:
            problems.append(f"{MASKER}: the wp-remoteip.conf heredoc was not found")
        elif any(l.strip() and not is_comment(l) for l in body.splitlines()):
            problems.append(f"{MASKER}: wp-remoteip.conf (mounted over "
                            f"mods-enabled/remoteip.conf) must be a directive-free mask")
        if not GUARD.search(mtext):
            problems.append(f"{MASKER}: no longer asserts the single-address "
                            f"contract on PROXY_IP")

    inst = os.path.join(REPO, "install.sh")
    itext = open(inst, encoding="utf-8", errors="replace").read()
    if "WASP_PROXY_IP" in itext and not GUARD.search(itext):
        problems.append("install.sh: accepts WASP_PROXY_IP but its contract preflight "
                        "no longer rejects a range or list")

    if problems:
        print(f"FOUND {len(problems)} trusted-proxy problem(s):")
        for p in problems:
            print(f"  {p}")
        print()
        print("  TRUST-COUNT: the proxy is declared once, in lib/03, as")
        print("  RemoteIPInternalProxy <one literal address>. A range lets any host")
        print("  inside it forge the client IP; RemoteIPTrustedProxy throws away the")
        print("  administrator's private address; a second file keeps the old value.")
        return 1

    print(f"Trusted proxy: CLEAN — declared once ({DECLARER}) as a single-literal "
          f"RemoteIPInternalProxy; mods-enabled mask carries no directive")
    return 0


if __name__ == "__main__":
    sys.exit(main())
