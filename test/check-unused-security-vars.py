#!/usr/bin/env python3
"""
check-unused-security-vars.py — a security constant that is never read is a lie.

WHY THIS EXISTS

`TRIVY_CHECKSUMS_SHA256` was declared with a comment stating "the binary is
then verified against that file, so this single hash anchors the whole
download". Nothing referenced the variable. The download was commit-pinned and
otherwise unverified.

That is worse than having no anchor. A reader — including a security reviewer,
including the author six months later — sees the constant, reads the comment,
and stops looking for the real control. An external evaluation caught it; the
test suite could not, because every check here proves that code DOES something
and none proved that a declared control is actually wired in.

WHAT IT CHECKS

Variables whose names indicate a security control (checksum, sha256, pubkey,
signature, fingerprint, denylist, allowlist) that are assigned exactly once and
never referenced. Deliberately narrow: an unused convenience variable is untidy,
an unused security constant is a false claim.
"""

import glob
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SECURITY = re.compile(
    r"(CHECKSUM|SHA256|SHA512|PUBKEY|PUBLIC_KEY|SIGNATURE|SIGNING|"
    r"FINGERPRINT|DENYLIST|ALLOWLIST|MINISIGN|GPG_KEY)", re.I)
ASSIGN = re.compile(r"^[ \t]*([A-Z][A-Z0-9_]*)=", re.M)


def scan(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    # Comments do not count as a use.
    code = re.sub(r"^[ \t]*#.*$", "", text, flags=re.M)
    out = []
    for name in set(ASSIGN.findall(code)):
        if not SECURITY.search(name):
            continue
        # Count references that are not the assignment itself.
        uses = len(re.findall(r"\$\{?" + re.escape(name) + r"\b", code))
        if uses == 0:
            line = next((n for n, l in enumerate(text.split("\n"), 1)
                         if re.match(r"^[ \t]*" + re.escape(name) + r"=", l)), 0)
            out.append((line, name))
    return out


def self_test():
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
        f.write('TRIVY_CHECKSUMS_SHA256="abc"\necho hello\n'); bad = f.name
    assert scan(bad), "self-test: unused security constant not detected"
    os.unlink(bad)
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
        f.write('TRIVY_CHECKSUMS_SHA256="abc"\necho "$TRIVY_CHECKSUMS_SHA256"\n'); ok = f.name
    assert not scan(ok), "self-test: used constant flagged"
    os.unlink(ok)
    return True


def main():
    self_test()
    files = sorted(
        glob.glob(os.path.join(REPO, "payload", "**", "*.sh"), recursive=True)
        + glob.glob(os.path.join(REPO, "lib", "*.sh"))
        + [os.path.join(REPO, "install.sh")])
    files = [f for f in files if os.path.exists(f)]
    problems = []
    for p in files:
        for line, name in scan(p):
            problems.append(f"{os.path.relpath(p, REPO)}:{line}: {name} is assigned and never read")
    if problems:
        print(f"FOUND {len(problems)} declared-but-unused security constant(s):")
        for x in problems:
            print(f"  {x}")
        print()
        print("  A security constant that nothing reads is a claim the code does")
        print("  not honour. Wire it in, or delete it and the comment beside it.")
        return 1
    print(f"Security constants: CLEAN — {len(files)} scripts, every one is read")
    return 0


if __name__ == "__main__":
    sys.exit(main())
