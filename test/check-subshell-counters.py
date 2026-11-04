#!/usr/bin/env python3
"""
check-subshell-counters.py — a counter must not be incremented inside a pipe.

WHY THIS EXISTS

The right-hand side of a pipe is a subshell, so a variable changed there is gone
when the pipe closes. wp-malware-scan.sh did this in eight loops:

    printf '%s\\n' "$_o" | while IFS= read -r o; do
      _crit "Autoloaded option contains code: ${o}"
    done

It printed [CRITICAL], then "critical 0" and "Nothing critical found", exited 0
and sent no email. A backdoor in an autoloaded option was reported as a clean
site. The YARA loop in the same file had already been fixed for exactly this,
with a comment explaining it, and the other loops stayed as they were.

WHAT IT CHECKS

Every `| while` loop in payload/bin, payload/stages and lib. It fails when the
body increments a variable directly, or calls a function in the same file that
does. Feed the loop from a here-document or a file instead.

A loop whose counter is used only inside that same loop is fine, and such a loop
can say so with a trailing `# subshell-ok: <reason>` on its `| while` line.
"""

import glob
import os
import re
import sys

REPO = os.environ.get("WASP_TEST_REPO") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PIPE_WHILE = re.compile(r'\|\s*while\b')
OPENS = re.compile(r'(^|[;&|]\s*|\s)(while|until|for)\b[^#]*\bdo\s*(#.*)?$')
CLOSES = re.compile(r'^\s*done\b')
INCREMENT = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)=\$\(\(\s*\1\s*\+')
FUNC = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{')


def counting_functions(lines):
    """Functions in this file that increment a variable."""
    found = set()
    for i, line in enumerate(lines):
        m = FUNC.match(line)
        if not m:
            continue
        # One-liners close on the same line. Otherwise read to a closing brace
        # at the indent the function opened on.
        indent = len(line) - len(line.lstrip())
        body = [line]
        if not re.search(r'\}\s*$', line):
            for later in lines[i + 1:]:
                body.append(later)
                if later.startswith(" " * indent + "}"):
                    break
        if INCREMENT.search("\n".join(body)):
            found.add(m.group(1))
    return found


def scan_text(text):
    lines = text.split("\n")
    helpers = counting_functions(lines)
    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        code = line.split("#", 1)[0] if not line.lstrip().startswith("#") else ""
        if PIPE_WHILE.search(code) and "subshell-ok:" not in line:
            depth, j, why = 1, i + 1, None
            while j < len(lines) and depth:
                body = lines[j]
                if not body.lstrip().startswith("#"):
                    if CLOSES.match(body):
                        depth -= 1
                    elif OPENS.search(body):
                        depth += 1
                    m = INCREMENT.search(body)
                    if m:
                        why = f"increments {m.group(1)}"
                    for h in helpers:
                        if re.search(rf'(^|[;&|\s]){re.escape(h)}\b', body):
                            why = f"calls {h}(), which increments a counter"
                j += 1
            if why:
                out.append((i + 1, why))
            i = j
            continue
        i += 1
    return out


def self_test():
    bad = (
        '_crit() { CRIT=$((CRIT+1)); printf x; }\n'
        'printf a | while IFS= read -r o; do\n  _crit "$o"\ndone\n'
    )
    assert scan_text(bad), "self-test: helper called in a pipe not detected"
    direct = 'n=0\nls | while read -r f; do\n  n=$((n + 1))\ndone\necho "$n"\n'
    assert scan_text(direct), "self-test: direct increment in a pipe not detected"
    nested = (
        'n=0\nls | while read -r f; do\n  for x in a; do\n    :\n  done\n'
        '  n=$((n + 1))\ndone\n'
    )
    assert scan_text(nested), "self-test: increment after a nested loop not detected"
    fixed = (
        '_crit() { CRIT=$((CRIT+1)); printf x; }\n'
        'while IFS= read -r o; do\n  _crit "$o"\ndone <<EOF\n$_o\nEOF\n'
    )
    assert not scan_text(fixed), "self-test: here-document form flagged"
    plain = 'ls | while read -r f; do\n  echo "$f"\ndone\n'
    assert not scan_text(plain), "self-test: a pipe with no counter flagged"
    allowed = (
        'ls | while read -r f; do  # subshell-ok: used only inside\n'
        '  n=$((n + 1))\n  echo "$n"\ndone\n'
    )
    assert not scan_text(allowed), "self-test: documented exception flagged"
    return True


def main():
    self_test()
    files = []
    for pat in ("payload/bin/*.sh", "payload/stages/*.sh", "lib/*.sh", "install.sh"):
        files += sorted(glob.glob(os.path.join(REPO, pat)))
    problems = []
    for p in files:
        text = open(p, encoding="utf-8", errors="replace").read()
        for n, why in scan_text(text):
            problems.append(f"{os.path.relpath(p, REPO)}:{n}: {why}")
    if problems:
        print(f"FOUND {len(problems)} loop(s) losing a counter in a subshell:")
        for x in problems:
            print(f"  {x}")
        print()
        print("  The right-hand side of a pipe is a subshell, so the count is")
        print("  gone when it closes. Use a here-document or a file instead.")
        return 1
    print(f"Subshell counters: CLEAN — {len(files)} scripts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
