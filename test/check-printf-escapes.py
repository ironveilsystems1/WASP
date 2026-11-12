#!/usr/bin/env python3
"""Detect `\\$` and `\\"` inside a single-quoted printf format.

Inside single quotes the shell removes nothing, so printf receives the
backslash. `\\$` and `\\"` are not printf escapes: both bash and BusyBox print
the backslash and the character. So

    printf 'proxy_set_header Host \\$host;\\n'

prints `proxy_set_header Host \\$host;`, and nginx reads `\\$host` as a literal
string. That shipped in `wp-hardening.sh nginx-snippet` for every header in
the generated proxy config: the upstream received `Host: \\example.com`-style
values, and the add_header lines with `\\"...\\"` failed `nginx -t` on stock
nginx outright. Copied in from a double-quoted original, the escapes look
deliberate, which is why twenty of them survived review.

`\\\\` (an escaped backslash, for a literal `\\.` in a regex) is fine and is
not matched here.
"""
import glob, re, sys

# printf, optional spaces, a single-quoted format containing \$ or \" that is
# not itself preceded by a backslash.
PAT = re.compile(r"""printf\s+'(?:[^'\\]|\\[^$"])*\\[$"]""")
problems = []
for f in sorted(set(glob.glob('**/*.sh', recursive=True)) | {'install.sh'}):
    if f.startswith('test/'):
        continue
    try: lines = open(f, errors='replace').read().split('\n')
    except FileNotFoundError: continue
    for n, line in enumerate(lines, 1):
        if line.lstrip().startswith('#'):
            continue
        if PAT.search(line):
            problems.append((f, n, line.strip()[:80]))
if problems:
    print(f"FOUND {len(problems)} single-quoted printf format(s) with \\$ or \\\":")
    for f, n, t in problems:
        print(f"  {f}:{n}")
        print(f"     {t}")
    print("  -> the backslash is printed. Drop it: single quotes already stop expansion.")
    sys.exit(1)
print("printf escape check: CLEAN")
