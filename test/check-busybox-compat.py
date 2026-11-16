#!/usr/bin/env python3
"""
check-busybox-compat.py — GNU-only forms that fail quietly on Alpine.

WHY THIS EXISTS

The VMs run Alpine: BusyBox tools on musl. The check suite runs its BusyBox
pass on a build host whose BusyBox is linked against glibc, so it inherits
glibc's regex engine and never saw what musl refuses. The first CI run on
real Alpine (10.23) found three bugs that had shipped for many releases, each
failing without an error anyone would see:

  - update.sh: `date -d "+90 days"`. BusyBox date has no relative dates; the
    fallback was today, so a vulnerability exception granted for 90 days
    expired the day it was granted.
  - wp-hardening.sh: `date -d "+14 days"`, same fallback: no exception was
    ever shown as expiring soon.
  - wp-import.sh: `[^<]{0,300}` in a grep pattern. musl refuses a repeat count
    over 255 (RE_DUP_MAX), grep failed, and the hidden-link check counted
    nothing on every import.

Fails on, in any shell script (tools, stages, installer, tests):
  - `date` or `touch` with -d and a relative phrase ("+14 days", "5 days ago",
    "yesterday"). Use an epoch offset: date -d "@$(( $(date +%s) + N*86400 ))".
  - a regex repeat count above 255 ({n,300}, {300}) on a grep, sed, awk or
    expr line. PHP's PCRE has no such limit, so PHP files are not checked.
"""
import glob, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def shell_files():
    out = []
    for f in glob.glob(os.path.join(ROOT, "**", "*"), recursive=True):
        rel = os.path.relpath(f, ROOT)
        if not os.path.isfile(f) or rel.startswith((".git" + os.sep, "docs" + os.sep)) or "__pycache__" in rel:
            continue
        if rel.endswith((".php", ".py", ".md", ".json", ".yml", ".yaml", ".js", ".css", ".html", ".svg", ".png")):
            continue
        try:
            with open(f, encoding="utf-8") as fh:
                first = fh.readline()
                if rel.endswith(".sh") or re.match(r"#!.*\b(sh|bash|ash)\b", first):
                    out.append((rel, [first] + fh.read().splitlines()))
        except (UnicodeDecodeError, OSError):
            continue
    return sorted(out)

RELATIVE = re.compile(
    r"""\b(date|touch)\b[^\n#]*?-d\s*["'][^"']*?(\bago\b|[+-]\s*(?:\d+|\$\{?\w+\}?)\s*(?:seconds?|minutes?|hours?|days?|weeks?|months?|years?)\b|\byesterday\b|\btomorrow\b|\bnext\s|\blast\s)""",
    re.I)
REGEX_TOOL = re.compile(r"\b(grep|sed|awk|expr)\b")
REPEAT = re.compile(r"\{(\d*),?(\d+)\}")

errors = []
for rel, lines in shell_files():
    for n, line in enumerate(lines, 1):
        code = line.split(" #", 1)[0] if not line.lstrip().startswith("#") else ""
        if not code.strip():
            continue
        if RELATIVE.search(code):
            errors.append(f"{rel}:{n}: relative date (BusyBox date/touch cannot read it): {code.strip()[:110]}")
        if REGEX_TOOL.search(code):
            for m in REPEAT.finditer(code):
                hi = int(m.group(2) or 0)
                lo = int(m.group(1)) if m.group(1) else 0
                if max(hi, lo) > 255:
                    errors.append(f"{rel}:{n}: regex repeat {m.group(0)} over 255 (musl refuses it): {code.strip()[:110]}")

if errors:
    print("check-busybox-compat: FAIL")
    for e in errors:
        print("  " + e)
    print("  Use an epoch offset for dates (date -d \"@$(( $(date +%s) + N*86400 ))\"),")
    print("  and keep regex repeat counts at 255 or below.")
    sys.exit(1)
print(f"check-busybox-compat: OK ({len(shell_files())} shell scripts: no relative dates, no repeat count over 255)")
