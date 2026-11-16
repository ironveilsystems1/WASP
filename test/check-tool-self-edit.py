#!/usr/bin/env python3
"""
check-tool-self-edit.py — no WASP script edits an installed tool in place.

WHY THIS EXISTS

Until 10.20, wp-geoip-setup.sh ran `sed -i ... /usr/local/bin/update.sh` to
change one fallback line. The installed tool then differed from its signed
copy: wasp-verify-integrity.sh and the weekly watch-integrity alert reported
it, and wasp-upgrade.sh refused to replace it as "modified since installed"
on every VM with GeoIP. State belongs in a state file (pinned.env, vars.sh);
a tool's bytes stay the bytes that were signed.

Fails on any `sed -i`, `>`/`>>` redirect, `tee`, `cp`, `mv` or `install`
whose target is a SIGNED tool -- one shipped in payload/bin/ or payload/lib/ --
outside the places that install tools: the stages and wasp-upgrade.sh. A
helper a tool generates for itself (wp-geoip-refresh.sh) is not signed and
not upgraded, so writing it is not editing a tool.
"""
import glob, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALLOWED = {"payload/bin/wasp-upgrade.sh"}
SIGNED = sorted({os.path.basename(x) for x in glob.glob(os.path.join(ROOT, "payload", "bin", "*")) + glob.glob(os.path.join(ROOT, "payload", "lib", "*"))})
TARGET = r"/usr/local/(?:bin|lib/wasp)/(?:" + "|".join(re.escape(x) for x in SIGNED) + r")(?![A-Za-z0-9._-])"
pats = [re.compile(r"\bsed\s+(?:-[a-zA-Z]*i[a-zA-Z]*\b|--in-place)[^\n]*" + TARGET),
        re.compile(r">>?\s*\"?" + TARGET),
        re.compile(r"\btee\b[^\n|]*" + TARGET)]
errors = []
for f in sorted(glob.glob(os.path.join(ROOT, "payload", "**", "*"), recursive=True)):
    rel = os.path.relpath(f, ROOT)
    if not os.path.isfile(f) or rel.startswith("payload/stages/") or rel in ALLOWED:
        continue
    try:
        lines = open(f, encoding="utf-8").read().splitlines()
    except UnicodeDecodeError:
        continue
    for n, line in enumerate(lines, 1):
        if line.lstrip().startswith("#"):
            continue
        if any(p.search(line) for p in pats):
            errors.append(f"{rel}:{n}: edits an installed tool in place: {line.strip()[:120]}")
if errors:
    print("check-tool-self-edit: FAIL")
    for e in errors:
        print("  " + e)
    sys.exit(1)
print("check-tool-self-edit: OK (no script edits an installed tool)")
