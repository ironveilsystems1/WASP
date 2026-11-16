#!/usr/bin/env python3
"""
check-subsystem-map.py — every shipped component belongs to exactly one subsystem.

WHY THIS EXISTS

ARCHITECTURE.md's "Subsystems" table places each tool, stage, mu-plugin and
library in one of five subsystems (Core, Security, Recovery, Import, Hive).
A map that silently stops matching the tree is worse than none: a reviewer
trusts it. So this fails when a shipped component is in no row, in two rows,
or when a row names something that no longer exists.

Components: install.sh, lib/*.sh, payload/install-wordpress.sh,
payload/stages/*.sh (written stages/<name>), and by basename everything in
payload/bin, payload/mu-plugins, payload/php-tools, payload/lib, plus
hive/install-hive.sh and hive/*.py (written hive/<name>).
"""
import glob, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def rel(pattern, fmt):
    return {fmt(os.path.relpath(p, ROOT)) for p in glob.glob(os.path.join(ROOT, pattern)) if os.path.isfile(p)}

required = set()
required |= {"install.sh", "payload/install-wordpress.sh"}
required |= rel("lib/*.sh", lambda r: r)
required |= rel("payload/stages/*.sh", lambda r: "stages/" + os.path.basename(r))
for d in ("payload/bin", "payload/mu-plugins", "payload/php-tools", "payload/lib"):
    required |= rel(d + "/*", os.path.basename)
required |= rel("hive/*.py", lambda r: r) | {"hive/install-hive.sh"}

text = open(os.path.join(ROOT, "ARCHITECTURE.md"), encoding="utf-8").read()
m = re.search(r"^## Subsystems\n(.*?)(?=^---$|^## )", text, re.S | re.M)
if not m:
    print("check-subsystem-map: FAIL\n  ARCHITECTURE.md has no '## Subsystems' section")
    sys.exit(1)

seen = {}
rows = 0
for line in m.group(1).splitlines():
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    if len(cells) != 3 or not cells[0].startswith("**WASP "):
        continue
    rows += 1
    name = cells[0].strip("*")
    for comp in re.findall(r"`([^`]+)`", cells[2]):
        seen.setdefault(comp, []).append(name)

errors = []
if rows != 5:
    errors.append(f"expected 5 subsystem rows, found {rows}")
for comp in sorted(required - set(seen)):
    errors.append(f"{comp}: shipped but in no subsystem")
for comp, where in sorted(seen.items()):
    if len(where) > 1:
        errors.append(f"{comp}: in more than one subsystem ({', '.join(where)})")
    if comp not in required:
        errors.append(f"{comp}: named in the map but not shipped (renamed or removed?)")
if errors:
    print("check-subsystem-map: FAIL")
    for e in errors:
        print("  " + e)
    sys.exit(1)
print(f"check-subsystem-map: OK ({len(required)} components, each in one of {rows} subsystems)")
