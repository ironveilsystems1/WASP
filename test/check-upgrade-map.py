#!/usr/bin/env python3
"""
check-upgrade-map.py — every file a stage installs is one wasp-upgrade.sh knows about.

WHY THIS EXISTS

wasp-upgrade.sh changes a VM only through payload/upgrade/files.map. A file a
stage installs at build time but the map does not list is installed on new VMs
and never upgraded on existing ones: the fleet splits silently, and the next
release's fix to that file reaches only VMs built after it. The opposite gap
matters too: a tool in payload/bin/ that no stage installs would be installed
by the first upgrade but missing from every freshly built VM.

So this holds, for the stages under payload/stages/:

  * every `install … ${PAYLOAD_DIR}/X …` and `cat ${PAYLOAD_DIR}/cron/X >>` is
    covered by a files.map entry, or lies under a BUILD-TIME directory (config
    holding the VM's own values, reported by the upgrade and never replaced);
  * every payload/bin/*.sh is installed by some stage;
  * every files.map source matches at least one file, and each kind is known;
  * every upgrade hook is named for a version and says what it does (# step:).
"""
import fnmatch, glob, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
P = os.path.join(ROOT, "payload")
BUILD_TIME = ("apache-conf/", "crowdsec/", "mariadb-conf/", "php-conf/", "squid/", "init.d/",
              "templates/", "etc/sysctl.d/", "etc/lynis-custom.prf")
errors = []

entries = []
for n, line in enumerate(open(os.path.join(P, "upgrade", "files.map")), 1):
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    f = line.split()
    if f[0] not in ("tool", "file", "mu", "cron"):
        errors.append(f"files.map:{n}: unknown kind {f[0]!r}")
        continue
    if f[0] == "cron" and (len(f) != 3 or f[2] not in ("always", "if-present")):
        errors.append(f"files.map:{n}: a cron entry is 'cron <file> always|if-present'")
    if f[0] != "cron" and len(f) != 5:
        errors.append(f"files.map:{n}: expected kind source destination mode owner")
    if not glob.glob(os.path.join(P, f[1])):
        errors.append(f"files.map:{n}: {f[1]} matches no file under payload/")
    entries.append(f)

def covered(rel):
    if any(fnmatch.fnmatch(rel, e[1]) for e in entries):
        return True
    return any(rel.startswith(b) or rel == b for b in BUILD_TIME)

installed = set()
pat_install = re.compile(r'(?:install|cp)\b[^\n]*?"?\$\{PAYLOAD_DIR\}/([A-Za-z0-9_./${}-]+)"?')
pat_cat = re.compile(r'cat\s+"?\$\{PAYLOAD_DIR\}/(cron/[A-Za-z0-9_.-]+)"?\s*>>')
for st in sorted(glob.glob(os.path.join(P, "stages", "*.sh"))):
    for n, line in enumerate(open(st), 1):
        if line.lstrip().startswith("#"):
            continue
        for m in list(pat_install.finditer(line)) + list(pat_cat.finditer(line)):
            rel = m.group(1)
            if "${" in rel:       # a loop variable: the loop's own list is checked by its directory
                rel = re.sub(r"\$\{[^}]+\}.*", "*", rel)
            installed.add(rel)
            probe = rel if "*" not in rel else rel.replace("*", "x")
            if not covered(probe) and not any(fnmatch.fnmatch(x, rel) and covered(x)
                                              for x in (os.path.relpath(q, P) for q in glob.glob(os.path.join(P, rel)))):
                errors.append(f"{os.path.relpath(st, ROOT)}:{n}: installs payload/{rel}, which files.map does not cover "
                              f"and is not build-time config: existing VMs would never get its updates")

for tool in sorted(glob.glob(os.path.join(P, "bin", "*.sh"))):
    rel = os.path.relpath(tool, P)
    if rel not in installed:
        errors.append(f"payload/{rel} is installed by no stage: a new VM would lack what an upgraded one has")

for h in sorted(glob.glob(os.path.join(P, "upgrade", "hooks", "*"))):
    b = os.path.basename(h)
    if not re.fullmatch(r"\d+(\.\d+)*\.sh", b):
        errors.append(f"payload/upgrade/hooks/{b}: hooks are named <version>.sh")
    elif not re.search(r"^# step: \S", open(h).read(), re.M):
        errors.append(f"payload/upgrade/hooks/{b}: needs a '# step: <what it does>' line (the plan prints it)")

if errors:
    print("check-upgrade-map: FAIL")
    for e in errors:
        print("  " + e)
    sys.exit(1)
print(f"check-upgrade-map: OK ({len(entries)} map entries, {len(installed)} stage installs covered)")
