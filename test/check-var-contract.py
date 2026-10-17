#!/usr/bin/env python3
"""Producer/consumer variable contract across the sourced stages.

PORTED INTO WASP after a real install on tispve (melroseparkfire, 2026-10-17).
lib/03 read "${SCRIPT_DIR}/payload/templates/slug-rewrite.rules"; SCRIPT_DIR is
assigned nowhere in this project (the repo root is REPO_DIR), so sed was handed
"/payload/templates/..." and failed. The command substitution yielded empty, the
heredoc completed, and the next line printed a green tick.

The rules in that template are the only thing setting E=WPVM_SLUG:1, and the
config 403s /wp-login.php without it — so the VM would have had NO login path:
the slug 404ing and wp-login 403ing, reported as configured. Every other check
in this directory passed that build.

WHY THIS EXISTS
---------------
A variable name that nothing assigns expands to the empty string under `set -e`
without `set -u`, and execution continues. Every other check in this directory
passes, because the syntax is valid — the damage is in the generated artifact.

This check came from the npmplus project, which found the same class after five
of its host-side stages were adapted by renaming paths and kept consuming the
old variable names. WASP had no equivalent until a real install proved it needed
one.

WHAT IT CHECKS
--------------
1. UNPRODUCED  -- a variable is expanded somewhere under lib/ or install.sh but
   never assigned anywhere in the sourced set. Fatal.
2. ORDER       -- a variable is expanded in a file that install.sh sources
   BEFORE the file that assigns it. bash -n passes; it is empty at runtime.

LIMITS, stated because a check that overstates itself is worse than none:
this is textual. It does not know about conditional assignment, and a variable
assigned only inside an `if` branch counts as produced. It covers the host-side
sourced set; payload/ stages source vars.sh at runtime and are checked against
that file's contents rather than by sourcing order.
"""
import glob
import os
import re
import sys

# Shell-provided, environment, or set by the caller's environment rather than
# by this codebase. Expanding these is not drift.
BUILTIN = {
    'PATH', 'HOME', 'PWD', 'OLDPWD', 'USER', 'LOGNAME', 'SHELL', 'TERM',
    'HOSTNAME', 'LANG', 'IFS', 'RANDOM', 'LINENO', 'FUNCNAME', 'REPLY',
    'SECONDS', 'EUID', 'UID', 'PPID', 'BASH_SOURCE', 'BASHPID', 'BASH_VERSION',
    'PS1', 'PS2', 'EDITOR', 'PAGER', 'TZ', 'COLUMNS', 'LINES', 'SHLVL',
    'OPTARG', 'OPTIND', 'TMPDIR',
    # Added when this was ported into WASP, from its first run here:
    'BASH_REMATCH',                      # set by [[ =~ ]]
    'NF', 'NR', 'FS', 'OFS', 'RS',       # awk built-ins, inside awk programs
    'SUDO_USER', 'DOAS_USER',
    'env',                               # $env:USERNAME — PowerShell key-generation
                                         # instructions printed to Windows operators
}

# Documented ENVIRONMENT inputs: consumed here, never assigned here, by design.
# install.sh's contract_preflight() validates each before the build starts, and
# README.md documents them.
#
# Listed by NAME rather than by a WASP_* prefix on purpose. A prefix rule would
# also absorb a typo — WASP_CROWDSEC_WHITLIST would read as "an intentional
# preset" and silently never match the real one. That is the same silent-empty
# failure this check exists to catch, so the allowlist is explicit and a new
# preset has to be added here deliberately.
EXTERNAL = {
    'WASP_PUBKEY', 'WASP_KEY_DNS', 'WASP_SKIP_KEY_DNS',
    'WASP_REQUIRE_SIGNATURE', 'WASP_ACCEPT_UNVERIFIED', 'WASP_DEV_UNVERIFIED',
    'WASP_PROXY_IP', 'WASP_CS_ENFORCEMENT', 'WASP_CS_LAPI_URL',
    'WASP_CS_LAPI_LOGIN', 'WASP_CS_LAPI_PASSWORD',
    'WASP_CROWDSEC_WHITELIST', 'WASP_LOOPBACK_HOSTS',
    'WASP_SSH_KEYS', 'WASP_SSH_KEY_FILE',
    'WPVM_REPO_REF', 'WPVM_BOOTSTRAP_DIR',
    'DEPLOYMENT_PROFILE',
}

# Assignments appear in more positions than the obvious one: after a case-arm
# `)`, after `&&`, inside `$( )`, and as several on one line. Requiring
# start-of-line missed `nfs|dir)  DISK_EXT=".qcow2"` and reported DISK_EXT as
# never produced -- a false positive, which is the failure mode that gets a
# check muted and is therefore worth more care than the true positives.
ASSIGN = re.compile(r'(?:^|[;&|()`{}\s])(?P<name>[A-Za-z_][A-Za-z0-9_]*)=')

# `local a b c` and `declare -r X` introduce names with no `=` on the line.
DECLARE_LIST = re.compile(r'\b(?:local|declare|typeset|readonly|export)\b(?P<rest>[^\n;|&]*)')
READ_INTO = re.compile(r'\bread\b(?P<opts>[^\n;|&]*)')
FOR_LOOP = re.compile(r'\bfor\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s+in\b')
USE = re.compile(r'\$\{?(?P<name>[A-Za-z_][A-Za-z0-9_]*)')
GUARDED = re.compile(r'\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*):[-=+?]')


def sourced_order():
    """Read install.sh to learn the real sourcing order rather than assuming it.

    Assuming lexical order would silently pass if install.sh sourced 05 before
    01, which is exactly the kind of thing this check exists to notice.
    """
    if not os.path.exists('install.sh'):
        return sorted(glob.glob('lib/*.sh'))
    order = ['install.sh']
    src = re.compile(r'^\s*\.\s+"\$\{LIB_DIR\}/([^"]+)"')
    for line in open('install.sh', encoding='utf-8', errors='replace'):
        m = src.match(line)
        if m:
            order.append(os.path.join('lib', m.group(1)))
    # Anything under lib/ that install.sh never sources is dead weight and
    # worth surfacing, so append it rather than dropping it.
    for f in sorted(glob.glob('lib/*.sh')):
        if f not in order:
            order.append(f)
    return order


def strip_comments(line):
    out, in_s, in_d = [], False, False
    for i, ch in enumerate(line):
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif ch == '#' and not in_s and not in_d:
            if i == 0 or line[i - 1] in ' \t':
                break
        out.append(ch)
    return ''.join(out)


def analyze():
    files = sourced_order()
    produced = {}     # name -> index of first file that assigns it
    uses = []         # (file_index, file, lineno, name, guarded)

    func_def = re.compile(r'^\s*(?:function\s+)?[A-Za-z_][A-Za-z0-9_-]*\s*\(\s*\)')
    for idx, path in enumerate(files):
        if not os.path.exists(path):
            continue
        depth = 0
        for n, raw in enumerate(open(path, encoding='utf-8', errors='replace'), 1):
            line = strip_comments(raw)
            if not line.strip():
                continue
            # A use inside a function body is DEFERRED -- cleanup() traps and
            # helpers run long after every stage is sourced, so ordering says
            # nothing about them. Only top-level uses can be genuinely early.
            in_func = depth > 0 or bool(func_def.match(line))
            depth += line.count('{') - line.count('}')
            if depth < 0:
                depth = 0

            for m in ASSIGN.finditer(line):
                produced.setdefault(m.group('name'), idx)
            m = DECLARE_LIST.search(line)
            if m:
                for tok in m.group('rest').split():
                    tok = tok.split('=', 1)[0]
                    if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', tok):
                        produced.setdefault(tok, idx)
            m = READ_INTO.search(line)
            if m:
                for tok in m.group('opts').split():
                    if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', tok):
                        produced.setdefault(tok, idx)
            m = FOR_LOOP.search(line)
            if m:
                produced.setdefault(m.group('name'), idx)

            guarded_here = {g.group('name') for g in GUARDED.finditer(line)}
            for u in USE.finditer(line):
                name = u.group('name')
                if name in BUILTIN or name in EXTERNAL or name.isdigit():
                    continue
                uses.append((idx, path, n, name, name in guarded_here, in_func))

    unproduced, misordered = [], []
    for idx, path, n, name, guarded, in_func in uses:
        if name not in produced:
            unproduced.append((path, n, name, guarded))
        elif produced[name] > idx and not in_func:
            misordered.append((path, n, name, files[produced[name]]))
    return unproduced, misordered, produced


def main():
    unproduced, misordered, _ = analyze()

    # Guarded uses (${VAR:-default}) are intentional optionality, not drift.
    # Reported separately and non-fatally so the fatal list stays trustworthy.
    hard = [u for u in unproduced if not u[3]]
    soft = [u for u in unproduced if u[3]]

    if not hard and not misordered:
        print("Variable-contract check: CLEAN")
        if soft:
            print(f"  ({len(soft)} guarded expansion(s) of never-assigned names — "
                  f"intentional defaults, or dead code)")
        return 0

    if hard:
        print(f"FOUND {len(hard)} expansion(s) of variables NOTHING assigns:")
        seen = set()
        for path, n, name, _ in hard:
            key = (path, name)
            if key in seen:
                continue
            seen.add(key)
            print(f"  {path}:{n}  ${name} is never assigned in the sourced set")
        print("")
        print("  Under `set -e` without `set -u` these expand to empty and the")
        print("  script continues. The guest silently gets no value.")
    if misordered:
        print(f"FOUND {len(misordered)} use(s) BEFORE the assigning file is sourced:")
        for path, n, name, src in misordered:
            print(f"  {path}:{n}  ${name} is not assigned until {src}")
    return 1


if __name__ == '__main__':
    sys.exit(main())
