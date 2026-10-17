#!/usr/bin/env python3
"""
check-seterr-capture.py — `_out=$(cmd); _rc=$?` is a trap under `set -e`.

WHY THIS EXISTS

This idiom looks like careful error handling and is the opposite:

    _out=$(some_command 2>&1); _rc=$?     # WRONG under set -e

A variable assignment takes the exit status of the command substitution. Under
`set -e` a failing command therefore kills the script AT THE ASSIGNMENT, and the
`_rc=$?` on the same line -- along with every bit of judgement written to use
it -- never runs.

It cost a real install. Stage 08 captured a plugin-install command this way; the
install failed, the stage died silently after printing only its header, and the
fourteen tool installs and the entire following stage never happened. The
operator was left with a box missing validate-wordpress.sh, the backups and the
menu, with no error explaining why.

The safe form guards the assignment so `set -e` cannot act on it:

    _rc=0
    _out=$(some_command 2>&1) || _rc=$?

This flags the unguarded form in any script that sets -e, or that is sourced
into one.
"""

import glob
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# assignment from $( ), then `; _rc=$?` on the SAME line, with no || guard.
BAD_RE = re.compile(r"^[^#\n]*?[A-Za-z_][A-Za-z0-9_]*=\$\([^\n]*\)\s*;\s*[A-Za-z_][A-Za-z0-9_]*=\$\?")

# ── A SECOND SHAPE, DELIBERATELY NOT AUTOMATED ───────────────────────────────
#
# This one shipped in wasp-sign-release.sh:
#
#     TRUSTED="... $([ -d .git ] && printf ' — %s' "$(git rev-parse ...)")"
#
# When .git is absent the substitution's last command is the failed test, so
# under `set -e` the ASSIGNMENT exits 1 and the script dies — having printed
# the line before it and nothing else. Harder to diagnose than a crash: no
# error, no output, and the command the operator was waiting on never ran. It
# read as a hung passphrase prompt.
#
# A rule for it WAS written and then removed, because it cannot be done with a
# line regex. Flagging "an assignment whose $( ) contains && or || without a
# fallback" produced nine false positives on correct code in this tree:
#
#   * `awk '$1>=a && $1<=b'`        — && inside awk PROGRAM TEXT, not shell
#   * `sed 's|^\./||'`              — the sed delimiters read as ||
#   * `_x=$(cmd) || _x=0`           — a trailing guard the pattern cannot see
#   * `$(date ... || date ...)`     — a fallback that is not true/:/echo
#
# Shell operators are not distinguishable from quoted program text by a
# per-line pattern, and a check that is wrong nine times out of ten gets
# suppressed or makes the suite permanently red. Both are worse than a comment.
#
# So: no rule. The shape is recorded here for review, and the symptom to
# recognise is a `set -e` script that stops after printing one line, with no
# error — look at the assignment immediately after that line.
#
# What DID change: tools/ is now in the scanned set (see main()), because that
# is where this bug lived and the check could not see the file at all.


def scan(paths):
    problems = []
    for path in paths:
        text = open(path, encoding="utf-8", errors="replace").read()
        for n, line in enumerate(text.split("\n"), 1):
            if BAD_RE.match(line):
                problems.append((path, n, line.strip()))
    return problems


def self_test():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        bad = os.path.join(d, "bad.sh")
        open(bad, "w").write("set -e\n_out=$(cmd 2>&1); _rc=$?\n")
        assert scan([bad]), "self-test: unguarded capture not detected"

        good = os.path.join(d, "good.sh")
        open(good, "w").write("set -e\n_rc=0\n_out=$(cmd 2>&1) || _rc=$?\n")
        assert not scan([good]), "self-test: guarded capture wrongly flagged"

        comment = os.path.join(d, "c.sh")
        open(comment, "w").write("# _out=$(cmd); _rc=$?\n")
        assert not scan([comment]), "self-test: commented example flagged"

    return True


def main():
    self_test()
    files = sorted(
        glob.glob(os.path.join(REPO, "payload", "**", "*.sh"), recursive=True)
        + glob.glob(os.path.join(REPO, "lib", "*.sh"))
        # tools/ added after a `set -e` capture bug shipped in
        # wasp-sign-release.sh and this check could not see it. These run as
        # root on the Proxmox host and use `set -euo pipefail`, which is
        # exactly the condition that makes an unguarded capture fatal — the
        # script stops with no error and no output, which is harder to
        # diagnose than a crash. Excluded from check-doas-prefix.py for a
        # different and still-correct reason (Proxmox uses sudo, not doas);
        # that exclusion is not a reason to exclude them here.
        + glob.glob(os.path.join(REPO, "tools", "*.sh"))
        + [os.path.join(REPO, "install.sh")]
    )
    files = [f for f in files if os.path.exists(f)]
    problems = scan(files)
    if problems:
        print(f"FOUND {len(problems)} unguarded capture(s):")
        for path, n, line in problems:
            print(f"  {os.path.relpath(path, REPO)}:{n}: {line}")
        print()
        print("  Under set -e the assignment inherits the command's exit status,")
        print("  so a failure kills the script before the _rc is ever read.")
        print("  Use:  _rc=0 ; _out=$(cmd) || _rc=$?")
        return 1
    print(f"set -e captures: CLEAN — {len(files)} scripts, no unguarded $( ) captures")
    return 0


if __name__ == "__main__":
    sys.exit(main())
