#!/usr/bin/env python3
"""
check-tool-availability.py — docs must not instruct with tools the VM may lack.

WHY THIS EXISTS

The documentation recommended `rsync` as the primary way to move files onto the
VM, describing it as "already installed". It is installed only when the
off-site backup method is `rsync`; an s3 or rclone install does not have it.

An operator following that instruction got:

    sh: rsync: not found
    rsync: connection unexpectedly closed (0 bytes received so far) [sender]

which is a REMOTE-side failure that reads like a transport problem. That was
the third consecutive documentation defect in the same paragraph — first the
missing SFTP subsystem, then filename case, then this.

A documented command that cannot run is the same class of defect as a printed
command with no space in it: it fails at the moment someone is following
instructions because something has already gone wrong.

WHAT IT CHECKS

Commands used at the start of a shell line in a fenced block, checked against
the set of tools the installer unconditionally installs. Conditionally
installed tools must not appear as a primary instruction; mentioning one
alongside how to install it is fine, and the exemption below is how that is
expressed.
"""

import glob
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Installed only under some configurations. Naming one as the way to do
# something is a defect unless the same block says how to get it.
CONDITIONAL = {
    "rsync": "installed only when OFFSITE_METHOD=rsync",
    # Added when docs/IMPORT-FETCH.md was written. These come from the SAME
    # conditional as rsync -- payload/stages/08-update-tooling.sh installs all
    # three only for the matching off-site backup method -- and the check was
    # never generalised past the one tool whose absence caused the original
    # defect. A fetch guide is exactly the document that reintroduces it.
    "rclone": "installed only when OFFSITE_METHOD=s3/rclone",
    "sftp":   "openssh-client, installed only when OFFSITE_METHOD=rsync/scp",
}

# NOT listed, deliberately: `scp`. It is also from openssh-client, but in these
# documents it is almost always run on the OPERATOR'S WORKSTATION to copy
# something INTO the VM -- `scp -O file admin@vm:...` -- where the VM's package
# set is irrelevant. The check cannot tell that apart from a VM-side `scp` by
# the command name alone, so listing it would flag every correct example in the
# tree. A check that cries wolf on the common case is a check people learn to
# ignore, which costs more than the one case it would catch.

# A block that also explains installation is documenting an option, not
# assuming a tool.
INSTALL_HINT = re.compile(r"apk add\s+(\S+)")

# A package does not always share its binary's name, and the check cannot
# connect `apk add openssh-client` to `sftp` without being told. Without this
# the only way to satisfy the check was to write a misleading `apk add sftp`,
# which installs nothing -- a check that can only be satisfied by a wrong
# command is worse than no check.
PROVIDES = {
    "openssh-client": {"sftp", "scp", "ssh-keygen"},
    "openssh": {"sftp", "scp"},
}


def scan(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    problems = []
    for block in re.findall(r"```(?:sh|bash|console)?\n(.*?)```", text, re.S):
        installed = set(INSTALL_HINT.findall(block))
        for pkg in list(installed):
            installed |= PROVIDES.get(pkg, set())
        for n, line in enumerate(block.split("\n"), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            cmd = line.split()[0]
            if cmd in ("doas", "sudo") and len(line.split()) > 1:
                cmd = line.split()[1]
            if cmd in CONDITIONAL and cmd not in installed:
                problems.append((cmd, CONDITIONAL[cmd], line[:60]))
    return problems


def self_test():
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
        f.write("```sh\nrsync -av a b\n```\n"); bad = f.name
    assert scan(bad), "self-test: conditional tool not detected"
    os.unlink(bad)
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
        f.write("```sh\ndoas apk add rsync\nrsync -av a b\n```\n"); ok = f.name
    assert not scan(ok), "self-test: block that installs the tool was flagged"
    os.unlink(ok)

    # rclone and sftp come from the same conditional as rsync. The check knew
    # only about rsync until a fetch guide was written against the other two.
    for cmd in ("rclone ls remote:", "sftp user@host"):
        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
            f.write("```sh\n%s\n```\n" % cmd); b = f.name
        assert scan(b), "self-test: %r not detected as conditional" % cmd
        os.unlink(b)

    # A package whose name differs from its binary must satisfy the check.
    # Without the PROVIDES map the only way to pass was `apk add sftp`, which
    # installs nothing — a check satisfiable only by a wrong command.
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
        f.write("```sh\ndoas apk add openssh-client\nsftp user@host\n```\n"); ok2 = f.name
    assert not scan(ok2), "self-test: apk add openssh-client did not satisfy sftp"
    os.unlink(ok2)

    # scp is deliberately NOT conditional: in these documents it is almost
    # always run on the operator's workstation, where the VM's package set is
    # irrelevant, and flagging it would hit every correct example in the tree.
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
        f.write("```sh\nscp -O file admin@vm:/path/\n```\n"); wk = f.name
    assert not scan(wk), "self-test: workstation-side scp was flagged"
    os.unlink(wk)
    return True


def main():
    self_test()
    files = glob.glob(os.path.join(REPO, "*.md")) + glob.glob(os.path.join(REPO, "docs", "*.md"))
    problems = []
    for p in files:
        if os.path.basename(p) == "CHANGELOG.md":
            continue
        for cmd, why, line in scan(p):
            problems.append(f"{os.path.relpath(p, REPO)}: '{cmd}' — {why}\n      {line}")

    if problems:
        print(f"FOUND {len(problems)} instruction(s) using a tool the VM may not have:")
        for x in problems:
            print(f"  {x}")
        print()
        print("  A documented command that cannot run fails at the moment someone")
        print("  is following instructions because something already went wrong.")
        print("  Either use a tool that is always present, or show how to install")
        print("  it in the same block.")
        return 1

    print(f"Tool availability: CLEAN — {len(files)} documents, no assumed tools")
    return 0


if __name__ == "__main__":
    sys.exit(main())
