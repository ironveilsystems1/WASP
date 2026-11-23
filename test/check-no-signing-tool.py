#!/usr/bin/env python3
"""The release-signing tool must not be in the public repository.

wasp-sign-release.sh is the operator's tool and stays with the release key.
It was in tools/ for an unpublished release; a copy dropped into a tree to
run it would be uploaded with that tree. This fails on any file named
wasp-sign-release* in the repository (and .gitignore lists the name, for git;
a browser upload does not read .gitignore, which is why this check exists).
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
found = []
for d, dirs, files in os.walk(ROOT):
    dirs[:] = [x for x in dirs if x != ".git"]
    for f in files:
        if f.startswith("wasp-sign-release"):
            found.append(os.path.relpath(os.path.join(d, f), ROOT))
if found:
    print("Signing-tool check: FOUND the release-signing tool in the repository:")
    for f in sorted(found):
        print("  " + f)
    print("  It stays with the key. Remove it before uploading.")
    sys.exit(1)
print("Signing-tool check: CLEAN — the release-signing tool is not in the repository")
