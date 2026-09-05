# Contributing to WASP

## Licensing of contributions

**By submitting a contribution — a pull request, patch, issue containing code,
or any other material — you agree that it is licensed to IronVeil Systems and
to all recipients of this software under the same MIT terms as the project
itself.**

This is the standard "inbound equals outbound" arrangement. It means:

- Your contribution can be merged, redistributed, relicensed as part of the
  project, and used commercially, on the same terms as the rest of WASP.
- You keep copyright in what you wrote. You are granting a licence, not
  assigning ownership.
- You confirm you have the right to grant that licence — that the work is
  yours, or that your employer permits it.

No separate CLA to sign. Opening a pull request is the agreement.

## What this does and does not secure

Worth stating plainly, because it is commonly misunderstood.

**Improvements made in a fork that remains MIT-licensed can be merged back
into this project.** MIT already permits that; it does not need a special
clause, and any suggestion that one is required would be misleading.

**Improvements made in a fork that is relicensed cannot.** MIT permits
derivative works to be released under different terms, including proprietary
ones. If someone forks WASP, improves it, and ships their version under a
closed licence, those improvements are theirs. No wording in this repository's
licence can reach work by someone who never agreed to it — a licence grants
rights to others, it cannot take rights from them.

If closing that gap ever matters more than permissive adoption does, the
mechanism is a copyleft licence such as **AGPL-3.0**, which requires
derivative works to be published under the same terms. That is a genuine
trade: copyleft protects the commons and deters commercial adoption, and MSPs
evaluating a platform frequently rule out AGPL on sight. This project chose
MIT deliberately. Changing it later would require the agreement of every
contributor whose work is in the tree, which is one reason these terms exist
from the start.

*Nothing here is legal advice. If the licensing model matters commercially,
have a solicitor look at it.*

## Before opening a pull request

Run the full suite. It is fast and it will catch most of what review would:

```sh
./test/run-all-checks.sh
```

That runs every static check, the syntax sweep across `bash`, `sh` and `dash`,
`php -l` on the mu-plugins, the fail-closed negative tests, and the MFA
harness. A red suite will not be merged.

## What gets merged

**Fixes with evidence.** The most valuable contributions to this project have
come from install logs on real hardware, not from reading the source. If you
hit a bug, the log is worth more than the patch.

**Controls that fail closed.** Every guard here refuses when its condition
fails. A new control needs a negative test in `test/test-fail-closed.sh`
proving it refuses, not only that it permits.

**Comments that explain the reasoning.** Roughly half the shell in this
repository is comments, deliberately. Several fixes here look wrong at a
glance and are correct for reasons that cost a day to discover. If your change
has a subtlety, write it down where the next person will find it.

## What will not be merged

- Changes that widen a trust boundary without a stated reason and a test
- New `source` of any operator-editable config file — parse it, do not execute
  it (see `test/check-config-sourcing.py` for why)
- Suggested commands that have not been run — a printed command that fails on
  paste is worse than no suggestion at all
- Version bumps without verifying the tag or digest actually exists upstream

## Reporting a security issue

Do not open a public issue. Email **security@ironveil.systems** with enough
detail to reproduce it. If it affects deployed installations we will
prioritise a fix and a signed release over anything else in progress.
