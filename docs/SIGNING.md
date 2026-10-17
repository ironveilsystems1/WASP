# Signing a WASP release

The release key is at **`minisign._wasp.ironveil.systems`** — that TXT record is
the second, independent place an operator can check the key, and it is the one
value in this document you cannot change without telling every client.

Everything here runs on your **build machine**. The secret key never goes on a
Proxmox host and never on a provisioned VM.

```sh
./tools/wasp-sign-release.sh --keygen     # once, ever
./tools/wasp-sign-release.sh --dns        # publish the TXT record
./tools/wasp-sign-release.sh              # sign a release
./tools/wasp-sign-release.sh --check      # prove it before publishing
```

---

## What the installer actually verifies

Worth knowing before signing, because the script exists to produce exactly
this and nothing else:

| | `install.sh` checks | Fails when |
|---|---|---|
| 1 | `WASP_PUBKEY` is non-empty | reports *"this build is unsigned"* and refuses |
| 2 | `MANIFEST.sha256` and `.minisig` both present | *"no signed manifest in this release"* |
| 3 | `minisign -Vm MANIFEST.sha256 -P "$WASP_PUBKEY"` | *"the release manifest signature is NOT valid"* |
| 4 | `sha256sum -c MANIFEST.sha256` from the release root | *"a file does not match the signed manifest"* |
| 5 | the key matches the TXT record | KEY MISMATCH — a prompt, not fatal |

**3 and 4 are different questions and both matter.** The signature proves the
manifest is authentic; the hashes prove the shipped files match that manifest.
A release with only one of them is not verified.

**5 is corroboration, not proof.** Without DNSSEC on the zone a resolver on the
network path could return that answer, and `install.sh` says so rather than
implying otherwise. It is not fatal because a stale checkout after a legitimate
rotation would otherwise brick every install — the signature is the control
that decides authenticity.

Under the production profile an unverified install is **refused outright**;
there is no bypass. A development checkout uses
`WASP_DEV_UNVERIFIED=1 ./install.sh`, and the VM is permanently stamped
UNVERIFIED and can never be certified.

---

## One time: generate the keypair

```sh
./tools/wasp-sign-release.sh --keygen
```

Writes `~/.minisign/wasp.key` (0600) and `~/.minisign/wasp.pub`. Use a strong
passphrase — it is the only thing protecting the key if the build machine is
compromised, and minisign asks for it on every signature, which is the point.

**Back it up to two places before you sign anything.** Losing it does not
invalidate existing releases — they still verify — but you cannot sign new
ones, and every client has to be told to trust a replacement key. Record both
locations in [KEY-CUSTODY.md](KEY-CUSTODY.md) under *Release signing*.

The script refuses to overwrite an existing key, because `--keygen` on a
machine that already has one is almost always a mistake rather than a rotation.

---

## One time: publish the DNS record

```sh
./tools/wasp-sign-release.sh --dns
```

```
Name   minisign._wasp.ironveil.systems
Type   TXT
TTL    3600
Value  RWS...          ← the key line only
```

**The value is the key line only.** Not the comment line above it in
`wasp.pub`, not a `minisign public key:` prefix, and not quotes you add
yourself. `install.sh` greps the answer for `^RW` and compares byte for byte,
so one extra character is a mismatch — and a mismatch is reported to the
operator as *either* a rotated key *or* an `install.sh` that did not come from
you. That is the right warning to get for the right reason and the wrong one to
get from a stray space.

Some panels add the quotes. Check the result, not what you typed:

```sh
dig +short TXT minisign._wasp.ironveil.systems
```

Expect **exactly one** line. More than one TXT record on that name is a
problem: `install.sh` takes the first `RW` line it sees, so a stale record can
win.

**Enable DNSSEC on the zone.** With it, `install.sh` reports
*"(DNSSEC-validated)"*; without it, it prints the caveat in full. The record
should also not live on the same system as the key — two independent places is
the entire value of having it.

---

## Every release: sign

From the root of a clean checkout:

```sh
./tools/wasp-sign-release.sh
```

In order, and the order is the point:

1. **Refuses a dirty tree.** Uncommitted changes under `install.sh`, `lib/` or
   `payload/` prompt before continuing. A signature's only meaning is *this is
   what the project published*; signing whatever happens to be in the working
   directory empties it out.
2. **Runs `test/run-all-checks.sh` first.** A signature says the files are
   authentic, not that they work. Signing a build that fails its own checks
   publishes the failure with a guarantee attached.
3. **Embeds the public key in `install.sh`.**
4. **Builds `MANIFEST.sha256`** over `install.sh`, `lib/` and `payload/`.
5. **Signs it**, with a trusted comment naming the version and commit.
6. **Verifies exactly as `install.sh` does**, both the signature and the
   hashes.

### The ordering trap

`install.sh` is **in** the manifest, and the public key is embedded **in**
`install.sh`. So embedding the key changes `install.sh`, which changes its
hash.

**Embed, then hash, then sign.** Any other order produces a release whose
signature is valid and whose `sha256sum -c` fails on `install.sh` — which
`install.sh` reports as *"the signature was valid, so the manifest itself is
authentic — which means a shipped file was modified after signing"*. In other
words, indistinguishable from tampering, caused by signing in the wrong order.

The script enforces the order. The trap is still worth knowing, because the
same thing happens if you edit **anything** after signing — including bumping
a version or fixing a typo in a comment. Re-sign; never hand-edit a signed
tree.

### The trusted comment

```
Trusted comment: WASP 10.4 — signed 2026-10-17T20:21:48Z — a1b2c3d
```

`minisign -t` puts this **inside the signature**, so it cannot be altered
without the secret key, and `install.sh` prints it. That makes it the one place
a version string is trustworthy: an attacker can relabel a tarball or a GitHub
release title, but not this.

---

## Every release: prove it before publishing

```sh
./tools/wasp-sign-release.sh --check
```

Runs the same checks `install.sh` will, in the same order, plus two it cannot:

- **manifest coverage** — a valid signature over an *incomplete* manifest
  verifies perfectly and leaves files unsigned. A file added after the last
  signing is caught here.
- **the DNS cross-check**, so a key rotation that was never published is found
  by you and not by a client.

```
  1. WASP_PUBKEY embedded in install.sh        yes
  2. manifest and signature present            yes
  3. signature valid for the embedded key      yes
       Trusted comment: WASP 10.4 — signed 2026-10-17T20:21:48Z
  4. every file matches its hash               yes
  5. manifest covers the whole signed set      yes
  6. DNS record matches the embedded key       yes
```

Anything other than six `yes` is not a publishable release.

---

## Publishing

Ship `MANIFEST.sha256` and `MANIFEST.sha256.minisig` alongside `install.sh`,
`lib/` and `payload/`.

A GitHub release tarball built from the commit you signed already contains
them. **A tarball built from a tag you signed before committing the embedded
key does not** — the key is in your working copy and not in the tag, so the
tarball's `install.sh` has a different hash and every install fails check 4.

So: sign, commit, tag, release. In that order.

```sh
./tools/wasp-sign-release.sh
./tools/wasp-sign-release.sh --check
git add -A && git commit -m "Release 10.4 — signed"
git tag -a v10.4 -m "WASP 10.4"
git push && git push --tags
```

---

## What an operator runs

Worth being able to recite, because it is what you tell a client to do when
they ask how they know what they are installing:

```sh
minisign -Vm MANIFEST.sha256 \
  -P "$(dig +short TXT minisign._wasp.ironveil.systems | tr -d '"')"
sha256sum -c MANIFEST.sha256
```

The first proves the manifest came from you. The second proves the files match
it. `install.sh` does both automatically and refuses to proceed unverified
under the production profile — these are for someone who wants to check by
hand, which is a reasonable thing to want before running a script as root on
their hypervisor.

---

## Rotating the key

Only when the secret key is lost or you believe it is compromised. A rotation
costs every client a trust decision, so it is not routine maintenance.

1. `--keygen` with the old key moved aside.
2. `--dns` and publish the new record, **replacing** the old one. Two TXT
   records means `install.sh` compares against whichever comes first.
3. Re-sign the current release with the new key and publish it.
4. Tell every client, and expect KEY MISMATCH prompts from anyone holding a
   stale `install.sh` — which is the warning working correctly.

Existing releases signed with the old key **still verify with the old key** and
stop verifying against the new record. If the old key was compromised rather
than lost, re-sign anything you still want people installing, and say plainly
which releases are affected.

---

## If something is wrong

| Symptom | Cause |
|---|---|
| *"this build is unsigned"* | `WASP_PUBKEY` empty in `install.sh`. Sign, which embeds it. |
| *"no signed manifest in this release"* | the `.minisig` was not shipped alongside the manifest. |
| Signature valid, hashes fail | something changed after signing — commonly the key was embedded after hashing. Re-sign. |
| Signature invalid | wrong key, or the manifest was altered. Not a re-sign; find out which. |
| KEY MISMATCH on a client | the DNS record and their `install.sh` disagree. Either a rotation they have not picked up, or an `install.sh` that is not yours. |
| *"minisign is not installed"* | on the operator's host. `apt install minisign`. Not downgraded to hashes-only, deliberately — hashes from an unverified manifest catch corruption, not tampering. |
| No record at the DNS name | not published, or the resolver cannot see it. The installer skips the cross-check and says so. |
| Script stops silently after a step | not expected; report it. A `set -e` script dying at an assignment prints nothing, and one such bug has already been fixed in this script. |

---

## Known gap

**`tools/` is not in the signed manifest.** The manifest covers `install.sh`,
`lib/` and `payload/` — what executes during an install or lands on the VM —
and `test/check-manifest-coverage.py` enforces exactly that set.
`wasp-sign-release.sh` and `wasp-topology.sh` both run as root on the Proxmox
host and are unsigned.

Widening the set is a change to the release trust boundary: the manifest, the
check, and `verify_release()` all have to move together. Recorded in
[STACK-DESIGN.md](STACK-DESIGN.md) for a decision rather than changed as a side
effect of adding a tool.
