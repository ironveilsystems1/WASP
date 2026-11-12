# Signing a WASP release

The release key is at **`minisign._wasp.ironveil.systems`** — that TXT record is
the second, independent place an operator can check the key, and it is the one
value in this document you cannot change without telling every client.

Everything here runs on your **build machine**. The secret key never goes on a
Proxmox host and never on a provisioned VM.

**The signing tool is not in this repository.** `wasp-sign-release.sh` only
ever runs on the machine holding the secret key, so shipping it to every
deployment added a root-run script nobody there could use. It lives with the
key. Everything it does is plain `minisign` and `sha256sum`, written out below,
so a release can be signed and checked without it:

```sh
minisign -G -p ~/.minisign/wasp.pub -s ~/.minisign/wasp.key    # once, ever
# publish the key line of wasp.pub as the TXT record             # once
test/run-all-checks.sh                                         # every release
{ printf '%s\n' install.sh; find lib payload hive -type f ! -path '*/__pycache__/*' | LC_ALL=C sort; } \
  | xargs sha256sum > MANIFEST.sha256                          # every release
minisign -Sm MANIFEST.sha256 -s ~/.minisign/wasp.key -t "WASP <ver> — signed <UTC> — <commit>"
minisign -Vm MANIFEST.sha256 -P "$(sed -n 's/^WASP_PUBKEY="\${WASP_PUBKEY:-\(RW[^}]*\)}".*/\1/p' install.sh)" \
  && sha256sum -c --quiet MANIFEST.sha256                      # prove it
```

---

## What the installer actually verifies

Worth knowing before signing, because a release exists to satisfy exactly
this and nothing else:

| | `install.sh` checks | Fails when |
|---|---|---|
| 1 | `WASP_PUBKEY` is non-empty (it is now the default inside `install.sh`) | reports *"this build is unsigned"* and refuses |
| 2 | `MANIFEST.sha256` and `.minisig` both present | *"no signed manifest in this release"* |
| 3 | `minisign -Vm MANIFEST.sha256 -P "$WASP_PUBKEY"` | *"the release manifest signature is NOT valid"* |
| 4 | `sha256sum -c MANIFEST.sha256` from the release root | *"a file does not match the signed manifest"* |
| 5 | the key matches the TXT record | KEY MISMATCH — a prompt, not fatal |

`hive/install-hive.sh` (the WASP Hive fleet console, since 10.12) makes the
same signature check against the same key, which it reads from `install.sh`.
It then checks the `hive/` lines of the manifest, and refuses a manifest that
does not list `hive/`.

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
minisign -G -p ~/.minisign/wasp.pub -s ~/.minisign/wasp.key
chmod 600 ~/.minisign/wasp.key
```

Writes `~/.minisign/wasp.key` and `~/.minisign/wasp.pub`. Use a strong
passphrase — it is the only thing protecting the key if the build machine is
compromised, and minisign asks for it on every signature, which is the point.

**Back it up to two places before you sign anything.** Losing it does not
invalidate existing releases — they still verify — but you cannot sign new
ones, and every client has to be told to trust a replacement key. Record both
locations in [KEY-CUSTODY.md](KEY-CUSTODY.md) under *Release signing*.

minisign refuses to overwrite an existing key without `-f`. Do not add it:
generating a key on a machine that already has one is almost always a mistake
rather than a rotation.

---

## One time: publish the DNS record

The value is the second line of `wasp.pub`:

```sh
sed -n 2p ~/.minisign/wasp.pub
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

From the root of the exact tree you are publishing:

```sh
git status --short                      # 1. nothing uncommitted
BUSYBOX=/path/to/busybox test/run-all-checks.sh     # 2.
{ printf '%s\n' install.sh; find lib payload hive -type f ! -path '*/__pycache__/*' | LC_ALL=C sort; } \
  | xargs sha256sum > MANIFEST.sha256   # 4.
minisign -Sm MANIFEST.sha256 -s ~/.minisign/wasp.key \
  -t "WASP 10.14 — signed $(date -u +%Y-%m-%dT%H:%M:%SZ) — $(git rev-parse --short HEAD)"   # 5.
```

In order, and the order is the point:

1. **A clean tree.** A signature's only meaning is *this is what the project
   published*; signing whatever happens to be in the working directory empties
   it out.
2. **The full suite, BusyBox run included.** A signature says the files are
   authentic, not that they work. Signing a build that fails its own checks
   publishes the failure with a guarantee attached.
3. **The public key is already in `install.sh`**, as the default of
   `WASP_PUBKEY`. Only a key rotation changes it, and then it must change
   *before* step 4.
4. **`MANIFEST.sha256`** over `install.sh` and every file under `lib/` and
   `payload/`, sorted, with no extension filter. That is the set
   `check-manifest-coverage.py` enforces.
5. **The signature**, with a trusted comment naming the version and commit.
6. **Verify exactly as `install.sh` does** — the next section.

Any change to `install.sh`, `lib/` or `payload/` after step 4 — a version
bump, a comment — means steps 4 and 5 again. A web upload of new files without
a new `.minisig` publishes a release that every install refuses, which is the
check working.

### The ordering trap

`install.sh` is **in** the manifest, and the public key is embedded **in**
`install.sh`. So embedding the key changes `install.sh`, which changes its
hash.

**Embed, then hash, then sign.** Any other order produces a release whose
signature is valid and whose `sha256sum -c` fails on `install.sh` — which
`install.sh` reports as *"the signature was valid, so the manifest itself is
authentic — which means a shipped file was modified after signing"*. In other
words, indistinguishable from tampering, caused by signing in the wrong order.

Since the key became the default in `install.sh` this only bites on a key
rotation. The same thing happens if you edit **anything** after signing — including bumping
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
K=$(sed -n 's/^WASP_PUBKEY="\${WASP_PUBKEY:-\(RW[^}]*\)}".*/\1/p' install.sh)
[ -n "$K" ] && echo "1. key embedded"
[ -f MANIFEST.sha256 ] && [ -f MANIFEST.sha256.minisig ] && echo "2. manifest and signature present"
minisign -Vm MANIFEST.sha256 -P "$K" && echo "3. signature valid"
sha256sum -c --quiet MANIFEST.sha256 && echo "4. every file matches"
python3 test/check-manifest-coverage.py                  # 5.
dig +short TXT minisign._wasp.ironveil.systems | tr -d '"' | grep -qxF "$K" && echo "6. DNS matches"
```

The same checks `install.sh` will run, in the same order, plus two it cannot:

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
# sign and check, as above, then:
git add MANIFEST.sha256 MANIFEST.sha256.minisig && git commit -m "Release 10.11 — signed"
git tag -a v10.11 -m "WASP 10.11"
git push && git push --tags
```

**Publishing through the GitHub web upload** works the same way with one
difference: an upload adds and replaces files but never deletes any. Upload the
whole tree with both manifest files in the same commit, then delete by hand
anything the release removed. A file left behind is outside the manifest if it
is outside `lib/` and `payload/`, and is caught by
`check-manifest-coverage.py` if it is inside them.

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

1. Generate a new keypair with the old key moved aside, and put the new key
   line in `install.sh` as the default of `WASP_PUBKEY`.
2. Publish the new record, **replacing** the old one. Two TXT
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
| *"this build is unsigned"* | `WASP_PUBKEY` empty in `install.sh`. Put the key line back as its default, then re-hash and re-sign. |
| *"no signed manifest in this release"* | the `.minisig` was not shipped alongside the manifest. |
| Signature valid, hashes fail | something changed after signing — commonly a file uploaded or edited without re-hashing, or the key embedded after hashing. Re-hash and re-sign. |
| Signature invalid | wrong key, or the manifest was altered. Not a re-sign; find out which. |
| KEY MISMATCH on a client | the DNS record and their `install.sh` disagree. Either a rotation they have not picked up, or an `install.sh` that is not yours. |
| *"minisign is not installed"* | on the operator's host. `apt install minisign`. Not downgraded to hashes-only, deliberately — hashes from an unverified manifest catch corruption, not tampering. |
| No record at the DNS name | not published, or the resolver cannot see it. The installer skips the cross-check and says so. |

---

## Known gap

**`tools/` is not in the signed manifest.** The manifest covers `install.sh`,
`lib/` and `payload/` — what executes during an install or lands on the VM —
and `test/check-manifest-coverage.py` enforces exactly that set.
`tools/wasp-topology.sh` runs as root on the Proxmox host and is unsigned. (The
signing tool no longer ships, and the external pentest harness moved to its
own project, so it is the last one.)

Widening the set is a change to the release trust boundary: the manifest, the
check, and `verify_release()` all have to move together. Recorded in
[STACK-DESIGN.md](STACK-DESIGN.md) for a decision rather than changed as a side
effect of adding a tool.
