# WASP 10.3

**Release 10.3** · WordPress 7.1 · Alpine 3.24 · MariaDB 11.4 · CrowdSec v1.7.8

Two security additions, a contact handler that removes the need for a plugin,
and a batch of documentation fixes — every one of which came from a real
deployment going slower than it should have because the documentation told an
operator something untrue.

**Versioning has changed.** There is now one number rather than a semantic
release plus a date build stamp. The build stamp was wrong for weeks — reading
`2026.08.x` through most of September — because nothing verified it and nobody
reads a build stamp closely enough to notice. An identifier that is silently
wrong is worse than one carrying less information.

---

## Username privacy — enumeration closed

WordPress leaks usernames three ways: the REST users endpoint, `?author=N`
redirects, and login errors distinguishing "unknown username" from "incorrect
password". Most guides rate that low severity — a username still leaves the
password.

**It matters more here, because the login guard locks accounts by username.**
An attacker who learns an administrator's login name can lock that
administrator out repeatedly, escalating to twenty-four hours, without going
near the password. That turns a protective control into a denial-of-service
against the client, and from outside it looks like a broken site.

All three routes closed, plus password-reset errors. The REST endpoint is
restricted rather than removed, since the block editor needs it.

## Slow-drip attacks — the window the rate limit cannot see

Every existing limit counts within a 20-minute rolling window that resets after
20 minutes of quiet. An attacker who stays under it is never counted:

```
4 attempts, wait 21 minutes, repeat   →  288 guesses/day, no lockout ever
1 per IP per hour across 1000 hosts   →  24,000 guesses/day, nothing near
                                          any threshold
```

CrowdSec does not close it either — 6 failures in 10 minutes is tighter still.
Short windows stop a burst and are blind to patience.

A second counter runs alongside: 20 failures per username per 24 hours,
deliberately generous, and **not reset on success** — an attacker who finally
guesses right should not erase the thousand attempts before it.

## Contact handler — one less plugin

`payload/mu-plugins/05-wasp-contact.php` takes a form POST and emails it
through the relay the VM already has. No admin screen, no stored submissions,
and being an mu-plugin it cannot be deactivated from wp-admin.

It exists so a contact-form plugin is not needed. The usual options are tens of
thousands of lines, an admin UI, a submissions table and a supply-chain
dependency, to accomplish "take three fields and email them" — and they are
over-represented in WordPress vulnerability disclosures, because they accept
unauthenticated input by definition and sit on millions of sites.

**The recipient is decided server-side and never read from the request.** A
handler that emails whatever address the form supplies is an open relay: anyone
POSTs to it and your server sends mail to anybody, carrying your domain's
reputation. The recipient here comes from `admin_email`, a `wp-config.php`
constant, or a PHP filter.

Works with any form — three required attributes, filterable field names, and
extra fields appear in the email automatically. Two limits are documented
rather than left to be found: no CSRF nonce (with the reason, and a nonce IS
verified when present), and the rate limit keys on `REMOTE_ADDR`, which behind a
misconfigured proxy makes every visitor share one bucket.

```html
<form method="post" action="/wp-admin/admin-post.php">
  <input type="hidden" name="action" value="wasp_contact">
  <input type="text" name="website" tabindex="-1" autocomplete="off"
         style="position:absolute;left:-9999px" aria-hidden="true">
  <input name="name"><input name="email" type="email">
  <textarea name="message"></textarea>
</form>
```

---

## Upstream version detection — `update.sh upstream`

`digest-check` compares the **pinned tag** against its current digest. It
detects a tag being re-published — a rebuild or a supply-chain swap — and
cannot detect a newer release existing. A clean report was reasonably read as
answering both questions, which is how a deliberate pin becomes a stale pin.

`update.sh upstream` enumerates registry tags and reports anything newer, for
WordPress, MariaDB and CrowdSec. It changes nothing. Tag patterns are derived
from the pin's own shape, pre-releases are excluded, and `sort -V` orders
`v1.10.0` above `v1.9.0`.

`update.sh check` now states the limit of what it checked and names the other
command.

---

## Documentation that was wrong

Three defects in one paragraph, each found by an operator following it.

**Every `scp` example was unrunnable.** The installer writes `sshd_config` with
no `Subsystem sftp`, and OpenSSH 9+ uses SFTP for `scp` by default —
`subsystem request failed on channel 0`, which reads like a network fault.
`scp -O` is now primary everywhere.

**`rsync` was recommended as "already installed".** It is installed only when
the off-site backup method is `rsync`. The failure is remote-side and reads
like a transport problem. Now documented as an option with the one-line
install, and why it is not present by default.

**`install-file` reported "No such file" for a file present under different
case.** It now suggests the correct name, lists the directory when there is no
near match, and names the transfer flag when the directory is empty.

New check: `check-tool-availability.py` fails the build if a document uses a
conditionally-installed tool as a primary instruction.

---

## Theme updates under DISALLOW_FILE_MODS

`DISALLOW_FILE_MODS` removes the **update** UI as well as the install UI, so a
commercial theme with a newer version shows no update section even with a valid
licence and working egress. Correct, and easily misread as an egress fault.

Now documented — `install-file` with the newer zip replaces in place, settings
survive — and stated by the tooling rather than only in a document.
`wp-hardening.sh status` reports the consequence next to the flag.

---

## Guided destination and credential changes

`set-destination` decomposes your current value and prints the exact string to
type, instead of describing an abstract format:

```
Current destination:  wasp-s3:test/wasp/ctrl
  remote    wasp-s3       the rclone remote — normally leave this alone
  bucket    test          your bucket at the storage provider
  prefix    wasp/ctrl     a folder path inside the bucket

  To change only the bucket to (say) 'testpress', enter:
      wasp-s3:testpress/wasp/ctrl
```

It names the two failures indistinguishable from a typo: the bucket must exist,
and the token must be scoped to the **new** bucket — object storage returns 403
rather than 404 for a bucket a caller cannot see.

---

## Also in this release

- `check-no-client-material.py` — customer-specific documents cannot ship
  inside the platform
- `check-stale-branding.py` — a superseded organisation or DNS name anywhere in
  the tree fails the build
- `CONTRIBUTING.md` — contributions licensed inbound on the same MIT terms,
  with an honest statement of what that does and does not secure against a
  relicensed fork
- `docs/VALIDATION.md` — 96 hardware cycles since 2026-06-23, what they found
  that review could not, and what remains unproven

---

## Upgrading

No migration required. Existing VMs are unaffected until re-provisioned.

- **`update.sh upstream` may report releases you were not tracking.** Nothing
  updates automatically. Verify a tag exists before pinning it — a version
  number is not a tag.
- **If your own runbooks contain `scp` commands**, they need `-O`.

---

## Verified

25 static checks · 27 fail-closed negative tests · syntax swept across `bash`,
`sh` and `dash` · `php -l` on every mu-plugin · 21-case MFA harness · a full
commission check passing 10 of 10 on hardware.

Signed with minisign:

```sh
minisign -Vm MANIFEST.sha256 -P "$(dig +short TXT minisign._wasp.ironveil.systems | tr -d '"')"
sha256sum -c MANIFEST.sha256
```

A production install refuses to proceed unverified. For a development checkout,
`WASP_DEV_UNVERIFIED=1 ./install.sh` builds a VM permanently marked unverified.
