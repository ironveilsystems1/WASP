# Safe Site Import — design

A plan, not an implementation. Written first because the ordering of this
feature is the security property: get the sequence wrong and the tool becomes
the thing that infects the VM.

---

## The one rule everything else follows from

**Nothing from the archive may be reachable by the web server, or executed by
anything, until it has been scanned.**

That sounds obvious and is the step most import tooling skips. The natural
implementation — extract into the document root, then scan — means a webshell
is live and serving for however long the scan takes. On a site being imported
*because* it is suspected compromised, that window is the whole problem.

So: extract to a staging path outside the docroot, scan there, decide there,
and only then move. If the scan fails, nothing was ever reachable.

---

## Threat model

What an untrusted WordPress backup can contain, roughly in order of how often
it is missed.

### Archive level — before a single file is read

| Threat | Why it matters |
|---|---|
| **Path traversal (zip slip)** | `../../etc/cron.d/x` in a member name writes outside the extraction directory. `tar`/`unzip` will happily do this unless told not to |
| **Symlinks** | A symlink to `/etc/shadow` or into the live docroot turns a later copy into an arbitrary write |
| **Decompression bomb** | A few KB expanding to fill the disk, taking the live site down with it |
| **Control characters in names** | Terminal escape sequences in a filename, rendered when an operator lists the directory |

Extraction has to be bounded and validated before the contents are trusted at
all. This is the layer where a tool that "just untars it" has already lost.

### File level

- **Webshells in uploads** — the classic. Near-zero false positives to detect,
  because nothing legitimate puts executable PHP there — with one exception
  that must be decided by content, not name: the `index.php` directory-index
  guard (`<?php // Silence is golden.`) that plugins drop into each upload
  subdirectory. Reported as compromise, it was the loudest finding on the
  first real import, and it was a protection.
- **Disarmed but still present** — PHP renamed so it no longer runs
  (`<name>.php.bak`, `.disabled`, `.suspected`). It is what a previous cleaner
  does to a file they were afraid of, and no build tool produces it. On the
  first real import this was the malware itself, and nothing reported it.
- **Backdoored plugins and themes** — the hard case. A modified legitimate
  plugin looks entirely normal, and there is no pristine copy to compare a
  *nulled* plugin against.
- **mu-plugins** — worse than plugins, because they are **active on arrival**.
  There is no "activate" step to withhold. A malicious mu-plugin runs the
  first time WordPress loads. Only top-level `*.php` loads; the rest of the
  directory is inert, and saying otherwise about it is a false alarm.
- **Modified core** — detectable, and the one case where a good answer exists:
  discard the imported core entirely and use the pinned image's.
- **`.htaccess` handler injection** — `AddType application/x-httpd-php .jpg`
  makes an innocuous upload executable.
- **`wp-config.php`** — contains the *old* site's database credentials, salts
  and often `define()`s that disable security features. It must never be
  imported; the receiving VM's own config is authoritative.

### Database level — the layer most often skipped entirely

- **Autoloaded options containing code.** `wp_options` with `autoload=yes`
  runs on every page load. Maximum reliability, invisible in the filesystem,
  and survives every file-based clean.
- **Scheduled events.** The `cron` option holds serialised scheduled tasks. A
  backdoor scheduled here **re-infects the filesystem after you clean it**,
  and the operator concludes the malware "came back". This is the persistence
  mechanism most likely to be missed, and it is worth a dedicated check.
- **Rogue administrators**, and `usermeta` capability grants on accounts that
  do not look like admins.
- **Injected post content** — SEO spam, script tags, base64 blobs.
- **Serialised-data traps.** Search-and-replace on a URL inside serialised PHP
  corrupts string lengths. Not a security issue but a correctness one, and it
  breaks sites silently.

### Format-specific

- **Duplicator's `installer.php`** must be deleted, never executed. A
  left-behind Duplicator installer is a documented site-takeover vector; a
  tool that runs one as part of "restore" is doing the attacker's work. It is
  recognised by the whole package — `installer.php` beside its
  `*archive.zip`/`.daf`, or `dup-installer/` — and deleted only outside
  `wp-content`. Matching the file name alone hit Composer's `Installer.php`
  and deleted plugins' own `installer.php`.
- **cPanel account exports** put the site at `<account>/public_html/`. Every
  stage that looks at "the site" must look there, not at the archive root:
  a structural check pointed one level too high finds no `wp-content` and,
  unless it says so, passes.
- **UpdraftPlus** splits into several archives (`-db.gz`, `-plugins.zip`,
  `-themes.zip`, `-uploads.zip` and `-uploads2.zip`…, `-others.zip`, and
  optionally `-mu-plugins`, `-wpcore`, `-more`). They share the prefix
  `backup_<date>-<hhmm>_<site>_<12-hex nonce>`. Each zip holds the folders
  *inside* `wp-content`, so the set is one site only once every part is
  unpacked into one `wp-content`.
  - **Since 10.14, extract and restore do that.** Any one part (or the
    prefix) names the set.
  - **Checked first.** Every zip passes the hostile-member checks before any
    is unpacked, and the set is refused without its `-db.gz` or with an
    encrypted `.crypt` one.
  - **Unpacking.** Parts are unpacked with `unzip -n`, so two parts cannot
    overwrite each other.
  - **Skipped parts.** `-wpcore` and `-more` are not part of `wp-content` and
    are skipped.
  - **A missing part.** A missing `-plugins.zip` still yields a site that
    half-works, so `list` and `inspect` name every missing part.
- **`.wpress`** (All-in-One WP Migration) is a *custom* format, not an
  archive. Header per file: 255-byte name, 14-byte size, 12-byte mtime,
  4088-byte path, 8-byte CRC32 (the last two were one 4096-byte path before
  plugin 7.104), then data, terminated by a null block or, since 7.104, a block
  holding the archive's length and CRC32. Content may be gzip-chunked or
  AES-encrypted. `payload/lib/wasp-wpress-reader.php` carries the full layout.
  Its dump is not a normal dump: tables and keys use a `SERVMASK_PREFIX_`
  placeholder, and the theme and active plugins are blank, with the real values
  in `package.json`. The plugin restores them itself; any other importer must.

---

## Supported inputs

| Format | Detect by | Notes |
|---|---|---|
| **UpdraftPlus** | `backup_<date>_<site>_<nonce>-<part>` | Implemented (10.14). Any part names the set; checked whole, staged as one site |
| **Duplicator** | `*archive.zip` (or `.daf`) + `installer.php` beside it, or `dup-installer/` | Installer deleted on sight, outside `wp-content` |
| **All-in-One WP Migration** | `.wpress` | Implemented. Encrypted and gzip read; bzip2 and multisite refused |
| **BackWPup / generic** | `.tar.gz` / `.zip` + `.sql` | Best effort |
| **Manual** | a directory + a `.sql` file | The simplest and most predictable path |

Started with **UpdraftPlus and manual**. `.wpress` followed as a self-contained
reader.

---

## Pipeline

```
 1. INSPECT     identify format, list contents, refuse hostile members
 2. EXTRACT     to /var/lib/wasp-import/<id>/ — outside the docroot, noexec
 3. SCAN FILES  wp-malware-scan.sh --path <site root inside staging>
 4. SCAN DB     the dump file, before it is ever loaded
 5. REPORT      findings, with a class per finding
 6. GATE        operator decides, with the findings in front of them
 7. NORMALISE   discard core, wp-config, mu-plugins; keep content
 8. IMPORT      files into place, then the database
 9. RE-HARDEN   regenerate salts, reset admin, re-apply the slug and rules
10. VERIFY      re-scan the live site; validate-wordpress.sh
```

All ten steps are implemented in `wp-import.sh` (`inspect`, `extract`,
`scan`, `apply`). Step 3 runs at the **site root**, found the same way `apply`
finds it — the shallowest `wp-content` with `wp-includes` or `wp-config.php`
beside it — not at the top of staging, where a nested archive has no
`wp-content` and every structural check would pass on nothing.

### Step 2 — extraction is a security boundary

- Extract as an **unprivileged user**, into a directory mounted `noexec`
- Reject any member whose normalised path escapes the target
- Reject symlinks and hard links outright — a backup does not need them
- Cap total extracted size and file count; abort past either
- Never preserve ownership or setuid bits from the archive

### Step 4 — scan the dump, not the database

The existing `wp-malware-scan.sh db` queries a *live* database. Importing needs
the same analysis against a **dump file**, before it is loaded — a different
code path, and the point of the exercise. Loading it first and scanning after
is the same mistake as extracting into the docroot.

Grep-level checks are adequate here and avoid needing a throwaway MariaDB:
autoloaded options containing `eval(`/`base64_decode`/`<?php`, `INSERT` rows
into `wp_users` with administrator capabilities, and the serialised `cron`
option.

### Step 7 — normalisation is where most of the safety comes from

Discard rather than inspect, wherever a good replacement exists:

| Component | Action | Why |
|---|---|---|
| **WordPress core** | **Discard.** Use the pinned image's | A pristine, digest-verified copy already exists. Comparing is strictly worse than replacing |
| **`wp-config.php`** | **Discard.** Keep the receiving VM's | Contains the old site's credentials and salts, and often security-weakening defines |
| **`.htaccess`** | **Discard.** Regenerate | Handler injection lives here; the VM's own rules are known-good |
| **mu-plugins** | **Quarantine all, re-add ours** | Active on arrival, no activation step to withhold |
| **`wp-content/uploads`** | Import, minus anything executable (set aside with its path kept, as evidence) | Media is the point of the import |
| **Plugins / themes** | Import, then scan for known vulnerabilities | The genuinely hard case — see below |
| **Database** | Import after scanning, then re-harden | Content is the point |

**The honest weak spot is plugins and themes.** A backdoored copy of a
legitimate plugin is not reliably distinguishable from the real thing without
a reference — and for nulled or abandoned plugins no reference exists. The
realistic mitigation is to reinstall from wordpress.org anything whose slug
exists there, keeping only genuinely custom code, and to run
`wp-plugins.sh vulns` immediately after. That should be offered, and its limit
stated, rather than implied to be a solved problem.

### Step 9 — re-harden, because an import undoes hardening

The imported database carries the old site's `siteurl`, users and settings.
After import:

- Regenerate salts and keys — the old ones may be known to whoever had the site
- Force a password reset on every administrator, or at minimum report them
- Re-apply `WP_HOME`/`WP_SITEURL` for this deployment
- Re-apply the login slug and the wp-admin restriction
- **Re-assert `active_plugins`** — see below, this one disarms MFA
- Re-run `wp-plugins.sh vulns`, because you have just installed someone else's
  plugin set
- Clear the `cron` option and let WordPress rebuild it — the cheapest defence
  against the scheduled-task persistence above

#### `active_plugins` is not a cosmetic one

**Observed live on a client import, 2026-10-25.** The dump carries the old
site's `active_plugins` option, which replaces this deployment's. Every plugin
WASP installed is deactivated by that single row — **Two Factor included**.

What makes it dangerous rather than merely annoying is how it interacts with
the mu-plugins. Those are not listed in `active_plugins` and so survive the
import untouched. `03-wpvm-mfa-enforce` therefore stays loaded and enforcing
while the plugin that *provides* the second factor is gone — and that file is
deliberately written to no-op when `Two_Factor_Core` is absent, because
enforcing an unavailable requirement would lock out every administrator.

Correct behaviour in both files. Together: the site runs with MFA enforcement
loaded, reporting nothing, and no second factor on any account. It stayed that
way until a validator run happened to catch it.

So re-asserting `active_plugins` is not tidying up after the import — it is
the step that keeps authentication working. Capture the option before the
load, and after it merge WASP's entries back into whatever the dump brought.
Do not simply restore the pre-import value: the client's own plugins are the
reason for the import.

#### `user_nicename` comes across too

The imported users table brings the old site's slugs, which are usually the
old site's login names. `06-wasp-username-privacy` rewrites slugs for users it
creates, and nothing it hooks fires for rows that arrived in a dump.

Its one-time migration covers this by design: the `wpvm_nicename_migrated`
flag lives in the options table, so an imported database arrives without it
and the migration runs on the next wp-admin request. Worth knowing rather than
rediscovering — and worth checking after an import rather than assuming, since
the symptom is a published login name and there is no error either way.

---

## The gate

What happens when the scan finds something. The wrong answers are obvious in
both directions: refusing outright is useless because **people import
compromised sites deliberately, in order to clean them**, and proceeding
silently defeats the tool's only purpose.

| Findings | Default |
|---|---|
| None | Proceed, with a summary |
| SUSPICIOUS only | Proceed, findings listed and recorded |
| HIGH | Proceed only with `--accept-findings`, which is recorded |
| **CRITICAL** | **Refuse.** Override needs `--force` **and** typing the finding count |
| Hostile archive member | **Refuse. No override.** Nothing legitimate needs it |

Flagged files are **quarantined rather than imported** — the site comes up
without them, which is usually still a working site and is always a safer
starting point than one that boots with a webshell in place.

Every import writes a record: what was imported, what was found, what was
quarantined, who accepted what. Same shape as the vulnerability exception
log, and for the same reason — a decision nobody can reconstruct later is not
a decision anyone can defend.

---

## What it will not do

Stated so the tool does not imply otherwise:

- **It cannot certify a site clean.** It finds what the scanners find. A
  backdoor written for that specific site, or hiding in a plugin nobody has
  audited, passes.
- **It cannot detect a backdoored plugin without a reference copy.** Nulled
  and abandoned plugins have no reference. This is the largest gap and no
  amount of engineering closes it.
- **It will not run the source site's code**, including Duplicator's
  installer, which is the fastest way to lose the VM you are importing into.
- **It does not merge.** Import is into a fresh WASP deployment; merging two
  live sites is a different, much harder problem.
- **It does not fix the database's serialisation.** URL search-and-replace is
  delegated to `wp search-replace`, which handles serialised data correctly.
- **It does not yet look inside mu-plugins at `scan` time.** They are withheld
  at `apply`, and `inspect` lists them and any renamed PHP among them, but a
  live obfuscated mu-plugin passes the structural checks. See
  [TODO.md](../TODO.md#import-pipeline--open-after-the-first-real-import).

---

## Open questions

1. **Staging on disk or in a scratch volume?** A 5 GB site plus its extraction
   needs ~10 GB free on a 20 GB VM. Probably: check free space first and refuse
   early rather than filling the disk mid-extract — the failure mode of
   running out is a broken live site alongside a failed import.
2. **Import into a live VM, or provision fresh?** Fresh is much safer — the
   rollback is `qm destroy`. Importing into a running site means a failed
   import has already replaced the working one. Leaning strongly toward
   requiring a fresh deployment for v1.
3. ~~**`.wpress` reader in shell or Python?**~~ Neither. PHP, in the pinned
   wp-cli image that every VM already has, run with no network, a read-only
   root, no capabilities and an unprivileged uid. It adds no package to the VM,
   and a parser of hostile binary input is the code to keep off the host anyway.
4. **Where does the operator put the archive?** Uploading several GB over SSH
   to a VM is awkward. Options: `wasp-offsite-backup.sh`'s rclone remote,
   a URL fetch with checksum, or a Proxmox-side mount.

---

## Implementation order

1. `wp-import.sh inspect <path>` — identify, list, refuse hostile members.
   Read-only, no extraction. Useful on its own and the safest thing to build
   first.
2. Extraction with the bounds above, into staging.
3. Dump-file scanning, reusing the existing detection patterns.
4. The gate and the record.
5. Normalisation and import.
6. Re-hardening.
7. `.wpress`. Done.

All seven are done. Steps 1–3 alone were worth shipping: *"tell me what is in this backup before I
touch it"* is a real need on its own, and it is the part with no destructive
failure mode.

---

*Written as the plan; implemented through 10.7 (`.wpress`) and corrected by
the first real import in 10.11. How it behaves now: [README — Importing an
existing site](../README.md) and [ARCHITECTURE.md §7](../ARCHITECTURE.md).*

— **IronVeil Systems DevOps**
