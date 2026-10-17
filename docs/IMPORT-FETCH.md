# Getting a site off someone else's hosting and into WASP

How to pull a WordPress site from a web designer's host, a client's old
provider, or anywhere you did not build — by object storage, by URL, or over
SFTP — and get it to the point where `wp-import.sh inspect` can tell you what
is in it.

This covers **the transfer only.** What happens after the file lands is
`wp-import.sh`'s job and is documented in
[IMPORT-DESIGN.md](IMPORT-DESIGN.md); the short version is at the end.

Everything lands in `/var/lib/wasp-import/incoming`.

---

## Read this first: which firewall is in your way

WASP has **two** separate outbound controls, and they govern different things.
Picking the wrong one to adjust is the most common way to lose an hour here,
because the fetch keeps failing while the thing you changed was never
involved.

| Control | Governs | Affects a fetch? |
|---|---|---|
| **Squid allowlist** (`EGRESS_PROXY=1`) | the **containers** — WordPress itself, source `10.89.10.0/24` | **No.** `wp-import.sh` runs on the VM's OS, not inside WordPress. |
| **Host egress** (`RESTRICT_EGRESS=1`) | the **VM's own** outbound connections | **Yes.** This is the one. |

So: **do not open a Squid maintenance window to fetch a backup.** Squid never
sees the request. `wasp-egress maintenance enable` is for letting *WordPress*
reach something — a licence server, a page builder's CDN — and it will not
help here.

### What host egress permits

With `RESTRICT_EGRESS=0` (the default) the VM's outbound is unrestricted and
every method below works with no change.

With `RESTRICT_EGRESS=1`, the host may open new connections on:

```
tcp 53, 80, 443          tcp 25, 465, 587          udp 53, 67, 68, 123
tcp/udp @egress_extra_*  icmp echo-request
```

Which means:

- **Object storage and URL fetches work** — both are HTTPS on 443.
- **SFTP does not.** Port 22 outbound is not on that list, so it is dropped.
  Opening it is one command, in the SFTP section below.

Check which you have:

```sh
doas wp-hardening.sh status | grep -i egress
doas nft list chain inet filter output | grep -c 'nft-egress-drop'
```

A non-zero count on the second means host egress is restricted.

---

## Before you start: space

Allow roughly **three times** the archive size — the file, its extraction, and
working room. Running out mid-import leaves a broken site and no import, which
is the worst outcome available here, so `wp-import.sh fetch` refuses below
2 GB free rather than filling the disk.

```sh
df -h /
doas wp-hardening.sh disk
```

A 5 GB site needs ~15 GB free on a 20 GB VM. If it does not fit, resize the
disk before you transfer rather than after.

---

## Method 1 — object storage (rclone)

Best when you already configured off-VM backups, because the credentials and
the rclone config already exist and there is nothing new to rotate or forget.

**On the designer's side**, or from your own workstation once you have the
archive: upload it to your bucket. A browser upload to Cloudflare R2 or
Backblaze B2 avoids the command line entirely, which matters when the person
sending it is not technical.

**On the WASP VM:**

```sh
# rclone is installed only when the off-VM backup method is s3/rclone, so
# install it first if this VM uses a different method. The apk reaches
# .alpinelinux.org, which is permitted under both egress controls.
command -v rclone >/dev/null || doas apk add rclone

doas wp-import.sh fetch s3 <bucket>/<path>/backup.zip
```

It reuses the remote already configured at `/etc/wp-install/rclone.conf`
by the off-VM backup setup, so a bare path is enough. A `remote:path` form
works too if you have more than one remote.

Not sure what is in the bucket:

```sh
command -v rclone >/dev/null || doas apk add rclone
doas rclone --config /etc/wp-install/rclone.conf ls <remote>:
```

### Giving a designer a drop box without giving them your bucket

Do not hand over your backup credentials. Issue a **scoped, time-limited
token** for one prefix:

- **Cloudflare R2** — an API token scoped to one bucket, Object Read & Write,
  with an expiry
- **Backblaze B2** — an application key restricted to one bucket and a name
  prefix
- **AWS S3** — a presigned PUT URL, which needs no account on their side at
  all and is the cleanest option when it is a one-off

Then delete the token when the transfer is done. A token that is still valid
six months later is a credential nobody is tracking.

---

## Method 2 — a URL

Works with anything that serves a direct download: the designer's own host,
Dropbox, Drive, WeTransfer, a signed S3 link.

```sh
doas wp-import.sh fetch url 'https://designer.example.com/backup.zip'
```

**With a checksum, if you can get one.** Ask the sender for it — on any Unix
`sha256sum backup.zip`, on Windows `certutil -hashfile backup.zip SHA256`:

```sh
doas wp-import.sh fetch url 'https://…/backup.zip' 3a7bd3e2360a...
```

A mismatch deletes the download and stops. Without one the fetch warns that
the file is unverified and continues, which is the right default — a backup
from a third party usually arrives with no checksum, and refusing it outright
would just mean doing the transfer some less visible way.

### The share-link trap

A share *page* is not a download. Dropbox, Drive and WeTransfer links all
return an HTML page that saves as a file of roughly the right size and is not
an archive — and the failure then surfaces three steps later as a corrupt
archive, which sends you looking at the wrong thing.

`fetch url` catches this: it checks the first 512 bytes for an HTML doctype,
deletes the file and tells you to find the direct link instead. Most services
offer "copy download link" separately from "share".

For Dropbox specifically, `?dl=1` on the end of a share link usually yields
the file. Verify rather than assume — the behaviour has changed more than
once.

### Quote the URL

```sh
doas wp-import.sh fetch url 'https://host/path?token=abc&expires=123'
```

Unquoted, the shell cuts the URL at the first `&` and backgrounds the rest.
The download then fails as a 403 for a truncated token, which looks like an
expired link.

---

## Method 3 — SFTP from the designer's host

Use this when the site is still live on their hosting and there is no archive
yet — most shared hosts give SFTP and nothing else.

Two things have to be true first, and neither is true by default.

### 1. Install an SFTP client

`openssh-client` is only installed when the off-VM backup method is
`rsync`/`scp`:

```sh
doas apk add openssh-client
```

### 2. Permit outbound 22, if host egress is restricted

Port 22 is not in the default permit list, so under `RESTRICT_EGRESS=1` the
connection is dropped with no error from the client beyond a timeout:

```sh
doas wp-hardening.sh egress-allow 22 tcp
```

Then close it again when the transfer is finished:

```sh
doas wp-hardening.sh egress-deny 22 tcp
```

Leaving 22 open outbound is a real cost and worth closing deliberately: it is
a convenient channel out of a compromised site, and the reason the egress
boundary is worth having is that the list is short.

### Pull the files

```sh
# Both prerequisites, in one block, because an sftp that is not installed
# fails at the moment you are already dealing with someone else's hosting.
doas apk add openssh-client                  # provides sftp
doas wp-hardening.sh egress-allow 22 tcp     # only needed if host egress is restricted

cd /var/lib/wasp-import/incoming
doas sftp -P 22 designer@their-host.example.com
```

Then at the `sftp>` prompt:

```
get -r public_html
bye
```

**Ask them to make an archive on their side instead if they can.** One file
transfers faster, survives an interruption better, and `wp-import.sh inspect`
can examine an archive without extracting anything — which is the whole point
of inspecting. A recursive `get` of 40,000 files gives you the files already
on disk, unscanned.

```sh
# what to ask them to run, on their host, in the site directory
tar czf ~/site-files.tar.gz public_html
mysqldump -u USER -p DBNAME > ~/site-db.sql
```

### The database is a separate ask

SFTP gets you files. **A WordPress site is files plus a database**, and the
database is where autoloaded options and scheduled events live — the two
persistence mechanisms that survive every file-based clean.

If they cannot run `mysqldump`, the realistic options are:

- **phpMyAdmin export** — almost every shared host has it. Ask for a single
  `.sql` or `.sql.gz`, not a zip of separate table files.
- **A backup plugin** — UpdraftPlus or Duplicator produces files and database
  together, and `wp-import.sh inspect` understands both layouts. This is
  usually the least painful route for a non-technical sender.

A files-only transfer is not an importable site. Establish that before you
start, not after.

### What you do not need

You do **not** need their WordPress admin login, their hosting control panel,
or `wp-config.php`. WASP discards the imported `wp-config.php` deliberately —
it carries the old site's credentials and salts and often `define()`s that
disable security features — so the receiving VM's own config stays
authoritative.

If a designer offers only a wp-admin account and no file access, you are
looking at a plugin-based export rather than a transfer.

---

## Method 4 — via the Proxmox host

When the file is already on the hypervisor, or is too large to want to move
twice:

```sh
# on the Proxmox host
scp -O /path/to/backup.zip root@<vm-ip>:/var/lib/wasp-import/incoming/
```

**The `-O` is required, not stylistic.** This VM's `sshd_config` is written
with no `Subsystem sftp`, and OpenSSH 9 and later use SFTP for `scp` by
default — so without it you get:

```
subsystem request failed on channel 0
scp: Connection closed
```

which reads like a network fault and is not one. `-O` forces the original SCP
protocol, which needs no subsystem.

**The same absence means a GUI client cannot put a file here.** FileZilla,
WinSCP and Cyberduck all speak SFTP, so they will connect, authenticate, and
fail to list the directory. Use `scp -O`, object storage, or a URL.

---

## Then: inspect before anything else

```sh
doas wp-import.sh list
doas wp-import.sh inspect backup.zip
```

`inspect` **reads only.** It identifies the format, lists the contents, and
refuses hostile archive members — path traversal, symlinks, decompression
bombs — before any of it exists on disk. It is safe to run on a backup you do
not trust, which is the point: you are frequently importing a site
*because* it is suspected compromised.

Nothing from the archive becomes reachable by the web server until it has been
staged outside the docroot and scanned. See
[IMPORT-DESIGN.md](IMPORT-DESIGN.md) for the full pipeline, the gate, and —
importantly — [what it cannot
do](IMPORT-DESIGN.md#what-it-will-not-do): it finds what the scanners find, and
it cannot detect a backdoored copy of a legitimate plugin without a reference
copy to compare against.

---

## When it will not transfer

| Symptom | Cause |
|---|---|
| Timeout, no error | host egress restricted and the port is not permitted. 443 is allowed; 22 is not. |
| `Connection refused` | nothing listening there. The network is fine. |
| Downloaded file is HTML | a share page, not a direct link. `fetch url` catches and deletes it. |
| `subsystem request failed on channel 0` | missing `-O` on `scp` **into** this VM. |
| GUI SFTP client connects then lists nothing | no `Subsystem sftp` here. Expected. Use `scp -O`. |
| 403 on a link that works in a browser | an unquoted URL truncated at `&`, or a token that has expired. |
| `rclone: command not found` | installed only with the s3 backup method. `apk add rclone`. |
| Fetch refuses before starting | under 2 GB free. Deliberate — see the space section. |
| Archive extracts, site half-works | an incomplete multi-part set. UpdraftPlus splits into `-db.gz` plus `-plugins`, `-themes`, `-uploads`, `-others`; every part must be present. |
| Files transferred, no database | SFTP moved files only. The database is a separate ask. |

A useful first question when a fetch fails: **was it 443 or was it 22?** The
answer decides whether you are looking at the egress boundary or at the far
end, and those have nothing to do with each other.

---

## Giving the designer instructions

Copy-pasteable, for someone who is not going to read any of the above.

> Please send the site as **two files**:
>
> 1. **Files** — in your hosting file manager or over SFTP, make an archive of
>    the WordPress directory (the one containing `wp-content`):
>    `tar czf site-files.tar.gz public_html`
>    A `.zip` is equally fine.
>
> 2. **Database** — in phpMyAdmin, pick the site's database, choose **Export**,
>    keep the defaults, and send the single `.sql` file. Or on the command
>    line: `mysqldump -u USER -p DBNAME > site-db.sql`
>
> If it is easier, install **UpdraftPlus**, run one full backup, and send every
> file it produces — there will be several and we need all of them.
>
> Upload to the link provided. If you can, also send the checksums:
> `sha256sum site-files.tar.gz site-db.sql`
>
> Please do **not** send `wp-config.php` or any password — we do not need them
> and they should not travel.

That last line is not politeness. An emailed `wp-config.php` is a set of live
credentials in a mailbox, and asking for it teaches a habit worth not
teaching.
