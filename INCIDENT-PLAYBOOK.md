# WASP Incident Playbook

> This playbook is the compromise-response procedure. For the broader
> "client reports X, do Y" guide across all severities and skill levels, see
> **[SUPPORT-RUNBOOK.md](SUPPORT-RUNBOOK.md)** — its Tier 2 section links back
> here for anything that turns out to be a compromise.


What to do when something here reports a finding. Written for the person on
call at the time, not for a reader with the whole system in their head.

Each section states **what the alert actually means**, what to do first, and —
importantly — what *not* to do. Several of the wrong moves are tempting and
destroy the evidence needed to stop it happening again.

---

## Responsibilities (RACI)

Roles rather than named people, so this survives someone leaving. In a
one-person shop the same person holds several — the value is then in knowing
which hat is on, particularly where **Accountable** and **Responsible** are
deliberately separated.

| Activity | Operator | Site owner | Governance / compliance | Hosting provider |
|---|---|---|---|---|
| Routine updates (`update.sh`) | **R/A** | I | — | — |
| Accepting a vulnerability exception | **R** | C | **A** | — |
| Responding to a CRITICAL malware finding | **R** | **A** | I | C |
| Deciding to take a site offline | C | **A** | C | — |
| Restoring from backup | **R** | **A** | I | — |
| Rotating credentials after a compromise | **R/A** | I | I | C |
| Verifying backups restore (`wasp-selftest.sh`) | **R/A** | I | I | — |
| Off-VM backup destination and retention | **R** | C | **A** | C |
| Holding the backup encryption private key | **R/A** | C | I | — |
| Holding the release signing key | **R/A** | — | I | — |
| Post-incident review | **R** | C | **A** | I |

**R** Responsible (does it) · **A** Accountable (owns the outcome) ·
**C** Consulted · **I** Informed

Two separations are deliberate:

- **Accepting a vulnerability exception** — the operator does it, governance
  owns it. The system enforces the record; it cannot enforce that a
  conversation happened. That is the point of emailing the governance address.
- **Taking a site offline** — the operator can advise, but the commercial
  consequence belongs to the site owner. Agree the threshold *before* an
  incident: at 02:00 is the wrong time to discover nobody can authorise it.

---

## CRITICAL malware finding

**Alert:** email tagged `wp-malware`, or `wp-malware-scan.sh` reporting
`[CRITICAL]`.

### What it means

Structural findings are near-certain, not probabilistic. A `.php` file in
`wp-content/uploads`, or a core file that differs from the pinned image, is
not a false positive — nothing legitimate produces either.

### Do not

- **Do not delete the files.** How they arrived matters more than that they
  are there. Delete them and you lose the only record of the entry point, and
  it will be used again.
- **Do not run an update to "clean" it.** An update overwrites evidence and
  may re-run attacker-modified code.
- **Do not restore from backup yet.** You do not know when the compromise
  started, so you do not know which backup is clean.

### Do, in order

```sh
# 1. Full picture — do not act on the first line of it
doas wp-malware-scan.sh full

# 2. WHEN did it appear, and what else happened then?
#    Do this BEFORE quarantining. The file's mtime is the anchor for
#    everything around it; once it moves, that anchor becomes the
#    quarantine time and the correlation is gone.
doas wp-forensics.sh timeline --around <file>
doas wp-forensics.sh entry-class          # the decision tree

# 3. Preserve. quarantine MOVES and records the original path; it is
#    reversible, and captures the timeline first.
doas wp-malware-scan.sh quarantine <file>
#    Or the whole known shape at once -- planted files quarantined with
#    their paths, modified wordpress.org plugins reinstalled clean, planted
#    accounts locked (not deleted). Read the plan before --apply.
doas wp-malware-scan.sh remediate
doas wp-malware-scan.sh remediate --apply

# 4. How did they get in? An outdated plugin is the usual door
doas wp-plugins.sh vulns
doas wp-plugins.sh status
doas wp-forensics.sh since-backup         # what changed since known-good

# 5. What else did they touch?
doas wasp-verify-integrity.sh
doas grep -E "wpvm-login|POST /wp-login" /home/wpuser/wp/logs/*.log | tail -50
doas podman exec crowdsec cscli alerts list
doas wp-forensics.sh admins               # persistence that outlives file cleaning

# 6. Who is the attacker? Only for an address that matters — the CTI
#    free tier is 40 lookups per MONTH.
doas wp-hardening.sh cti <ip>
```

**If egress control is enabled, check what the site tried to reach.** A
compromised site calling out is often the clearest evidence of what the
payload was for, and the denial log records attempts that succeeded at
nothing:

```sh
doas wasp-egress discovery
doas grep DENIED /opt/squid/logs/access.log | tail -30
```

**What `remediate` will not do for you.** It removes what the checks
recognise: files of the shapes seen on real sites, plugins with a published
copy to restore from, accounts with two or more planted-account signals. A
backdoor written for this site, a modified theme or commercial plugin, or code
in a database option stays — those are listed "for a human" — and the way in
is still open until step 4 finds it. A cleaned site with the original
vulnerability is compromised again, usually within days.

### Then decide

Take the site offline if there is evidence of **active** data access, if
payment or personal data may be involved, or if you cannot establish the entry
point. That decision belongs to the site owner — see the RACI above.

```sh
doas rc-service wp-container stop      # site offline, data intact
```

### Recovery

1. Establish the earliest evidence of compromise — file timestamps,
   `wp_users` `user_registered`, access logs.
2. Restore from a backup **predating** that:
   `wasp-offsite-backup.sh restore --list`
3. Patch the entry point **before** the site returns, or you will repeat this.
4. Rotate everything: WordPress admins, database, SMTP relay, any API keys in
   `wp_options`. Use `wp-rotate-secrets.sh all` for the infrastructure
   credentials; change the admin passwords in WordPress itself.
5. If MFA is enforced, force every admin to re-enrol a second factor — a
   compromise may have captured or added one. Clear each admin's Two Factor
   providers from the console (see SUPPORT-RUNBOOK.md, *An admin has lost their
   second factor*) so they must set up a fresh factor on next login. If MFA was
   NOT enforced, this is the moment to turn it on.
6. `doas wasp-selftest.sh all` before declaring it done.

> A restored site with the original vulnerability is a site that gets
> compromised again, usually within days. Step 3 is not optional.

---

## Vulnerability finding

**Alert:** email tagged `wp-vulns`, or `wp-plugins.sh vulns` output.

### What it means

An installed plugin or theme matches a **disclosed** vulnerability. It does
not mean you have been exploited, and a clean scan does not mean you are safe
— roughly 46% of plugin vulnerabilities have no patch when disclosed, and an
unaudited plugin has no CVEs by definition.

### Triage

| CVSS | Response |
|---|---|
| 9.0+ **and** unauthenticated | Same day. Update, or deactivate **and delete** |
| 7.0–8.9 | Within the week |
| 4.0–6.9 | Next maintenance window |
| Authenticated-only, admin-only | Lower — but only if you trust every account that has that role |

```sh
doas wp-plugins.sh update-plugins <slug>
doas wp-plugins.sh vulns              # confirm it cleared
```

**No fix available?** Deactivating is not enough — deactivated plugin code is
still on disk and still reachable by direct request. Delete it, or accept the
risk formally:

```sh
doas wp-hardening.sh exceptions       # what is already accepted
```

An exception is recorded against that exact image digest, expires (90 days by
default), and is emailed to the governance address with the CVE list. It is
not approval — it is the record that makes an out-of-band approval auditable.

---

## Content spam (casino, pharmacy, adult links)

**Alert:** email tagged `wp-content-spam` (the weekly scan), a security alert
"Spam link saved on page N" (as it was saved), or `wp-import.sh scan` reporting
spam links, titles or articles in a backup.

### What it means

Someone placed links to gambling, pharmacy or adult sites in the site's
content, usually to sell the site's search ranking. It is **content, not code**:
no file scan sees it, and nothing on the server has to be compromised for it to
happen. It goes in through a valid session, so treat the account that saved it
as possibly in someone else's hands until shown otherwise. The usual trail is a
paste from a Google Sheet (the scan says so) and an article on the site's own
address that the SEO plugin announced to search engines.

It does not harm visitors' computers. It does harm the site's ranking and
trust: search engines treat a business linking to casinos as a hacked site.

### Do not

- **Edit the text by hand in the widget.** Pasted spam often hides a second
  link or a hidden block. Delete the whole widget.
- **Restore an older revision of the page.** Revisions from the time of the
  spam hold it too; the scan counts them.
- **Delete the account that saved it before looking.** Its sessions and
  application passwords are the evidence of how, and an application password
  survives a password change.

### Do, in order

1. **Who and when.** The alert names who saved it and from where. For an import,
   the scan names the accounts and any application passwords that came with it.
   ```sh
   doas wp-forensics.sh admins
   doas wp-forensics.sh app-passwords
   ```
2. **Close the way in.** If the account is not yours, or you cannot tell:
   ```sh
   doas wp-plugins.sh lock-user <id> "content spam"
   doas wp-forensics.sh app-passwords revoke <id>
   doas wp-rotate-secrets.sh salts        # signs everyone out
   ```
   Ask everyone who edits the site to close any open Elementor tabs: an open
   editor can save the old version, spam included, over your clean-up.
3. **See everything to clean, with IDs.**
   ```sh
   doas wp-links.sh spam
   doas wp-links.sh clean                 # what could be cleaned; changes nothing
   ```
4. **Preview, then clean.** Name each thing. It is refused unless it also tests
   as spam:
   ```sh
   doas wp-links.sh clean --links <domain>,<domain> --trash <post id> \
                          --revisions --indexnow
   doas wp-links.sh clean <the same> --apply
   ```
   `--links` works whichever builder or theme holds the links: the block
   editor, Divi, WPBakery, Beaver Builder, Bricks, Oxygen, Elementor, the
   Customizer, widgets, menus. Elementor widgets can also go whole by ID
   (`--widgets <id>`), and a spam title is set with `--title <id>="<real title>"`.
   ```sh
   ```
   The evidence (the scan, the plan, the IndexNow log) is saved under
   `/var/lib/wasp/evidence/`, and a database backup is taken before anything
   changes. A Proxmox snapshot first costs nothing: `qm snapshot <vmid> pre-clean`.
5. **Update what let it in.** Page builders and SEO plugins are the usual
   route. Then confirm the site is clean:
   ```sh
   doas wp-plugins.sh vulns
   doas wp-plugins.sh update-plugins <slug>
   doas wp-links.sh spam                  # exit 0: clean
   doas wp-malware-scan.sh full
   ```
6. **Tell the search engines.** The spam articles now answer 404.
   - In Rank Math → Instant Indexing, submit those addresses.
   - In Google Search Console, check Security & Manual Actions, request
     removal of the addresses, and resubmit the sitemap.
   - In Bing Webmaster Tools, do the same.

### Then decide

Whether the site owner needs to be told, and what. Saved revisions and the
evidence directory date the spam: when it first appeared, and under which
account. That is usually enough to say whether it came with an import, a
contractor's account, or a stolen password. The weekly scan and the save-time
alert stay on, so a return is reported the same day.

---

## Backup failure

**Alert:** email tagged `wp-db-backup`. **No cooldown — this one repeats
deliberately.**

### What it means

Last night's backup did not complete. Yesterday's was kept, so you have not
lost anything **yet**. A backup failing silently for months is the most common
way people discover they have no backups.

```sh
doas wp-db-backup.sh                          # what does it say now?
df -h /                                       # full disk is the usual cause
doas podman logs --tail 30 mariadb
doas validate-wordpress.sh --section backups
```

Once it succeeds, prove it actually restores — the whole point:

```sh
doas wasp-selftest.sh restore-test
```

---

## Integrity or self-test failure

**Alert:** `wasp-verify-integrity.sh` reporting modified files, or
`wasp-selftest.sh` failing.

### Modified tooling is not a small thing

Files under `/usr/local/bin` run **as root, on a schedule**. A modification
there is a persistence mechanism until proven otherwise — and it is invisible
to every other check here, because every other check trusts the scripts it is
running.

Treat it as the malware section above. **Do not simply overwrite the files:**
the modification is the evidence.

An attacker with root can also edit the checker, the manifest and the key. For
an answer that does not depend on the compromised host, mount the disk from
the Proxmox host and compare from there.

### Self-test failure

`restore-test` failing means the backup does not restore. That is worse than a
backup failure, because the alert never fired — the file existed and looked
fine. Do not wait for a maintenance window.

`candidate-isolation` failing means the read-only account is not refusing
writes, so an update candidate could modify production data. Do not run
`update.sh` until it passes.

---

## Locked out

| Symptom | Likely cause | Fix |
|---|---|---|
| **403** on admin paths | Your address is not allowed, or mod_remoteip is not substituting it | `wp-hardening.sh proxy-check`, then `wp-hardening.sh web-allow <your-ip>` for a direct path that does not depend on the proxy |
| **403** persists, cause unclear | Possibly the fail-closed `Require not ip <proxy>` rule | `wp-hardening.sh admin-rule simple` to isolate it; `admin-rule strict` to restore |
| **503** on admin paths | nginx `limit_req` — its default status is 503 | Remove `limit_req` from the NPM Advanced tab, or set `limit_req_status 429` |
| Proxy host will not save, or `nginx -t` fails, after pasting the WASP snippet | Snippet generated by 10.10 or earlier: `\$host` and `\"…\"` with stray backslashes | Regenerate with `wp-hardening.sh nginx-snippet` (10.11+). If `limit_req` names an unknown zone, `http_top.conf` is in the wrong place — NPMplus reads `/opt/npmplus/custom_nginx/` |
| SSH refused | CrowdSec banned you | Console: `podman exec crowdsec cscli decisions delete --ip <ip>` |
| Plugin or update failing, no error | Egress proxy blocking an unlisted destination | `wasp-egress discovery` — check *before* assuming the plugin is broken |
| Site unreachable, no alert fired | Nothing on the VM can report the VM being gone | Configure `wp-notify.sh --heartbeat-url` |
| Locked out of WordPress | Login guard lockout | Wait it out, or clear the transient via wp-cli |

Console access via `qm terminal <VMID>` from the Proxmox host always works —
root SSH is disabled, but the console is not, and that is deliberate.

To tell a VM problem from a proxy problem in one command:

```sh
doas podman exec wordpress php -r '
$c=stream_context_create(["http"=>["timeout"=>8,"ignore_errors"=>true]]);
@file_get_contents("http://127.0.0.1/wp-login.php",false,$c);
echo ($http_response_header[0]??"none")."\n";'
```

**403 or 200 there means the VM is fine and the problem is the proxy.** A 403
is correct — that request comes from an address not in your allow list.

---

## After any incident

Within a week, while it is still fresh:

1. **What was the entry point?** Not "a plugin" — which plugin, which version,
   which CVE.
2. **How long between compromise and detection?** If it was long, which check
   should have caught it sooner?
3. **What did detection actually depend on?** If one control found it and the
   others were silent, understand why.
4. **What would have prevented it?** Faster updates? A removed plugin? An
   allow-list that was too wide?

Record it somewhere the next person will find. A finding nobody wrote down
gets rediscovered the expensive way.

---

*Nothing here detects a backdoor written specifically for your site. Clean
output is evidence, not proof — and this playbook is worth more than the
scanners that trigger it.*

— **IronVeil Systems DevOps**
