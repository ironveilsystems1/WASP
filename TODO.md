# WASP — status and open work

*As of 10.30 (2026-11-22).*

Everything WASP claims sits in one of three evidence categories. They are kept
apart because they are different promises: a mechanism proven once on hardware
is not proof that a given client's copy works, and a feature that passes its
tests has not yet met a real VM.

| Category | Means |
|---|---|
| **Proven on hardware** | Run on real Proxmox hosts and VMs, with the result recorded |
| **Proven in automated tests** | Passes `test/run-all-checks.sh` (host shell and BusyBox), not yet run on a real VM |
| **Awaiting client-environment validation** | Proven as a mechanism; each deployment must show it works with its own keys, network and accounts, and keep showing it |

Then what is open, and what was decided against, with the reason. The history
behind every entry (the reviews, field findings and decisions, in order) is
kept unchanged in [`docs/history/TODO-HISTORY.md`](docs/history/TODO-HISTORY.md).
What changed in each release is in [`CHANGELOG.md`](CHANGELOG.md).

## Proven on hardware

| Capability | Evidence |
|---|---|
| Signed releases: the signature is checked before any file is read, then every file against the signed manifest | In production since August 2026. A correct release verifies; a release with a file altered after signing is refused, naming the file. The 10.20 fleet upgrade (2026-11-15) verified on three VMs against each VM's pinned key |
| Encrypted offsite backup restores on another machine | `remote-restore-drill`, 2026-08-20: object pulled from Cloudflare R2, decrypted with the operator's age key, restored into a throwaway MariaDB, 12 tables verified, RTO 33 s for a 977 KB archive. Proves the mechanism; see the per-client drill below |
| WordPress image update: candidate, cutover, rollback | Cutover in both directions (6.9.4-php8.3 ↔ php8.4); rollback by fault injection (`test/vm-rollback-test.sh`): forced post-cutover failure, automatic restore, site healthy, nothing left behind |
| Tooling upgrade (`wasp-upgrade.sh`) | 2026-11-15: three VMs at 10.4, 10.10 and 10.14 brought to 10.20, each verified, planned, backed up, hooks run, tools matching the manifest after |
| wp-admin through the reverse proxy from LAN and overlay addresses (`RemoteIPInternalProxy`, 10.15) | Fixed by hand on two field VMs before 10.15 shipped; on a third, provisioned at 10.4, the image's own `remoteip.conf` was masked by hand on 2026-11-15 and Apache confirmed loading one declaration (`apache2ctl -D DUMP_INCLUDES`) |
| Site import of a real compromised site | First real import in 10.11; what it found was fixed and is in `CHANGELOG.md` 10.11. The UpdraftPlus restore fixes in 10.16 came from a real import |
| Content spam found and removed with evidence | 2026-11-15, a client site: 8 links in 3 pages and 4 Elementor widgets removed by `wp-links.sh clean --links`, a spam title restored, 104 spam revisions and 6 IndexNow entries removed, evidence and a database backup saved first each time. The same run exposed the false spam count fixed in 10.23 |
| Login events reach CrowdSec | Field fault found 2026-08-20 (acquisition watched the wrong log file), fixed; `crowdsec-doctor` checks the file PHP writes is acquired |
| PHP patched against CVE-2026-109618 / 109619 | 2026-11-15: all three production VMs on PHP 8.4.27 with `session.upload_progress` off; `validate-wordpress.sh` checks both |

## Proven in automated tests, not yet on hardware

| Capability | Test | What would prove it on hardware |
|---|---|---|
| Credential rotation without downtime (`wp-rotate-secrets.sh`) | Suite, against stand-ins | A first rotation on a throwaway VM with a snapshot |
| Two-factor enforcement and lockout recovery | `test/test-mfa-enforcement.php` | Lock a test administrator out deliberately and bring them back through the console |
| Candidate update runs on a SELECT-only database account | `wasp-selftest.sh candidate-isolation` | Run it on a VM and keep the output with the VM's records |
| CrowdSec AppSec request inspection (10.13) | `test/test-appsec.sh` | `wasp-appsec.sh on` and `test` on a real VM; its memory recorded over a week; the upstream-LAPI key path, which has never run |
| WASP Hive installer and install.sh's Hive role | `test/test-hive.py`, `test/test-hive-role.sh` | `install-hive.sh` on a real Alpine VM (community packages resolve, `supervise-daemon` restarts, 443 redirect answers); the Hive role on a real Proxmox host; the Wazuh connector against a real manager |
| `.wpress` archives in the 7.x format | `test/test-wpress-reader.php` (the plugin's 4.5 archiver and a third-party 7.x builder) | A real 7.x export |
| Imports from two files, a files archive and a separate `.sql.gz` (10.30) | `test/test-import-separate-db.sh` (podman, wp-cli and the database stood in) | A real host's two-file export imported on a field VM, the site coming up with its content |
| Wordfence, login-hiding plugins and login limiters not imported (10.30) | `test/test-import-separate-db.sh` | An import of a site that ran them: the site and its login working, `active_plugins` without them, Wordfence's tables gone |
| Findings marked when CISA lists them as exploited in the wild, leading the scan, the daily mail, the weekly report and the Hive (10.29) | `test/test-vuln-scan.sh` (the list stood in), `test/test-hive-report.sh` | The real catalog downloaded on a field VM, and one real finding on it |
| Opener isolation and hotlink protection (10.29) | `test/test-headers.sh` (WASP's own header file, Apache and the live headers stood in), including the 10.29 upgrade step | The upgrade step on a field VM; a PayPal or Google sign-in popup still working with COOP on; an image on another domain refused with hotlink protection on |
| A release manifest that covers `hive/`, signed and checked by the release-signing tool (10.29; the tool and its test are kept with the key, not here) | `check-manifest-coverage.py` and the signature job on main here; the tool's own test (real minisign, a throwaway key) where it is kept | The 10.29 release signed with it, CI's signature job green, and `install-hive.sh` accepting it |
| Security-header exceptions for embeds, with a report-only mode (10.28) | `test/test-embeds.sh` (WASP's own header file, Apache and the live header stood in), `test/test-csp-report.php` | On a field VM whose footer map and reCAPTCHA were fixed by hand: `embeds status` adopts the edit, `embeds report` shows nothing blocked, and `validate-wordpress.sh` passes |
| Accepting a reviewed file in the malware scan (10.28) | `test/test-malware-accept.sh` (structural and YARA passes) | The first accepted file on a field VM, and the daily mail quiet until it changes |
| The vulnerability scan using an older answer when WPVulnerability is busy, refreshing at most 15 per run, and saying whether the update on offer fixes a finding (10.28) | `test/test-vuln-scan.sh` | A week of daily scans on a VM with 30+ plugins and no INCOMPLETE mail from a rate limit |
| HTTPS checked for both names, the chain and reachability (10.28) | `test/test-tls-check.sh` (a throwaway CA and real TLS on local ports) | The daily check on a field VM with `LOOPBACK_HOSTS`, and on one whose VLAN cannot reach the public address (`TLS_CHECK_ADDR`) |
| WordPress waits at boot until it could connect (10.28) | `test/test-boot-wait.sh`, including the upgrade step on an older service | A reboot of a field VM, with no "Error establishing a database connection" while MariaDB starts |
| Offsite copies recorded as the hypervisor's (10.28) | `test/test-offsite-hypervisor.sh` | A Proxmox-backed VM's next backups and weekly report |
| The Hive's log rotated (10.28) | None: `install-hive.sh` on a real Alpine VM, which has not run (see the Hive row above) | `logrotate -d /etc/logrotate.d/wasp-hive` on the Hive, then a week |
| The site's mail through the client's own Microsoft 365 or SMTP server, WASP's alerts on the relay (10.27) | `test/test-mail-wordpress.sh` (real WordPress, two STARTTLS SMTP servers, Microsoft's endpoints stood in), `test/test-smtp-config.sh` | A client's real Microsoft 365 tenant: the app scoped to one mailbox, a form enquiry in their inbox and the mailbox's Sent Items, an alert still from the relay |
| `wasp-egress reconcile` adding a VM's missing egress on upgrade (10.26) | `test/test-egress-reconcile.sh`, `test/test-upgrade.sh` | The next upgrade of a field VM running Ultimate Addons for Elementor: `support.brainstormforce.com` added, its denials stop |
| `remoteip-fix` repairing a VM provisioned before 10.6 (10.21) | `test/test-remoteip-fix.sh` | The same repair ran by hand on a field VM; the tool's own run waits for the next such VM |
| A failed second factor with a correct password reaches CrowdSec | None: needs a real Two Factor plugin | Fail a second factor on a VM and look for the event |
| CI on Alpine (BusyBox native) | `.github/workflows/checks.yml`. Its first run (10.23) found four Alpine-only bugs, fixed in 10.24 | Its first green run; then drop its `continue-on-error` |

## Awaiting client-environment validation

Each of these is proven as a mechanism. What has to be shown again, per client,
is that it works with that client's keys, accounts and network, so each is a
recurring item on `docs/WEEKLY-CHECKLIST.md` and the client's record, not a box
ticked once.

| Check | How | When |
|---|---|---|
| This client's offsite backups restore (their key, token and bucket) | `wasp-offsite-backup.sh remote-restore-drill` | Monthly |
| The newest local backup restores | `wasp-selftest.sh restore-test` | Weekly, from cron |
| WordPress cannot reach anything not on its allowlist, even round the proxy | `wasp-egress test` | At onboarding and after any allowlist change |
| Security alerts reach the operator | `wasp-alerts.sh test` | At onboarding and after any mail change |
| An outside heartbeat is configured, so a dead VM is noticed | `validate-wordpress.sh --check` | At onboarding |
| Every administrator is enrolled in two-factor | wp-admin → Users, each administrator's two-factor status (`validate-wordpress.sh` checks only that enforcement is on and working) | At onboarding, then monthly |
| Someone other than the operator could restore this client | `docs/KEY-CUSTODY.md`, filled in | At onboarding, then yearly |

## Open

| Item | Why it matters | State |
|---|---|---|
| Google Workspace through the Gmail API | SMTP with an app password works, but Google's servers change addresses and drift out of the firewall pin (the relay takes the mail meanwhile) | Considered: a service account with domain-wide delegation, over HTTPS like Microsoft 365 |
| Candidate update code still reads live data | The SELECT-only account stops writes, not reads | Design work |
| The CrowdSec enrolment key is briefly visible in a process list | A local user could read it during install | Depends on whether the installed `cscli` takes the key on stdin |
| AppSec watchdog margin | A workaround for crowdsecurity/crowdsec#4797 | Remove when CrowdSec 1.8.3 ships the fix and a week's memory holds |
| Elementor pass of the real-WordPress test is manual | CI runs `test-links-wordpress.sh` without Elementor (19 cases; 20 with) | Run it with `WASP_TEST_ELEMENTOR` before a release that touches the content tools |
| Historical narrative in long file headers | Slows a first read | Partly: move field stories from headers over ~60 lines to `docs/design-notes.md`, keep decision rationale inline |
| Rename the `standard` profile to `lab` and default to `production` | Clearer, but changes behaviour for existing automation | At a major version, with a migration note |

## Not planned

Decided, with the reason, so a "no" stays a decision rather than something that
fell off the list. The full reasoning for each is in the history file.

| Proposal | Decision |
|---|---|
| AIDE or Tripwire file integrity | Redundant here: core is compared with the pinned image, tooling with the signed manifest, content by the scanners. Host `/etc` and `/usr` change on every nightly `apk upgrade`. Reconsider if a client's regime names host FIM |
| A `lynis_extra=auditd+aide` profile flag | Adds a daemon to raise a score nothing reads. A client regime that names auditd is a documented deviation per client |
| LUKS inside the guest | Unattended boot needs the key present, so it protects only a stolen disk image. Proxmox storage-level encryption covers that without breaking reboots; offsite backups are already age-encrypted |
| An approval workflow for vulnerability exceptions | Belongs in the operator's own process. What WASP records makes an approval reviewable: written, digest-scoped, expiring, attributed, in an append-only log |
| `allow_url_fopen = Off` | Breaks many payment gateways and plugin APIs; `allow_url_include` is already off, and the egress allowlist is the stronger control |
| A full dump-and-restore copy for every candidate update | Minutes per gigabyte on every update; the pieces exist for an operator whose regime requires it |
| SMTP pinning that fails closed on DNS failure | Would silently break a client's password resets; it warns instead. Worth revisiting for `production` |
| Enforcing two-factor after the Two Factor plugin is removed | Would lock every administrator out of a working site; enforcement steps aside and warns |
| Rootless Podman everywhere | Tried and removed in v7-6d for reliability. A hybrid root and rootless design is being planned separately; this entry changes if it lands |
