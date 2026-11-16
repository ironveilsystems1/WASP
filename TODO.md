# WASP — status and open work

*As of 10.23 (2026-11-15).*

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
| `remoteip-fix` repairing a VM provisioned before 10.6 (10.21) | `test/test-remoteip-fix.sh` | The same repair ran by hand on a field VM; the tool's own run waits for the next such VM |
| A failed second factor with a correct password reaches CrowdSec | None: needs a real Two Factor plugin | Fail a second factor on a VM and look for the event |
| CI on Alpine (BusyBox native) | `.github/workflows/checks.yml`, written in 10.22 without access to an Alpine image | Its first green run; then drop its `continue-on-error` |

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
| TLS certificates are not monitored | TLS ends at the proxy, so nothing on the VM sees a certificate. A missing `www` name on a client site's certificate was found on 2026-11-15 by `wp-links.sh broken`, not by monitoring | A check against the public endpoint is cheap and not yet written |
| Boot ordering says "started", not "ready" | After a reboot WordPress can show "Error establishing a database connection" for 20–60 s while MariaDB starts | Deferred; the completion banner and support notes say it is expected. Fix: a readiness wait in `wp-container` using `mariadb-health-check.sh` |
| Candidate update code still reads live data | The SELECT-only account stops writes, not reads | Design work |
| The CrowdSec enrolment key is briefly visible in a process list | A local user could read it during install | Depends on whether the installed `cscli` takes the key on stdin |
| `/var/log/wasp-hive.log` is not rotated | About 1,200 lines a day for 12 VMs; small, but unbounded | A weekly truncate or a `logrotate` stanza |
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
