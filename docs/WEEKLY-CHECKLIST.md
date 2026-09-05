# WASP 9.3 — Weekly MSP Maintenance Checklist

Client: ______________________  VM/Site: ______________________
Date: ________________________  Operator: _____________________
Ticket/Change #: ______________  Build on VM: ___________________

> Run `doas wasp-menu` → **7) Testing** → **1) Commission check** first. It
> covers ten of the items below in one pass and prints the command to fix
> anything it finds. This list is what the commission check cannot judge for
> you — currency against upstream, client-specific policy, and evidence.

---

## Start here

- [ ] `doas wasp-triage.sh` — no CRITICAL findings
- [ ] `doas wasp-menu` → Commission check — record PASS/FAIL counts: ______
- [ ] If `--check` reports a PRODUCTION-BLOCKER, run
      `doas wasp-triage.sh --recheck-blockers` before investigating; the
      condition may already be resolved and the marker stale.

## Release and platform integrity

- [ ] Deployment is a SIGNED release, not a development tarball
- [ ] `wasp-verify-integrity.sh` passes
- [ ] Installed WordPress matches the current release at wordpress.org
      — `doas wp-plugins.sh core-version` shows files AND image agreeing
- [ ] Alpine updates reviewed; reboot scheduled if the kernel changed
- [ ] Container image digests current — `doas update.sh digest-check`

## WordPress and plugins

- [ ] `doas wp-plugins.sh vulns` reviewed
- [ ] `doas wp-plugins.sh verify --strict` — core and plugin checksums
- [ ] Every **SKIPPED** plugin (commercial or bespoke) has an approved source,
      a recorded hash, and FIM coverage from the SIEM side
- [ ] No unknown, unused or abandoned plugin or theme remains
- [ ] MFA: Two Factor active and every administrator holds a real second factor
- [ ] `DISALLOW_FILE_MODS` still enabled — `doas wp-hardening.sh status`
- [ ] PHP shell functions still blocked — same command, `php-exec` line

## Firewall, CrowdSec, egress

- [ ] `doas nft list ruleset` — rules present, counters moving, no surprises
- [ ] `doas wp-hardening.sh crowdsec-doctor` — including the live ban test
- [ ] `doas wasp-egress.sh status` and `test` both pass
- [ ] **After any reboot**, confirm Squid came back — it has a boot service as
      of 9.3, but verify rather than assume
- [ ] Squid DENIED entries and `nft-egress-bypass` logs reviewed
- [ ] No expired maintenance window left open
- [ ] Runtime allowlist contains only continuing dependencies — a page builder
      the client no longer uses is pure surface
- [ ] SMTP reaches ONLY the approved relay; the destination pin still resolves

## Backup and recovery

- [ ] Newest local backup is inside the client's RPO
- [ ] Newest copy is actually **off-VM** — `doas wasp-offsite-backup.sh status`
- [ ] No stale push failure recorded; staleness warning absent from `--check`
- [ ] **Object-storage token expiry checked in the provider console.** A token
      with a TTL returns 403 while still displaying correct permissions, and
      the only symptom is backups quietly stopping. Note next expiry: _________
- [ ] `doas wasp-selftest.sh all` passed this week
- [ ] **Monthly:** `remote-restore-drill` run, RTO recorded: ______ (vs RPO/RTO
      target: ______)
- [ ] Destination immutability / versioning / delete-separation still enforced
- [ ] Proxmox-level VM backup reviewed

## Email, TLS, monitoring

- [ ] `doas wp-mail.sh doctor` passes — including the TCP reachability line
- [ ] A real message delivered this month — `wp-mail.sh test <addr>`
- [ ] `doas wp-notify.sh --status` — the notifier runs; silence from a crashed
      notifier is indistinguishable from all-clear
- [ ] SPF, DKIM and DMARC reviewed after any mail or DNS change
- [ ] TLS renewal healthy; expiry more than 21 days out
- [ ] External heartbeat current; central logs receiving
- [ ] Disk and log growth within expected range

---

## Findings and actions

______________________________________________________________________________
______________________________________________________________________________

## Exceptions, risk acceptance, expiry

______________________________________________________________________________

## Recovery evidence (attach or reference)

Last restore drill: ____________  RTO: ______  Object: ____________________

Operator sign-off: __________________________

---

*This checklist ships with the repository so it versions alongside the code.
If a command here does not exist on the VM you are auditing, that VM predates
the tooling and is worth upgrading before the next review.*
