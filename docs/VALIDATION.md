# Validation record

How this platform was tested, and what that testing produced.

Written because the numbers are only knowable while the work is fresh, and they
answer three separate questions: what an RFP response can claim, what a
licensing conversation is actually protecting, and — if it ever matters — what
the human contribution to this codebase consisted of.

The first file was written on **23 June 2026**. What follows is two months of
provisioning against real hardware, not a burst of activity in August. The
August entries are dense in `CHANGELOG.md` because that is when the platform
was being hardened against live client deployments and every defect was being
recorded as it was found; the earlier work established the architecture the
hardening was applied to.

---

## Summary

| | |
|---|---|
| **Deploy–test–diagnose cycles on real hardware** | 96 |
| **Development began** | 2026-06-23 |
| **Period covered by this record** | 2026-06-23 to 2026-08-22 (two months) |
| **Release entries recorded** | 190 |
| **Defects traced to a live VM rather than review** | 31 recorded |
| **Static checks now enforcing** | 23 |
| **Negative (fail-closed) test cases** | 27 |
| **Test and check code** | ~2,700 lines, 16% of executable code |

Each cycle was a full provision on Proxmox against a real network, a real
reverse proxy, a real mail relay and real object storage — not a container
harness or a mock.

---

## What the hardware found that review did not

This is the part worth stating precisely, because it is the argument for the
method and the reason the codebase looks the way it does.

**Every one of these passed code review, syntax checking and the static suite.
All of them were broken.**

| Defect | Why review could not see it |
|---|---|
| Squid `allowed_methods` omitted CONNECT | Config was valid. Every HTTPS request was denied before the allowlist was consulted, and the deny probes all "passed" |
| CrowdSec acquisition watched `error.log` while PHP wrote `php-errors.log` | Every component was correct — mu-plugin, parser grok, scenario, bouncer. The chain could never fire |
| nftables rule expanded an empty variable | Shell syntax valid. `nft` rejected the whole file; the VM booted with no firewall and the install reported success |
| SMTP allow rule sat below the catch-all drop | Both rules correct. First-match-wins meant the allow was unreachable, and outbound mail silently stopped |
| `wp-config.php` never received the proxy constants | The variable was passed correctly. The image only writes that file on first run, so a later rebuild dropped it |
| `TRIVY_CHECKSUMS_SHA256` declared and never read | The constant was present and the comment described a verification that did not happen |
| Forwarding headers set inside one nginx location | `/slug` resolved the real client, everything else showed the proxy. Three controls degraded together, silently |
| Squid had no OpenRC service | Worked until the first reboot, then the firewall pointed at a proxy that was not running |
| Object-storage token expired | Backups stopped for seven days. Every check passed; nothing asked how long since the last success |

The pattern is consistent enough to name: **the control was present, correct,
and inert.** Positive testing proved it existed. Only running it on hardware
proved it did nothing.

---

## What that produced

The check suite exists because of the above, not in anticipation of it. Each
check was written after a specific defect reached hardware:

- `check-expansion-order.py` — after an empty variable left a VM with no firewall
- `check-heredoc-backticks.py` — after a comment inside a quoted string executed
- `check-config-sourcing.py` — after `offsite.conf` was found to be executed as root
- `check-unused-security-vars.py` — after a checksum anchor was found unread
- `check-slug-rewrites.py` — after two rule generators drifted into a login loop
- `check-doas-prefix.py` — after printed commands failed on paste
- `check-stale-branding.py` — after a superseded org name survived a rename in 15 files
- `test-fail-closed.sh` — after four separate controls were found present and inert

Several caught their own class again within days of being written, including
two mistakes made while writing the fix for the original.

---

## What is proven, and what is not

Stated separately because the distinction is the point.

**Demonstrated on hardware:**

- Off-site recovery end to end — encrypted object pulled from object storage,
  decrypted with the recovery key, restored into an isolated database and
  verified. **Measured RTO: 33 seconds** for a 977 KB archive, 2026-08-20
- Admin MFA enforced, with the Two Factor plugin active
- Outbound mail delivered through an authenticated relay and received
- Egress boundary enforcing — allowed destinations tunnel, denied refused,
  cloud metadata blocked, CONNECT confined to 443
- CrowdSec remediation reaching nftables, verified with an injected decision
- Firewall ruleset loading, with 53 validation checks passing
- **Signed-release installation.** Minisign signing has been in use throughout
  August: releases are signed, the signature is verified before any file is
  read, and each file is then checked against the signed manifest. Both halves
  have been exercised on hardware — signatures validating on a correct release,
  and the manifest check REFUSING when files were modified after signing:

      Trusted comment: WASP 2026.08.22 | 2026-08-22T21:05:33Z | 71 files
      payload/bin/wasp-offsite-backup.sh: FAILED
      FATAL: a file does not match the signed manifest.

  That refusal is the more valuable of the two results. A verification that has
  only ever passed has not been tested; this one has been observed to stop an
  install, and to explain correctly that the signature was valid and therefore
  a shipped file had been altered after signing.

**Not yet demonstrated:**

- A CrowdSec ban triggered by real failed logins from an external client, now
  that client-IP forwarding is correct
- Lockout alerting with a genuine client address rather than the proxy

Claiming the second list as proven would undo the value of the first.

---

## Method

Each cycle followed the same shape:

1. Provision from a clean image on Proxmox
2. Run the commission check and the self-test suite
3. Capture the full install log
4. Diagnose from the log and the running system — not from re-reading the source
5. Fix, add a check that would have caught it, re-provision

Step 4 is load-bearing. Reasoning from the code produced the wrong answer
repeatedly — most starkly on a plugin-install failure where six successive
hypotheses were wrong, and the cause was finally identified from an access log
showing that the request never left the VM at all.

Step 5 is why the suite is 16% of the codebase. A fix without a check is a
defect that returns.

---

*Maintained by IronVeil Systems DevOps. Figures are drawn from the deploy
history and `CHANGELOG.md`, which records each defect at the point it was
found.*
