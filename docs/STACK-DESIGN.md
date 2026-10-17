# Stack design — WASP, NPMplus and OPNsense from one installer

A design document, not a description of shipped behaviour. What exists today is
`tools/wasp-topology.sh`; everything below it is the plan that tool was built to
serve, written down before the orchestration so the sequencing argument can be
had before the code exists rather than after.

The goal: select WASP, NPMplus and OPNsense at one prompt and get three VMs
already tuned to each other — the proxy pinned to the WASP VM's address, the
firewall's VLANs and rules matching the segments the VMs actually landed on,
CrowdSec detecting on the tenant and enforcing at the edge.

---

## 1. What already exists, and what that changes

The single most useful finding from scoping this: **`ironveilsystems1/npmplus`
is not a different kind of project.** It is the same architecture as WASP —
`install.sh` + `lib/00`…`07` + `payload/` + `test/` — with the same self-
bootstrap, the same deployment profiles, the same `vars.sh` injection, the same
static-check discipline. 79 files.

That makes this a composition problem rather than a rewrite. The two installers
already agree on how a VM gets built; what they lack is a layer above them that
decides the addresses and passes them between.

It is also already WASP-aware. Its README states the TRUST-COUNT rule
independently, in the same terms:

> WASP pins it as `RemoteIPTrustedProxy`, and that value must be a **single
> literal address, never a CIDR**.

And `OPNSENSE.md` in this project already contains §7 "Why a backend cannot
enforce its own bans" — the B2 reasoning WASP 10.4 acted on — plus a
config.xml reference precise enough to generate from.

So three of the four pieces are further along than the request assumed. The gap
is the orchestration and the topology, not the per-VM work.

### The defect worth fixing first

npmplus has a CrowdSec `lapi` mode. Choosing it prints:

> NOTE: CrowdSec LAPI mode selected. WASP VMs must be registered as agents
> against this VM. That step is NOT automated yet and the premise behind it is
> unverified — see TODO.md B2.

But `lib/03-dynamic-configs.sh` publishes the LAPI as:

```yaml
    ports:
      - "127.0.0.1:7422:7422"
      - "127.0.0.1:8080:8080"
```

**A mode that exists, is selectable, says it is for WASP VMs, and cannot serve
one.** No remote agent can reach a loopback-published port however correct its
credentials are. This is the same shape as the defect WASP 10.4 closed, in the
companion repo, and it is the thing gating the whole CrowdSec topology at Site
B.

Its own TODO is honest about the dependency — "B2 … Blocks: CrowdSec LAPI
topology, and therefore `lib/07-crowdsec.sh`". **B2 is now confirmed**, so that
block is lifted. The work is bounded:

1. publish `8080` on the VM's own address when `CROWDSEC_MODE=lapi`, loopback
   otherwise
2. `cscli machines add` per tenant, with the credential handed back to the
   caller
3. a `validate-npmplus.sh` check so an `apk upgrade` or redeploy reverting it
   is caught — the treatment `bouncer-init.sha256` already gets

Point 3 matters more than it looks. A hand-patch on one VM survives until the
next rebuild and then vanishes without a sound, which is how this gate came to
exist in the first place.

---

## 2. Scope boundaries, decided

### OPNsense is configured, not installed

OPNsense has no cloud-init and its installer is interactive over the console.
Driving that unattended is possible and is not worth it: it is the most fragile
part of the whole stack and the least valuable to automate, because it happens
once per site.

What *is* worth automating — and what the request is really asking for — is the
**`config.xml`**. `OPNSENSE.md` specifies this well enough to generate from: the
generation order, the element set per Filter model version, the comma-vs-space
trap in `<members>`, the `vlan0N` naming rule, which fields are uppercase in
filter rules and lowercase in NAT.

So the OPNsense option means:

- create the VM (disk, NICs on WAN and trunk, ISO attached)
- generate a `config.xml` carrying the VLANs, interfaces, groups, aliases,
  rules, NAT and CrowdSec settings for *this* stack
- hand the operator the file and the one console step that imports it
  (option **13) Restore a backup**, which does not depend on the network —
  which is what makes it survivable on a host you cannot physically reach)

Generating a config is also reviewable in a way an unattended install is not.
The operator reads the firewall rules before they are the firewall rules.

**The install is not automated and the document should say so rather than
implying a one-command firewall.**

### What the stack does not do

- **No load balancing.** npmplus TODO already argues this out: NPMplus state is
  SQLite with no clustering, two active nodes means two divergent databases,
  and active/passive with a CARP VIP risks a split-brain where both nodes write
  certificates. Single VM plus Proxmox HA and a fast rebuild is the better
  trade.
- **No mail through the proxy.** Decided in npmplus TODO and OPNSENSE.md §6:
  SMTP, submission, IMAP and sieve go straight to the mail host. Reverse-
  proxying them destroys the source address, which breaks postscreen, RBL
  checks and rspamd scoring — permissively.
- **No network scanning.** The topology tool reads Proxmox configuration only.
  Stated again in §4 because it bounds what the plan can promise.

---

## 3. The builder

`https://netlockrmm.com/install/` is a browser wizard that processes input
locally and emits a Docker Compose file plus an install script. Its first step
is the one worth copying: *Installation Type* — "Full Installation
(Recommended)" versus "With Existing Reverse Proxy". It asks what you already
have before it asks for any values.

That is the right first question here too, and for a stronger reason: the three
VMs are not independent choices. Each combination changes what the others need
to be told.

| Selection | What it means |
|---|---|
| WASP only | today's behaviour. Asks for the proxy's address because something else is the proxy. |
| WASP + NPMplus | two VMs. The proxy's address is *generated*, not asked for, and WASP's TRUST-COUNT value and LAPI URL come from it. |
| WASP + NPMplus + OPNsense | three VMs, plus a `config.xml` whose VLANs and rules match the segments the other two landed on. |
| NPMplus only | an edge in front of backends WASP did not build. |

**The builder should be a terminal flow, not a web page.** Everything it needs
to know is on the Proxmox host — bridges, VLAN tags, free VM IDs, storage — and
a browser form cannot read any of it, so a web builder would have to *ask* for
the facts the topology tool can *discover*. That is strictly worse: it moves
the most error-prone values from discovery back to typing.

A `--vars` output and a web page are not in conflict, though. The shape
`wasp-topology.sh --plan --vars` already produces is exactly what a page would
need to emit, so a browser front end remains possible later as a convenience
for someone planning before they have host access.

---

## 4. Topology discovery — shipped

`tools/wasp-topology.sh`. Runs on the Proxmox host, reads only.

```sh
wasp-topology.sh                  the map, and what is wrong with it
wasp-topology.sh --plan           plus a proposed 3-VM stack
wasp-topology.sh --plan --vars    just the assignments, for a stack build
wasp-topology.sh --collect DIR    a support bundle
wasp-topology.sh --from DIR       read a bundle instead of the live host
```

It reports bridges and **whether each is VLAN-aware**, every guest with its
bridge, tag and address, the subnets and tags in use, and storage. Then it
proposes a stack that collides with none of it.

### Conventions encoded, not improvised

Taken from `OPNSENSE.md` so the plan and the firewall generator cannot disagree
about what a tag means:

- one VLAN per trust boundary
- the third octet **is** the VLAN tag — so a firewall log is legible without a
  lookup table
- each site gets its own second octet; a subnet reused across two sites makes
  the remote one invisible over an overlay, because the directly-connected
  route wins
- `.1` gateway, `.10`–`.49` static servers, `.100`–`.200` DHCP
- the proxy on a low tag; tenants in the `101+` band

On a clean host this reproduces the canonical layout — proxy `10.20.10.10`,
tenant `10.20.101.10` — which is the same layout Site B arrived at by hand.
That agreement is the point: if the tool had produced something else, one of the
two would have been wrong.

### What it refuses to claim

**It reads Proxmox configuration. It does not scan.** A statically-addressed
appliance on a VLAN with no Proxmox guest on it is invisible, so `--plan` can
propose a subnet something else is using. That limit is printed with every plan,
with the two commands that check it, rather than left implicit.

### Findings name the consequence

A warning that states a condition gets dismissed. Each finding says what breaks
silently:

- **no VLAN-aware bridge** — Proxmox *accepts* a tag on a non-aware bridge and
  delivers the frames untagged, so the guest comes up on the wrong segment with
  no error anywhere
- **one bridge only** — an OPNsense VM on it becomes the gateway for the segment
  you administer the hypervisor from, so a wrong rule locks you out of Proxmox
  too
- **addressless guests** — normal for VMs, and it means those addresses are
  outside the collision checks

Tested against two fixtures — a segmented host modelled on Site B and a flat
single-bridge homelab — by `test/test-topology.sh`, 30 cases. Three of them are
regressions for defects found while writing it, including a `--vars` mode that
printed the map to stdout and therefore could not be `eval`'d.

---

## 5. Orchestration — the part not yet written

### Build order is forced by dependency, not preference

```
1. OPNsense      segments must exist before anything is addressed on them
2. NPMplus       the LAPI and the proxy address must exist before WASP is told them
3. WASP          consumes both
```

And the order is wrong in one specific way that has to be handled: **OPNsense
is not configured when it is created.** Its config.xml import is a manual
console step, and the other two VMs cannot reach anything until it has happened.

So the run has a deliberate stop:

```
create all three VMs  →  generate config.xml  →  STOP
                         "import this, confirm the segments are up, re-run
                          with --continue"
                      →  build NPMplus, then WASP
```

A stack build that pretends to be one unattended command would spend twelve
minutes provisioning onto segments that do not exist yet. Stopping is the honest
shape, and it is also where the operator reviews the firewall rules.

### Config handoff

One direction only, to keep it auditable: each stage writes the facts the next
stage needs, and no stage reaches backwards.

```
topology  →  STACK_* assignments        (wasp-topology.sh --plan --vars)
OPNsense  →  segment addresses, gateways
NPMplus   →  proxy address, LAPI URL, machine credential per tenant
WASP      →  consumes all of the above
```

The WASP end of this already exists and is already validated:
`WASP_PROXY_IP`, `WASP_CS_ENFORCEMENT`, `WASP_CS_LAPI_URL`,
`WASP_CS_LAPI_LOGIN`, `WASP_CS_LAPI_PASSWORD`, `WASP_CROWDSEC_WHITELIST`,
`WASP_LOOPBACK_HOSTS` — with `install.sh`'s contract preflight refusing a CIDR
proxy, an unreachable LAPI URL, and an `upstream` declaration missing a
credential. `test/test-topology.sh` asserts that `--vars` emits the names
`install.sh` actually reads, so a rename on either side fails the suite rather
than silently producing a stack that configures nothing.

**The machine credential is the one value that cannot be planned.** It has to be
created on the LAPI after NPMplus exists, which is why it is NPMplus's output
rather than the topology tool's.

### What each VM gets told about the others

| | learns | from | consequence if wrong |
|---|---|---|---|
| WASP | the proxy's single literal address | NPMplus | forged client IPs; CrowdSec bans the wrong party |
| WASP | the LAPI URL and its own credential | NPMplus | detection reaches nobody |
| NPMplus | the WASP segment as a backend CIDR | topology | proxy cannot reach the backend |
| NPMplus | that it is the enforcement point | selection | nothing blocks anywhere |
| OPNsense | both segments, and the two cross-segment rules | topology | WP-Cron dies; agents cannot reach the LAPI |

The two OPNsense rules are the ones `OPNSENSE.md` §5 names, and both are easy
to omit because neither breaks the site immediately:

- `PROXY_NET → BACKEND_NETS` on `WEB_PORTS`
- `SITE_NETS → PROXY_NET` on TCP 8080 — **on the backend's interface**, since
  the agent dials the LAPI

### Failure and rollback

A three-VM build has partial-failure states a one-VM build does not. The
position taken: **leave what was built, record where it stopped, and never
roll back a VM that came up.** A half-built stack with a marker is
diagnosable; a stack that deleted its own first VM on a later failure is not,
and the operator loses the one artefact that would have explained it.

That is the same reasoning as `block_production` in `payload/install-wordpress.sh`
— finish, record, refuse to certify — applied one level up.

---

## 6. Service registry, beyond the three

npmplus TODO already names this and it should land there rather than here:

> **Backend type registry.** `npm-backend.sh register --type
> wasp|passbolt|mailcow|internal|generic` with a per-type header contract,
> location set and exposure class. Not written.

With a per-type contract, "whatever other options NPMplus offers that make
sense for WASP or other services" becomes a table rather than a special case
per service. Passbolt needs `X-Forwarded-Proto: https` or it emits `http://`
URLs; MeshCentral needs `trustedProxy`; Zammad and GLPI have equivalents. Each
is a header contract plus an exposure class.

**Exposure class must default to internal**, for the reason npmplus TODO gives:
community-scripts LXCs are convenience installers, explicitly not hardened, and
a meaningful fraction ship with no authentication because they assume a trusted
LAN. Publishing one puts an unauthenticated admin panel on the internet behind
an obscure hostname. A static check should make publishing require *naming* the
authentication the service has, so nothing is exposed by omission.

---

## 7. Sequencing

Ordered by what unblocks the most and risks the least.

**1. Topology discovery.** Done. Nothing else can generate an address without
it, and it is useful on its own for auditing a host.

**2. Publish the npmplus LAPI.** The smallest change with the largest effect:
it is what makes WASP 10.4's `upstream` mode usable at all, and it is a bounded
change to a repo that already has the mode. Needs the `validate-npmplus.sh`
check in the same commit, or the next redeploy reverts it silently.

**3. Tenant registration.** `cscli machines add` on the NPMplus side, feeding
`wp-hardening.sh cs-lapi` on the WASP side. Both ends exist; the handoff does
not.

**4. The config.xml generator.** Largest piece, fully specified by
`OPNSENSE.md`'s appendix, and independently valuable — it replaces clicking a
fifteen-segment firewall together by hand, which is the thing currently done
once per site.

**5. The orchestrator.** Last, because it is mostly sequencing and handoff
between four things that by then all work on their own. Written first, it would
be sequencing between three things that do not.

**6. Backend type registry.** In npmplus, for services beyond WASP.

### Honest unknowns

- **B1 — what NPMplus sends as `X-Forwarded-For`**, replace or append. Open in
  both repos. Nothing above depends on the answer, because single-literal
  `RemoteIPTrustedProxy` is correct either way — belt and braces if replace,
  load-bearing if append. Settle it before the tenant count makes a retrofit
  expensive; npmplus TODO has the raw-listener procedure.
- **OPNsense config.xml import across versions.** The appendix is verified
  against 26.7 with Filter model 1.0.5 and a 1.0.6 deployment. A generator must
  *detect* the running model version rather than assume: declaring 1.0.6 while
  writing 54 elements means migrations skip or double-apply.
- **Whether a VLAN-aware bridge can be added safely to a live host.** Changing
  `bridge-vlan-aware` is a network change on the interface Proxmox is
  administered through. The topology tool flags it and says to wrap it in a
  revert timer; it should not try to make the change.
- **`tools/` is outside the signed manifest.** `MANIFEST.sha256` covers
  `install.sh`, `lib/` and `payload/` — the files that execute during an
  install or land on the VM — and `check-manifest-coverage.py` enforces exactly
  that set. `wasp-topology.sh` and `wasp-pentest.sh` both run as root on the
  Proxmox host and are not signed. The topology tool reads only and changes
  nothing, which lowers the stakes without removing them: an attacker who can
  edit it can make a plan propose an address they control.
  Widening the signed set is a change to the release trust boundary — the
  manifest, the check, and `verify_release()` in `install.sh` — so it is noted
  here for a decision rather than made quietly as part of adding a tool.

---

## 8. What is true today

| Piece | State |
|---|---|
| `tools/wasp-topology.sh` | shipped, 30 tests, 2 fixtures |
| WASP preset contract (`WASP_*`) | shipped in 10.4, validated before build |
| WASP upstream CrowdSec mode | shipped in 10.4 |
| npmplus VM installer | exists, same architecture, own test suite |
| npmplus LAPI publication | **the gate.** Mode exists, port is loopback-only |
| npmplus tenant registration | not written |
| OPNsense config.xml generator | specified in `OPNSENSE.md`, not written |
| Orchestrator | this document |
| Backend type registry | named in npmplus TODO, not written |
