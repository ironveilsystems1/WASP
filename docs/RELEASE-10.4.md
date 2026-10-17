# WASP 10.4

**Release 10.4** · WordPress 7.1 · Alpine 3.24 · MariaDB 11.4 · CrowdSec v1.7.8

One defect, found by reading a deployed topology rather than this code, plus the
checks that stop it coming back.

If you run WASP behind a reverse proxy — Nginx Proxy Manager, Caddy, HAProxy,
NPMplus — **read the first section before the next install.** It is the
difference between a site that blocks attackers and a site that writes down
their addresses.

---

## A control that was present, correct, and inert

A reverse proxy terminates the client connection, so every packet reaching a
WASP VM comes from the proxy.

`mod_remoteip` recovers the real client address for the access log, so CrowdSec
reads the right address, detects correctly, and bans correctly — at this VM's
nftables, where no packet from that address ever arrives.

```
cscli decisions list              →  the ban is there
nft list set inet crowdsec ...    →  the address is there
the CrowdSec console              →  1 remediation component
the attacker                      →  unaffected
```

Four signals agreeing, none of them looking at the only question that matters:
whether traffic from a banned address can reach the firewall holding the ban.

## The part that was worse than the defect

**Production required that bouncer.** The gate added earlier in this series
refused to certify a VM whose local bouncer was not running and registered, on
the correct reasoning that detection without enforcement is not what production
promises.

Behind a proxy that made the strictest profile insist on the one configuration
that cannot work, and read its presence as proof of enforcement.

A fail-closed gate on an inert control is not fail-closed. It is a gate that
cannot fail.

This is the fourth control in this project found present, correct and doing
nothing. It is the first time the fail-closed check was itself pointing the
wrong way.

---

## Enforcement is chosen, not assumed

Give the installer a reverse proxy address and it asks where bans are enforced.
No default, because there is no safe one.

| Mode | Detection | Enforcement | When |
|---|---|---|---|
| `upstream` | here | the LAPI's bouncer, at the proxy or edge firewall | Behind a proxy. Nearly always this. |
| `detect-only` | here | nowhere | Enforcement lives somewhere this VM cannot see. A production blocker. |
| `local` | here | this VM's nftables | Direct access, or a proxy preserving the client source address at layer 3. A blocker when a proxy is set. |

In `upstream` mode **no local bouncer is installed.** That absence is
deliberate: a bouncer here would fill nftables with client addresses that never
send this VM a packet, and the next person to read that set would reasonably
conclude blocking was happening.

The production gate now asks whether enforcement exists on this traffic path,
not whether a local service is running. It also uses `block_production` rather
than `err`, so it no longer aborts mid-stage and strands the operator without
stage 10's diagnostic tooling — a lesson this same stage had already taught
once.

## Moving a VM that is already running

```sh
# On the LAPI host — prefix with `podman exec crowdsec` if it runs in a container
cscli machines add wp01 --password 'generated'

# On the WASP VM
doas wp-hardening.sh cs-lapi http://10.20.10.10:8080/ wp01 'generated'
```

Re-creates the agent, confirms it authenticated, stops the local bouncer,
removes its nftables table, records the topology. If it cannot authenticate it
says so and changes nothing permanent.

It refuses a loopback LAPI URL, and resolves the CrowdSec image from the running
container rather than falling back to a floating tag — a credential fix should
not silently discard digest pinning.

## The LAPI questions, asked properly

Three things present identically from a WASP VM and have unrelated causes: an
agent that cannot reach the LAPI, an agent whose login was never registered, and
an agent pointed at a LAPI with no bouncer behind it. All three give a clean
start, a healthy service, and nothing blocked.

So the installer asks about each rather than collecting three values and hoping:

- **The agent/LAPI/bouncer split is explained before the address is asked for.**
  "Which of the three is missing" is the question an operator needs to be able to
  form, and nothing in a CrowdSec install volunteers it.
- **The address is tested from the Proxmox host.** A LAPI still on its default
  `127.0.0.1:8080` binding serves no remote agent however correct the
  credentials are — and the symptom points at credentials, so the hour goes into
  password resets. The caveat is stated both ways: this host is not where the VM
  will be, so a refusal is evidence rather than proof, and a success does not
  mean the VM's segment is permitted.
- **Deferring is a first-class answer.** "The LAPI does not exist yet" is the
  state most tenants are in. The agent installs unconfigured, a production
  blocker is recorded, and one command finishes it later.
- **The machine login defaults to the hostname**, with the reason for one
  credential per tenant stated: a shared login makes `cscli machines list`
  useless for finding which site raised an alert, and revoking one site's access
  takes every site down with it.
- **It names what this VM can never tell you** — whether a bouncer exists on
  that LAPI, and whether a decision becomes a dropped packet — with the commands
  that answer both, on the host that can.

## Never-ban lists, and a blast radius that changes

The whitelist prompt was written for a VM that enforces locally, where a false
positive locks you out of one VM. Under upstream enforcement, a decision made on
a tenant goes to the central LAPI and the bouncer there applies it to **every
site behind that proxy** — so the same mistake is a fleet-wide outage you cannot
fix remotely, because the path you would fix it through is also blocked.

The prompt now says that, in the mode where it is true. The whitelist is written
in every mode: locally it stops this VM's firewall dropping you, upstream it
stops the decision being *proposed*, which is the only place it can be stopped.

- **The proxy's address leads the suggested set**, with the specific route to
  needing it: if `X-Forwarded-For` substitution breaks, this VM sees every
  request as coming from the proxy, and one brute-force attempt bans it. Remove
  it and the installer asks once more, then takes no for an answer.
- **`100.64.0.0/10` is offered separately.** Overlay addresses (NetBird,
  Tailscale, ZeroTier) are CGNAT, not RFC1918, so CrowdSec's stock whitelist
  never covers them — and remote administration is where a lockout is expensive.
  Offered rather than defaulted: a `/10` is a large trust grant and should not be
  accepted by pressing Enter past a long line.
- **Postoverflow rather than parser stage, and now said so.** The bucket still
  fills and the alert still fires, so a whitelisted machine of your own that
  starts tripping scenarios stays visible. At the parser stage the events are
  discarded before any scenario sees them and the address goes dark.
- **It says what the whitelist does not cover.** The engines on the proxy and
  the firewall read their own logs and never consult this file, so either can
  ban you while this VM proposed nothing — fumbling an SSH password on the
  firewall is the usual way. The installer prints a ready postoverflow block
  filled in with your own answers, for the enforcing hosts, and says to paste it
  there before enabling the bouncer.
- `wp-hardening.sh crowdsec-whitelist add|remove` is named at the prompt, so the
  answer is visibly not permanent.

`WASP_CROWDSEC_WHITELIST` presets it, and `install.sh` validates it for a
different reason than the other presets: a malformed entry fails **nowhere** at
runtime. CrowdSec loads the file, ignores what it cannot parse, and the address
you believe is protected is not.

## `cs-doctor` reads the topology first

In `upstream` mode it tests that a decision reaches the LAPI, then says plainly
what it cannot see. Steps 4 and 6 invert: a *running* local bouncer is reported
as the fault.

And a new **step 8** asks what none of the others could — can a local ban match
real traffic at all? It counts access-log addresses other than the proxy's, and
reports a fault when a VM set to enforce locally has only ever seen the proxy.
Steps 1 through 7 can all pass on a VM where nothing is ever blocked.

A VM built before 10.4 has no recorded topology. `cs-doctor` says so, infers
from the configured proxy, and warns that the live test proves the plumbing
rather than the protection.

---

## TRUST-COUNT

```apache
RemoteIPTrustedProxy 10.20.10.10      # correct
RemoteIPTrustedProxy 10.20.0.0/16     # authentication bypass
```

`mod_remoteip` walks `X-Forwarded-For` from the right, popping entries while
they match a trusted proxy. Name a range and every host inside it can prepend
whatever client address it likes and have Apache believe it.

That forged address is the one CrowdSec bans, the one `Require ip` checks for
wp-admin, the one the login guard counts attempts against, and the one the
contact-form rate limit keys on. One compromised neighbour becomes an
authentication bypass, a way to get any third party banned on demand, and a way
to never be rate-limited.

The interactive prompt already rejected a CIDR. That was one input. The
constraint is now asserted where it is relied upon:

- `install.sh` refuses a range, a list or a hostname before anything is built
- `lib/03` and `lib/06` each assert it at their own write site — a guard on one
  of two write paths is not a guard
- `check-trusted-proxy.py` holds it in the source tree, which is the one failure
  the runtime assertions cannot catch: they would faithfully assert whatever
  weaker rule replaced them

A hostname is refused because Apache resolves the directive once at startup, so
a name that later resolves elsewhere leaves Apache trusting an address nothing
told it about.

`RemoteIPInternalProxy` — which the upstream WordPress image ships
pre-populated with every RFC1918 range — can no longer re-enter the tree.

---

## Split-horizon loopback

WordPress calls its own public hostname for WP-Cron, Site Health and parts of
the REST API. With split-horizon DNS that name resolves to the proxy, so the
call leaves the VM and needs a permitted path back on 80 and 443 — which, where
each site has its own VLAN, does not exist by default. The call is dropped and
the symptom is "scheduled posts stopped working", which names neither DNS nor
the firewall.

The installer now offers a hosts entry mapping the site's name to `127.0.0.1`,
with the cost stated rather than discovered: loopback then stops exercising the
real path, so a broken proxy host or certificate no longer surfaces in Site
Health. The firewall-rule alternative is documented beside it, including that it
needs an explicit sequence number to sort above an east-west block.

Pick one deliberately and write down which. Doing both and forgetting which is
load-bearing is how this becomes unexplainable six months later.

---

## Presets, for a fleet

```sh
export WASP_PROXY_IP=10.20.10.10          # single literal address
export WASP_CS_ENFORCEMENT=upstream       # local | upstream | detect-only
export WASP_CS_LAPI_URL=http://10.20.10.10:8080/
export WASP_CS_LAPI_LOGIN=wp01            # must already exist on that LAPI
export WASP_CS_LAPI_PASSWORD='...'
export WASP_LOOPBACK_HOSTS=1
export WASP_CROWDSEC_WHITELIST=10.20.10.10,10.0.0.160,100.64.0.0/10

sudo -E ./install.sh
```

Ten tenants behind one proxy becomes a loop rather than ten identical
interactive sessions answered slightly differently — and the values live in a
runbook rather than in someone's terminal history.

A contract preflight validates all of it **before** an image is downloaded or a
disk created. A preset typo caught in `lib/06` costs fifteen minutes and a
half-built VM; the same typo costs two seconds here. It refuses an `upstream`
declaration missing any credential rather than letting it degrade to
detect-only with a message nobody is present to read, and it echoes the contract
it was given, so an unattended run records what it was told and not only what it
did.

`sudo -E` matters. Without `-E` the environment is stripped and every preset is
silently absent.

`WASP_`-prefixed rather than bare: a common name in the environment of a root
shell on a Proxmox host is too easy to inherit by accident, and inheriting this
one silently widens what Apache trusts.

---

## Also in this release

- `check-doas-prefix.py` gained a narrow exemption for commands naming another
  host. The CrowdSec registration steps run on the LAPI host, which may be
  OPNsense with no `doas` or a container needing `podman exec` — and the cheap
  way past the check would have been to add a `doas` that is confidently wrong.
  The line must say where it runs, which makes the escape visible in review.
- The loopback question is asked where `WP_DOMAIN` exists rather than beside the
  other proxy questions. Written in the topically obvious place first, where its
  own guard would have been false every time and the question would never have
  appeared while reading as though it did — the same class of defect as the empty
  `_SMTP_PORTS` expansion that produced a VM with no firewall at all.
- Stage 09 builds the CrowdSec container through a function taking the
  mode-specific flags, not `set --` before the run: the stage is *sourced*, so
  `set --` would rewrite the dispatcher's positional parameters for everything
  sourced after it.
- `/etc/wp-install/crowdsec-topology` records the declared topology, so later
  tooling judges a VM against what it was built to do rather than re-deriving
  intent from whether a bouncer happens to be installed.
- README documents one version number. It had still described the release-plus-
  build-stamp scheme that 10.3 removed.

---

## Upgrading

No migration. Existing VMs are unaffected until re-provisioned.

- **A VM behind a proxy is almost certainly not enforcing.** Run
  `doas wp-hardening.sh cs-doctor` and read step 8. If every logged request came
  from the proxy, that VM has never blocked anything.
- Move it with `doas wp-hardening.sh cs-lapi <url> <login> <password>`, after
  registering the machine on the LAPI host.
- **A LAPI bound to `127.0.0.1:8080` serves no remote agent.** Publishing it is
  a change on that host. Until it is, every tenant runs an isolated engine and
  its bans remain no-ops.
- **Whitelist your own management addresses on the enforcing engine first.** A
  false positive against your own source address locks you out of a remote
  site. Use a postoverflow whitelist rather than a parser one — at the parser
  stage the event is dropped before any scenario sees it and the address becomes
  invisible; at postoverflow the alert is still raised and only the ban is
  suppressed.
- If your own runbooks pin `RemoteIPTrustedProxy` to a range, the next install
  will refuse it. That refusal is the point.

---

## Verified

26 static checks · 57 fail-closed negative tests · syntax swept across `bash`,
`sh` and `dash` · `php -l` on every mu-plugin · 21-case MFA harness · eight
installer prompt flows driven end to end with scripted answers, confirming the
LAPI and whitelist branches produce the right values and that none of the proxy
questions appear on a direct-access install.

Each new gate has a negative test driven through the real guard, and each new
test was confirmed to fail when its guard is removed — a fail-closed control
with no negative test is the same failure this release is about.

Signed with minisign:

```sh
minisign -Vm MANIFEST.sha256 -P "$(dig +short TXT minisign._wasp.ironveil.systems | tr -d '"')"
sha256sum -c MANIFEST.sha256
```

A production install refuses to proceed unverified. For a development checkout,
`WASP_DEV_UNVERIFIED=1 ./install.sh` builds a VM permanently marked unverified.
