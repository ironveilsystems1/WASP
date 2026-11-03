#!/bin/sh
# =============================================================================
# wasp-menu.sh — one front door to the WASP tooling
# =============================================================================
# A task-grouped menu over the ~20 operator tools, so nobody has to remember
# which flag does what. Built for the way this box is actually operated:
#
#   - Pure POSIX sh, ZERO new packages. It runs in the `qm terminal` console
#     (where root operates and CANNOT paste) and over SSH for admins, on any
#     terminal, with no whiptail/dialog/ncurses dependency to add to a hardened
#     VM. Adding a TUI toolkit or a web UI for a menu would spend the
#     minimal-surface budget this whole project is built to protect.
#
#   - It is a teaching tool as much as a launcher: EVERY action prints the exact
#     command it is about to run before running it. A tech learns the command by
#     watching; an engineer confirms nothing surprising happens and can skip the
#     menu next time. Nothing here does anything you could not do by typing the
#     command yourself — it just means you do not have to remember it.
#
#   - Guardrails match the audience without splitting into two programs:
#     destructive or high-impact actions (rotate, update, restore, purge) are
#     marked [!] and require typing 'yes'. Everything else runs on a keystroke.
#
# This launches the tools; it does not reimplement them. If a tool changes, its
# entry here keeps working because it just calls the tool.
# =============================================================================
set -u

BIN=/usr/local/bin
IS_TTY=0; [ -t 0 ] && [ -t 1 ] && IS_TTY=1

# ── colours, only if the terminal supports them ─────────────────────────────
if [ -t 1 ] && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
  B=$(printf '\033[1m'); DIM=$(printf '\033[2m'); R=$(printf '\033[0m')
  GRN=$(printf '\033[32m'); YEL=$(printf '\033[33m'); RED=$(printf '\033[31m')
  CYN=$(printf '\033[36m')
else
  B=''; DIM=''; R=''; GRN=''; YEL=''; RED=''; CYN=''
fi

# ── privilege: most tools need root; elevate once via doas if available ──────
if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then exec doas "$0" "$@"; fi
  echo "wasp-menu must run as root (or via doas)." >&2
  exit 1
fi

# ── a run helper: show the command, (confirm if destructive), then run ──────
# usage: run "<label>" "<danger 0|1>" <tool> arg arg...
# The <tool> is a bare script name; run() resolves it under $BIN so the menu
# does not depend on $BIN being in PATH (it often is not in a bare console).
run() {
  _label="$1"; _danger="$2"; _tool="$3"; shift 3
  # Resolve to an absolute path if it is one of our tools; otherwise run as-is.
  if [ -x "$BIN/$_tool" ]; then _exe="$BIN/$_tool"; else _exe="$_tool"; fi
  echo ""
  printf '%s%s%s\n' "$B" "$_label" "$R"
  printf '%s$ %s %s%s\n' "$DIM" "$_tool" "$*" "$R"
  if [ "$_danger" = "1" ]; then
    printf '%s[!] This changes state or is high-impact.%s Type %syes%s to run: ' \
      "$RED" "$R" "$B" "$R"
    read -r _c
    case "$_c" in
      yes|YES) : ;;
      *) echo "    Skipped."; _pause; return 0 ;;
    esac
  fi
  echo "$DIM----------------------------------------$R"
  # shellcheck disable=SC2068
  "$_exe" "$@"
  _rc=$?
  echo "$DIM----------------------------------------$R"
  [ "$_rc" -eq 0 ] && printf '%s[ok] done%s\n' "$GRN" "$R" \
                   || printf '%s[!!] exited %s%s\n' "$YEL" "$_rc" "$R"
  _pause
}

# Prompt for one argument. Returns non-zero (and prints nothing) if left blank,
# so a caller can abort cleanly rather than run a tool with a missing operand.
ask() { # prompt varname
  printf '  %s: ' "$1"
  read -r _ans
  [ -n "$_ans" ] || { echo "    (nothing entered — cancelled)"; return 1; }
  eval "$2=\$_ans"
  return 0
}

_pause() { [ "$IS_TTY" = 1 ] && { printf '\n%spress Enter%s' "$DIM" "$R"; read -r _; }; }

_missing() { # tool
  printf '%s  %s is not installed on this VM.%s\n' "$YEL" "$1" "$R"
  _pause
}

_have() { [ -x "$BIN/$1" ]; }

# ── headers ─────────────────────────────────────────────────────────────────
_banner() {
  clear 2>/dev/null || true
  _ver="unknown"
  # Strip surrounding quotes with sed, not `tr -d` with nested shell quotes:
  # the concatenated `tr` form can degrade into an invalid character range.
  [ -r /etc/wp-install/vars.sh ] && _ver=$(sed -n 's/^WASP_VERSION=//p' /etc/wp-install/vars.sh | sed -e 's/^["'\'']//' -e 's/["'\'']$//' | head -1)
  _prof=$(sed -n 's/^DEPLOYMENT_PROFILE=//p' /etc/wp-install/vars.sh 2>/dev/null | sed -e 's/^["'\'']//' -e 's/["'\'']$//' | head -1)
  printf '%s┌────────────────────────────────────────────────────┐%s\n' "$CYN" "$R"
  printf '%s│%s  %sWASP operator menu%s   build %s  %s%s\n' "$CYN" "$R" "$B" "$R" "${_ver}" "${_prof:-standard}" ""
  printf '%s└────────────────────────────────────────────────────┘%s\n' "$CYN" "$R"
  # A one-line health pulse at the top so the operator sees state before acting.
  if _have validate-wordpress.sh; then
    _h=$(validate-wordpress.sh --check 2>/dev/null | head -1)
    case "$_h" in
      *OK*|*ok*)     printf '  health: %s%s%s\n' "$GRN" "$_h" "$R" ;;
      *WARN*|*warn*) printf '  health: %s%s%s\n' "$YEL" "$_h" "$R" ;;
      *CRIT*|*crit*) printf '  health: %s%s%s\n' "$RED" "$_h" "$R" ;;
      *)             [ -n "$_h" ] && printf '  health: %s\n' "$_h" ;;
    esac
  fi
}

# =============================================================================
#  GUIDANCE LAYER — help cards, and a guided path for a first-time operator
# =============================================================================
# WHY THIS IS NOT A TUI
#
# The obvious way to make a menu friendly is whiptail, the way the Proxmox
# community scripts do it. That would mean the `newt` package and its ncurses
# dependencies on every hardened VM, to draw boxes. This project spends its
# surface budget on things that defend the site, so the guidance is built out
# of the same POSIX sh and ANSI the rest of the menu already uses.
#
# What a first-time operator actually lacks is not arrow keys. It is knowing
# which option to pick, what it will ask, and what a correct answer looks
# like. That is text, and text is free.
#
#   ?N   on any menu  -> a card for option N: what it does, when to use it,
#                        what it will ask, and a worked example
#   ?    on any menu  -> what the whole menu is for and where to start
#
# Every card answers the same four questions in the same order, so an
# operator learns the shape once.
# =============================================================================

_rule() { printf '%s──────────────────────────────────────────────────────────────%s\n' "$DIM" "$R"; }

_card() {   # $1 = title; body on stdin
  clear 2>/dev/null || true
  printf '%s┌──────────────────────────────────────────────────────────────┐%s\n' "$CYN" "$R"
  # No right border on the title line. printf's %-58s pads by BYTES, and the
  # em-dash in these titles is three bytes for one column, so a padded box
  # closes two characters short on exactly the titles that use one. _banner
  # has always left this edge open for the same reason; match it.
  printf '%s│%s  %s%s%s\n' "$CYN" "$R" "$B" "$1" "$R"
  printf '%s└──────────────────────────────────────────────────────────────┘%s\n' "$CYN" "$R"
  echo ""
  cat
  echo ""
  _pause
}

# Read a selection, intercepting help requests. Sets `c`, the variable every
# submenu already dispatches on. After a card is shown, `c` is cleared so the
# caller's loop falls through its case and redraws the menu -- which means no
# submenu needed its dispatch touched to gain help.
_sel() {    # $1 = help key prefix for this menu
    _pfx="$1"
    while :; do
        printf '\n  select  %s(?N = help on option N,  ? = about this menu)%s : ' "$DIM" "$R"
        read -r c || { c=q; return 0; }
        case "$c" in
            '?'|h|H|help) _help "${_pfx}.menu"; c=''; return 0 ;;
            '?'*)         _help "${_pfx}.${c#\?}"; c=''; return 0 ;;
            *)            return 0 ;;
        esac
    done
}

_help() {
  case "$1" in

  # ── Health ────────────────────────────────────────────────────────────────
  health.menu) _card "Health & status — start here" <<'EOF'
  Everything in this menu is READ-ONLY. Nothing changes the site, so you can
  run any of it on a live production VM without a maintenance window.

  Where to start:
    New VM you just built ........ 2 (full validation)
    Something feels wrong ........ 1 (quick check), then 2
    Handing the VM to a client ... 3 (a report you can send)
    Site is slow or erroring ..... 4, then 5
EOF
    ;;
  health.1) _card "1 — Quick health check" <<'EOF'
  WHAT IT DOES
    Runs about a dozen fast probes: containers running, WordPress answering,
    database reachable, certificate valid. Takes a few seconds.

  WHEN TO USE IT
    As a first look when something seems wrong, or in a script -- it sets an
    exit code, so `validate-wordpress.sh --check && echo ok` works.

  WHAT IT ASKS YOU
    Nothing. It runs immediately.

  EXAMPLE
    Just press 1. You want a line reading OK. WARN means degraded but
    serving; CRIT means the site is down or a control has failed open.
EOF
    ;;
  health.2) _card "2 — Full validation (~45 checks)" <<'EOF'
  WHAT IT DOES
    The complete suite: every hardening control, the firewall, egress, MFA,
    backups, mail, TLS, file permissions. One to two minutes.

  WHEN TO USE IT
    After building a VM, after any update, and before handing a site to a
    client. This is the check that decides whether the VM is fit to hand over.

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    Press 2 and read the FAIL lines. Each one names the control and tells you
    the command that fixes it. It does not stop at the first failure -- you
    get the whole picture in one pass.
EOF
    ;;
  health.3) _card "3 — Full test report (send-able)" <<'EOF'
  WHAT IT DOES
    Runs the validation suite and writes a single file you can send to a
    client or keep as commissioning evidence.

  WHEN TO USE IT
    At handover, or when a client asks "is it secure?" and wants something
    on paper.

  WHAT IT ASKS YOU
    Nothing. It prints the path of the report when it finishes.

  EXAMPLE
    Press 3, then copy the report off the VM with scp. Note the -O flag:
      scp -O admin@10.20.101.10:/var/log/wasp-testreport-*.txt .
EOF
    ;;
  health.4) _card "4 — Container / WordPress health" <<'EOF'
  WHAT IT DOES
    Checks the WordPress container specifically: HTTP responding, PHP
    executing, the database name resolving, database auth working, and a real
    query returning. Five separate things that all present as "site down".

  WHEN TO USE IT
    The site is erroring and you need to know WHICH layer broke.

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    Press 4. If PHP executes but the query fails, the problem is the database
    or its credentials, not WordPress.
EOF
    ;;
  health.5) _card "5 — Database health" <<'EOF'
  WHAT IT DOES
    Checks MariaDB: running, accepting connections, the WordPress database
    present, and table integrity.

  WHEN TO USE IT
    After option 4 points at the database, or after an unclean shutdown.

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    Press 5. A healthcheck stuck at "starting" forever is a known quirk of
    running containers without systemd -- if queries work, the database is
    fine regardless of what the status column says.
EOF
    ;;

  # ── Backup ────────────────────────────────────────────────────────────────
  backup.menu) _card "Backup & restore — the one to get right" <<'EOF'
  A backup you have never restored is a hope, not a backup. This menu is
  ordered so you can prove recovery rather than assume it.

  First time on a new VM, in order:
    2 ... is off-site configured at all?
    7 ... if not, this tells you exactly what is missing
    1 ... take a backup now
    4 ... prove you can actually get it back  <- the one people skip

  [!] marks actions that change or replace data. They ask you to type 'yes'.
EOF
    ;;
  backup.1) _card "1 — Run a backup now" <<'EOF'
  WHAT IT DOES
    Dumps the database, compresses it, and writes it locally -- then pushes a
    copy off-VM if off-site backup is configured.

  WHEN TO USE IT
    Before any change you might regret: an update, an import, a plugin
    install, editing wp-config.

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    Press 1. If it says the local backup succeeded but the OFF-VM copy
    failed, you are not protected against losing the VM. Use option 7.
EOF
    ;;
  backup.2) _card "2 — Off-site backup status" <<'EOF'
  WHAT IT DOES
    Reports whether backups are leaving this VM, where they go, and when the
    last one succeeded.

  WHEN TO USE IT
    First thing on any VM you have inherited or just built.

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    Press 2. "Off-VM backup is not configured" means every backup you have is
    on the same disk as the site. That is the single most common gap on a
    freshly built VM, and it is the one that matters when a host dies.
EOF
    ;;
  backup.3) _card "3 — List off-site backups" <<'EOF'
  WHAT IT DOES
    Lists what is actually in the remote bucket, with dates and sizes.

  WHEN TO USE IT
    To confirm backups are arriving, and to pick one before a restore.

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    Press 3. Check the newest date against today. A list that stops three
    weeks ago means backups have been failing silently for three weeks.
EOF
    ;;
  backup.4) _card "4 — [!] Prove offsite recovery (restore drill)" <<'EOF'
  WHAT IT DOES
    Pulls a real encrypted backup from remote storage, decrypts it with your
    recovery key, and verifies it restores. This is the only step that proves
    recovery works end to end.

  WHEN TO USE IT
    Once per VM at commissioning, and periodically after. Until you have run
    it, off-site recovery is an assumption.

  WHAT IT ASKS YOU
    Your recovery key, and confirmation ('yes'). It restores into a scratch
    area, NOT over the live site.

  EXAMPLE
    Have the recovery key to hand before you start -- it is not stored on
    this VM on purpose. If you cannot find it, that IS the finding.
EOF
    ;;
  backup.5) _card "5 — [!] Restore from backup" <<'EOF'
  WHAT IT DOES
    Replaces the live database with a backup. This is destructive and real.

  WHEN TO USE IT
    After a bad update, a failed import, or a compromise -- when you want the
    site back as it was.

  WHAT IT ASKS YOU
    Which backup, your recovery key if the backup is encrypted, and
    confirmation ('yes').

  EXAMPLE
    Run option 1 FIRST. Restoring replaces the current state, and if the
    restore turns out to be the wrong backup you will want the one you just
    overwrote.
EOF
    ;;
  backup.6) _card "6 — Self-test (local restore)" <<'EOF'
  WHAT IT DOES
    Takes a backup and restores it into a scratch database to prove the
    backup/restore machinery works. Does not touch the live site.

  WHEN TO USE IT
    A safe rehearsal when you are not ready to run the full off-site drill
    (option 4), or to check the local half after changing backup settings.

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    Press 6. It proves the mechanism, not your off-site copy. Option 4 is the
    one that proves you could survive losing this VM.
EOF
    ;;
  backup.7) _card "7 — Why is nothing off-VM?" <<'EOF'
  WHAT IT DOES
    Diagnoses off-site backup: credentials present, destination reachable,
    bucket writable, encryption key set. Names the specific missing piece.

  WHEN TO USE IT
    Whenever option 2 says off-site is not configured or not working.

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    Press 7. It will tell you which of credentials / destination / key is
    missing, and options 8 and 9 set those.
EOF
    ;;
  backup.8) _card "8 — Replace storage credentials" <<'EOF'
  WHAT IT DOES
    Sets the access key and secret for your object storage (S3, Backblaze B2,
    Wasabi, MinIO -- anything S3-compatible).

  WHEN TO USE IT
    First-time setup, or after rotating keys at the provider.

  WHAT IT ASKS YOU
    Access key ID, then secret access key. The secret is not echoed.

  EXAMPLE
    Access key ID      : AKIA2XYZEXAMPLE7PQ4R
    Secret access key  : (typed, not shown)
    Use a key scoped to ONE bucket with write-but-not-delete if your
    provider supports it. A backup key that can delete is a ransomware target.
EOF
    ;;
  backup.9) _card "9 — Change backup destination" <<'EOF'
  WHAT IT DOES
    Sets where backups are written: provider endpoint, bucket, and path.

  WHEN TO USE IT
    First-time setup, or moving a client to different storage.

  WHAT IT ASKS YOU
    An endpoint URL, a bucket name, and a path prefix.

  EXAMPLE
    Endpoint : https://s3.us-west-002.backblazeb2.com
    Bucket   : ironveil-client-backups
    Prefix   : client-a/
    Give every client their own prefix, so one client's restore can never
    reach another's data.
EOF
    ;;

  # ── Security ──────────────────────────────────────────────────────────────
  security.menu) _card "Security & hardening" <<'EOF'
  Options 1-8 are read-only: they report, scan and test. Safe any time.

  Options 10-14 CHANGE hardening. Each says plainly whether it raises or
  lowers protection. The pairs exist because real work sometimes needs a
  control relaxed briefly -- relax it, do the work, put it back.

  Where to start:
    Just built the VM ............ 1, then 3
    Site behaving oddly .......... 5, then 6
    Suspect a compromise ......... 7, then menu 6 (Diagnostics)
    Plugin cannot reach vendor ... 2
EOF
    ;;
  security.1) _card "1 — Hardening status" <<'EOF'
  WHAT IT DOES
    Lists every hardening control and whether it is on: file editing, theme
    and plugin installs, PHP shell functions, XML-RPC, user enumeration, MFA.

  WHEN TO USE IT
    First thing on any VM, and after anyone has been "fixing" something.

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    Press 1. Anything showing ALLOWED that you did not deliberately allow is
    worth asking about -- options 11 and 13 put them back.
EOF
    ;;
  security.2) _card "2 — Egress (proxy) status" <<'EOF'
  WHAT IT DOES
    Shows the destination allowlist -- every domain this site is permitted to
    reach. WordPress cannot make outbound connections to anything else.

  WHEN TO USE IT
    When a plugin or theme cannot reach its licence or update server.

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    Press 2. To add a vendor, from a shell:
      doas wasp-egress.sh allow .elementor.com
    Every entry is also a route OUT for a compromised site, so add the
    specific host the log names, not a wildcard you guessed.
EOF
    ;;
  security.3) _card "3 — Test egress is enforced" <<'EOF'
  WHAT IT DOES
    Proves the firewall actually blocks non-allowlisted destinations, by
    removing WordPress's proxy setting and confirming the connection still
    fails. Tests the enforcement, not the configuration.

  WHEN TO USE IT
    At commissioning. A proxy that is merely CONFIGURED can be bypassed by a
    plugin that ignores it; this proves the firewall stops that.

  WHAT IT ASKS YOU
    Nothing. It restores the setting afterwards.

  EXAMPLE
    Press 3. You want it to report that the direct connection was BLOCKED.
EOF
    ;;
  security.4) _card "4 — CrowdSec whitelist" <<'EOF'
  WHAT IT DOES
    Lists the addresses CrowdSec will never ban.

  WHEN TO USE IT
    After locking yourself out, or before testing from a new location.

  WHAT IT ASKS YOU
    Nothing in list mode.

  EXAMPLE
    Press 4. Your office IP and your management overlay belong here. An
    uptime monitor that hits the login page also belongs here, or it will
    eventually ban itself.
EOF
    ;;
  security.5) _card "5 — Plugin vulnerability scan" <<'EOF'
  WHAT IT DOES
    Checks every installed plugin and theme against known vulnerability
    feeds, matched locally -- the plugin list is not sent anywhere.

  WHEN TO USE IT
    Weekly, and always after importing a site you did not build.

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    Press 5. An outdated plugin with a known exploit is the single most
    common way a WordPress site is taken over.
EOF
    ;;
  security.6) _card "6 — Malware scan (quick)" <<'EOF'
  WHAT IT DOES
    The high-signal checks: PHP files where PHP never belongs (uploads),
    core files that differ from the pinned image, world-writable files.

  WHEN TO USE IT
    Routinely, and immediately after any import.

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    Press 6. A .php file under wp-content/uploads is essentially never
    legitimate -- that finding alone is worth acting on.
EOF
    ;;
  security.7) _card "7 — Malware scan (full)" <<'EOF'
  WHAT IT DOES
    Everything in the quick scan plus signature rules and database analysis:
    injected options, hidden admin users, suspicious scheduled tasks.

  WHEN TO USE IT
    When you suspect a compromise, or after inheriting a site.

  WHAT IT ASKS YOU
    Nothing. Takes a few minutes.

  EXAMPLE
    Press 7. Read the summary counts, but read the findings above them too --
    and remember no scanner detects a backdoor written for this site alone.
EOF
    ;;
  security.8) _card "8 — Verify tooling integrity" <<'EOF'
  WHAT IT DOES
    Checks every WASP tool on this VM against the signed manifest, so you
    know the tools reporting on the site have not themselves been edited.

  WHEN TO USE IT
    Before trusting any other result during an incident.

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    Press 8. If this fails, stop and treat every other tool's output as
    unreliable until you know why.
EOF
    ;;
  security.9) _card "9 — [!] Rotate a secret" <<'EOF'
  WHAT IT DOES
    Opens a submenu to rotate WordPress salts, database passwords, or SMTP
    credentials. Verifies the new value works before committing, and rolls
    back if it does not.

  WHEN TO USE IT
    After any suspected exposure, after staff turnover, and after any
    compromise -- rotation is part of recovery, not optional.

  WHAT IT ASKS YOU
    Which secret, and confirmation ('yes').

  EXAMPLE
    Rotating salts logs every user out immediately, including an intruder
    holding a stolen session cookie. That is usually what you want.
EOF
    ;;
  security.10) _card "10 — Theme/plugin uploads: ALLOW (lowers hardening)" <<'EOF'
  WHAT IT DOES
    Turns OFF DISALLOW_FILE_MODS, re-enabling plugin and theme installs from
    inside wp-admin.

  WHEN TO USE IT
    Rarely. The console path (option 12) installs from a file without
    lowering anything, and it is logged.

  WHAT IT ASKS YOU
    Confirmation ('yes'), because this reduces protection.

  EXAMPLE
    If you do use it, put it back with option 11 the moment you are done.
    An admin session an attacker has taken over can install a plugin, and a
    plugin is arbitrary code.
EOF
    ;;
  security.11) _card "11 — Theme/plugin uploads: BLOCK (restores hardening)" <<'EOF'
  WHAT IT DOES
    Turns DISALLOW_FILE_MODS back on: no plugin or theme installs, updates or
    deletions from wp-admin.

  WHEN TO USE IT
    Immediately after finishing whatever needed option 10.

  WHAT IT ASKS YOU
    Nothing -- it raises protection, so it runs on a keystroke.

  EXAMPLE
    Press 11. Afterwards wp-admin shows NO update section at all, even for
    plugins with valid licences. That is the control working, and it is very
    commonly mistaken for an egress fault.
EOF
    ;;
  security.12) _card "12 — Install a theme/plugin ZIP" <<'EOF'
  WHAT IT DOES
    Installs a plugin or theme from a local .zip, recording its SHA-256.
    Works WITHOUT lowering hardening, and it is logged.

  WHEN TO USE IT
    Any commercial theme or plugin: Elementor Pro, BeTheme, Divi -- anything
    not on WordPress.org.

  WHAT IT ASKS YOU
    The path to the zip.

  EXAMPLE
    Get the file onto the VM first:
      scp -O betheme.zip admin@10.20.101.10:/var/lib/wasp-import/incoming/
    then answer:
      /var/lib/wasp-import/incoming/betheme.zip
    Commercial plugins have no published checksums, so "does not verify" is
    the expected and correct answer, not a failure.
EOF
    ;;
  security.13) _card "13 — PHP shell functions: BLOCK (restores hardening)" <<'EOF'
  WHAT IT DOES
    Disables exec, shell_exec, system, passthru and friends in PHP.

  WHEN TO USE IT
    Always, unless a specific plugin genuinely needs them.

  WHAT IT ASKS YOU
    Nothing -- it raises protection.

  EXAMPLE
    Press 13. Most webshells need one of these functions. Turning them off
    makes a whole class of attack inert even if a file is planted.
EOF
    ;;
  security.14) _card "14 — PHP shell functions: ALLOW (lowers hardening)" <<'EOF'
  WHAT IT DOES
    Re-enables PHP's shell execution functions.

  WHEN TO USE IT
    Only when a plugin you trust genuinely requires it, and only for as long
    as that is true.

  WHAT IT ASKS YOU
    Confirmation ('yes').

  EXAMPLE
    If a plugin demands this, consider whether you want that plugin on a
    public site at all. Put it back with option 13 as soon as you can.
EOF
    ;;
  security.17) _card "17 — Is CrowdSec actually blocking?" <<'EOF'
  WHAT IT DOES
    Tests the whole chain live: CrowdSec sees an event, makes a decision, and
    the firewall enforces it. Proves bans actually block rather than just
    being recorded.

  WHEN TO USE IT
    At commissioning, and whenever you doubt the bans are real.

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    Press 17. CrowdSec logging a decision that nothing enforces is a very
    quiet failure -- the dashboard looks busy and nobody is being stopped.
EOF
    ;;
  security.18) _card "18 — Report bans to a central LAPI" <<'EOF'
  WHAT IT DOES
    Points this VM's CrowdSec agent at a shared Local API on another host, so
    several sites feed one decision set and a ban learned on one protects all.

  WHEN TO USE IT
    When you run more than one WASP VM behind a common reverse proxy.

  WHAT IT ASKS YOU
    The LAPI URL, a machine login, and a machine password.

  EXAMPLE
    LAPI URL : http://10.20.10.10:8080/
    Login    : wp01-clientname
    Password : (typed, not shown)
    Register the machine on the LAPI host FIRST:
      cscli machines add wp01-clientname --password '<pw>'
    Passwords cap at 72 characters there -- longer ones are rejected.
EOF
    ;;

  # ── Updates ───────────────────────────────────────────────────────────────
  updates.menu) _card "Updates" <<'EOF'
  Two different questions, often confused:

    Has my pinned version been REBUILT with security fixes?   -> 1
    Is there a NEWER RELEASE than the one I pinned?           -> 22

  Updates run a CVE scan first and refuse to proceed on an incomplete scan
  under the production profile -- "the scanner did not run" is not the same
  as "the scanner found nothing".

  Take a backup (menu 2, option 1) before applying anything.
EOF
    ;;
  updates.1) _card "1 — Check what's available" <<'EOF'
  WHAT IT DOES
    Compares each pinned image against the registry by digest. Finds security
    rebuilds of the version you are already on. Changes nothing.

  WHEN TO USE IT
    Weekly.

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    Press 1. "digest up to date" everywhere means you are current on the
    versions you pinned -- which is a different question from option 22.
EOF
    ;;
  updates.2) _card "2 — Current versions / status" <<'EOF'
  WHAT IT DOES
    Shows what is actually running: image versions, digests, container state,
    firewall and bouncer status.

  WHEN TO USE IT
    Before and after any update, and when reporting a problem.

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    Press 2. A bouncer line reading "agent-only, reporting to a remote LAPI"
    is normal when the LAPI lives on another host.
EOF
    ;;
  updates.22) _card "22 — Newer versions upstream?" <<'EOF'
  WHAT IT DOES
    Asks the registry whether newer RELEASES exist than the versions you
    pinned. Changes nothing.

  WHEN TO USE IT
    Monthly, and when a CVE is announced for something you run.

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    Press 22, then apply one component at a time from a console:
      update.sh crowdsec v1.8.1
    Updates are interactive by design and cannot run over `qm guest exec`,
    which gives the prompt no input and silently skips.
EOF
    ;;

  # ── Import ────────────────────────────────────────────────────────────────
  import.menu) _card "Import a site" <<'EOF'
  Importing a site you did not build means running someone else's files and
  database. The order here exists so nothing is executed or served before it
  has been examined.

    1 ... how to get the archive onto this VM
    2 ... look inside it WITHOUT extracting anything
    3 ... extract to staging, outside the web root, non-executable
    4 ... scan the staged files AND the database dump
    then apply, which asks you to type IMPORT

  Take a backup first (menu 2, option 1). Import replaces the database.
EOF
    ;;
  import.1) _card "1 — How to get a backup here" <<'EOF'
  WHAT IT DOES
    Prints the ways to deliver an archive to this VM, with the exact
    commands.

  WHEN TO USE IT
    Before your first import.

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    The usual route, from your own machine:
      scp -O backup.zip admin@10.20.101.10:/var/lib/wasp-import/incoming/
    The -O flag is required: there is no SFTP subsystem on this VM.
EOF
    ;;
  import.2) _card "2 — Inspect an archive" <<'EOF'
  WHAT IT DOES
    Reads the archive index and reports what is inside. Extracts NOTHING.

  WHEN TO USE IT
    Always, before extracting. It costs seconds and tells you what you have.

  WHAT IT ASKS YOU
    The archive path.

  EXAMPLE
    /var/lib/wasp-import/incoming/backup.zip
    A cPanel account backup nests the site under <account>/public_html/ and
    carries mail, logs and the panel's own files. A plugin export is a
    different shape. Knowing which you have decides everything after.
EOF
    ;;
  import.3) _card "3 — Extract (bounded staging)" <<'EOF'
  WHAT IT DOES
    Unpacks into a staging area outside the web root, strips the execute bit
    from everything, removes known takeover installers, and collects any
    database dumps it finds.

  WHEN TO USE IT
    After inspecting.

  WHAT IT ASKS YOU
    The archive path.

  EXAMPLE
    /var/lib/wasp-import/incoming/backup.zip
    Nothing here is web-reachable and nothing is executable. If the archive
    holds several dated dumps, it will list them and ask you to keep one --
    picking silently would restore whichever sorted first, not the newest.
EOF
    ;;
  import.4) _card "4 — Scan staged content" <<'EOF'
  WHAT IT DOES
    Runs the malware scanner over the staged files AND inspects the database
    dump for injected admin users, code in option rows, and suspicious
    scheduled tasks -- BEFORE any of it reaches the live site.

  WHEN TO USE IT
    Always, and the import refuses to proceed without it.

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    Press 4. Findings do not necessarily stop you: people import compromised
    sites deliberately, to clean them. They stop you importing one by
    ACCIDENT.
EOF
    ;;

  # ── Diagnostics ───────────────────────────────────────────────────────────
  diag.menu) _card "Diagnostics & forensics" <<'EOF'
  Two different jobs:

    Something is broken and you want help ....... 1 or 2 (capture)
    Something is wrong and you suspect intent ... 3 and 4 (forensics)

  If you think the site was compromised, capture BEFORE you clean. Deleting
  the evidence is how an incident becomes unexplainable -- and an attacker
  who got in once gets in again by the same door if you never find it.
EOF
    ;;
  diag.1) _card "1 — Capture a session for review" <<'EOF'
  WHAT IT DOES
    Records your terminal session plus diagnostics into one local bundle,
    redacting secrets by value. Uploads nowhere.

  WHEN TO USE IT
    When you want someone else to see what you are seeing.

  WHAT IT ASKS YOU
    Nothing to start. Type exit to stop recording.

  EXAMPLE
    Press 1, reproduce the problem, type exit. It prints the bundle path.
    Read it before sending it anywhere.
EOF
    ;;
  diag.2) _card "2 — Capture current state only" <<'EOF'
  WHAT IT DOES
    Collects diagnostics without recording a session: versions, container
    state, recent logs, configuration, health results.

  WHEN TO USE IT
    For a bug report, or a snapshot before making a change.

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    Press 2. Secrets are redacted by value, not by guessing at names.
EOF
    ;;
  diag.3) _card "3 — Forensics: unexpected admins" <<'EOF'
  WHAT IT DOES
    Lists every WordPress administrator with its registration date and
    capabilities.

  WHEN TO USE IT
    Immediately on any suspected compromise, and after inheriting a site.

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    Press 3. An administrator you cannot account for is persistence: it
    survives cleaning whatever created it. Check registration dates against
    option 4 -- an account appearing minutes after a suspicious file is one
    event, not two.
EOF
    ;;
  diag.4) _card "4 — Forensics: change timeline" <<'EOF'
  WHAT IT DOES
    Builds a timeline from file timestamps, database changes, backups and
    CrowdSec decisions, so you can see what happened around an event.

  WHEN TO USE IT
    After finding something suspicious, to see what accompanied it.

  WHAT IT ASKS YOU
    Nothing, though it accepts a file or time to centre on.

  EXAMPLE
    Press 4. Be aware of the window: HTTP logs rotate hourly, so anything
    older has file and database timestamps but no request context. A file
    dated two years ago will not have logs explaining how it arrived.
EOF
    ;;
  diag.5) _card "5 — Mail: status" <<'EOF'
  WHAT IT DOES
    Reports SMTP configuration and whether WordPress can send mail.

  WHEN TO USE IT
    When password resets or notifications are not arriving.

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    Press 5. Mail being unconfigured is common and mostly harmless -- until
    someone needs a password reset and cannot get one.
EOF
    ;;
  diag.6) _card "6 — Mail: send a test" <<'EOF'
  WHAT IT DOES
    Sends a real test message through the configured path and reports what
    happened.

  WHEN TO USE IT
    After configuring SMTP, to prove it works.

  WHAT IT ASKS YOU
    The destination address.

  EXAMPLE
    you@yourcompany.com
    Use an address you can actually check. Then look in spam -- delivered but
    filtered is a different problem from not sent, and needs SPF and DKIM
    rather than more debugging here.
EOF
    ;;
  diag.7) _card "7 — Self-test (full)" <<'EOF'
  WHAT IT DOES
    Exercises the machinery itself: backup and restore, candidate isolation,
    egress enforcement.

  WHEN TO USE IT
    At commissioning, or when you doubt a control.

  WHAT IT ASKS YOU
    Nothing. Takes several minutes.

  EXAMPLE
    Press 7. This tests that the safety nets work, which is a different
    question from whether the site is currently healthy.
EOF
    ;;

  # ── Testing ───────────────────────────────────────────────────────────────
  testing.menu) _card "Testing & validation" <<'EOF'
  Everything here is read-only except 18 (installs the MFA plugin).

  A sensible commissioning order:
    2  ... quick health
    3  ... full validation
    7  ... egress really enforced
    8  ... tooling integrity
    14 ... MFA state
    4  ... full self-test
    21 ... anything still blocking production?
EOF
    ;;
  updates.3) _card "3 — [!] Update everything" <<'EOF'
  WHAT IT DOES
    Updates every component in one pass: WordPress, database, CrowdSec,
    Squid. Each gets its own CVE scan, health check and rollback.

  WHEN TO USE IT
    On a VM you are comfortable with. On one that has been misbehaving,
    update components one at a time (4-8) so you know what moved.

  WHAT IT ASKS YOU
    Confirmation before each component, and a written justification if a
    component has HIGH or CRITICAL vulnerabilities.

  EXAMPLE
    Back up first (menu 2, option 1). Updates are interactive by design --
    run them from a console, not over `qm guest exec`, which gives the
    prompts no input and silently skips every one.
EOF
    ;;
  updates.4) _card "4 — [!] Update WordPress" <<'EOF'
  WHAT IT DOES
    Starts a CANDIDATE container on a private port with a read-only database
    account, proves it is healthy, and only then swaps it into place. The old
    container is kept as the rollback until the new one proves itself.

  WHEN TO USE IT
    When option 1 or 22 shows a newer WordPress.

  WHAT IT ASKS YOU
    Confirmation, plus a justification if the image has open CVEs.

  EXAMPLE
    Afterwards run:  wp-plugins.sh core-update-db
    A new core against an old database schema fails in ways that do not
    announce themselves.
EOF
    ;;
  updates.5) _card "5 — [!] Update database" <<'EOF'
  WHAT IT DOES
    Updates MariaDB, taking a backup and a data-directory snapshot first.

  WHEN TO USE IT
    Least often of all of these, and never casually -- a major version
    upgrades the data directory in place and cannot be undone by swapping
    the image back.

  WHAT IT ASKS YOU
    Confirmation, and the version if you are moving between LTS lines.

  EXAMPLE
    Do this one alone, after everything else is verified, and only with an
    OFF-VM backup you have actually restored (menu 2, option 4). A higher
    version number is not always better supported: stay on LTS lines.
EOF
    ;;
  updates.6) _card "6 — [!] Update CrowdSec" <<'EOF'
  WHAT IT DOES
    Replaces the CrowdSec container, carrying forward the deployment's own
    topology -- an agent-only install stays agent-only and keeps reporting
    to its remote LAPI.

  WHEN TO USE IT
    When your central LAPI is on a newer version than this agent.

  WHAT IT ASKS YOU
    Confirmation, plus justification if CVEs are open.

  EXAMPLE
    A version change migrates config on first start and can take a couple of
    minutes before the API answers. Afterwards, confirm on the LAPI host that
    this machine still has a live heartbeat:  cscli machines list
EOF
    ;;
  updates.7) _card "7 — [!] Update Squid (egress proxy)" <<'EOF'
  WHAT IT DOES
    Replaces the egress proxy container, then re-validates WordPress.

  WHEN TO USE IT
    When a digest check shows a rebuild. Canonical ships security fixes in
    place, so newness here appears as a digest change rather than a new tag.

  WHAT IT ASKS YOU
    Confirmation.

  EXAMPLE
    Afterwards check the allowlist survived (menu 3, option 2) and that
    enforcement still holds (menu 3, option 3).
EOF
    ;;
  updates.8) _card "8 — [!] Update Alpine OS packages" <<'EOF'
  WHAT IT DOES
    Runs apk update and upgrade on the VM itself -- the host side, not the
    containers.

  WHEN TO USE IT
    Monthly, and whenever an Alpine security advisory affects something
    installed here.

  WHAT IT ASKS YOU
    Confirmation.

  EXAMPLE
    This reaches .alpinelinux.org through the egress proxy, so it works
    without opening anything new. Reboot afterwards if the kernel moved.
EOF
    ;;
  import.5) _card "5 — [!] Apply the import" <<'EOF'
  WHAT IT DOES
    Backs up the CURRENT site, then replaces its content, plugins, themes and
    database with the staged import. Normalises URLs and the table prefix,
    regenerates salts, clears scheduled tasks. Core, wp-config.php, .htaccess
    and the mu-plugins are NOT imported -- this VM's own are kept, because
    those are exactly where a compromised source hides things that survive a
    content clean.

  WHEN TO USE IT
    After inspect, extract and scan, and not before.

  WHAT IT ASKS YOU
    You must type IMPORT in full. It refuses if the staging set has not been
    scanned, and refuses on CRITICAL findings without --force.

  EXAMPLE
    Run it from a CONSOLE. Over `qm guest exec` the confirmation gets no
    input and it cancels.
    Afterwards: the imported site's USERS replace yours. If none of their
    administrators is an account you hold the password for, make yourself one
    with wp-cli before you close the terminal.
EOF
    ;;
  testing.1) _card "1 — Commission check (guided)" <<'EOF'
  WHAT IT DOES
    Runs the whole read-only validation sequence end to end, in the order
    that makes sense: does it work, is it hardened, can it recover. It does
    NOT stop at the first failure.

  WHEN TO USE IT
    Before handing a VM to a client. This is the single best answer to "is
    this ready?"

  WHAT IT ASKS YOU
    Confirmation to begin. Nothing it runs changes the site.

  EXAMPLE
    Press 1. The one thing it cannot prove for you is OFF-SITE recovery --
    that needs your recovery key and stays a deliberate separate step
    (menu 2, option 4). Until you run that, off-site recovery is an
    assumption rather than evidence.
EOF
    ;;
  testing.12) _card "12 — wp-cli can reach the site" <<'EOF'
  WHAT IT DOES
    Proves wp-cli can actually see WordPress and its database.

  WHEN TO USE IT
    When a plugin or MFA command reports something odd -- this separates
    "wp-cli cannot reach WordPress" from "WordPress says no".

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    Press 12. Those two failures look identical from a command's output, and
    chasing the wrong one wastes an afternoon.
EOF
    ;;
  testing.2) _card "2 — Quick health (exit code)" <<'EOF'
  WHAT IT DOES
    The same quick check as Health menu option 1, but chosen here when you
    care about the EXIT CODE -- for a script or a monitoring probe.

  WHEN TO USE IT
    From cron or a monitor, rather than by hand.

  EXAMPLE
    validate-wordpress.sh --check && echo healthy || echo degraded
EOF
    ;;
  testing.3) _card "3 — Full validation" <<'EOF'
  WHAT IT DOES
    The complete ~45-check suite. Identical to Health menu option 2.

  WHEN TO USE IT
    Commissioning, after updates, before handover.

  EXAMPLE
    Press 3 and read the FAIL lines; each names its own fix.
EOF
    ;;
  testing.4) _card "4 — Self-test: everything" <<'EOF'
  WHAT IT DOES
    Exercises the SAFETY MACHINERY rather than the site: backup and restore,
    candidate isolation during updates, egress enforcement.

  WHEN TO USE IT
    At commissioning. "The site is healthy" and "the safety nets work" are
    different questions, and this answers the second.

  EXAMPLE
    Press 4. Several minutes. Nothing here touches the live site.
EOF
    ;;
  testing.5) _card "5 — Self-test: local restore" <<'EOF'
  WHAT IT DOES
    Backs up and restores into a scratch database to prove the mechanism.

  WHEN TO USE IT
    After changing backup settings, or as a safe rehearsal before the real
    off-site drill.

  EXAMPLE
    Press 5. This proves the machinery. Backup menu option 4 proves you could
    survive losing this VM, which is the harder and more useful claim.
EOF
    ;;
  testing.6) _card "6 — Self-test: candidate isolated" <<'EOF'
  WHAT IT DOES
    Proves that during an update the candidate container cannot write to the
    live database -- it runs against a temporary read-only account.

  WHEN TO USE IT
    At commissioning, or if you doubt an update could corrupt live data.

  EXAMPLE
    Press 6. This is why a failed update rolls back cleanly instead of
    leaving half-migrated data behind.
EOF
    ;;
  testing.7) _card "7 — Egress is really enforced" <<'EOF'
  WHAT IT DOES
    Removes WordPress's proxy setting and confirms outbound connections STILL
    fail -- proving the firewall enforces the boundary, not just the config.

  WHEN TO USE IT
    At commissioning. A plugin that ignores the proxy would otherwise walk
    straight past a perfectly configured allowlist.

  EXAMPLE
    Press 7. You want BLOCKED. The setting is restored afterwards.
EOF
    ;;
  testing.8) _card "8 — Tooling integrity vs manifest" <<'EOF'
  WHAT IT DOES
    Verifies every WASP tool against the signed manifest.

  WHEN TO USE IT
    Before trusting any other result during an incident.

  EXAMPLE
    Press 8. If the tools have been edited, everything else they tell you is
    unreliable -- check this first, not last.
EOF
    ;;
  testing.9) _card "9 — Updates available (no change)" <<'EOF'
  WHAT IT DOES
    Read-only check for newer image digests. Same as Updates menu option 1.

  WHEN TO USE IT
    Weekly, or as part of a commissioning sweep.

  EXAMPLE
    Press 9. Nothing is pulled or changed.
EOF
    ;;
  testing.10) _card "10 — Image CVE scan (no change)" <<'EOF'
  WHAT IT DOES
    Scans the images actually running for HIGH and CRITICAL vulnerabilities.

  WHEN TO USE IT
    Monthly, and before handover.

  EXAMPLE
    Press 10. The first run downloads a vulnerability database of several
    hundred MB. If it fails complaining about the database, check disk --
    that error names the DB and means the disk.
EOF
    ;;
  testing.11) _card "11 — Mail path works" <<'EOF'
  WHAT IT DOES
    Diagnoses the whole mail path end to end rather than just reporting
    configuration.

  WHEN TO USE IT
    Before handover -- password resets depend on it.

  EXAMPLE
    Press 11. Mail unconfigured is survivable until someone needs a reset
    and cannot get one.
EOF
    ;;
  testing.15) _card "15 — WordPress core version" <<'EOF'
  WHAT IT DOES
    Reports the version actually SERVED, read from the files on disk rather
    than from the image tag.

  WHEN TO USE IT
    After a core update, and whenever a version claim matters.

  EXAMPLE
    Press 15. The tag and the served version disagree whenever core files
    have not been synced -- a real and silent failure mode. Never trust the
    tag for this question.
EOF
    ;;
  testing.16) _card "16 — WordPress file integrity" <<'EOF'
  WHAT IT DOES
    Compares installed plugins and core against published checksums.

  WHEN TO USE IT
    On any suspected compromise, and after importing a site.

  EXAMPLE
    Press 16. Commercial plugins have no published checksums, so "no
    checksums available" for Elementor Pro or BeTheme is expected, not a
    finding. A MISMATCH on a WordPress.org plugin is a real finding.
EOF
    ;;
  testing.13) _card "13 — [!] Prove OFFSITE recovery" <<'EOF'
  WHAT IT DOES
    The same restore drill as Backup menu option 4: pulls a real encrypted
    backup from remote storage, decrypts it with your recovery key, and
    verifies it restores. It restores into a scratch area, not over the site.

  WHEN TO USE IT
    Once per VM at commissioning, and periodically after. The commission
    check deliberately does NOT run this for you -- it needs your recovery
    key, so it stays a separate, conscious step.

  WHAT IT ASKS YOU
    Your recovery key, and confirmation ('yes').

  EXAMPLE
    Have the key to hand before starting; it is not stored on this VM on
    purpose. If you cannot find it, that IS the finding, and it is better
    found now than during an outage.
EOF
    ;;
  testing.20) _card "20 — Known-defect triage" <<'EOF'
  WHAT IT DOES
    Checks this VM against the known defects of the build it was installed
    from, and tells you which apply, which are already fixed, and what the
    workaround is for the rest.

  WHEN TO USE IT
    When something behaves oddly and you want to know whether it is a known
    issue before investigating it as a new one.

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    Press 20. A VM built from an older release can carry defects fixed
    upstream since -- this tells you which, rather than leaving you to
    rediscover them.
EOF
    ;;
  testing.14) _card "14 — MFA / Two Factor status" <<'EOF'
  WHAT IT DOES
    Reports whether the enforcement mu-plugin is installed, whether
    enforcement is on, and whether the Two Factor plugin is active -- three
    separate things that are often confused.

  WHEN TO USE IT
    Any time you need to know whether MFA is actually protecting admins.

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    Press 14. The dangerous combination is enforcement ON with the plugin
    NOT active: admins past their grace window cannot enrol and cannot log
    in. It flags that explicitly.
EOF
    ;;
  testing.18) _card "18 — Install Two Factor NOW" <<'EOF'
  WHAT IT DOES
    Installs and activates the Two Factor plugin immediately, rather than
    waiting for the deferred installer to do it after setup completes.

  WHEN TO USE IT
    When you have finished the WordPress setup wizard and do not want to wait
    for the scheduled run.

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    Press 18, then check with option 14. If it reports the site is not
    installed yet, finish the setup wizard in a browser first.
EOF
    ;;
  testing.19) _card "19 — Why hasn't MFA installed?" <<'EOF'
  WHAT IT DOES
    Explains the deferred installer's state: whether it has run, what it
    found, and what it is waiting for.

  WHEN TO USE IT
    When MFA was requested at build time but is not active yet.

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    Press 19. The usual answer is that the WordPress setup wizard has not
    been completed -- the plugin cannot install before WordPress exists.
EOF
    ;;
  testing.21) _card "21 — Re-test production blockers" <<'EOF'
  WHAT IT DOES
    Re-checks every condition that is currently refusing to certify this VM
    for production, and clears the ones you have fixed.

  WHEN TO USE IT
    After fixing whatever the build flagged, to confirm it is actually clear.

  WHAT IT ASKS YOU
    Nothing.

  EXAMPLE
    Press 21. A blocker is recorded when a control could not be verified at
    build time. It stays until re-tested, because an unverified control is
    not the same as a working one.
EOF
    ;;

  # ── Main ──────────────────────────────────────────────────────────────────
  main.menu) _card "WASP operator menu" <<'EOF'
  Every action prints the exact command before it runs, so you can learn the
  command by watching -- and skip the menu once you know it.

  Destructive actions are marked [!] and ask you to type 'yes'.

  If this VM is new, press g for a guided walkthrough of what to do first.

  Type ?N on any menu for help on option N -- what it does, when to use it,
  what it will ask, and an example of a correct answer.
EOF
    ;;

  *) _card "No help for that" <<'EOF'
  There is no help card for that option.

  Type ? on its own for an overview of this menu, or pick an option number
  that appears in the list.
EOF
    ;;
  esac
}

# ── Guided first run ────────────────────────────────────────────────────────
# Not a wizard. A new operator's real problem is not that the commands are
# hard to type, it is not knowing WHICH ones matter or in what order. This
# states the order and the reason for it, then hands over.
guided_start() {
  _card "First time on this VM — what to do, in order" <<'EOF'
  1. KNOW WHAT YOU HAVE
       Menu 1 -> option 2 (full validation)
       Read the FAIL lines. Each names the control and the fix.

  2. MAKE RECOVERY REAL
       Menu 2 -> option 2 (is off-site configured?)
       If not: option 7 tells you what is missing, 8 and 9 set it.
       Then option 4 -- prove a restore actually works.
       A backup you have never restored is a hope, not a backup.

  3. CLOSE THE ADMIN DOOR
       Menu 7 -> option 14 (MFA state)
       Enforcement on without the plugin active locks admins out; the
       check says so explicitly.

  4. PROVE THE PERIMETER
       Menu 3 -> option 3 (egress really enforced)
       Menu 3 -> option 17 (CrowdSec really blocking)
       Both test enforcement rather than configuration. A control that is
       configured but not enforced looks identical from the outside.

  5. IF YOU IMPORTED A SITE YOU DID NOT BUILD
       Menu 3 -> option 7 (full malware scan)
       Menu 6 -> option 3 (unexpected admins)

  6. WHEN IT ALL PASSES
       Main menu -> c (commission check) for the whole picture in one pass,
       then Menu 1 -> option 3 for a report you can send a client.
EOF
}

# =============================================================================
#  SUBMENUS — grouped by the task an operator actually has in mind
# =============================================================================

menu_health() {
  while :; do
    _banner
    cat <<EOF

  ${B}Health & status${R}
    1) Quick health check            ${DIM}validate-wordpress.sh --check${R}
    2) Full validation (~45 checks)  ${DIM}validate-wordpress.sh${R}
    3) Full test report (send-able)  ${DIM}wasp-testreport.sh${R}
    4) Container / WordPress health  ${DIM}wp-health-check.sh${R}
    5) Database health               ${DIM}mariadb-health-check.sh${R}
    b) back
EOF
    _sel health
    case "$c" in
      1) _have validate-wordpress.sh && run "Quick health check" 0 validate-wordpress.sh --check || _missing validate-wordpress.sh ;;
      2) _have validate-wordpress.sh && run "Full validation" 0 validate-wordpress.sh || _missing validate-wordpress.sh ;;
      3) _have wasp-testreport.sh && run "Full test report" 0 wasp-testreport.sh || _missing wasp-testreport.sh ;;
      4) _have wp-health-check.sh && run "WordPress health" 0 wp-health-check.sh || _missing wp-health-check.sh ;;
      5) _have mariadb-health-check.sh && run "Database health" 0 mariadb-health-check.sh || _missing mariadb-health-check.sh ;;
      b|B) return ;;
    esac
  done
}

menu_backup() {
  while :; do
    _banner
    cat <<EOF

  ${B}Backup & restore${R}
    1) Run a backup now              ${DIM}wp-db-backup.sh${R}
    2) Off-site backup status        ${DIM}wasp-offsite-backup.sh status${R}
    7) Why is nothing off-VM?        ${DIM}wasp-offsite-backup.sh doctor${R}
    8) Replace storage credentials   ${DIM}wasp-offsite-backup.sh set-credentials${R}
    9) Change backup destination     ${DIM}wasp-offsite-backup.sh set-destination${R}
    3) List off-site backups         ${DIM}wasp-offsite-backup.sh list${R}
    4) ${RED}[!]${R} Prove offsite recovery      ${DIM}wasp-offsite-backup.sh remote-restore-drill${R}
    5) ${RED}[!]${R} Restore from backup          ${DIM}wasp-offsite-backup.sh restore${R}
    6) Self-test (local restore)     ${DIM}wasp-selftest.sh restore-test${R}
    b) back
EOF
    _sel backup
    case "$c" in
      1) _have wp-db-backup.sh && run "Run a backup" 0 wp-db-backup.sh || _missing wp-db-backup.sh ;;
      2) _have wasp-offsite-backup.sh && run "Off-site status" 0 wasp-offsite-backup.sh status || _missing wasp-offsite-backup.sh ;;
      7) _have wasp-offsite-backup.sh && run "Off-site diagnosis" 0 wasp-offsite-backup.sh doctor || _missing wasp-offsite-backup.sh ;;
      8) _have wasp-offsite-backup.sh && run "Replace storage credentials" 1 wasp-offsite-backup.sh set-credentials || _missing wasp-offsite-backup.sh ;;
      9) _have wasp-offsite-backup.sh && run "Change backup destination" 1 wasp-offsite-backup.sh set-destination || _missing wasp-offsite-backup.sh ;;
      3) _have wasp-offsite-backup.sh && run "List off-site" 0 wasp-offsite-backup.sh list || _missing wasp-offsite-backup.sh ;;
      4) _have wasp-offsite-backup.sh && run "Remote restore drill" 1 wasp-offsite-backup.sh remote-restore-drill || _missing wasp-offsite-backup.sh ;;
      5) _have wasp-offsite-backup.sh && run "Restore from backup" 1 wasp-offsite-backup.sh restore || _missing wasp-offsite-backup.sh ;;
      6) _have wasp-selftest.sh && run "Self-test restore" 0 wasp-selftest.sh restore-test || _missing wasp-selftest.sh ;;
      b|B) return ;;
    esac
  done
}

menu_security() {
  while :; do
    _banner
    cat <<EOF

  ${B}Security & hardening${R}
    1) Hardening status              ${DIM}wp-hardening.sh status${R}
    2) Egress (proxy) status         ${DIM}wasp-egress.sh status${R}
    3) Test egress is enforced       ${DIM}wasp-egress.sh test${R}
    4) CrowdSec whitelist            ${DIM}wp-hardening.sh crowdsec-whitelist list${R}
   17) Is CrowdSec actually blocking? ${DIM}wp-hardening.sh crowdsec-doctor${R}
   18) Report bans to a central LAPI ${DIM}wp-hardening.sh cs-lapi <url> <login> <pw>${R}
    5) Plugin vulnerability scan     ${DIM}wp-plugins.sh vulns${R}
    6) Malware scan (quick)          ${DIM}wp-malware-scan.sh quick${R}
    7) Malware scan (full)           ${DIM}wp-malware-scan.sh full${R}
    8) Verify tooling integrity      ${DIM}wasp-verify-integrity.sh${R}
   10) Theme/plugin uploads: ALLOW  ${DIM}wp-hardening.sh disable file-mods${R}
   11) Theme/plugin uploads: BLOCK  ${DIM}wp-hardening.sh enable file-mods${R}
   12) Install a theme/plugin ZIP   ${DIM}wp-plugins.sh install-file <path>${R}
   13) PHP shell functions: BLOCK   ${DIM}wp-hardening.sh enable php-exec${R}
   14) PHP shell functions: ALLOW   ${DIM}wp-hardening.sh disable php-exec${R}
    9) ${RED}[!]${R} Rotate a secret              ${DIM}wp-rotate-secrets.sh ...${R}
    b) back
EOF
    _sel security
    case "$c" in
      1) _have wp-hardening.sh && run "Hardening status" 0 wp-hardening.sh status || _missing wp-hardening.sh ;;
      2) _have wasp-egress.sh && run "Egress status" 0 wasp-egress.sh status || _missing wasp-egress.sh ;;
      3) _have wasp-egress.sh && run "Egress enforcement test" 0 wasp-egress.sh test || _missing wasp-egress.sh ;;
      4) _have wp-hardening.sh && run "CrowdSec whitelist" 0 wp-hardening.sh crowdsec-whitelist list || _missing wp-hardening.sh ;;
      17) _have wp-hardening.sh && run "CrowdSec remediation chain (live test)" 0 wp-hardening.sh crowdsec-doctor || _missing wp-hardening.sh ;;
      18) # Needs three arguments, so prompt rather than offering a bare run
          # that would print usage and look broken.
          printf '  LAPI URL (e.g. http://10.20.10.10:8080/) : '; read -r _lu
          printf '  Machine login (registered on that LAPI)  : '; read -r _ll
          printf '  Machine password : '; stty -echo 2>/dev/null; read -r _lp; stty echo 2>/dev/null; echo ""
          if [ -z "$_lu" ] || [ -z "$_ll" ] || [ -z "$_lp" ]; then
            echo "  All three are needed — nothing changed."
          else
            _have wp-hardening.sh && run "Point CrowdSec at a central LAPI" 1 wp-hardening.sh cs-lapi "$_lu" "$_ll" "$_lp" || _missing wp-hardening.sh
          fi
          unset _lu _ll _lp ;;
      5) _have wp-plugins.sh && run "Plugin vulnerabilities" 0 wp-plugins.sh vulns || _missing wp-plugins.sh ;;
      6) _have wp-malware-scan.sh && run "Malware quick scan" 0 wp-malware-scan.sh quick || _missing wp-malware-scan.sh ;;
      7) _have wp-malware-scan.sh && run "Malware full scan" 0 wp-malware-scan.sh full || _missing wp-malware-scan.sh ;;
      8) _have wasp-verify-integrity.sh && run "Integrity check" 0 wasp-verify-integrity.sh || _missing wasp-verify-integrity.sh ;;
      10) _have wp-hardening.sh && run "Allow theme/plugin uploads (reduces hardening)" 1 wp-hardening.sh disable file-mods || _missing wp-hardening.sh ;;
      11) _have wp-hardening.sh && run "Block theme/plugin uploads (restore hardening)" 0 wp-hardening.sh enable file-mods || _missing wp-hardening.sh ;;
      12) if _have wp-plugins.sh; then
            echo ""
            echo "  Copy the zip to the VM first, e.g.:"
            echo "    scp divi.zip admin@$(hostname):/var/lib/wasp-import/incoming/"
            if ask "Path to the .zip" _z; then
              run "Install from file" 1 wp-plugins.sh install-file "$_z" --activate
            fi
          else _missing wp-plugins.sh; fi ;;
      13) _have wp-hardening.sh && run "Block PHP shell functions (restore hardening)" 0 wp-hardening.sh enable php-exec || _missing wp-hardening.sh ;;
      14) _have wp-hardening.sh && run "Allow PHP shell functions (reduces hardening)" 1 wp-hardening.sh disable php-exec || _missing wp-hardening.sh ;;
      9) menu_rotate ;;
      b|B) return ;;
    esac
  done
}

menu_rotate() {
  _banner
  cat <<EOF

  ${B}Rotate a secret${R}  ${DIM}(each verifies before committing, rolls back on failure)${R}
    1) ${RED}[!]${R} Salts                         ${DIM}wp-rotate-secrets.sh salts${R}
    2) ${RED}[!]${R} Database password             ${DIM}wp-rotate-secrets.sh db${R}
    3) ${RED}[!]${R} SMTP relay password           ${DIM}wp-rotate-secrets.sh smtp <pass>${R}
    4) ${RED}[!]${R} Everything                    ${DIM}wp-rotate-secrets.sh all${R}
    b) back
EOF
  _sel security
  _have wp-rotate-secrets.sh || { _missing wp-rotate-secrets.sh; return; }
  case "$c" in
    1) run "Rotate salts" 1 wp-rotate-secrets.sh salts ;;
    2) run "Rotate DB password" 1 wp-rotate-secrets.sh db ;;
    3) if ask "New SMTP password" _p; then run "Rotate SMTP password" 1 wp-rotate-secrets.sh smtp "$_p"; fi ;;
    4) run "Rotate everything" 1 wp-rotate-secrets.sh all ;;
    b|B) return ;;
  esac
}

menu_updates() {
  while :; do
    _banner
    cat <<EOF

  ${B}Updates${R}  ${DIM}(each scans for CVEs and can roll back)${R}
    1) Check what's available        ${DIM}update.sh check${R}
   22) Newer versions upstream?      ${DIM}update.sh upstream${R}
    2) Current versions / status     ${DIM}update.sh status${R}
    3) ${RED}[!]${R} Update everything            ${DIM}update.sh all${R}
    4) ${RED}[!]${R} Update WordPress             ${DIM}update.sh wp${R}
    5) ${RED}[!]${R} Update database              ${DIM}update.sh db${R}
    6) ${RED}[!]${R} Update CrowdSec              ${DIM}update.sh crowdsec${R}
    7) ${RED}[!]${R} Update Squid (egress proxy)  ${DIM}update.sh squid${R}
    8) ${RED}[!]${R} Update Alpine OS packages    ${DIM}update.sh os${R}
    b) back
EOF
    _sel updates
    _have update.sh || { _missing update.sh; return; }
    case "$c" in
      1) run "Update check" 0 update.sh check ;;
      22) _have update.sh && run "Upstream currency" 0 update.sh upstream || _missing update.sh ;;
      2) run "Update status" 0 update.sh status ;;
      3) run "Update everything" 1 update.sh all ;;
      4) run "Update WordPress" 1 update.sh wp ;;
      5) run "Update database" 1 update.sh db ;;
      6) run "Update CrowdSec" 1 update.sh crowdsec ;;
      7) run "Update Squid" 1 update.sh squid ;;
      8) run "Update OS packages" 1 update.sh os ;;
      b|B) return ;;
    esac
  done
}

menu_import() {
  while :; do
    _banner
    cat <<EOF

  ${B}Import a site${R}  ${DIM}(inspect and scan BEFORE anything is applied)${R}
    1) How to get a backup here      ${DIM}wp-import.sh where${R}
    2) Inspect an archive            ${DIM}wp-import.sh inspect <file>${R}
    3) Extract (bounded staging)     ${DIM}wp-import.sh extract <file>${R}
    4) Scan staged content           ${DIM}wp-import.sh scan${R}
    5) ${RED}[!]${R} Apply the import             ${DIM}wp-import.sh apply${R}
    b) back
EOF
    _sel import
    _have wp-import.sh || { _missing wp-import.sh; return; }
    case "$c" in
      1) run "Import: where" 0 wp-import.sh where ;;
      2) if ask "Path to archive" _f; then run "Inspect archive" 0 wp-import.sh inspect "$_f"; fi ;;
      3) if ask "Path to archive" _f; then run "Extract archive" 0 wp-import.sh extract "$_f"; fi ;;
      4) run "Scan staged" 0 wp-import.sh scan ;;
      5) run "Apply import" 1 wp-import.sh apply ;;
      b|B) return ;;
    esac
  done
}

menu_testing() {
  while :; do
    _banner
    cat <<EOF

  ${B}Testing & validation${R}  ${DIM}(prove it works — nothing here changes the site)${R}
    1) ${GRN}Commission check (guided)${R}      ${DIM}runs the full sequence below${R}
   20) ${GRN}Known-defect triage${R}            ${DIM}wasp-triage.sh${R}
   21) Re-test production blockers   ${DIM}wasp-triage.sh --recheck-blockers${R}
    ---
    2) Quick health (exit code)      ${DIM}validate-wordpress.sh --check${R}
    3) Full validation               ${DIM}validate-wordpress.sh${R}
    4) Self-test: everything         ${DIM}wasp-selftest.sh all${R}
    5) Self-test: local restore      ${DIM}wasp-selftest.sh restore-test${R}
    6) Self-test: candidate isolated ${DIM}wasp-selftest.sh candidate-isolation${R}
    7) Egress is really enforced     ${DIM}wasp-egress.sh test${R}
    8) Tooling integrity vs manifest ${DIM}wasp-verify-integrity.sh${R}
   16) WordPress file integrity      ${DIM}wp-plugins.sh verify${R}
    9) Updates available (no change) ${DIM}update.sh check${R}
   10) Image CVE scan (no change)    ${DIM}update.sh trivy${R}
   11) Mail path works               ${DIM}wp-mail.sh doctor${R}
   12) wp-cli can reach the site     ${DIM}wp-plugins.sh doctor${R}
   14) MFA / Two Factor status       ${DIM}wp-plugins.sh mfa${R}
   18) Install Two Factor NOW        ${DIM}wasp-mfa-deferred.sh --now${R}
   19) Why hasn't MFA installed?     ${DIM}wasp-mfa-deferred.sh --status${R}
   15) WordPress core version        ${DIM}wp-plugins.sh core-version${R}
   13) ${RED}[!]${R} Prove OFFSITE recovery      ${DIM}wasp-offsite-backup.sh remote-restore-drill${R}
    b) back
EOF
    _sel testing
    case "$c" in
      1) commission_check ;;
      20) _have wasp-triage.sh && run "Known-defect triage" 0 wasp-triage.sh || _missing wasp-triage.sh ;;
      21) _have wasp-triage.sh && run "Re-test production blockers" 0 wasp-triage.sh --recheck-blockers || _missing wasp-triage.sh ;;
      2) _have validate-wordpress.sh && run "Quick health" 0 validate-wordpress.sh --check || _missing validate-wordpress.sh ;;
      3) _have validate-wordpress.sh && run "Full validation" 0 validate-wordpress.sh || _missing validate-wordpress.sh ;;
      4) _have wasp-selftest.sh && run "Self-test: all" 0 wasp-selftest.sh all || _missing wasp-selftest.sh ;;
      5) _have wasp-selftest.sh && run "Self-test: restore" 0 wasp-selftest.sh restore-test || _missing wasp-selftest.sh ;;
      6) _have wasp-selftest.sh && run "Self-test: candidate isolation" 0 wasp-selftest.sh candidate-isolation || _missing wasp-selftest.sh ;;
      7) _have wasp-egress.sh && run "Egress enforcement" 0 wasp-egress.sh test || _missing wasp-egress.sh ;;
      8) _have wasp-verify-integrity.sh && run "Tooling integrity" 0 wasp-verify-integrity.sh || _missing wasp-verify-integrity.sh ;;
      9) _have update.sh && run "Updates available" 0 update.sh check || _missing update.sh ;;
      10) _have update.sh && run "Image CVE scan" 0 update.sh trivy || _missing update.sh ;;
      11) _have wp-mail.sh && run "Mail doctor" 0 wp-mail.sh doctor || _missing wp-mail.sh ;;
      12) _have wp-plugins.sh && run "wp-cli doctor" 0 wp-plugins.sh doctor || _missing wp-plugins.sh ;;
      14) _have wp-plugins.sh && run "MFA / Two Factor status" 0 wp-plugins.sh mfa || _missing wp-plugins.sh ;;
      18) _have wasp-mfa-deferred.sh && run "Install Two Factor now" 0 wasp-mfa-deferred.sh --now || _missing wasp-mfa-deferred.sh ;;
      19) _have wasp-mfa-deferred.sh && run "Deferred MFA installer status" 0 wasp-mfa-deferred.sh --status || _missing wasp-mfa-deferred.sh ;;
      15) _have wp-plugins.sh && run "WordPress core version (files vs image)" 0 wp-plugins.sh core-version || _missing wp-plugins.sh ;;
      16) _have wp-plugins.sh && run "WordPress file integrity (checksums)" 0 wp-plugins.sh verify || _missing wp-plugins.sh ;;
      13) _have wasp-offsite-backup.sh && run "Remote restore drill" 1 wasp-offsite-backup.sh remote-restore-drill || _missing wasp-offsite-backup.sh ;;
      b|B) return ;;
    esac
  done
}

# ── Commission check ─────────────────────────────────────────────────────────
# The sequence you actually want on a fresh VM, in the order that makes sense:
# does it work, is it hardened, can it recover. Each step is read-only or
# self-contained, reports pass/fail, and does NOT stop the run on a failure --
# a commissioning pass should tell you everything that is wrong in one go,
# rather than making you fix one thing and re-run to discover the next.
commission_check() {
  clear 2>/dev/null || true
  printf '%s┌────────────────────────────────────────────────────┐%s\n' "$CYN" "$R"
  printf '%s│%s  %sCommission check%s — is this VM fit to hand over?\n' "$CYN" "$R" "$B" "$R"
  printf '%s└────────────────────────────────────────────────────┘%s\n' "$CYN" "$R"
  cat <<EOF

  Runs the read-only validation suite end to end. Nothing here changes the
  site. It does NOT stop at the first failure — you get the whole picture in
  one pass, so you can fix everything before re-running.

  The one thing it cannot do for you is prove OFFSITE recovery: that pulls a
  real encrypted object and needs your recovery key, so it stays a separate,
  deliberate step (option 13). Until you have run it, offsite recovery is an
  assumption, not evidence.

EOF
  printf '  Run the commission check now? [y/N] : '
  read -r _go
  case "$_go" in y|Y|yes|YES) : ;; *) echo "  Cancelled."; _pause; return 0 ;; esac

  _cc_pass=0; _cc_fail=0; _cc_skip=0
  _step() { # label tool args...
    _l="$1"; _t="$2"; shift 2
    printf '\n%s── %s%s\n' "$B" "$_l" "$R"
    if [ ! -x "$BIN/$_t" ]; then
      printf '   %sSKIP%s  %s is not installed\n' "$YEL" "$R" "$_t"
      _cc_skip=$((_cc_skip+1)); return 0
    fi
    printf '%s   $ %s %s%s\n' "$DIM" "$_t" "$*" "$R"
    _cc_log="/var/log/wasp-commission-${_t%.sh}.log"
    if "$BIN/$_t" "$@" >"$_cc_log" 2>&1; then
      printf '   %sPASS%s\n' "$GRN" "$R"
      _cc_pass=$((_cc_pass+1))
      rm -f "$_cc_log"
    else
      _rc=$?
      printf '   %sFAIL%s (exit %s)\n' "$RED" "$R" "$_rc"
      # Show the lines that actually SAY something. A blind `tail` gave six
      # lines of summary boilerplate ("Result: FAILED") and hid the one line
      # naming the failing probe -- on a real commission run that made two of
      # four failures undiagnosable without re-running the tool by hand.
      # Prefer explicit failure markers; fall back to the tail only if none
      # are found.
      if grep -qE '✗|FAIL|failed|not holding|Unknown option' "$_cc_log" 2>/dev/null; then
        grep -E '✗|\[FAIL\]|not holding|Unknown option' "$_cc_log" \
          | grep -vE 'CHECKS FAILED|Result: FAILED|failed [0-9]+$|silently for a week' \
          | head -8 | sed 's/^/       /'
      else
        tail -8 "$_cc_log" | sed 's/^/       /'
      fi
      printf '       %sfull output: %s%s\n' "$DIM" "$_cc_log" "$R"
      _cc_fail=$((_cc_fail+1))
    fi
  }

  _step "Health — does it work at all"        validate-wordpress.sh --check
  _step "Full validation — ~45 checks"        validate-wordpress.sh
  _step "Self-test — restore, isolation"      wasp-selftest.sh all
  _step "Egress — is the proxy enforced"      wasp-egress.sh test
  _step "Integrity — tooling vs manifest"     wasp-verify-integrity.sh
  _step "Updates — anything outstanding"      update.sh check
  _step "Mail — can it actually send"         wp-mail.sh doctor
  _step "wp-cli — can it reach the site"      wp-plugins.sh doctor
  _step "File integrity — core + plugins"     wp-plugins.sh verify
  _step "CrowdSec — is it actually blocking"  wp-hardening.sh crowdsec-doctor

  echo ""
  printf '%s┌─ Commission result ────────────────────────────────┐%s\n' "$CYN" "$R"
  printf '   %sPASS %s%s   %sFAIL %s%s   %sSKIP %s%s\n' \
    "$GRN" "$_cc_pass" "$R" "$RED" "$_cc_fail" "$R" "$YEL" "$_cc_skip" "$R"
  if [ "$_cc_fail" -eq 0 ]; then
    printf '   %sNothing failed.%s Still owed before you call it proven:\n' "$GRN" "$R"
    echo "     - the offsite restore drill (option 13) — the only real"
    echo "       evidence that recovery works"
    echo "     - if MFA is enforced: lock out a test admin and confirm the"
    echo "       console recovery brings them back (SUPPORT-RUNBOOK.md)"
  else
    printf '   %sFix the failures above, then re-run.%s Each tool prints the\n' "$YEL" "$R"
    echo "   command to fix what it found."
  fi
  printf '%s└────────────────────────────────────────────────────┘%s\n' "$CYN" "$R"
  _pause
}

menu_diagnostics() {
  while :; do
    _banner
    cat <<EOF

  ${B}Diagnostics & forensics${R}
    1) Capture a session for review  ${DIM}wasp-capture.sh start${R}
    2) Capture current state only    ${DIM}wasp-capture.sh report${R}
    3) Forensics: unexpected admins  ${DIM}wp-forensics.sh admins${R}
    4) Forensics: change timeline    ${DIM}wp-forensics.sh timeline${R}
    5) Mail: status                  ${DIM}wp-mail.sh status${R}
    6) Mail: send a test             ${DIM}wp-mail.sh test <addr>${R}
    7) Self-test (full)              ${DIM}wasp-selftest.sh all${R}
    b) back
EOF
    _sel diag
    case "$c" in
      1) _have wasp-capture.sh && run "Start session capture" 0 wasp-capture.sh start || _missing wasp-capture.sh ;;
      2) _have wasp-capture.sh && run "Capture state" 0 wasp-capture.sh report || _missing wasp-capture.sh ;;
      3) _have wp-forensics.sh && run "Forensics: admins" 0 wp-forensics.sh admins || _missing wp-forensics.sh ;;
      4) _have wp-forensics.sh && run "Forensics: timeline" 0 wp-forensics.sh timeline || _missing wp-forensics.sh ;;
      5) _have wp-mail.sh && run "Mail status" 0 wp-mail.sh status || _missing wp-mail.sh ;;
      6) _have wp-mail.sh && { if ask "Send test to" _a; then run "Mail test" 0 wp-mail.sh test "$_a"; fi; } || _missing wp-mail.sh ;;
      7) _have wasp-selftest.sh && run "Full self-test" 0 wasp-selftest.sh all || _missing wasp-selftest.sh ;;
      b|B) return ;;
    esac
  done
}

# =============================================================================
#  MAIN MENU
# =============================================================================
main() {
  while :; do
    _banner
    cat <<EOF

  ${B}What do you need?${R}
    1) Health & status
    2) Backup & restore
    3) Security & hardening
    4) Updates
    5) Import a site
    6) Diagnostics & forensics
    7) Testing & validation

    ${DIM}Every action shows the command before it runs. Destructive ones${R}
    ${DIM}are marked ${R}${RED}[!]${R}${DIM} and ask you to type 'yes'.${R}

    ${CYN}g)${R} First time here? ${DIM}guided walkthrough of what to do first${R}
    ${CYN}c)${R} Commission check ${DIM}is this VM fit to hand over?${R}

    ${DIM}Type ${R}${CYN}?N${R}${DIM} for help on any option — what it does, when to${R}
    ${DIM}use it, what it asks you, and an example answer.${R}

    q) quit
EOF
    _sel main
    case "$c" in
      1) menu_health ;;
      2) menu_backup ;;
      3) menu_security ;;
      4) menu_updates ;;
      5) menu_import ;;
      6) menu_diagnostics ;;
      7) menu_testing ;;
      g|G) guided_start ;;
      c|C) commission_check ;;
      q|Q) clear 2>/dev/null || true; exit 0 ;;
    esac
  done
}

# If not on a TTY, a menu is meaningless — point the caller at the tools.
if [ "$IS_TTY" -ne 1 ]; then
  echo "wasp-menu is interactive; run it in a terminal."
  echo "The tools it launches are all in ${BIN} and can be run directly."
  exit 1
fi

main
