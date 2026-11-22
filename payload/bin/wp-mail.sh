#!/bin/sh
# =============================================================================
# wp-mail.sh — outbound email status, testing, and (re)configuration
# =============================================================================
# WordPress mail fails silently by default on this VM: the official container
# has no sendmail binary, so PHP's mail() has nothing to hand a message to,
# and wp_mail() returns without a visible error. This tool exists because
# "did that actually send?" is otherwise unanswerable without reading logs.
#
#   wp-mail.sh status              what is configured (password redacted)
#   wp-mail.sh test you@example.com  send a real message through the relay
#   wp-mail.sh setup               (re)configure the relay interactively
#   wp-mail.sh log                 recent mail failures from the PHP error log
#   wp-mail.sh doctor              config + mount + mu-plugin + DNS checks
#
#   wp-mail.sh client [status]     the client's own mail server, if any
#   wp-mail.sh client setup        Microsoft 365 (Graph) or SMTP for the site's mail
#   wp-mail.sh client test <addr>  send through the client's server
#   wp-mail.sh client off          the site's mail back to the relay
#
# TWO PATHS (10.27). The relay set at install is the OPERATOR's: WASP's
# security alerts and lockout notices always go through it, so a client
# changing their mailbox can never silence an alert. The site's own mail --
# contact forms, password resets, notifications -- goes through the CLIENT's
# server when `client setup` has set one: Microsoft 365 through Graph (HTTPS,
# no SMTP, no port 25), or SMTP submission on 587/465 (Google Workspace with
# an app password, or any host). If the client's path fails, the message goes
# through the relay instead and the failure is logged; nothing is lost.
# Host-side alerts (wp-notify.sh, backups, heartbeat) use the relay as before.
# =============================================================================
set -e

if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then exec doas "$0" "$@"; fi
  echo "Run as root (or install doas and run as a wheel user)" >&2
  exit 1
fi
[ -r /etc/wp-install/pinned.env ] && . /etc/wp-install/pinned.env
# Only the WORDPRESS_* values. The root password stays out of containers that
# run site code. A VM built before 10.10 has just the one file.
WP_ENV_FILE=/etc/wordpress/wp.env
[ -r "$WP_ENV_FILE" ] || WP_ENV_FILE=/etc/wordpress/env

SECRETS_DIR="/home/wpuser/wp/secrets"
CLIENT_FILE="${SECRETS_DIR}/client-mail.ini"
# PHP's errors (and so the mail plugin's) go to Apache's error log here.
WP_LOG_DIR="${WP_LOG_DIR:-/home/wpuser/wp/logs}"
# SMTP_HOST: the relay the firewall was pinned to at install.
[ -r /etc/wp-install/vars.sh ] && SMTP_HOST=$(sed -n 's/^SMTP_HOST=//p' /etc/wp-install/vars.sh | sed -e "s/^[\"']//" -e "s/[\"']\$//" | head -1)
# INI, not PHP. The credentials file is data now, so reading it cannot
# execute anything -- see the note in 01-wpvm-smtp.php for why that changed.
# Legacy smtp.php is still read if present so an existing VM keeps working
# until `setup` migrates it.
SMTP_FILE="${SECRETS_DIR}/smtp.ini"
SMTP_FILE_LEGACY="${SECRETS_DIR}/smtp.php"
_cfg() {
  if [ -r "$SMTP_FILE" ]; then
    if [ "$1" = "pass" ]; then
      sed -n 's/^[[:space:]]*pass_b64[[:space:]]*=[[:space:]]*//p' "$SMTP_FILE" | head -1 | base64 -d 2>/dev/null
    else
      sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$SMTP_FILE" | head -1
    fi
    return 0
  fi
  [ -r "$SMTP_FILE_LEGACY" ] || return 1
  sed -n "s/^[[:space:]]*'$1'[[:space:]]*=>[[:space:]]*'\{0,1\}\([^',]*\)'\{0,1\},.*/\1/p" "$SMTP_FILE_LEGACY" | head -1
}

_configured() { [ -r "$SMTP_FILE" ] && [ -n "$(_cfg host)" ]; }

# The SMTP mu-plugin. Referenced by `doctor` and never defined, so under
# 10.15 and earlier every doctor run printed "mu-plugin : MISSING" -- on sites
# whose mail was working, which taught the operator to ignore the line.
MU_PLUGIN="${WASP_MU_PLUGIN:-/home/wpuser/wp/html/wp-content/mu-plugins/01-wpvm-smtp.php}"

# Plugins that take WordPress's mail over: they replace or reconfigure the
# mailer with their OWN stored relay and password, so WASP's relay settings
# are bypassed. Imported sites bring them along still configured for the old
# host. Found on a real import: FluentSMTP active, every send aimed at the old
# host's mail server, WASP's firewall dropping it (it allows only the relay),
# and the error -- "Could not connect to SMTP host" -- naming WASP's relay,
# because that is what WASP's own message prints.
_MAIL_OVERRIDE_SLUGS="fluent-smtp wp-mail-smtp wp-mail-smtp-pro post-smtp easy-wp-smtp wp-smtp smtp-mailer gmail-smtp suremails site-mailer wp-ses wp-offload-ses mailgun sendgrid-email-delivery-simplified sendinblue-wp-mailer"
_mail_overrides() {
  _active=$(_wp plugin list --status=active --field=name 2>/dev/null) || return 0
  for _sl in $_active; do
    case " $_MAIL_OVERRIDE_SLUGS " in
      *" $_sl "*) printf '%s\n' "$_sl" ;;
      *) case "$_sl" in *smtp*) printf '%s\n' "$_sl" ;; esac ;;
    esac
  done
}
_override_warning() {  # $1 = list of slugs
  [ -n "$1" ] || return 0
  echo "  ⚠  Active plugin(s) that take over WordPress mail with their OWN settings:"
  printf '%s\n' "$1" | sed 's/^/       /'
  echo "     WASP's relay is bypassed while they are active. An imported site's"
  echo "     copy still points at the old host. Deactivate and delete:"
  echo "       wp-admin → Plugins   (or: wp-plugins.sh list)"
}

# wp-cli runs in its OWN container: the wordpress image ships no `wp` binary.
# This file called _wp without ever defining it, so `wp-mail.sh test` died with
# "_wp: not found" on a live VM -- the mail path could not be verified at all.
_wpcli_image() {
  _wi=$(sed -n 's/^WPCLI_IMAGE=//p' /etc/wp-install/pinned.env 2>/dev/null | tr -d '"' | head -1)
  [ -n "$_wi" ] || _wi="docker.io/library/wordpress:cli"
  printf '%s' "$_wi"
}
_wp() {
  # shellcheck disable=SC2086
  # The wp-cli container also mounts /var/www/private (read-only). Without it
  # the SMTP mu-plugin loads, finds no config, and returns early -- so
  # PHPMailer falls back to PHP mail() and tries a local sendmail that does not
  # exist: "sendmail: can't connect to remote host (127.0.0.1)". Every other
  # mail check passes, because the relay, DNS and firewall are fine; the
  # credential simply was not visible to the process being asked to send.
  podman run --rm \
    --network "container:wordpress" \
    --user 33:33 \
    --env-file "$WP_ENV_FILE" \
    -e WORDPRESS_DB_HOST=mariadb:3306 \
    ${WPCLI_ENV:-} \
    -v /home/wpuser/wp/secrets:/var/www/private:ro \
    -v /home/wpuser/wp/html:/var/www/html \
    "$(_wpcli_image)" wp --path=/var/www/html "$@"
}

show_status() {
  echo ""
  echo "Outbound email status"
  echo "━━━━━━━━━━━━━━━━━━━━━"
  if ! _configured; then
    echo "  ✗  NOT CONFIGURED — WordPress cannot send mail."
    echo ""
    echo "     Password resets, new-user notifications, comment alerts and"
    echo "     WooCommerce receipts are all failing silently right now."
    echo "     Configure with:  wp-mail.sh setup"
    return
  fi
  printf "  %-14s %s\n" "Relay:"     "$(_cfg host):$(_cfg port)"
  printf "  %-14s %s\n" "Encryption:" "$(_cfg encryption)"
  printf "  %-14s %s\n" "Username:"  "$(_cfg user)"
  printf "  %-14s %s\n" "Password:"  "(set — redacted)"
  printf "  %-14s %s\n" "From:"      "$(_cfg from) <$(_cfg from_name)>"
  echo ""
  # Permissions are part of the status, not a separate audit: a
  # world-readable credentials file is the failure worth catching early.
  # Numeric, not names. GID 33 is www-data on Debian but has NO name on
  # Alpine, so `stat %G` returns "UNKNOWN" and a name comparison can never
  # match — reporting a permission fault on a perfectly correct file. The
  # container is Debian; this host is Alpine. Numbers mean the same on both.
  _perm=$(stat -c '%a %u:%g' "$SMTP_FILE" 2>/dev/null || echo "?")
  case "$_perm" in
    "440 0:33") printf "  %-14s %s\n" "File mode:" "${_perm} (root:uid33)  ✔" ;;
    *) printf "  %-14s %s\n" "File mode:" "$_perm  ⚠ expected 440 0:33 (root, group 33)" ;;
  esac
  # MU_PLUGIN was never assigned, so this tested `[ -r "" ]` and always
  # printed MISSING — on a VM where the validator confirmed the file present
  # and parsing. A status screen that reports a fault which is not there is
  # worse than one that says nothing: it sends the operator to fix something
  # that works, in the middle of a real problem elsewhere.
  # ── Has the relay moved since the firewall was pinned to it? ───────────────
  # Raised by an external evaluation, and it is a real operational risk rather
  # than a theoretical one: SMTP egress is pinned to the addresses the relay
  # resolved to AT INSTALL. A hosted relay behind a load balancer can change
  # them at any time, and when it does, mail stops with no error anywhere --
  # the firewall silently drops packets to an address that is no longer in the
  # set, and every other check still passes.
  #
  # Comparing what the relay resolves to NOW against what the ruleset actually
  # permits turns a silent outage into a line of output.
  _relay_now=$(getent ahostsv4 "${SMTP_HOST:-}" 2>/dev/null | awk '{print $1}' | sort -u)
  if [ -n "$_relay_now" ]; then
    _pinned=$(nft list ruleset 2>/dev/null \
              | grep -oE 'ip daddr \{[^}]*\}' | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
    if [ -n "$_pinned" ]; then
      _drift=0
      for _a in $_relay_now; do
        printf '%s\n' "$_pinned" | grep -qx "$_a" || _drift=1
      done
      if [ "$_drift" = 1 ]; then
        printf "  %-14s %s\n" "relay pin:" "DRIFTED ⚠ — mail will stop"
        echo "                 resolves now : $(printf '%s' "$_relay_now" | tr '\n' ' ')"
        echo "                 firewall has : $(printf '%s' "$_pinned" | tr '\n' ' ')"
        echo "                 Re-pin with:  doas wp-hardening.sh smtp-repin"
      else
        printf "  %-14s %s\n" "relay pin:" "current DNS matches the firewall set ✔"
      fi
    else
      printf "  %-14s %s\n" "relay pin:" "port-only (no destination pin in the ruleset)"
    fi
  fi

  _mu="$MU_PLUGIN"
  if [ -r "$_mu" ]; then
    # Present is not the same as loading. Ask PHP whether the hook is live.
    if podman exec wordpress php -l /var/www/html/wp-content/mu-plugins/01-wpvm-smtp.php >/dev/null 2>&1; then
      printf "  %-14s %s\n" "mu-plugin:" "present and parses ✔"
    else
      printf "  %-14s %s\n" "mu-plugin:" "present but has a PHP SYNTAX ERROR ⚠ — mail will fail"
    fi
  else
    printf "  %-14s %s\n" "mu-plugin:" "MISSING ⚠ — mail will fall back to PHP mail() and fail"
  fi
  echo ""
  echo "  Verify delivery end-to-end:  wp-mail.sh test you@example.com"
}

do_test() {
  _to="$1"
  [ -n "$_to" ] || { echo "Usage: wp-mail.sh test <recipient@example.com>" >&2; exit 1; }
  # Reject anything that is not plausibly an address before it reaches a
  # shell word-split list or the container environment.
  case "$_to" in
    *[!A-Za-z0-9._%+@-]*|*@*@*|@*|*@) 
      echo "✗  '${_to}' does not look like an email address." >&2; exit 1 ;;
    *@*.*) : ;;
    *) echo "✗  '${_to}' does not look like an email address." >&2; exit 1 ;;
  esac
  _configured || { echo "✗  No relay configured — run: wp-mail.sh setup" >&2; exit 1; }
  # Check the name resolves before sending. Without this the failure surfaces
  # as PHPMailer's "Could not instantiate mail function", which points at the
  # mail system when the actual problem is a typo in the hostname.
  _h=$(_cfg host)
  if ! podman exec wordpress getent hosts "$_h" >/dev/null 2>&1; then
    echo "✗  ${_h} does not resolve from inside the container." >&2
    echo "   Nothing was sent. This is a DNS or hostname problem, not a mail one." >&2
    echo "   Check the spelling:  wp-mail.sh doctor" >&2
    echo "   Reconfigure:         wp-mail.sh setup" >&2
    exit 1
  fi
  echo "Sending a test message to ${_to} via ${_h}:$(_cfg port)…"
  # wp_mail()'s own return value is the ground truth — it is what every
  # plugin and core feature calls. Testing the relay with something else
  # (swaks, openssl s_client) would prove the relay works while saying
  # nothing about whether WordPress can actually use it, which is the
  # question being asked.
  # BUG FIX (found on a live VM): this passed the recipient as a second
  # positional argument to `wp eval`, which accepts exactly one (the code) and
  # has no $argv passthrough -- that is `wp eval-file`. wp-cli rejected the
  # call outright with "Too many positional arguments", so the send never even
  # reached the relay, and the failure looked like a mail problem when the
  # relay was fine. Passed through the environment instead: no quoting to get
  # wrong, and the address never becomes part of the PHP source, so an odd
  # character in it cannot alter the code being evaluated.
  # X-WASP-Mail: operator -- the relay, even when the client has their own
  # server for the site's mail (that path is `wp-mail.sh client test`).
  WPCLI_ENV="-e WPMAIL_TO=${_to}"
  _out=$(_wp eval '
    $to = getenv("WPMAIL_TO");
    $ok = wp_mail($to, "wp-mail.sh test message",
        "If you are reading this, WordPress on this VM can send mail.\n\n" .
        "Relay, credentials, TLS, and the SMTP mu-plugin are all working.\n" .
        "Sent: " . gmdate("c") . " UTC\n", array("X-WASP-Mail: operator"));
    echo $ok ? "SENT" : "FAILED";
  ' 2>&1) || true
  WPCLI_ENV=""
  case "$_out" in
    *SENT*)
      echo "✔  wp_mail() reported success — check ${_to} (including spam)."
      echo "   If it does not arrive, the relay accepted it but something"
      echo "   downstream dropped it: check SPF/DKIM alignment for $(_cfg from)"
      echo "   and your relay's own outbound log." ;;
    *"Error establishing a database connection"*|*"database connection"*)
      echo "✗  wp-cli could not reach the database, so the message was never sent." >&2
      echo "   This is NOT a mail problem — the relay was never contacted." >&2
      printf '   %s\n' "$_out" >&2
      echo "   Check:  wp-plugins.sh doctor   (same wp-cli path)" >&2
      exit 1 ;;
    *)
      echo "✗  Send failed. Output:" >&2
      printf '%s\n' "$_out" >&2
      echo "" >&2
      _ov=$(_mail_overrides)
      if [ -n "$_ov" ]; then
        _override_warning "$_ov" >&2
        echo "     Likely cause: the message went to THAT plugin's server, not ${_h}." >&2
        echo "" >&2
      fi
      echo "   Next: wp-mail.sh doctor   (checks DNS, port reachability, config)" >&2
      exit 1 ;;
  esac
}

do_setup() {
  echo ""
  echo "Configure the outbound SMTP relay"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "Use a DEDICATED mailbox or app password for this site — it is stored"
  echo "on this VM, and if the site is compromised you want to revoke exactly"
  echo "one credential without disturbing anything else that sends mail."
  echo ""
  printf "  SMTP server hostname : "; read -r _h
  [ -n "$_h" ] || { echo "Hostname is required." >&2; exit 1; }
  case "$_h" in *[!A-Za-z0-9.-]*) echo "✗  Not a hostname: ${_h}" >&2; exit 1 ;; esac
  printf "  Port [587] : "; read -r _p; _p="${_p:-587}"
  case "$_p" in 465) _enc="ssl" ;; *) _enc="tls" ;; esac
  printf "  Username (full mailbox address) : "; read -r _u
  printf "  Password / app password : "
  stty -echo 2>/dev/null || true; read -r _pw; stty echo 2>/dev/null || true; echo
  [ -n "$_pw" ] || { echo "Password is required." >&2; exit 1; }
  printf "  From address [%s] : " "$_u"; read -r _f; _f="${_f:-$_u}"
  printf "  From name [WordPress] : "; read -r _fn; _fn="${_fn:-WordPress}"

  # INI, not PHP: the config is data, so it can never be executed. Password
  # base64-encoded so quotes/semicolons/'=' cannot interact with INI parsing.
  mkdir -p "$SECRETS_DIR"
  chown root:33 "$SECRETS_DIR" 2>/dev/null || true
  chmod 0750 "$SECRETS_DIR"
  # No `install`: not every BusyBox build has it.
  : > "$SMTP_FILE"; chown 0:33 "$SMTP_FILE"; chmod 0600 "$SMTP_FILE"
  {
    printf '; WASP SMTP relay settings. Data, not code -- never include() this.\n'
    printf 'host = %s\n'       "$_h"
    printf 'port = %s\n'       "$_p"
    printf 'user = %s\n'       "$_u"
    printf 'pass_b64 = %s\n'   "$(printf '%s' "$_pw" | base64 | tr -d '\n')"
    printf 'from = %s\n'       "$_f"
    printf 'from_name = %s\n'  "$_fn"
    printf 'encryption = %s\n' "$_enc"
    printf 'timeout = 10\n'
  } > "$SMTP_FILE"
  chmod 0440 "$SMTP_FILE"; chown root:33 "$SMTP_FILE"
  # Retire the executable form if this VM predates the change.
  [ -f "$SMTP_FILE_LEGACY" ] && { rm -f "$SMTP_FILE_LEGACY"; echo "  Removed legacy executable smtp.php"; }
  echo "✔  Written to ${SMTP_FILE} (INI, non-executable, root:33 0440, dir 0750)"
  # The firewall lets mail out only to the relay's addresses. Until 10.27 this
  # wrote the new relay and left the rule on the old one, so mail to a new
  # relay was dropped with nothing saying why. Record the host, then re-pin.
  if [ -w /etc/wp-install/vars.sh ] && [ "$_h" != "${SMTP_HOST:-}" ]; then
    # A hostname (checked above): letters, digits, dots and hyphens only.
    if grep -q '^SMTP_HOST=' /etc/wp-install/vars.sh; then
      _tmpv=$(mktemp); sed "s|^SMTP_HOST=.*|SMTP_HOST='${_h}'|" /etc/wp-install/vars.sh > "$_tmpv" && cat "$_tmpv" > /etc/wp-install/vars.sh; rm -f "$_tmpv"
    else
      printf "SMTP_HOST='%s'\n" "$_h" >> /etc/wp-install/vars.sh
    fi
    SMTP_HOST="$_h"
  fi
  if command -v wp-hardening.sh >/dev/null 2>&1; then
    echo "  Re-pinning the firewall to ${_h}…"
    wp-hardening.sh smtp-repin || echo "  ⚠  Mail to ${_h} stays blocked until: doas wp-hardening.sh smtp-repin" >&2
  fi
  # The mount is read-only and already in place, and PHP reads the file per
  # request, so no container restart is needed — but opcache can hold a
  # compiled copy, so nudge it.
  podman exec wordpress sh -c 'command -v php >/dev/null && php -r "opcache_reset();" 2>/dev/null' >/dev/null 2>&1 || true
  echo "   Test it:  wp-mail.sh test you@example.com"
}

# ── The client's own mail server ─────────────────────────────────────────────
_ccfg() {  # key -> value from client-mail.ini
  [ -r "$CLIENT_FILE" ] || return 1
  case "$1" in
    secret) sed -n 's/^[[:space:]]*secret_b64[[:space:]]*=[[:space:]]*//p' "$CLIENT_FILE" | head -1 | base64 -d 2>/dev/null ;;
    pass)   sed -n 's/^[[:space:]]*pass_b64[[:space:]]*=[[:space:]]*//p' "$CLIENT_FILE" | head -1 | base64 -d 2>/dev/null ;;
    *)      sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$CLIENT_FILE" | head -1 | tr -d '\r' ;;
  esac
}
_ctransport() { _t=$(_ccfg transport); printf '%s' "${_t:-smtp}"; }
# Recent client-path failures that went through the relay instead.
_cfallbacks() {
  grep -h 'wpvm-smtp\] client mail failed' "$WP_LOG_DIR"/*.log 2>/dev/null | tail -"${1:-3}"
}

client_status() {
  echo ""
  echo "The site's mail (contact forms, password resets, notifications)"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  if [ ! -r "$CLIENT_FILE" ]; then
    echo "  Through the operator relay ($(_cfg host 2>/dev/null || echo 'not configured')), like WASP's own alerts."
    echo ""
    echo "  To send it through the client's own Microsoft 365 or mail server:"
    echo "    doas wp-mail.sh client setup"
    return 0
  fi
  case "$(_ctransport)" in
    m365)
      printf "  %-16s %s\n" "Transport:" "Microsoft 365 through Graph (HTTPS, no SMTP)"
      printf "  %-16s %s\n" "Sends as:" "$(_ccfg from)"
      printf "  %-16s %s\n" "Tenant:" "$(_ccfg tenant)"
      printf "  %-16s %s\n" "App (client) ID:" "$(_ccfg client_id)"
      printf "  %-16s %s\n" "Secret:" "(set — redacted)"
      _exp=$(_ccfg secret_expires)
      if [ -n "$_exp" ]; then
        _now=$(date -u +%Y-%m-%d)
        _soon=$(date -u -d "@$(( $(date +%s) + 30*86400 ))" +%Y-%m-%d 2>/dev/null)
        if [ "$_exp" \< "$_now" ] || [ "$_exp" = "$_now" ]; then
          printf "  %-16s %s\n" "Secret expires:" "${_exp}  ✗ EXPIRED — the site's mail is going through the relay"
        elif [ -n "$_soon" ] && [ "$_exp" \< "$_soon" ]; then
          printf "  %-16s %s\n" "Secret expires:" "${_exp}  ⚠ within 30 days: ask for a new secret, then client setup"
        else
          printf "  %-16s %s\n" "Secret expires:" "${_exp}"
        fi
      else
        printf "  %-16s %s\n" "Secret expires:" "not recorded (re-run client setup to record it)"
      fi
      _al="/opt/squid/config/allowlist-runtime.txt"
      if [ -r "$_al" ]; then
        _miss=""
        for _gh in login.microsoftonline.com graph.microsoft.com; do
          grep -v '^[[:space:]]*#' "$_al" | tr -d ' \t\r' | grep -qxE "${_gh}|\.(${_gh#*.})" || _miss="${_miss} ${_gh}"
        done
        if [ -n "$_miss" ]; then
          printf "  %-16s %s\n" "Egress:" "MISSING${_miss} ⚠ — run: doas wasp-egress.sh reconcile"
        else
          printf "  %-16s %s\n" "Egress:" "login.microsoftonline.com and graph.microsoft.com allowed ✔"
        fi
      fi ;;
    smtp)
      printf "  %-16s %s\n" "Transport:" "SMTP submission, $(_ccfg host):$(_ccfg port)"
      printf "  %-16s %s\n" "Username:" "$(_ccfg user)"
      printf "  %-16s %s\n" "Password:" "(set — redacted)"
      printf "  %-16s %s\n" "Sends as:" "$(_ccfg from)" ;;
    *)
      printf "  %-16s %s\n" "Transport:" "$(_ctransport) — UNKNOWN ⚠ (the site's mail is going through the relay)" ;;
  esac
  printf "  %-16s %s\n" "From name:" "$(_ccfg from_name)"
  _perm=$(stat -c '%a %u:%g' "$CLIENT_FILE" 2>/dev/null || echo "?")
  case "$_perm" in
    "440 0:33") printf "  %-16s %s\n" "File mode:" "${_perm} (root:uid33)  ✔" ;;
    *) printf "  %-16s %s\n" "File mode:" "$_perm  ⚠ expected 440 0:33" ;;
  esac
  printf "  %-16s %s\n" "WASP's alerts:" "the operator relay, $(_cfg host 2>/dev/null || echo 'not configured')"
  _fb=$(_cfallbacks 3)
  echo ""
  if [ -n "$_fb" ]; then
    echo "  ⚠  Recent messages the client's server did not take (sent through the relay):"
    printf '%s\n' "$_fb" | sed 's/^/     /'
  else
    echo "  No recent failures on the client's path."
  fi
  echo ""
  echo "  Verify:  doas wp-mail.sh client test <the client's address>"
}

client_setup() {
  echo ""
  echo "The site's mail through the client's own server"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "Contact forms, password resets and notifications will be sent by the"
  echo "client's mailbox. WASP's security alerts stay on the operator relay."
  echo ""
  echo "  1) Microsoft 365 through Graph (recommended for Microsoft 365)"
  echo "     An app the client's tenant registers; HTTPS, no SMTP, no port 25."
  echo "  2) SMTP submission, 587 or 465"
  echo "     Google Workspace with an app password, or any other mail host."
  echo "     Microsoft 365 too, while its tenant still allows SMTP AUTH."
  echo ""
  printf "  Choice [1] : "; read -r _c; _c="${_c:-1}"
  _tmp=$(mktemp)
  case "$_c" in
    1)
      echo ""
      echo "  From the app registration in the client's Microsoft Entra admin center"
      echo "  (README: Microsoft 365 for the site's mail):"
      printf "  Directory (tenant) ID, or their domain : "; read -r _tn
      case "$_tn" in ''|*[!A-Za-z0-9.-]*) echo "✗  Not a tenant ID or domain: ${_tn}" >&2; rm -f "$_tmp"; exit 1 ;; esac
      printf "  Application (client) ID : "; read -r _ci
      printf '%s' "$_ci" | grep -qE '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' \
        || { echo "✗  An application ID looks like 3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90" >&2; rm -f "$_tmp"; exit 1; }
      printf "  Client secret VALUE (not its ID) : "
      stty -echo 2>/dev/null || true; read -r _sec; stty echo 2>/dev/null || true; echo
      [ -n "$_sec" ] || { echo "✗  The secret is required." >&2; rm -f "$_tmp"; exit 1; }
      printf "  Secret expires (YYYY-MM-DD, blank = not recorded) : "; read -r _ex
      case "$_ex" in ''|[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]) : ;; *) echo "✗  Use YYYY-MM-DD." >&2; rm -f "$_tmp"; exit 1 ;; esac
      printf "  Mailbox that sends (e.g. forms@clientdomain.com) : "; read -r _fr
      printf "  From name [%s] : " "$(_cfg from_name 2>/dev/null || echo Website)"; read -r _fn
      _fn="${_fn:-$(_cfg from_name 2>/dev/null || echo Website)}"
      {
        printf '; The site'"'"'s mail through the client'"'"'s Microsoft 365. Data, not code.\n'
        printf 'transport = m365\n'
        printf 'tenant = %s\n' "$_tn"
        printf 'client_id = %s\n' "$_ci"
        printf 'secret_b64 = %s\n' "$(printf '%s' "$_sec" | base64 | tr -d '\n')"
        [ -n "$_ex" ] && printf 'secret_expires = %s\n' "$_ex"
        printf 'from = %s\n' "$_fr"
        printf 'from_name = %s\n' "$_fn"
      } > "$_tmp" ;;
    2)
      echo ""
      printf "  SMTP server (smtp.gmail.com, smtp.office365.com, …) : "; read -r _h
      case "$_h" in ''|*[!A-Za-z0-9.-]*) echo "✗  Not a hostname: ${_h}" >&2; rm -f "$_tmp"; exit 1 ;; esac
      printf "  Port [587] : "; read -r _p; _p="${_p:-587}"
      case "$_p" in
        587) _enc=tls ;; 465) _enc=ssl ;;
        25) echo "✗  Port 25 is server-to-server delivery, not submission. Use 587 or 465." >&2; rm -f "$_tmp"; exit 1 ;;
        *) echo "✗  Use 587 (STARTTLS) or 465 (TLS)." >&2; rm -f "$_tmp"; exit 1 ;;
      esac
      printf "  Username (the full mailbox address) : "; read -r _u
      printf "  Password or app password : "
      stty -echo 2>/dev/null || true; read -r _pw; stty echo 2>/dev/null || true; echo
      [ -n "$_pw" ] || { echo "✗  The password is required." >&2; rm -f "$_tmp"; exit 1; }
      printf "  From address [%s] : " "$_u"; read -r _fr; _fr="${_fr:-$_u}"
      printf "  From name [%s] : " "$(_cfg from_name 2>/dev/null || echo Website)"; read -r _fn
      _fn="${_fn:-$(_cfg from_name 2>/dev/null || echo Website)}"
      {
        printf '; The site'"'"'s mail through the client'"'"'s SMTP server. Data, not code.\n'
        printf 'transport = smtp\n'
        printf 'host = %s\n' "$_h"
        printf 'port = %s\n' "$_p"
        printf 'user = %s\n' "$_u"
        printf 'pass_b64 = %s\n' "$(printf '%s' "$_pw" | base64 | tr -d '\n')"
        printf 'from = %s\n' "$_fr"
        printf 'from_name = %s\n' "$_fn"
        printf 'encryption = %s\n' "$_enc"
        printf 'timeout = 10\n'
      } > "$_tmp" ;;
    *) echo "Choose 1 or 2." >&2; rm -f "$_tmp"; exit 1 ;;
  esac
  case "$_fr" in *@*.*) : ;; *) echo "✗  '${_fr}' is not a mailbox address." >&2; rm -f "$_tmp"; exit 1 ;; esac
  mkdir -p "$SECRETS_DIR"; chown root:33 "$SECRETS_DIR" 2>/dev/null || true; chmod 0750 "$SECRETS_DIR"
  [ -f "$CLIENT_FILE" ] || { : > "$CLIENT_FILE"; chown 0:33 "$CLIENT_FILE"; }
  # In place: the secrets folder is mounted into the container as it is.
  chmod 0640 "$CLIENT_FILE"; cat "$_tmp" > "$CLIENT_FILE"; rm -f "$_tmp"
  chmod 0440 "$CLIENT_FILE"; chown root:33 "$CLIENT_FILE"
  echo "✔  Written to ${CLIENT_FILE} (INI, root:33 0440)"
  if [ "$_c" = 1 ]; then
    command -v wasp-egress.sh >/dev/null 2>&1 && { wasp-egress.sh reconcile || echo "  ⚠  Allow them by hand: doas wasp-egress.sh reconcile" >&2; }
  else
    command -v wp-hardening.sh >/dev/null 2>&1 && { wp-hardening.sh smtp-repin || echo "  ⚠  Mail to ${_h} is blocked until: doas wp-hardening.sh smtp-repin" >&2; }
  fi
  podman exec wordpress sh -c 'command -v php >/dev/null && php -r "opcache_reset();" 2>/dev/null' >/dev/null 2>&1 || true
  echo ""
  echo "  Next:  doas wp-mail.sh client test <an address at the client>"
}

client_test() {
  _to="$1"
  case "$_to" in
    *[!A-Za-z0-9._%+@-]*|*@*@*|@*|*@|'') echo "Usage: wp-mail.sh client test <recipient@example.com>" >&2; exit 1 ;;
    *@*.*) : ;;
    *) echo "✗  '${_to}' does not look like an email address." >&2; exit 1 ;;
  esac
  [ -r "$CLIENT_FILE" ] || { echo "✗  No client mail server set up; the site's mail uses the relay (wp-mail.sh test)." >&2; exit 1; }
  echo "Sending through the client's $( [ "$(_ctransport)" = m365 ] && echo 'Microsoft 365' || echo "server $(_ccfg host)") to ${_to}…"
  WPCLI_ENV="-e WPMAIL_TO=${_to}"
  _out=$(_wp eval '
    $ok = wp_mail(getenv("WPMAIL_TO"), "wp-mail.sh client test",
        "If you are reading this, the site'"'"'s own mail (contact forms, password\n" .
        "resets) reaches this mailbox through the client'"'"'s server.\n\n" .
        "Sent: " . gmdate("c") . " UTC\n", array("X-WASP-Mail: client"));
    global $phpmailer;
    $fb = is_object($phpmailer) && !empty($phpmailer->wpvm_fellback);
    echo $ok ? ($fb ? "FELLBACK" : "SENT") : "FAILED";
  ' 2>&1) || true
  WPCLI_ENV=""
  case "$_out" in
    *FELLBACK*)
      echo "✗  The client's server did NOT take it. It was delivered through the relay instead." >&2
      printf '%s\n' "$_out" | grep 'client mail failed' | sed 's/.*client mail failed (/   Why: /; s/); sent through.*//' >&2
      echo "   Fix it, then test again. Until then the site's mail keeps arriving, from the relay." >&2
      exit 1 ;;
    *SENT*)
      echo "✔  Sent by the client's $( [ "$(_ctransport)" = m365 ] && echo 'Microsoft 365' || echo 'server'). Check ${_to}, and the sending mailbox's Sent Items." ;;
    *)
      echo "✗  Not sent:" >&2; printf '%s\n' "$_out" >&2; exit 1 ;;
  esac
}

client_off() {
  [ -r "$CLIENT_FILE" ] || { echo "The site's mail already uses the relay."; return 0; }
  printf "  Send the site's mail through the operator relay again? Type OFF to confirm: "
  read -r _a; _a=$(printf '%s' "$_a" | tr -d ' \t\r')
  [ "$_a" = OFF ] || { echo "Nothing changed."; return 0; }
  cp -p "$CLIENT_FILE" "${CLIENT_FILE}.off-$(date -u +%Y%m%d%H%M%S)"
  chmod 0400 "${CLIENT_FILE}".off-* 2>/dev/null || true
  rm -f "$CLIENT_FILE"
  echo "✔  The site's mail goes through the relay. The old settings are kept beside it (.off-*)."
  echo "   Egress for Microsoft 365, if any, stays allowed: doas wasp-egress.sh deny <host>"
}

show_log() {
  echo "Recent wp_mail failures (from the PHP error log):"
  if [ -d "$WP_LOG_DIR" ]; then
    grep -h "wpvm-smtp" "$WP_LOG_DIR"/*.log 2>/dev/null | tail -25 \
      || echo "  (none — no logged mail failures)"
  else
    echo "  ${WP_LOG_DIR} not found"
  fi
}

do_doctor() {
  echo "Mail diagnostics"
  echo "━━━━━━━━━━━━━━━━"
  _configured && echo "  config      : present" || { echo "  config      : MISSING (wp-mail.sh setup)"; exit 1; }
  _h=$(_cfg host); _p=$(_cfg port)
  echo "  relay       : ${_h}:${_p}"
  [ -r "$MU_PLUGIN" ] && echo "  mu-plugin   : present" || echo "  mu-plugin   : MISSING — mail falls back to PHP mail() and fails"
  _ov=$(_mail_overrides)
  if [ -n "$_ov" ]; then
    echo "  overrides   : $(printf '%s' "$_ov" | tr '\n' ' ')⚠"
    _override_warning "$_ov"
  else
    echo "  overrides   : none (no active plugin replaces the mailer)"
  fi
  printf "  mount       : "
  _m=$(podman inspect wordpress --format '{{range .Mounts}}{{.Destination}}={{.RW}} {{end}}' 2>/dev/null \
       | tr ' ' '\n' | grep '/var/www/private')
  case "$_m" in
    *=false) echo "/var/www/private mounted READ-ONLY (correct)" ;;
    *=true)  echo "/var/www/private mounted WRITABLE — should be :ro" ;;
    *)       echo "/var/www/private NOT MOUNTED — wp_mail cannot read the relay settings" ;;
  esac
  printf "  DNS         : "
  podman exec wordpress sh -c "getent hosts ${_h} >/dev/null 2>&1" \
    && echo "${_h} resolves from the container" \
    || echo "${_h} does NOT resolve from the container ⚠"
  printf "  TCP ${_p}     : "
  # nc is not guaranteed in the container; use PHP, which definitely is.
  podman exec wordpress php -r "
    \$e=null;\$s=@fsockopen('${_h}',${_p},\$n,\$e,5);
    echo \$s?'reachable':'UNREACHABLE ('.\$e.')';
    if(\$s)fclose(\$s);" 2>/dev/null || echo "check failed"
  # The client's path, when the site's mail has one.
  if [ -r "$CLIENT_FILE" ]; then
    case "$(_ctransport)" in
      m365)
        echo "  client path : Microsoft 365 through Graph, as $(_ccfg from)"
        printf "  client HTTPS: "
        # WordPress's own HTTP API, through the proxy, as a send would go.
        _r=$(_wp eval '$r = wp_remote_get("https://login.microsoftonline.com/common/discovery/keys", array("timeout" => 8)); echo is_wp_error($r) ? "BLOCKED " . $r->get_error_message() : "reachable (HTTP " . wp_remote_retrieve_response_code($r) . ")";' 2>/dev/null || echo "check failed")
        case "$_r" in reachable*) echo "Microsoft sign-in ${_r}" ;; *) echo "Microsoft sign-in ${_r} ⚠ — doas wasp-egress.sh reconcile" ;; esac ;;
      *)
        _chh=$(_ccfg host); _chp=$(_ccfg port)
        case "${_chh}:${_chp}" in *[!A-Za-z0-9.:-]*|:*) _chh=invalid.invalid; _chp=587 ;; esac
        echo "  client path : SMTP ${_chh}:${_chp:-587}, as $(_ccfg from)"
        printf "  client TCP  : "
        podman exec wordpress php -r "
          \$e=null;\$s=@fsockopen('${_chh}',${_chp:-587},\$n,\$e,5);
          echo \$s?'reachable':'UNREACHABLE ('.\$e.') — doas wp-hardening.sh smtp-repin';
          if(\$s)fclose(\$s);" 2>/dev/null || echo "check failed"
        echo "" ;;
    esac
    _fb=$(_cfallbacks 1)
    [ -n "$_fb" ] && echo "  last client failure: $(printf '%s' "$_fb" | sed 's/.*client mail failed (//; s/); sent through.*//')"
  else
    echo "  client path : none; the site's mail uses the relay too"
  fi
  echo ""
  echo "  Firewall note: outbound submission is rate limited to 30 new"
  echo "  connections/hour (burst 10). Hitting that logs 'nft-smtp-ratelimit'"
  echo "  to the system log — check there if sends start failing in bulk."
}

case "${1:-status}" in
  status) show_status; [ -r "$CLIENT_FILE" ] && echo "  The site's own mail goes through the client's server: wp-mail.sh client" ;;
  test)   do_test "${2:-}" ;;
  setup)  do_setup ;;
  log)    show_log ;;
  doctor) do_doctor ;;
  client)
    case "${2:-status}" in
      status) client_status ;;
      setup)  client_setup ;;
      test)   client_test "${3:-}" ;;
      off)    client_off ;;
      *) echo "Usage: wp-mail.sh client [status|setup|off]"; echo "       wp-mail.sh client test <recipient@example.com>"; exit 1 ;;
    esac ;;
  *)
    echo "Usage: wp-mail.sh [status|setup|doctor|log]"
    echo "       wp-mail.sh test <recipient@example.com>"
    echo "       wp-mail.sh client [status|setup|off]"
    echo "       wp-mail.sh client test <recipient@example.com>" ;;
esac
