#!/bin/sh
# =============================================================================
# wasp-egress.sh — manage and prove the egress boundary
# =============================================================================
#   wasp-egress status              current mode, allowlist, recent denies
#   wasp-egress test                PROVE the boundary holds (see below)
#   wasp-egress discovery report    what was denied, classified for review
#   wasp-egress allow <domain> [--for MIN]   open for MIN minutes (default and
#                                   maximum 60), then closed automatically
#   wasp-egress allow <domain> --permanent   theme/builder vendors only
#   wasp-egress deny <domain>       remove it, permanent and temporary
#   wasp-egress fileshare list | open <service...> [--for MIN] | close
#                                   dropbox gdrive onedrive wetransfer box syncedtool
#   wasp-egress temporary           what is open temporarily, and for how long
#   wasp-egress close <domain>|--all  close temporary entries now
#   wasp-egress maintenance enable --duration N --reason "..." --host X
#   wasp-egress maintenance status | disable
#   wasp-egress import-source add|remove|list [host]
#                                   other hosts wp-import.sh may open for one download
#   wasp-egress expire              cron, every minute: close what has expired
#   wasp-egress hive set <address> | test | status | refresh | remove
#                                   the path from this VM to its WASP Hive
#
# THE BOUNDARY
#
#   wp-front  ──:3128──►  Squid  ──80/443──►  approved destinations only
#   wp-front  ──X──────►  the internet directly
#   wp-db     ──X──────►  anything
#
# Two independent controls, and both matter:
#
#   Squid decides WHERE traffic may go — by destination, from the plaintext
#   CONNECT hostname, without decrypting anything.
#
#   nftables decides that WordPress CANNOT GO ROUND IT. Without that, the
#   proxy is a suggestion: a plugin calling fsockopen() or curl with
#   CURLOPT_PROXY unset simply ignores WordPress's proxy settings.
#
# `test` exists because a control nobody has verified is a claim. The most
# important case it covers is removing WordPress's proxy configuration and
# confirming egress STILL fails — that is what distinguishes a firewall
# enforcing a boundary from an application politely observing one.
# =============================================================================
set -u

if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then exec doas "$0" "$@"; fi
  echo "Run as root (or via doas)" >&2; exit 1
fi
[ -r /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh

SQ=/opt/squid
CONF="${SQ}/config"
LOGS="${SQ}/logs"
RUNTIME="${CONF}/allowlist-runtime.txt"
MAINT="${CONF}/allowlist-maintenance.txt"
MAINT_META="${CONF}/.maintenance"
IMPORT_SOURCES=/etc/wp-install/import-sources.txt
HIVE_EGRESS=${HIVE_EGRESS:-/etc/wp-install/hive-egress}
HIVE_CONF_FILE=${HIVE_CONF_FILE:-/etc/wp-install/hive.conf}
FW_RULE=${FW_RULE:-/usr/local/bin/wasp-fw-rule.sh}
PROXY_HOST=10.89.10.2
PROXY_PORT=3128

_ok()   { printf '  \033[32m✔\033[0m  %s\n' "$1"; }
_bad()  { printf '  \033[31m✗\033[0m  %s\n' "$1"; }
_warn() { printf '  \033[33m⚠\033[0m  %s\n' "$1"; }
_note() { printf '     %s\n' "$1"; }
_hdr()  { printf '\n\033[1m%s\033[0m\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n' "$1"; }

# ── Temporary entries ────────────────────────────────────────────────────────
# Everything that is not on the permanent allowlist lives in one ledger, one
# line per entry:   <until-epoch> <tag> <domain> <by> <reason...>
# and allowlist-maintenance.txt (Squid's maint_allow ACL) is rebuilt from it.
# Tags: allow, fileshare, maintenance, import-<pid>. An entry is closed by
# its own tag, so an import closing its download never closes an operator's
# window for the same host.
#
# Nothing here can be open for more than TEMP_MAX minutes, and expiry does not
# depend on anyone running this tool: cron calls `expire` every minute. Before
# 10.11 a window's expiry was checked only when wasp-egress ran, so a window
# nobody looked at again stayed open in Squid indefinitely while its own
# message said "Closes automatically".
LEDGER="${CONF}/.temporary"
TEMP_MAX=60

# File-sharing services. Each is every host its download links use (see
# `fileshare` below). Dot-prefixed entries are Squid dstdomain wildcards.
FS_SERVICES="dropbox gdrive onedrive wetransfer box syncedtool"
_fs_domains() {
  case "$1" in
    dropbox)    echo ".dropbox.com .dropboxusercontent.com" ;;
    gdrive)     echo ".drive.google.com .usercontent.google.com" ;;
    onedrive)   echo "onedrive.live.com 1drv.ms .1drv.com api.onedrive.com .microsoftpersonalcontent.com .sharepoint.com" ;;
    wetransfer) echo ".wetransfer.com .wetransfer.net we.tl" ;;
    box)        echo ".box.com .box.net .boxcloud.com .boxcdn.net" ;;
    syncedtool) echo "activeit.syncedtool.com" ;;
  esac
}

# Does Squid dstdomain entry $1 cover host $2?
_covers() {
  case "$1" in
    .*) [ "$2" = "${1#.}" ] && return 0
        case "$2" in *"$1") return 0 ;; esac ;;
    *)  [ "$2" = "$1" ] && return 0 ;;
  esac
  return 1
}

_who() { printf '%s' "${SUDO_USER:-${DOAS_USER:-${USER:-unknown}}}"; }
_hhmm() { date -u -d "@$1" +%H:%M 2>/dev/null || echo "+$(( ($1 - $(date -u +%s)) / 60 ))m"; }

_valid_domain() {
  printf '%s' "$1" | grep -qE '^\.?[a-z0-9-]+(\.[a-z0-9-]+)+$' \
    || { _bad "'$1' does not look like a domain"; return 1; }
  # A bare TLD or a wildcard over one defeats the point of the list.
  case "$1" in
    .*) [ "$(printf '%s' "$1" | tr -cd . | wc -c)" -lt 2 ] && {
          _bad "'$1' is too broad — that is most of a TLD."
          _note "Allow the specific host you need."; return 1; } ;;
  esac
  return 0
}

# Minutes for a temporary entry: a whole number, 1..TEMP_MAX. Over the cap is
# capped, said, and not refused -- the operator asked for access, not a lecture.
_minutes() {
  case "$1" in ''|*[!0-9]*|0) _bad "--for takes whole minutes, 1 to ${TEMP_MAX}" >&2; return 1 ;; esac
  if [ "$1" -gt "$TEMP_MAX" ]; then
    _warn "Capped at ${TEMP_MAX} minutes. Nothing temporary stays open longer." >&2
    echo "$TEMP_MAX"
  else echo "$1"; fi
}

_squid_reload() {
  podman exec squid squid -k parse >/dev/null 2>&1 \
    && podman exec squid squid -k reconfigure >/dev/null 2>&1
}

_reload_or_restore() {
  if podman exec squid squid -k parse 2>/dev/null && podman exec squid squid -k reconfigure 2>/dev/null; then
    _ok "Squid reloaded"
  else
    _bad "Squid rejected the configuration — restoring the previous list"
    cp "$(ls -1t "${RUNTIME}".bak-* | head -1)" "$RUNTIME"; exit 1
  fi
}

_notify_open() {
  logger -t wasp-egress "$1" 2>/dev/null || true
  [ -x /usr/local/bin/wp-notify.sh ] || return 0
  _b=$(mktemp)
  { printf '%s on %s, by %s.\n\n' "$1" "$(hostname)" "$(_who)"
    printf 'It closes by itself. Open now:\n\n'
    sed 's/^/  /' "$LEDGER" 2>/dev/null
  } > "$_b"
  NOTIFY_COOLDOWN_HOURS=0 /usr/local/bin/wp-notify.sh wasp-egress "$1 — $(hostname)" "$_b" >/dev/null 2>&1
  rm -f "$_b"
}

# Rebuild Squid's temporary list from the ledger. In place (cat >, never mv):
# the file is bind-mounted into the container as a single file, and a new
# inode is one the container never sees. A host already covered by a
# dot-domain in the same list is dropped, because Squid warns on the overlap.
# Returns 0 when the file changed.
_temp_rebuild() {
  _act=$(awk 'NF>=3 {print $3}' "$LEDGER" 2>/dev/null | sort -u \
    | awk 'NF { d[++n]=$0 }
           END { for (i=1;i<=n;i++) { k=d[i]; c=0
                   for (j=1;j<=n;j++) { w=d[j]
                     if (i!=j && substr(w,1,1)=="." &&
                         (k==substr(w,2) || (length(k)>length(w) && substr(k,length(k)-length(w)+1)==w))) c=1 }
                   if (!c) print k } }')
  { printf 'wasp-placeholder.invalid\n'; [ -n "$_act" ] && printf '%s\n' "$_act"; } > "${MAINT}.new"
  if cmp -s "${MAINT}.new" "$MAINT" 2>/dev/null; then rm -f "${MAINT}.new"; return 1; fi
  cat "${MAINT}.new" > "$MAINT"; rm -f "${MAINT}.new"
  return 0
}

# A VM upgraded in place may still hold a 10.10-style window (.maintenance).
# Carried into the ledger once, with its own expiry, capped like any other.
_migrate_maint() {
  [ -r "$MAINT_META" ] || return 0
  _u=$(sed -n 's/^until=//p' "$MAINT_META"); _r=$(sed -n 's/^reason=//p' "$MAINT_META")
  _cap=$(( $(date -u +%s) + TEMP_MAX * 60 ))
  case "$_u" in ''|*[!0-9]*) _u=0 ;; esac
  [ "$_u" -gt "$_cap" ] && _u=$_cap
  for _h in $(sed -n 's/^hosts=//p' "$MAINT_META"); do
    printf '%s maintenance %s migrated %s\n' "$_u" "$_h" "${_r:-window}" >> "$LEDGER"
  done
  rm -f "$MAINT_META"
}

_temp_add() {  # tag minutes reason domain...
  _tg="$1"; _mins="$2"; _rsn=$(printf '%s' "$3" | tr -d '\n\r'); shift 3
  _until=$(( $(date -u +%s) + _mins * 60 ))
  mkdir -p "$CONF"; touch "$LEDGER"; chmod 600 "$LEDGER"
  cp "$LEDGER" "${LEDGER}.prev"
  for _d in "$@"; do
    awk -v t="$_tg" -v d="$_d" '!($2==t && $3==d)' "$LEDGER" > "${LEDGER}.tmp"
    cat "${LEDGER}.tmp" > "$LEDGER"
    printf '%s %s %s %s %s\n' "$_until" "$_tg" "$_d" "$(_who)" "${_rsn:--}" >> "$LEDGER"
  done
  rm -f "${LEDGER}.tmp"
  _temp_rebuild || true
  if ! _squid_reload; then
    _bad "Squid rejected the temporary list — nothing was opened."
    cat "${LEDGER}.prev" > "$LEDGER"; _temp_rebuild || true; _squid_reload || true
    rm -f "${LEDGER}.prev"; return 1
  fi
  rm -f "${LEDGER}.prev"
  logger -t wasp-egress "temporary ${_tg} (${_mins}m) $*: ${_rsn}" 2>/dev/null || true
  return 0
}

_temp_close() {  # tag|* domain|*
  [ -f "$LEDGER" ] || return 0
  awk -v t="$1" -v d="$2" '!((t=="*" || $2==t) && (d=="*" || $3==d))' "$LEDGER" > "${LEDGER}.tmp"
  cat "${LEDGER}.tmp" > "$LEDGER"; rm -f "${LEDGER}.tmp"
  if _temp_rebuild; then _squid_reload || true; fi
  return 0
}

# Close what has expired. Returns 1 when something was closed.
_expire_temp() {
  _migrate_maint
  [ -s "$LEDGER" ] || return 0
  _now=$(date -u +%s)
  _gone=$(awk -v n="$_now" '$1<=n {print $3" ("$2")"}' "$LEDGER")
  [ -n "$_gone" ] || return 0
  awk -v n="$_now" '$1>n' "$LEDGER" > "${LEDGER}.tmp"
  cat "${LEDGER}.tmp" > "$LEDGER"; rm -f "${LEDGER}.tmp"
  if _temp_rebuild; then _squid_reload || true; fi
  printf '%s\n' "$_gone" | while IFS= read -r _g; do
    logger -t wasp-egress "temporary egress expired: ${_g}" 2>/dev/null || true
  done
  return 1
}

_mode() {
  _n=$(awk 'NF>=3' "$LEDGER" 2>/dev/null | grep -c .) || _n=0
  if [ "$_n" -gt 0 ]; then echo "STRICT + ${_n} temporary"; else echo STRICT; fi
}

case "${1:-status}" in

status)
  _expire_temp && _exp=0 || _exp=1
  _hdr "Egress control"
  _m=$(_mode)
  printf '  Mode : %s\n' "$_m"
  [ "$_exp" = 1 ] && _note "(a temporary entry expired just now and was closed)"

  # Ask podman with a FILTER rather than grepping its formatted output, and
  # confirm the proxy is actually SERVING rather than merely present.
  #
  # Reported from a live VM: this said "Squid is NOT running" while Squid's own
  # access log showed it tunnelling to api.wordpress.org and correctly refusing
  # example.com in the same second. A false negative here is expensive -- it
  # sent an investigation after a working proxy and made every downstream
  # failure look like a consequence of it.
  if podman ps --filter 'name=^squid$' --filter status=running \
       --format '{{.Names}}' 2>/dev/null | grep -qx squid; then
    _ok "Squid is running"
    # Running is not the same as answering. One probe settles it.
    if podman exec squid squid -k check >/dev/null 2>&1; then
      _ok "  and responding to its own control interface"
    else
      _note "  (control check did not answer; see: doas podman logs --tail 30 squid)"
    fi
  else
    _bad "Squid is NOT running"
    _note "  If Squid's access log shows recent traffic, this check is wrong,"
    _note "  not Squid. Confirm directly:"
    _note "    doas podman ps -a --filter name=squid"
    _note "    doas podman logs --tail 20 squid"
    _note "WordPress web egress is therefore failing — which is the intended"
    _note "behaviour, not a secondary fault. The boundary fails closed."
    _note "  doas podman logs --tail 30 squid"
  fi

  echo ""
  _n=$(grep -cvE '^\s*(#|$)' "$RUNTIME" 2>/dev/null) || _n=0
  printf '  Runtime allowlist (%s):\n' "$_n"
  grep -vE '^\s*(#|$)' "$RUNTIME" 2>/dev/null | sed 's/^/    /'

  if [ "$_m" != "STRICT" ]; then
    echo ""
    _warn "Temporarily open (closes by itself):"
    _now=$(date -u +%s)
    awk -v n="$_now" '{ printf "    + %-32s %3d min left  [%s]\n", $3, int(($1-n+59)/60), $2 }' "$LEDGER"
  fi

  echo ""
  echo "  Recent denials (what WordPress tried and could not reach):"
  grep -E 'TCP_DENIED|DENIED' "${LOGS}/access.log" 2>/dev/null | tail -8 \
    | awk '{print "    "$4" "$7}' | sort -u || echo "    (none)"
  echo ""
  _note "Prove the boundary actually holds:  wasp-egress test"
  ;;

# ── Proof, not configuration review ─────────────────────────────────────────
test)
  _hdr "Egress boundary — enforcement test"
  _pass=0; _fail=0
  # Takes the command as ARGUMENTS, not as a string to eval. The earlier
  # version eval'd, which meant every test containing a nested quote had to be
  # escaped correctly twice -- and one of them was not. A test harness whose
  # own quoting can silently change what it runs is not a test harness.
  _t() { # expected(allow|deny), description, command...
    _e="$1"; _d="$2"; shift 2
    if "$@" >/dev/null 2>&1; then _r=allow; else _r=deny; fi
    if [ "$_r" = "$_e" ]; then _pass=$((_pass+1)); printf '  \033[32m✔\033[0m  %-52s %s\n' "$_d" "$_r"
    else _fail=$((_fail+1)); printf '  \033[31m✗\033[0m  %-52s got %s, expected %s\n' "$_d" "$_r" "$_e"; fi
  }

  # A pass/fail probe that only asks "did curl exit zero" cannot tell a POLICY
  # denial from a connectivity failure, and those need completely different
  # fixes. On a real VM this reported "api.wordpress.org: got deny" and the
  # operator had no way to know whether Squid had refused it, DNS was broken,
  # or the URL simply 404s. Capture the HTTP status instead and classify:
  #
  #   200-399  reached it            -> allow
  #   403      Squid refused it      -> deny BY POLICY (the allowlist)
  #   407      proxy auth demanded   -> misconfiguration
  #   503      Squid could not resolve or connect upstream
  #   000      never reached Squid   -> firewall, or Squid is down
  #
  # Note the removal of `-f`: with it, any 4xx from the DESTINATION also makes
  # curl exit nonzero, so an allowlisted host that returns 404 for the probed
  # path looks identical to a blocked one. That is exactly the trap the old
  # probe fell into by requesting `https://api.wordpress.org/`, whose root path
  # is not a 200.
  _code() { # description, url  -> echoes the classification
    _u="$2"
    # Values go through the ENVIRONMENT, never interpolated into the PHP
    # source, so a URL containing a quote cannot alter the code being run.
    export WASP_PROBE_URL="$_u" WASP_PROBE_PROXY="${_PX_FOR_PROBE:-}"
    # curl's %{http_code} ALREADY prints 000 when it never got a response, so
    # a `|| echo 000` fallback concatenates a second one and yields "000000",
    # which then matched no case arm and printed as a nonsense status.
    # Probe with PHP, not curl. The official WordPress image is minimal -- it
    # has no netstat, no ss, and curl is not guaranteed either. When curl is
    # absent, `podman exec wordpress curl ...` produces no output at all, the
    # status comes back empty, and the test reports "000 / no response" for
    # what is actually a missing binary. That sent a real investigation after
    # a firewall that was working.
    #
    # PHP is guaranteed present, and it is a BETTER probe: it exercises the
    # exact runtime and proxy path WordPress itself uses to reach the network,
    # so a pass here means the thing we care about works, not merely that some
    # tool in the container could reach the internet.
    _hc=$(podman exec -e WASP_PROBE_URL -e WASP_PROBE_PROXY wordpress php -r '
        $u = getenv("WASP_PROBE_URL"); $p = getenv("WASP_PROBE_PROXY");
        $o = ["http" => ["method"=>"GET","timeout"=>12,"ignore_errors"=>true]];
        if ($p !== false && $p !== "") {
          $o["http"]["proxy"] = str_replace("http://","tcp://",$p);
          $o["http"]["request_fulluri"] = true;
        }
        $c = stream_context_create($o);
        $f = @file_get_contents($u, false, $c);
        $code = "000";
        if (isset($http_response_header[0]) &&
            preg_match("~ (\d{3}) ~x", $http_response_header[0], $m)) { $code = $m[1]; }
        echo $code;
      ' 2>/dev/null)
    case "$_hc" in
      ''|*[!0-9]*) _hc=000 ;;
      ???) : ;;
      *) _hc=000 ;;   # anything not exactly three digits is not a status
    esac
    printf '%s' "$_hc"
  }
  _tc() { # expected(allow|deny), description, url
    _e="$1"; _d="$2"; _u="$3"
    _PX_FOR_PROBE="$_PX"
    _hc=$(_code "$_d" "$_u")
    case "$_hc" in
      2*|3*)  _r=allow; _why="HTTP ${_hc}" ;;
      403)    _r=deny;  _why="403 — refused by the proxy policy" ;;
      407)    _r=deny;  _why="407 — proxy demanded auth (misconfigured)" ;;
      503)    _r=deny;  _why="503 — Squid could not resolve or reach it" ;;
      000)    _r=deny;  _why="no response — Squid unreachable or blocked by the firewall" ;;
      *)      _r=deny;  _why="HTTP ${_hc}" ;;
    esac
    if [ "$_r" = "$_e" ]; then
      _pass=$((_pass+1)); printf '  \033[32m✔\033[0m  %-52s %s\n' "$_d" "$_why"
    else
      _fail=$((_fail+1)); printf '  \033[31m✗\033[0m  %-52s %s (expected %s)\n' "$_d" "$_why" "$_e"
      # A 503 or 000 on a line that should ALLOW is a connectivity problem, not
      # an allowlist problem, and saying so saves an afternoon of editing a
      # file that was never wrong.
      case "${_e}:${_hc}" in
        allow:503) printf '       %s\n' "Squid reached, but it could not resolve/connect. Check Squid's DNS:" ;;
        allow:000) printf '       %s\n' "Nothing answered. Is Squid running? podman ps --filter name=squid" ;;
        allow:403) printf '       %s\n' "Squid refused it. Confirm the host is in allowlist-runtime.txt." ;;
      esac
    fi
  }
  _PX="http://${PROXY_HOST}:${PROXY_PORT}"

  echo "  Through the proxy — allowlisted destination should work:"
  # The core version-check endpoint, which returns 200 and is what WordPress
  # itself calls. The bare root of api.wordpress.org does not return 200, so
  # probing it made a working proxy look broken.
  # NOTE the http:// scheme, deliberately. PHP's stream wrapper cannot perform
  # a CONNECT tunnel, so an https:// URL through a proxy returns nothing at all
  # and the probe reports "no response" for a proxy that is answering fine --
  # which happened on a live VM while Squid's own log showed a clean
  # TCP_DENIED/403. A plain http:// request goes through the same ACL chain
  # (source, method, destination allowlist), which is what this test is for.
  # Real HTTPS reachability is proven separately by the plugin install itself.
  _tc allow "api.wordpress.org via proxy" \
     "http://api.wordpress.org/core/version-check/1.7/"

  echo ""
  echo "  Through the proxy — everything else should be refused:"
  _t deny "example.com via proxy (not allowlisted)" \
     podman exec wordpress curl -sf -m 12 -x "$_PX" https://example.com/ -o /dev/null
  _t deny "cloud metadata 169.254.169.254 via proxy" \
     podman exec wordpress curl -sf -m 8 -x "$_PX" http://169.254.169.254/ -o /dev/null
  _t deny "bare IP literal via proxy" \
     podman exec wordpress curl -sf -m 8 -x "$_PX" https://1.1.1.1/ -o /dev/null
  _t deny "CONNECT to a non-443 port (tunnel attempt)" \
     podman exec wordpress curl -sf -m 8 -x "$_PX" https://api.wordpress.org:22/ -o /dev/null

  echo ""
  echo "  BYPASSING the proxy entirely — the test that matters:"
  _note "If any of these succeed, the proxy is a suggestion rather than a"
  _note "boundary. A plugin using fsockopen() or curl without CURLOPT_PROXY"
  _note "ignores WordPress's proxy settings completely."
  _t deny "direct HTTPS to an ALLOWLISTED host, no proxy" \
     podman exec wordpress curl -sf -m 8 --noproxy "*" https://api.wordpress.org/ -o /dev/null
  _t deny "direct HTTPS to any host, no proxy" \
     podman exec wordpress curl -sf -m 8 --noproxy "*" https://example.com/ -o /dev/null
  _t deny "direct HTTP on port 80, no proxy" \
     podman exec wordpress curl -sf -m 8 --noproxy "*" http://example.com/ -o /dev/null
  # A plugin opening its own socket is the case the firewall exists for.
  _t deny "raw socket to 1.1.1.1:443 (simulating fsockopen)" \
     podman exec wordpress php -r "exit(@fsockopen('1.1.1.1',443,\$e,\$s,5)?0:1);"

  echo ""
  echo "  Database container — should reach nothing:"
  _t deny "mariadb direct to the internet" \
     podman exec mariadb timeout 6 bash -c "exec 3<>/dev/tcp/1.1.1.1/443"

  _hdr "Result"
  printf '  passed %s   failed %s\n\n' "$_pass" "$_fail"
  if [ "$_fail" -gt 0 ]; then
    _bad "The boundary is NOT holding."
    _note "A failure on a 'no proxy' line means the firewall is not enforcing"
    _note "the restriction and only WordPress's own settings are. Any plugin"
    _note "that opens its own socket walks straight past it."
    _note "  doas nft list ruleset | grep -A6 'wp-front egress'"
    exit 1
  fi
  _ok "WordPress can reach approved destinations only, and cannot go round the proxy."
  _note "This proves WHERE traffic may go. It does not inspect what it carries:"
  _note "an approved destination that is itself compromised is still reachable."
  ;;

# ── Discovery ───────────────────────────────────────────────────────────────
discovery)
  _hdr "Discovery — what was denied"
  _note "Denied destinations are NEVER promoted automatically. Classify each,"
  _note "then add only what is genuinely required. An allowlist grown by"
  _note "accepting whatever asked is not an allowlist."
  echo ""
  _d=$(grep -E 'TCP_DENIED|DENIED' "${LOGS}/access.log" 2>/dev/null \
       | awk '{print $7}' | sed 's|^https\?://||; s|[:/].*||' | sort | uniq -c | sort -rn | head -30)
  if [ -z "$_d" ]; then
    echo "  Nothing denied since the log was last rotated."
    echo "  Either the allowlist already covers this site, or nothing has run"
    echo "  yet — exercise updates, cron and admin workflows first."
    exit 0
  fi
  printf '  %-8s %s\n' "HITS" "DESTINATION"
  printf '%s\n' "$_d" | sed 's/^/  /'
  echo ""
  echo "  Classify each as:"
  echo "    REQUIRED     the site genuinely does not work without it"
  echo "    MAINTENANCE  needed occasionally, not at runtime  -> maintenance window"
  echo "    UNNECESSARY  a plugin phoning home, a font CDN, telemetry"
  echo "    SUSPICIOUS   you cannot account for it            -> investigate"
  echo ""
  echo "  Then:  wasp-egress allow <domain>"
  echo ""
  _warn "A destination you cannot explain is a finding, not an allowlist entry."
  ;;

# ── Temporary egress: the only kind a file host or a one-off ever gets ───────
temporary|temp)
  _expire_temp >/dev/null
  _hdr "Temporary egress (closes by itself, ${TEMP_MAX} minutes at most)"
  if [ -s "$LEDGER" ]; then
    _now=$(date -u +%s)
    awk -v n="$_now" '{ m=int(($1-n+59)/60); r=""; for(i=5;i<=NF;i++) r=r (i>5?" ":"") $i;
                        printf "  %-34s %3d min left  [%s, by %s] %s\n", $3, m, $2, $4, r }' "$LEDGER"
  else
    echo "  (none — only the permanent allowlist is in force)"
  fi ;;

expire)
  # Every minute from cron. Quiet, and touches Squid only when something
  # actually expired.
  _expire_temp >/dev/null 2>&1
  exit 0 ;;

close)
  # Removes TEMPORARY entries only. A permanent entry is removed with deny.
  shift
  case "${1:-}" in
    --all)  _temp_close '*' '*'; _ok "All temporary egress closed." ;;
    --tag)  _temp_close "${2:-}" '*' ;;
    ''|-*)  echo "Usage: wasp-egress close <domain> | --all" >&2; exit 1 ;;
    *)      _d=$(printf '%s' "$1" | tr 'A-Z' 'a-z')
            _temp_close '*' "$_d"; _ok "Closed: ${_d}" ;;
  esac ;;

# ── File-sharing services, opened together and never for long ───────────────
# A file host is an exfiltration route with an upload button, so it is never
# on the permanent list. Each service is the set of hosts its download links
# actually use, because a share link redirects: www.dropbox.com hands the file
# over from *.dropboxusercontent.com, Drive from drive.usercontent.google.com.
# Opening only the host in the link fails on the redirect.
fileshare)
  _sub="${2:-list}"
  case "$_sub" in
    list)
      _hdr "File-sharing services (open with: wasp-egress fileshare open <name>)"
      for _s in $FS_SERVICES; do printf '  %-11s %s\n' "$_s" "$(_fs_domains "$_s")"; done
      echo ""
      _note "Each opens for ${TEMP_MAX} minutes at most and closes by itself."
      _note "Not offered: MEGA. Its files are decrypted in the browser, so no"
      _note "command-line download can fetch one, whatever the firewall allows." ;;
    open)
      shift 2
      _svcs=""; _mins=$TEMP_MAX; _rsn=""; _tg=fileshare
      while [ $# -gt 0 ]; do
        case "$1" in
          --for)    _mins="${2:-}"; shift 2 ;;
          --reason) _rsn="${2:-}"; shift 2 ;;
          --tag)    _tg="${2:-fileshare}"; shift 2 ;;
          all)      _svcs="$FS_SERVICES"; shift ;;
          *)        _svcs="${_svcs} $1"; shift ;;
        esac
      done
      [ -n "$_svcs" ] || { echo "Usage: wasp-egress fileshare open <$(echo $FS_SERVICES | tr ' ' '|')|all> [--for MIN]" >&2; exit 1; }
      _mins=$(_minutes "$_mins") || exit 1
      _doms=""
      for _s in $_svcs; do
        _d=$(_fs_domains "$_s")
        [ -n "$_d" ] || { _bad "Unknown service '${_s}'. See: wasp-egress fileshare list"; exit 1; }
        _doms="${_doms} ${_d}"
      done
      [ -n "$_rsn" ] || _rsn="file download (${_svcs# })"
      # shellcheck disable=SC2086
      _temp_add "$_tg" "$_mins" "$_rsn" $_doms || exit 1
      _ok "Open for ${_mins} minute(s):${_svcs}"
      _note "Closes by itself at $(_hhmm "$(( $(date -u +%s) + _mins * 60 ))") UTC. Close sooner: wasp-egress fileshare close"
      if [ "$_tg" = fileshare ]; then
        _notify_open "File-sharing egress opened (${_svcs# }) for ${_mins} minutes"
      fi ;;
    close)
      shift 2
      if [ $# -eq 0 ]; then _temp_close fileshare '*'; _ok "File-sharing egress closed."
      else
        for _s in "$@"; do
          for _d in $(_fs_domains "$_s"); do _temp_close fileshare "$_d"; done
        done
        _ok "Closed: $*"
      fi ;;
    match)
      # Which service a download host belongs to. Used by wp-import.sh fetch.
      _h=$(printf '%s' "${3:-}" | tr 'A-Z' 'a-z')
      [ -n "$_h" ] || exit 1
      _found=""
      for _s in $FS_SERVICES; do
        for _d in $(_fs_domains "$_s"); do
          if _covers "$_d" "$_h"; then _found="$_s"; break; fi
        done
        [ -n "$_found" ] && break
      done
      [ -n "$_found" ] && { echo "$_found"; exit 0; }
      exit 1 ;;
    *) echo "Usage: wasp-egress fileshare list | open <service...> [--for MIN] | close [service...]" >&2; exit 1 ;;
  esac ;;

# ── Maintenance (a temporary allow with a reason, kept for its name) ────────
maintenance)
  _sub="${2:-status}"
  case "$_sub" in
    status)
      _expire_temp >/dev/null
      if grep -q ' maintenance ' "$LEDGER" 2>/dev/null; then
        _hdr "Maintenance window OPEN"
        _now=$(date -u +%s)
        awk -v n="$_now" '$2=="maintenance" { r=""; for(i=5;i<=NF;i++) r=r (i>5?" ":"") $i;
            printf "  + %-32s closes in %d minute(s) — %s\n", $3, int(($1-n+59)/60), r }' "$LEDGER"
      else
        echo ""; echo "  STRICT — no maintenance window open."
      fi ;;
    enable)
      shift 2
      _mins=$TEMP_MAX; _rsn=""; _hosts=""
      while [ $# -gt 0 ]; do
        case "$1" in
          --duration) _mins="${2:-}"; shift 2 ;;
          --reason)   _rsn="${2:-}"; shift 2 ;;
          --host)     _hosts="${_hosts} $(printf '%s' "${2:-}" | tr 'A-Z' 'a-z')"; shift 2 ;;
          *) shift ;;
        esac
      done
      _mins=$(_minutes "$_mins") || exit 1
      [ ${#_rsn} -ge 10 ] || {
        _bad "A reason of at least 10 characters is required."
        _note "It is recorded and emailed. \"testing\" tells a reviewer nothing."
        exit 1; }
      [ -n "$_hosts" ] || { _bad "Give at least one --host"; exit 1; }
      for _h in $_hosts; do _valid_domain "$_h" || exit 1; done
      # shellcheck disable=SC2086
      _temp_add maintenance "$_mins" "$_rsn" $_hosts || exit 1
      _hdr "MAINTENANCE window open"
      printf '  Hosts   :%s\n  Duration: %s minutes\n  Closes  : %s UTC\n' \
        "$_hosts" "$_mins" "$(_hhmm "$(( $(date -u +%s) + _mins * 60 ))")"
      _note "Closes automatically. Nothing needs to remember to close it."
      _notify_open "Egress maintenance opened for${_hosts} (${_mins}m): ${_rsn}" ;;
    disable)
      _temp_close maintenance '*'
      _ok "Closed. Back to STRICT." ;;
  esac ;;

# ── Allowlist ───────────────────────────────────────────────────────────────
# `allow` is temporary unless told otherwise. The permanent list is what a
# compromised WordPress may reach at any hour, so it should hold the theme or
# builder vendors a site updates from and little else; a one-off download,
# a file host or a test does not belong there and now cannot end up there by
# default.
allow)
  shift
  _dom=""; _mins=$TEMP_MAX; _perm=0; _rsn=""; _tg=allow
  while [ $# -gt 0 ]; do
    case "$1" in
      --for)       _mins="${2:-}"; shift 2 ;;
      --permanent) _perm=1; shift ;;
      --reason)    _rsn="${2:-}"; shift 2 ;;
      --tag)       _tg="${2:-allow}"; shift 2 ;;
      -*) echo "Usage: wasp-egress allow <domain> [--for MIN | --permanent]" >&2; exit 1 ;;
      *)  _dom=$(printf '%s' "$1" | tr 'A-Z' 'a-z'); shift ;;
    esac
  done
  [ -n "$_dom" ] || { echo "Usage: wasp-egress allow <domain> [--for MIN | --permanent]" >&2; exit 1; }
  _valid_domain "$_dom" || exit 1
  if [ "$_perm" = 0 ]; then
    _mins=$(_minutes "$_mins") || exit 1
    _temp_add "$_tg" "$_mins" "${_rsn:-allow ${_dom}}" "$_dom" || exit 1
    _ok "Allowed for ${_mins} minute(s): ${_dom}"
    _note "Closes by itself at $(_hhmm "$(( $(date -u +%s) + _mins * 60 ))") UTC."
    _note "A theme or builder vendor the site updates from: add --permanent."
    if [ "$_tg" = allow ]; then _notify_open "Egress opened to ${_dom} for ${_mins} minutes"; fi
    exit 0
  fi
  cp "$RUNTIME" "${RUNTIME}.bak-$(date -u +%s)"
  grep -qxF "$_dom" "$RUNTIME" && { echo "Already allowed: ${_dom}"; exit 0; }
  printf '%s\n' "$_dom" >> "$RUNTIME"
  _ok "Allowed permanently: ${_dom}"
  _warn "Every permanent entry is a route out for a compromised site, at any hour."
  _note "Keep this list to the theme and builder vendors the site updates from."
  _reload_or_restore ;;

deny)
  _dom=$(printf '%s' "${2:-}" | tr 'A-Z' 'a-z')
  [ -n "$_dom" ] || { echo "Usage: wasp-egress deny <domain>" >&2; exit 1; }
  _valid_domain "$_dom" || exit 1
  # Temporary entries for it go too: "deny" means not reachable, now.
  _temp_close '*' "$_dom"
  cp "$RUNTIME" "${RUNTIME}.bak-$(date -u +%s)"
  # BUG FIX (found on a live VM, 2026-10-20): this was
  #   grep -v … > tmp && mv -f tmp "$RUNTIME"
  # and `mv` REPLACES THE INODE. allowlist-runtime.txt is bind-mounted into
  # the Squid container as a SINGLE FILE, so the container goes on reading
  # the old inode and never sees the removal -- while this printed
  # "Removed". cat > truncates and rewrites in place, preserving the inode.
  grep -vxF "$_dom" "$RUNTIME" > "${RUNTIME}.tmp" \
    && cat "${RUNTIME}.tmp" > "$RUNTIME" \
    && rm -f "${RUNTIME}.tmp"
  # Verify from INSIDE the container, which is the only view that decides
  # policy. Checking the host file would re-create the same blind spot.
  if podman exec squid grep -qxF "$_dom" /etc/squid/allowlist-runtime.txt 2>/dev/null; then
    _bad "${_dom} is STILL present in Squid's view of the allowlist."
    _note "  The host file was written but the container did not see it."
    _note "  Restart Squid to re-establish the mount:  podman restart squid"
    exit 1
  fi
  _ok "Removed: ${_dom}"
  _reload_or_restore ;;

# ── Import sources ───────────────────────────────────────────────────────────
# A host that is not one of the file-sharing services above but that backups
# come from. Listing one grants nothing: `wp-import.sh fetch url` opens it for
# its own download, through a temporary entry, and closes it after.
#
# Exact hostnames only. A leading dot would admit every customer of a shared
# platform, including one an attacker signed up for.
import-source)
  _sub="${2:-list}"; _h=$(printf '%s' "${3:-}" | tr 'A-Z' 'a-z')
  case "$_sub" in
    list)
      _hdr "Import sources"
      if [ -s "$IMPORT_SOURCES" ]; then sed 's/^/  /' "$IMPORT_SOURCES"
      else echo "  (none)"; fi
      echo ""
      _note "Reachable only while wp-import.sh fetch url is downloading from them."
      _note "Dropbox, Drive, OneDrive, WeTransfer, Box and SyncedTool need no entry:"
      _note "fetch opens the matching file-sharing service by itself." ;;
    add|remove|has)
      case "$_h" in
        ''|.*|*[!a-z0-9.-]*|*..*|-*)
          [ "$_sub" = has ] && exit 1
          _bad "Give an exact hostname, with no scheme, path or leading dot."
          exit 1 ;;
      esac
      case "$_h" in *.*) : ;; *) [ "$_sub" = has ] && exit 1; _bad "Give a full hostname."; exit 1 ;; esac
      case "$_sub" in
        has) grep -qxF "$_h" "$IMPORT_SOURCES" 2>/dev/null ;;
        add)
          mkdir -p "$(dirname "$IMPORT_SOURCES")"
          grep -qxF "$_h" "$IMPORT_SOURCES" 2>/dev/null || printf '%s\n' "$_h" >> "$IMPORT_SOURCES"
          logger -t wasp-egress "import source added: ${_h}" 2>/dev/null || true
          _ok "${_h} may be opened for an import download." ;;
        remove)
          if [ -f "$IMPORT_SOURCES" ]; then
            grep -vxF "$_h" "$IMPORT_SOURCES" > "${IMPORT_SOURCES}.tmp" || true
            cat "${IMPORT_SOURCES}.tmp" > "$IMPORT_SOURCES"; rm -f "${IMPORT_SOURCES}.tmp"
          fi
          _ok "${_h} removed." ;;
      esac ;;
    *) echo "Usage: wasp-egress import-source add|remove|list [host]" >&2; exit 1 ;;
  esac
  ;;

# ── WASP Hive: the one connection this VM makes to its fleet console ────────
# HOW THE HIVE IS REACHED. wasp-hive-report.sh runs on the HOST (cron, as
# root), not in the WordPress container, so Squid is not in the path and has
# nothing to allow: the host's own nftables output chain decides. It sends one
# HTTPS POST every 15 minutes to the Hive's address, and the Hive never
# connects back.
#   - RESTRICT_EGRESS=0: nothing is blocked; this only records and tests.
#   - RESTRICT_EGRESS=1: tcp/443 to anywhere is already allowed, so a Hive on
#     443 (install-hive.sh redirects 443 to the service) needs nothing. A Hive
#     on any other port gets ONE rule, to that address and port only.
#   - A NAME is resolved here, once, and the address is pinned:
#     wasp-hive-report.sh connects to that address (curl --resolve), so the
#     firewall rule and the connection always agree, and a changed DNS answer
#     cannot redirect the report. `hive refresh` re-resolves deliberately.
#   - Who is at that address is proven by the TLS key pin taken at
#     enrollment, not by the address. `hive test` shows the key the address
#     presents, so it can be compared with `hive-admin pin` before enrolling.
hive)
  _sub="${2:-status}"
  _hv() { sed -n "s/^$1=//p" "$HIVE_EGRESS" 2>/dev/null | head -1; }
  _resolve4() {
    case "$1" in *[!0-9.]*) : ;; *) printf '%s' "$1"; return 0 ;; esac
    _r=$(getent hosts "$1" 2>/dev/null | awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $1; exit}')
    [ -n "$_r" ] || _r=$(nslookup "$1" 2>/dev/null | awk '/^Name:/ {n=1} n && /^Address/ {sub(/^Address( [0-9]+)?:[ \t]*/, ""); if ($0 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {print; exit}}')
    [ -n "$_r" ] && printf '%s' "$_r"
  }
  _hive_test() {
    _h=$(_hv host); _i=$(_hv ip); _p=$(_hv port)
    [ -n "$_h" ] || { _bad "No WASP Hive address set: wasp-egress hive set <address>"; return 1; }
    _out=$(curl -sk --noproxy '*' --max-time 10 --resolve "${_h}:${_p}:${_i}" "https://${_h}:${_p}/api/v1/ping" 2>&1)
    if printf '%s' "$_out" | grep -q '"wasp-hive"'; then
      _ok "WASP Hive answers at ${_h}:${_p} (${_i})"
    else
      _bad "No WASP Hive at ${_h}:${_p} (${_i}): $(printf '%s' "$_out" | head -1)"
      _note "From this VM the path is: host nftables (output) → the VLAN's firewall → the Hive's nftables."
      _note "Check the inter-VLAN rule allows this VM to ${_i} tcp/${_p}."
      return 1
    fi
    if command -v openssl >/dev/null 2>&1; then
      _pin=$(openssl s_client -connect "${_i}:${_p}" -servername "$_h" </dev/null 2>/dev/null \
             | openssl x509 -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform der 2>/dev/null \
             | openssl dgst -sha256 -binary | base64)
      _enr=$(sed -n 's/^pin=//p' "$HIVE_CONF_FILE" 2>/dev/null)
      _note "Key pin presented: sha256//${_pin}"
      if [ -n "$_enr" ]; then
        [ "$_pin" = "$_enr" ] && _ok "It matches the pin this VM enrolled with." \
          || _bad "It does NOT match the pin this VM enrolled with (${_enr}). Reports are withheld until you know why."
      else
        _note "Compare it with 'hive-admin pin' on the Hive before enrolling."
      fi
    fi
  }
  case "$_sub" in
    set)
      _a="${3:-}"; _a="${_a#https://}"; _a="${_a%%/*}"
      [ -n "$_a" ] || { echo "Usage: wasp-egress hive set <https://host[:port] | host[:port] | ip[:port]>" >&2; exit 1; }
      case "$_a" in *:*) _host="${_a%:*}"; _port="${_a##*:}" ;; *) _host="$_a"; _port=443 ;; esac
      case "$_port" in ''|*[!0-9]*) _bad "Port must be a number."; exit 1 ;; esac
      [ "$_port" -ge 1 ] && [ "$_port" -le 65535 ] || { _bad "Port must be 1-65535."; exit 1; }
      case "$_host" in ''|*[!A-Za-z0-9.-]*|.*|*..*|-*) _bad "Give a hostname or IPv4 address."; exit 1 ;; esac
      _ip=$(_resolve4 "$_host")
      [ -n "$_ip" ] || { _bad "${_host} does not resolve from this VM."; exit 1; }
      # (WASP_TEST_LOOPBACK_HIVE lets test/test-hive-report.sh use a Hive on localhost.)
      case "${WASP_TEST_LOOPBACK_HIVE:-0}:$_ip" in 1:127.*) : ;; *:127.*|*:0.*|*:169.254.*|*:10.89.*) _bad "${_ip} cannot be a WASP Hive (loopback, link-local or a container network)."; exit 1 ;; esac
      if [ "${RESTRICT_EGRESS:-0}" = 1 ] && [ "$_port" != 443 ] && [ "$_port" != 80 ]; then
        "$FW_RULE" add hive output ip daddr "$_ip" tcp dport "$_port" accept || exit 1
      else
        "$FW_RULE" del hive >/dev/null 2>&1 || true
        if [ "${RESTRICT_EGRESS:-0}" = 1 ]; then
          _note "tcp/${_port} is already allowed outbound under RESTRICT_EGRESS; no rule needed."
        fi
      fi
      mkdir -p "$(dirname "$HIVE_EGRESS")"
      { printf 'host=%s
ip=%s
port=%s
set_at=%s
' "$_host" "$_ip" "$_port" "$(date +%s)"; } > "$HIVE_EGRESS"
      chmod 644 "$HIVE_EGRESS"
      logger -t wasp-egress "WASP Hive path set: ${_host} (${_ip}) tcp/${_port}" 2>/dev/null || true
      _ok "WASP Hive path: ${_host} → ${_ip} tcp/${_port}"
      _hive_test || true ;;
    test) _hive_test ;;
    status)
      echo ""
      echo "WASP Hive connection"
      echo "━━━━━━━━━━━━━━━━━━━━"
      if [ -r "$HIVE_EGRESS" ]; then
        printf '  Address : %s → %s tcp/%s
' "$(_hv host)" "$(_hv ip)" "$(_hv port)"
        if [ "${RESTRICT_EGRESS:-0}" = 1 ]; then
          if nft list chain inet filter output 2>/dev/null | grep -q 'comment "wasp:hive"'; then
            _ok "Firewall: rule wasp:hive allows exactly that address and port"
          elif [ "$(_hv port)" = 443 ] || [ "$(_hv port)" = 80 ]; then
            _ok "Firewall: tcp/$(_hv port) is open outbound already"
          else
            _bad "Firewall: no rule for tcp/$(_hv port) — run: wasp-egress hive set $(_hv host):$(_hv port)"
          fi
        else
          _note "Firewall: outbound is not restricted on this VM"
        fi
        _u=$(sed -n 's/^url=//p' "$HIVE_CONF_FILE" 2>/dev/null)
        if [ -n "$_u" ]; then
          _uh="${_u#https://}"; _uh="${_uh%%/*}"; _uh="${_uh%:*}"
          [ "$_uh" = "$(_hv host)" ] && _ok "Enrolled with ${_u}" \
            || _bad "Enrolled with ${_u}, but the path is set for $(_hv host) — one of them is wrong"
        else
          _note "Not enrolled yet: on the Hive, hive-admin enroll <node>; then menu → Security → 24"
        fi
      else
        _note "No WASP Hive address set. wasp-egress hive set <address>  (menu: Security → 25)"
      fi
      echo "" ;;
    refresh)
      [ -r "$HIVE_EGRESS" ] || { _bad "No WASP Hive address set."; exit 1; }
      _h=$(_hv host); _old=$(_hv ip)
      _new=$(_resolve4 "$_h")
      [ -n "$_new" ] || { _bad "${_h} does not resolve; keeping ${_old}."; exit 1; }
      if [ "$_new" = "$_old" ]; then _ok "${_h} still resolves to ${_old}."
      else exec "$0" hive set "${_h}:$(_hv port)"; fi ;;
    remove)
      "$FW_RULE" del hive >/dev/null 2>&1 || true
      rm -f "$HIVE_EGRESS"
      _ok "WASP Hive path removed. (Enrollment is separate: wasp-hive-report.sh leave)" ;;
    *) echo "Usage: wasp-egress hive set <address> | test | status | refresh | remove" >&2; exit 1 ;;
  esac
  ;;

*) sed -n '5,22p' "$0" ;;
esac
