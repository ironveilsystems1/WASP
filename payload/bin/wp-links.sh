#!/bin/sh
# =============================================================================
# wp-links.sh — spam links in the content, and broken links on the site
# =============================================================================
#   wp-links.sh spam [--json] [--all-domains]   injected links, spam titles and
#                                               pages, what was announced to
#                                               search engines; names each page
#                                               and Elementor widget
#   wp-links.sh spam --notify                   the same, emailed when it finds
#                                               anything (weekly cron)
#   wp-links.sh broken [--max-pages N] [--delay S] [--url URL]
#                                               crawl the site the way a visitor
#                                               does; broken pages, images,
#                                               files, and certificate problems
##   wp-links.sh clean                           what could be cleaned, with IDs
#   wp-links.sh clean [--links DOMAIN,..] [--widgets ID,..] [--title POST=TEXT]
#                     [--trash POST,..] [--revisions] [--indexnow] [--apply [--yes]]
#                                               --links: every link to those spam domains,
#                                               whichever builder, theme setting, widget
#                                               or menu holds it
#                                               remove named spam: preview first,
#                                               then --apply (evidence saved and a
#                                               database backup taken first)
#
# WHY
#
# A real import carried casino links into three live pages and a casino advert
# into a page title. Every file and signature scan passed: it is content, not
# code. And a link-checking service could not reach the site at all, because
# the site rightly refuses requests that carry no browser identity -- so the
# check ran from a workstation, by hand. Both are now one command on the VM.
#
# SPAM reads the database directly from inside the wordpress container
# (wasp-content-scan.php, stdin; read-only; no WordPress or plugin code runs).
#
# BROKEN crawls through the reverse proxy, as visitors do: the VM resolves its
# own domain to the proxy (split-horizon DNS) and connects on 443, which its
# firewall already allows. Only this site's pages are fetched. Links to OTHER
# sites are listed, not fetched: this VM's outbound traffic is limited by
# design, so it cannot tell a dead external link from a blocked one -- the
# command for checking them from a workstation is printed instead.
# One page a second by default, and never the login, admin or API paths: the
# proxy's own crawler detection should not ban this VM for checking its site.
# =============================================================================
set -u
if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then exec doas "$0" "$@"; fi
  echo "Run as root (or via doas)" >&2; exit 1
fi
[ -r /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh

PAYLOAD="${WASP_PAYLOAD:-/etc/wp-install/payload}"
SCANNER="${WASP_CONTENT_SCANNER:-${PAYLOAD}/php-tools/wasp-content-scan.php}"
NOTIFY="${WASP_NOTIFY:-/usr/local/bin/wp-notify.sh}"
ALERTS_INI="${WASP_SECRETS_DIR:-/home/wpuser/wp/secrets}/alerts.ini"
UA="Mozilla/5.0 (compatible; WASP-LinkCheck/1.0)"
CLEANER_DIR="${WASP_PHP_TOOLS:-${PAYLOAD}/php-tools}"
WP_PLUGINS="${WASP_WP_PLUGINS:-/usr/local/bin/wp-plugins.sh}"
DB_BACKUP="${WASP_DB_BACKUP:-/usr/local/bin/wp-db-backup.sh}"
EVIDENCE="${WASP_EVIDENCE_DIR:-/var/lib/wasp/evidence}"

_ok()   { printf '  \033[32m✔\033[0m  %s\n' "$1"; }
_bad()  { printf '  \033[31m✗\033[0m  %s\n' "$1"; }
_warn() { printf '  \033[33m⚠\033[0m  %s\n' "$1"; }
_note() { printf '     %s\n' "$1"; }

_alert_on() { # alerts.ini key; on unless explicitly off
  [ -r "$ALERTS_INI" ] || return 0
  case "$(sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$ALERTS_INI" | head -1 | tr 'A-Z' 'a-z')" in
    off|0|no|false) return 1 ;;
  esac
  return 0
}

case "${1:-}" in

# ── spam ─────────────────────────────────────────────────────────────────────
spam)
  shift
  _notify=0; _pass=""
  for _a in "$@"; do
    case "$_a" in
      --notify) _notify=1 ;;
      --json|--all-domains) _pass="${_pass} ${_a}" ;;
      *) echo "Unknown option: ${_a}" >&2; exit 1 ;;
    esac
  done
  [ -r "$SCANNER" ] || { _bad "Content scanner not found: ${SCANNER}"; exit 2; }
  _out=$(mktemp) || exit 2
  _rc=0
  # shellcheck disable=SC2086
  podman exec -i --user www-data wordpress php -d display_errors=stderr -d memory_limit=512M -- $_pass \
    < "$SCANNER" > "$_out" 2>&1 || _rc=$?
  if [ "$_rc" -ge 2 ]; then
    _bad "The content scan did not run (exit ${_rc}):"
    sed 's/^/       /' "$_out" >&2
    _note "Is WordPress running?  doas podman ps"
    rm -f "$_out"; exit 2
  fi
  if [ "$_notify" = 1 ]; then
    if [ "$_rc" = 1 ] && _alert_on content_spam && [ -x "$NOTIFY" ]; then
      _b=$(mktemp)
      { echo "The weekly content check found spam in this site's pages."
        echo "This is content placed through WordPress, not a file: no malware scan sees it."
        sed 's/\x1b\[[0-9;]*m//g' "$_out"
        echo "Run it again on the VM:  doas wp-links.sh spam"; } > "$_b"
      # Default cooldown: the same findings are not re-sent within a day, and
      # are sent again next week if still there.
      NOTIFY_EMAIL="$(sed -n 's/^[[:space:]]*to[[:space:]]*=[[:space:]]*//p' "$ALERTS_INI" 2>/dev/null | head -1)" \
        "$NOTIFY" wp-content-spam "Spam links found in the site's content" "$_b" >/dev/null 2>&1
      rm -f "$_b"
    fi
    logger -t wp-links "content scan: exit ${_rc}" 2>/dev/null
  else
    cat "$_out"
  fi
  rm -f "$_out"
  exit "$_rc"
  ;;

# ── broken ───────────────────────────────────────────────────────────────────
broken)
  shift
  _max=300; _delay=1; _url=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --max-pages) _max="${2:-}"; shift 2 ;;
      --delay)     _delay="${2:-}"; shift 2 ;;
      --url)       _url="${2:-}"; shift 2 ;;
      *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
  done
  case "$_max" in ''|*[!0-9]*) _bad "--max-pages takes a number"; exit 1 ;; esac
  case "$_delay" in ''|*[!0-9.]*) _bad "--delay takes seconds"; exit 1 ;; esac
  if [ -z "$_url" ]; then
    [ -n "${WP_DOMAIN:-}" ] || { _bad "No site domain (WP_DOMAIN) in vars.sh; give --url https://example.com"; exit 1; }
    _url="${WP_SCHEME:-https}://${WP_DOMAIN}/"
  fi
  command -v curl >/dev/null 2>&1 || { _bad "curl is required"; exit 2; }
  _scheme=${_url%%://*}
  _rest=${_url#*://}
  _host=${_rest%%/*}
  _bare=${_host#www.}
  _origin="${_scheme}://${_host}"
  _slug="${WP_ADMIN_SLUG:-}"
  W=$(mktemp -d) || exit 2
  trap 'rm -rf "$W"' EXIT
  : > "$W/seen"; : > "$W/queue"; : > "$W/status"; : > "$W/edges"; : > "$W/ext"; : > "$W/assets"

  # Normalise a link found on page $2 to an absolute URL, or nothing.
  _abs() {
    _l=$(printf '%s' "$1" | sed 's/&amp;/\&/g; s/#.*$//; s/^[[:space:]]*//; s/[[:space:]]*$//')
    case "$_l" in
      ''|mailto:*|tel:*|javascript:*|data:*|sms:*|whatsapp:*) return ;;
      //*)      printf '%s:%s' "$_scheme" "$_l" ;;
      http://*|https://*) printf '%s' "$_l" ;;
      /*)       printf '%s%s' "$_origin" "$_l" ;;
      *)        _d=$(printf '%s' "$2" | sed 's#[^/]*$##'); printf '%s%s' "$_d" "$_l" ;;
    esac
  }
  _lhost() { printf '%s' "$1" | sed -E 's#^[a-zA-Z]+://##; s#[/?].*$##; s#:[0-9]+$##' | tr 'A-Z' 'a-z'; }
  _internal() { _h=$(_lhost "$1"); _hb=${_h#www.}; [ "$_hb" = "$_bare" ] || [ "$_h" = "${_host%%:*}" ]; }
  _skip() { # paths never crawled: admin, login, API, feeds, comment replies
    case "$1" in
      */wp-admin*|*/wp-login.php*|*/xmlrpc.php*|*/wp-json*|*/feed/*|*/feed|*replytocom=*|*/wp-cron.php*|*/?s=*|*\?s=*) return 0 ;;
    esac
    [ -n "$_slug" ] && case "$1" in */"$_slug"|*/"$_slug"/*|*/"$_slug"\?*) return 0 ;; esac
    return 1
  }
  _is_asset() {
    case "$(printf '%s' "${1%%\?*}" | tr 'A-Z' 'a-z')" in
      *.jpg|*.jpeg|*.png|*.gif|*.webp|*.svg|*.ico|*.avif|*.css|*.js|*.pdf|*.mp4|*.webm|*.mp3|*.woff|*.woff2|*.ttf|*.eot|*.zip|*.docx|*.xlsx) return 0 ;;
    esac
    return 1
  }
  # curl exit codes a person can act on.
  _why() {
    case "$1" in
      6)  echo "name does not resolve" ;;
      7)  echo "connection refused" ;;
      28) echo "timed out" ;;
      35) echo "TLS handshake failed" ;;
      51|60) echo "certificate does not match this name (add it to the proxy host and its certificate)" ;;
      47) echo "too many redirects" ;;
      *)  echo "request failed (curl ${1})" ;;
    esac
  }

  echo ""
  echo "Broken links — ${_origin}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  _note "Crawling this site's own pages, at most ${_max}, one every ${_delay}s. Other sites' links are listed, not fetched."

  printf '%s\n' "$_url" > "$W/queue"; printf '%s\n' "$_url" > "$W/seen"
  _pages=0
  while [ "$_pages" -lt "$_max" ] && [ -s "$W/queue" ]; do
    _u=$(head -1 "$W/queue"); sed -i '1d' "$W/queue" 2>/dev/null || { tail -n +2 "$W/queue" > "$W/q2"; mv "$W/q2" "$W/queue"; }
    _pages=$((_pages + 1))
    _rc=0
    _meta=$(curl -sS --noproxy '*' -A "$UA" --max-time 20 -L --max-redirs 5 \
              -o "$W/body" -w '%{http_code}\t%{content_type}\t%{url_effective}' "$_u" 2>"$W/err") || _rc=$?
    _code=$(printf '%s' "$_meta" | cut -f1); _ct=$(printf '%s' "$_meta" | cut -f2)
    if [ "$_rc" -ne 0 ]; then
      printf '%s\t%s\n' "$_u" "$(_why "$_rc")" >> "$W/status"
    else
      printf '%s\t%s\n' "$_u" "$_code" >> "$W/status"
    fi
    if [ "$_rc" -eq 0 ] && [ "$_code" = 200 ] && case "$_ct" in *text/html*) true ;; *) false ;; esac; then
      _final=$(printf '%s' "$_meta" | cut -f3)
      { grep -oiE "(href|src)=\"[^\"]+\"" "$W/body"; grep -oiE "(href|src)='[^']+'" "$W/body"; } 2>/dev/null \
        | sed -E "s/^[a-zA-Z]+=[\"']//; s/[\"']$//" | sort -u > "$W/links"
      while IFS= read -r _raw; do
        _a=$(_abs "$_raw" "$_final"); [ -n "$_a" ] || continue
        case "$_a" in http://*|https://*) ;; *) continue ;; esac
        if _internal "$_a"; then
          _skip "$_a" && continue
          printf '%s\t%s\n' "$_a" "$_u" >> "$W/edges"
          grep -qxF "$_a" "$W/seen" && continue
          printf '%s\n' "$_a" >> "$W/seen"
          if _is_asset "$_a"; then printf '%s\n' "$_a" >> "$W/assets"
          else printf '%s\n' "$_a" >> "$W/queue"; fi
        else
          printf '%s\t%s\n' "$(_lhost "$_a")" "$_u" >> "$W/ext"
        fi
      done < "$W/links"
    fi
    [ "$_delay" = 0 ] || sleep "$_delay"
  done
  _left=$(grep -c . "$W/queue") || _left=0

  # Images, stylesheets, files: a HEAD each (GET when HEAD is refused).
  while IFS= read -r _a; do
    _rc=0
    _code=$(curl -sS --noproxy '*' -A "$UA" --max-time 20 -I -L --max-redirs 5 -o /dev/null -w '%{http_code}' "$_a" 2>/dev/null) || _rc=$?
    case "$_code" in 403|405|501)
      _rc=0; _code=$(curl -sS --noproxy '*' -A "$UA" --max-time 20 -L --max-redirs 5 -r 0-0 -o /dev/null -w '%{http_code}' "$_a" 2>/dev/null) || _rc=$? ;;
    esac
    if [ "$_rc" -ne 0 ]; then printf '%s\t%s\n' "$_a" "$(_why "$_rc")" >> "$W/status"
    else printf '%s\t%s\n' "$_a" "$_code" >> "$W/status"; fi
  done < "$W/assets"

  _nchk=$(grep -c . "$W/status") || _nchk=0
  awk -F '\t' '$2 !~ /^(2|3)[0-9][0-9]$/' "$W/status" > "$W/bad"
  _nbad=$(grep -c . "$W/bad") || _nbad=0
  echo ""
  if [ "$_nbad" = 0 ]; then
    _ok "No broken links: ${_pages} page(s) and $(grep -c . "$W/assets" || true) file(s) checked."
  else
    _bad "${_nbad} broken link(s) on this site (${_nchk} URLs checked)"
    while IFS="$(printf '\t')" read -r _a _c; do
      echo ""
      printf '     %s\n' "$_a"
      case "$_c" in
        404) printf '       404 — the page or file does not exist\n' ;;
        410) printf '       410 — removed on purpose\n' ;;
        403) printf '       403 — refused\n' ;;
        5*)  printf '       %s — the server failed on it\n' "$_c" ;;
        [0-9][0-9][0-9]) printf '       %s\n' "$_c" ;;
        *)   printf '       %s\n' "$_c" ;;
      esac
      _src=$(awk -F '\t' -v a="$_a" '$1 == a { print $2 }' "$W/edges" | sort -u)
      _ns=$(printf '%s\n' "$_src" | grep -c .) || _ns=0
      if [ "$_ns" -gt 0 ]; then
        printf '       linked from %s page(s):\n' "$_ns"
        printf '%s\n' "$_src" | head -5 | sed 's/^/         /'
        [ "$_ns" -gt 5 ] && printf '         … and %s more\n' "$((_ns - 5))"
      fi
    done < "$W/bad"
  fi
  [ "$_left" -gt 0 ] && { echo ""; _warn "Stopped at ${_max} pages with ${_left} still queued:  wp-links.sh broken --max-pages $((_max * 2))"; }

  echo ""
  _ne=$(cut -f1 "$W/ext" | sort -u | grep -c .) || _ne=0
  if [ "$_ne" -gt 0 ]; then
    echo "  Links to other sites: ${_ne} domain(s), NOT checked from here"
    _note "This VM may only reach the sites it needs, so a dead link and a blocked one look"
    _note "the same from here. The domains, by number of links to them:"
    cut -f1 "$W/ext" | sort | uniq -c | sort -rn | head -15 | awk '{ printf "       %-40s %s\n", $2, $1 }'
    [ "$_ne" -gt 15 ] && _note "  … and $((_ne - 15)) more"
    _note "Check them from a workstation that can reach ${_host} through NetBird:"
    _note "  on the admin machine:  podman run --rm --network host docker.io/raviqqe/muffet:latest ${_url} \\"
    _note "    --header 'User-Agent: ${UA}' --max-connections 3 --rate-limit 3 \\"
    _note "    --exclude 'wp-admin|wp-login|wp-json|xmlrpc${_slug:+|$_slug}'"
  fi
  echo ""
  [ "$_nbad" = 0 ] && exit 0 || exit 1
  ;;

# ── clean ────────────────────────────────────────────────────────────────────
# Removes what `spam` found, through WordPress and Elementor's own save (the
# page's HTML copy and CSS are rebuilt; a database edit would leave them holding
# the spam). Only what is NAMED and also tests as spam is changed: see
# php-tools/wasp-content-clean.php. --apply saves the evidence first -- the scan,
# the plan and the IndexNow log -- then takes a database backup, and refuses to
# go on if that backup fails. Afterwards the scan runs again and says what is left.
clean)
  shift
  _w=""; _t=""; _tr=""; _lk=""; _rev=0; _ix=0; _apply=0; _yes=0; _titles=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --widgets) _w="${2:-}"; shift 2
                 case "$_w" in ''|*[!a-z0-9,]*) _bad "--widgets takes Elementor widget IDs, comma-separated (from the scan)"; exit 1 ;; esac ;;
      --links)   _lk=$(printf '%s' "${2:-}" | tr 'A-Z' 'a-z'); shift 2
                 case "$_lk" in ''|*[!a-z0-9.,-]*|.*|*,) _bad "--links takes domains, comma-separated (from the scan), e.g. --links casino-site.example"; exit 1 ;; esac ;;
      --trash)   _tr="${2:-}"; shift 2
                 case "$_tr" in ''|*[!0-9,]*) _bad "--trash takes post IDs, comma-separated"; exit 1 ;; esac ;;
      --title)   _t="${2:-}"; shift 2
                 case "$_t" in [0-9]*=?*) : ;; *) _bad "--title takes POST_ID=new title, e.g. --title 120='Our services'"; exit 1 ;; esac
                 case "${_t%%=*}" in *[!0-9]*) _bad "--title: the part before = is a post ID"; exit 1 ;; esac
                 _titles="${_titles}${_titles:+
}title=${_t}" ;;
      --revisions) _rev=1; shift ;;
      --indexnow)  _ix=1; shift ;;
      --apply)     _apply=1; shift ;;
      --yes|-y)    _yes=1; shift ;;
      *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
  done
  [ -r "${CLEANER_DIR}/wasp-content-clean.php" ] || { _bad "Cleaner not found: ${CLEANER_DIR}/wasp-content-clean.php"; exit 2; }
  [ -x "$WP_PLUGINS" ] || { _bad "wp-plugins.sh not found (${WP_PLUGINS}): it runs WP-CLI for this"; exit 2; }
  _wpc() { WPCLI_MOUNT="-v ${CLEANER_DIR}:/tmp/wasp-php-tools:ro" "$WP_PLUGINS" __wp "$@"; }
  _admin=$(_wpc user list --role=administrator --field=ID --orderby=ID --order=ASC 2>/dev/null | head -1)
  case "$_admin" in ''|*[!0-9]*) _bad "Could not find an administrator to act as (is WordPress running?  doas podman ps)"; exit 2 ;; esac
  # Arguments for the cleaner, one per line (a title may hold spaces).
  _al=""; _add() { _al="${_al}${_al:+
}$1"; }
  [ -n "$_lk" ] && _add "links=${_lk}"
  [ -n "$_w" ] && _add "widgets=${_w}"
  [ -n "$_tr" ] && _add "trash=${_tr}"
  [ -n "$_titles" ] && _add "$_titles"
  [ "$_rev" = 1 ] && _add revisions
  [ "$_ix" = 1 ] && _add indexnow
  [ -z "$_al" ] && { _add report; _apply=0; }
  _run() { # extra words...
    _oifs=$IFS; IFS='
'
    # shellcheck disable=SC2086
    set -- $_al "$@"; IFS=$_oifs
    _wpc --user="$_admin" eval-file /tmp/wasp-php-tools/wasp-content-clean.php --use-include "$@"
  }
  if [ "$_apply" != 1 ]; then
    _run; _rc=$?
    [ "$_al" = report ] || { echo ""; _note "Nothing was changed. To do it:  the same command with --apply"; }
    exit "$_rc"
  fi
  # ── apply ──
  _plan=$(mktemp) || exit 2
  _run > "$_plan" 2>&1; _prc=$?
  cat "$_plan"
  if [ "$_prc" != 0 ]; then
    rm -f "$_plan"
    _bad "Some of what you named is refused above. Fix the command (nothing was changed)."; exit 1
  fi
  if [ "$_yes" != 1 ]; then
    [ -t 0 ] || { rm -f "$_plan"; _bad "Not a terminal: add --yes to apply without the prompt."; exit 1; }
    printf '  Apply the changes above? Type CLEAN to continue: '; read -r _ans
    [ "$_ans" = CLEAN ] || { rm -f "$_plan"; _note "Not applied."; exit 1; }
  fi
  _ev="${EVIDENCE}/content-spam-$(date -u +%Y%m%dT%H%M%SZ)"
  ( umask 077; mkdir -p "$_ev" ) || { _bad "Cannot create ${_ev}"; exit 2; }
  mv "$_plan" "$_ev/plan.txt"
  sh "$0" spam > "$_ev/scan-before.txt" 2>&1
  _wpc --user="$_admin" eval-file /tmp/wasp-php-tools/wasp-content-clean.php --use-include export-indexnow > "$_ev/indexnow-log.json" 2>/dev/null
  _ok "Evidence saved: ${_ev}"
  if ! "$DB_BACKUP" >"$_ev/db-backup.log" 2>&1; then
    _bad "The database backup failed (${_ev}/db-backup.log). Nothing was changed."; exit 2
  fi
  _ok "Database backed up first ($(basename "$DB_BACKUP"))"
  _run apply > "$_ev/applied.txt" 2>&1; _arc=$?
  cat "$_ev/applied.txt"
  sh "$0" spam > "$_ev/scan-after.txt" 2>&1; _src=$?
  logger -t wp-links "content clean applied (exit ${_arc}); evidence ${_ev}" 2>/dev/null
  echo ""
  if [ "$_src" = 0 ]; then
    _ok "The content scan now finds no spam."
  else
    _warn "The content scan still finds something (${_ev}/scan-after.txt):"
    sed 's/\x1b\[[0-9;]*m//g' "$_ev/scan-after.txt" | grep -E '^ *(page|post|elementor_library|menu item|widget|Announced|[0-9]+ saved revision)' | head -12 | sed 's/^/       /'
    _note "Run  wp-links.sh clean  again for the IDs that are left."
  fi
  _note "Next: tell search engines (README: \"Cleaning up content spam\")."
  [ "$_arc" = 0 ] || exit 1
  [ "$_src" = 0 ] || exit 1
  exit 0 ;;

*)
  sed -n '4,20p' "$0"
  exit 1 ;;
esac
