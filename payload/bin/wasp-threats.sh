#!/bin/sh
# =============================================================================
# wasp-threats.sh — the shapes real compromises took, as reusable checks
# =============================================================================
#   wasp-threats.sh renamed <dir>         PHP renamed so it no longer runs
#   wasp-threats.sh obfuscated <dir>      PHP that is mostly \xNN / \NNN escapes
#   wasp-threats.sh foreign-mu <dir>      top-level mu-plugins WASP did not install
#   wasp-threats.sh suspect-users         stdin: id<TAB>login<TAB>email<TAB>registered<TAB>caps
#                                         stdout: the accounts that look planted, and why
#   wasp-threats.sh dump-users [prefix]   stdin: an SQL dump -> the users table as TSV
#   wasp-threats.sh dump-caps  [prefix]   stdin: an SQL dump -> user_id<TAB>capabilities
#
# Read-only. Nothing here changes a file or a row; wp-import.sh and
# wp-malware-scan.sh decide what to do with what it finds. One copy of each
# check, so the importer, the daily scan and the clean-up cannot disagree about
# what a planted file or account looks like -- which is how inspect and scan
# once reported opposite verdicts on the same six files.
#
# Every check here comes from a real site (the 10.11 field test):
#
#   renamed       mu-plugins/<x>.php.bak — a hex-obfuscated SEO-spam injector
#                 that someone found, could not deactivate, and renamed.
#   obfuscated    the same file: no literal eval, base64_decode or curl_exec,
#                 every function name a \xNN escape behind a dispatcher. YARA
#                 matched nothing because there was nothing to match. What
#                 gives it away is density: ordinary code is not mostly escapes.
#   suspect-users wpadmin<random>, registered at exactly 00:00:00, dated before
#                 the owner's own account although its ID came after, role
#                 stripped to a:0:{} rather than the account deleted.
# =============================================================================
set -u

# WASP's own mu-plugins. Anything else at the top of mu-plugins on a WASP VM
# was put there by someone else. test/test-threats.sh checks this list against
# payload/mu-plugins/ so the two cannot drift.
WASP_MU="00-wpvm-login-slug.php 01-wpvm-smtp.php 02-wpvm-login-guard.php 03-wpvm-mfa-enforce.php 05-wasp-contact.php 06-wasp-username-privacy.php"

# Extensions that stop PHP running. Kept identical to inspect's listing check.
RENAMED_RE='\.(php[0-9]?|phtml|phar)(\.(bak|bk|old|orig|save|sav|back|backup|copy|disabled?|off|suspected|quarantined?|infected|hacked|malware|txt|tmp)|~)$'

# Obfuscation thresholds. A file is reported when at least OBF_MIN escape
# sequences, in runs of two or more, make up at least OBF_PCT percent of it. Calibrated against
# WordPress core and large plugins (see CHANGELOG 10.11): ordinary code,
# including bundled crypto and charset libraries, stays far below both.
OBF_MIN="${OBF_MIN:-64}"
OBF_PCT="${OBF_PCT:-20}"

case "${1:-}" in

renamed)
  [ -d "${2:-}" ] || { echo "Usage: wasp-threats.sh renamed <dir>" >&2; exit 2; }
  find "$2" -type f 2>/dev/null | grep -iE "$RENAMED_RE" || true ;;

obfuscated)
  # Two passes. A cheap grep for six escapes in a row finds candidates in one
  # read of the tree; only those are measured. Renamed PHP is included: the
  # payload that started this was a .php.bak.
  [ -d "${2:-}" ] || { echo "Usage: wasp-threats.sh obfuscated <dir>" >&2; exit 2; }
  find "$2" -type f \( -name '*.php' -o -name '*.php[0-9]' -o -name '*.phtml' -o -name '*.inc' \
       -o -name '*.php.*' -o -name '*.phtml.*' \) -size -4096k \
       -exec grep -lE '(\\x[0-9A-Fa-f]{2}){6}|(\\[0-7]{3}){6}' {} + 2>/dev/null \
  | while IFS= read -r _f; do
      _sz=$(wc -c < "$_f" 2>/dev/null) || continue
      [ "${_sz:-0}" -gt 0 ] || continue
      # Only escapes in a run of two or more count. An escape on its own is
      # how real code writes a NUL or a control byte -- WordPress core's HTML5
      # entity table is a quarter isolated \x00 separators -- while hiding a
      # name means escaping every letter of it in a row.
      _rb=$(grep -oE '(\\x[0-9A-Fa-f]{2}|\\[0-7]{3}){2,}' "$_f" 2>/dev/null | tr -d '\n' | wc -c | tr -cd '0-9')
      _n=$(( ${_rb:-0} / 4 ))   # each escape is 4 bytes of source for 1 byte of meaning
      _pct=$(( ${_rb:-0} * 100 / _sz ))
      if [ "$_n" -ge "$OBF_MIN" ] && [ "$_pct" -ge "$OBF_PCT" ]; then
        printf '%s\t%s\t%s\n' "$_pct" "$_n" "$_f"
      fi
    done ;;

foreign-mu)
  [ -d "${2:-}" ] || exit 0
  for _f in "$2"/*.php; do
    [ -f "$_f" ] || continue
    _b=$(basename "$_f"); _ours=0
    for _w in $WASP_MU; do [ "$_b" = "$_w" ] && _ours=1; done
    [ "$_ours" = 1 ] || printf '%s\n' "$_f"
  done ;;

suspect-users)
  # Input sorted by nothing in particular; sorted by ID here, because one
  # signal is a registration date that runs backwards against the ID.
  # A planted account is flagged on TWO signals or more. Each one alone has an
  # innocent explanation; together they have been, so far, a backdoor.
  sort -t "$(printf '\t')" -k1,1n | awk -F '\t' '
    function lc(s) { return tolower(s) }
    {
      id=$1; login=$2; email=$3; reg=$4; caps=$5; sig=""
      if (reg ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2} 00:00:00$/ && reg !~ /^0000/) sig=sig ",midnight"
      d=substr(reg,1,10)
      if (d ~ /^[12][0-9]{3}-/ && maxd != "" && d < maxd) sig=sig ",backdated"
      if (d ~ /^[12][0-9]{3}-/ && d > maxd) maxd=d
      l=lc(login)
      if (l ~ /^(wp|wordpress)[-_.]?(admin|adm|support|sys|system|root|backup|update|user|manager)[-_.]?[a-z0-9]{3,}$/ ||
          l ~ /^(admin|support|root)[-_.]?(wp|wordpress)[a-z0-9]{2,}$/) sig=sig ",login-pattern"
      if (caps == "a:0:{}") sig=sig ",role-stripped"
      n=split(substr(sig,2), parts, ",")
      if (n >= 2) {
        role = (caps ~ /administrator/) ? "administrator" : (caps == "a:0:{}" ? "none" : "other")
        printf "%s\t%s\t%s\t%s\t%s\t%s\n", id, login, email, reg, substr(sig,2), role
      }
    }' ;;

dump-users|dump-caps)
  # Rows out of an SQL dump, without loading it: a small tokenizer for
  # INSERT ... VALUES (...),(...); in either quote style (mysqldump writes
  # single quotes, phpMyAdmin and several backup plugins double) and across
  # line breaks (phpMyAdmin puts one row per line). An explicit column list is
  # honoured; without one, WordPress's column order is assumed.
  #   dump-users  id<TAB>login<TAB>email<TAB>registered
  #   dump-caps   user_id<TAB>capabilities   (every *capabilities meta row)
  # Give the table prefix when it is known; otherwise any table ending in
  # users/usermeta is read, which a plugin's own *_users table could confuse.
  _mode=users; [ "$1" = dump-caps ] && _mode=caps
  _pfx=$(printf '%s' "${2:-}" | tr -cd 'A-Za-z0-9_')
  awk -v mode="$_mode" -v pfx="$_pfx" '
    function emit(   a, b, c, d) {
      if (mode == "users") {
        a=f[ci["ID"]]; b=f[ci["user_login"]]; c=f[ci["user_email"]]; d=f[ci["user_registered"]]
        gsub(/[\t\r\n]/, " ", b); gsub(/[\t\r\n]/, " ", c)
        printf "%s\t%s\t%s\t%s\n", a, b, c, d
      } else if (f[ci["meta_key"]] ~ /capabilities$/) {
        d=f[ci["meta_value"]]; gsub(/[\t\r\n]/, " ", d)
        printf "%s\t%s\n", f[ci["user_id"]], d
      }
    }
    function setcols(list,   n, a, i) {
      split("", ci)
      if (list == "") {
        if (mode == "users") { ci["ID"]=1; ci["user_login"]=2; ci["user_email"]=5; ci["user_registered"]=7 }
        else { ci["user_id"]=2; ci["meta_key"]=3; ci["meta_value"]=4 }
        return
      }
      n=split(list, a, ",")
      for (i=1;i<=n;i++) ci[a[i]]=i
    }
    function feed(s,   i, c, L) {
      L=length(s)
      for (i=1;i<=L;i++) {
        c=substr(s,i,1)
        if (instr) {
          if (esc) { buf=buf c; esc=0; continue }
          if (c=="\\") { esc=1; continue }
          if (c==q) { if (substr(s,i+1,1)==q) { buf=buf c; i++; continue } instr=0; continue }
          buf=buf c; continue
        }
        if (c=="\047" || c=="\"") { instr=1; q=c; continue }
        if (c=="(") { depth++; if (depth==1) { nf=0; buf="" } continue }
        if (c==",") { if (depth==1) { f[++nf]=buf; buf="" } continue }
        if (c==")") { if (depth==1) { f[++nf]=buf; buf=""; emit() } depth--; continue }
        if (c==";" && depth==0) { active=0; return }
        if (depth>=1 && c!=" ") buf=buf c
      }
      if (instr) buf=buf " "
    }
    BEGIN {
      t = (mode == "users") ? "users" : "usermeta"
      head = "^((INSERT|REPLACE)( IGNORE)? INTO) [`\"]?" (pfx != "" ? pfx : "[A-Za-z0-9_]*") t "[`\"]?"
    }
    active { feed($0); next }
    $0 ~ (head "[ (]") {
      line=$0
      sub(head "[ ]*", "", line)
      cols=""
      if (substr(line,1,1)=="(") {
        e=index(line, ")"); cols=substr(line, 2, e-2); line=substr(line, e+1)
        gsub(/[`" ]/, "", cols)
      }
      setcols(cols)
      v=index(toupper(line), "VALUES"); line=substr(line, v+6)
      active=1; instr=0; esc=0; depth=0
      feed(line)
    }' ;;

*)
  sed -n '4,13p' "$0"; exit 2 ;;
esac
