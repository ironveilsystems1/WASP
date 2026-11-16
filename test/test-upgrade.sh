#!/usr/bin/env bash
# =============================================================================
# test-upgrade.sh — wasp-upgrade.sh on a VM filesystem built from an older release
# =============================================================================
#
# A fake VM root (WASP_ROOT) at "10.14": an edited copy of every staged file,
# its tools installed, mu-plugins rendered with ITS slug and two-factor values,
# a cron table with a line a later release retired and one the operator added.
# The release is this tree, signed with a test key by a stand-in minisign.
#
#   - an unsigned release, a wrong key, a file changed after signing, a file
#     the manifest does not list and a tarball with ../ are refused
#   - check changes nothing and names every tool, mu-plugin, cron line and
#     build-time config change
#   - a tool edited on the VM blocks the upgrade; --force overwrites it
#   - apply: tools, rules and mu-plugins match the release; mu-plugins keep the
#     VM's own slug and two-factor values (not vars.sh's); cron gains the new
#     lines once, loses the retired one, keeps the operator's; a removed tool
#     goes; the staged copy, manifest and version are the release's; the
#     version hooks between run once each; a site's own mu-plugin is untouched
#   - a second apply changes nothing
#   - a new mu-plugin that fails PHP's check stops the upgrade before any change
#   - rollback puts back exactly what was there
#   - a downgrade is refused
#
# Host shell and BusyBox (BUSYBOX=/path/to/busybox, required). Needs php.
# =============================================================================
set -u
set -o pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
_p() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
_f() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n         %s\n' "$1" "${2:-}"; }
TOOL="$REPO/payload/bin/wasp-upgrade.sh"
KEY="RWStestkeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
NEWVER=$(sed -n 's/^WASP_VERSION="\([^"]*\)".*/\1/p' "$REPO/install.sh" | head -1)

echo ""
echo "wasp-upgrade.sh: verified, planned, idempotent upgrades with rollback"
[ "$(id -u)" -eq 0 ] || { _f "must run as root" "the tool re-executes through doas otherwise"; exit 1; }
command -v php >/dev/null 2>&1 || { _f "php is required" ""; exit 1; }
BB="${BUSYBOX:-$(command -v busybox 2>/dev/null || true)}"

# ── the release: this tree, signed with the test key ────────────────────────
_mkrel() { # dir key
  mkdir -p "$1/wasp-$NEWVER"
  ( cd "$REPO" && tar cf - --exclude='__pycache__' install.sh payload ) | tar xf - -C "$1/wasp-$NEWVER"
  ( cd "$1/wasp-$NEWVER" && { printf '%s\n' install.sh; find payload -type f | LC_ALL=C sort; } \
      | xargs sha256sum > MANIFEST.sha256 )
  [ -n "$2" ] && printf 'testsig %s %s\n' "$2" "$(sha256sum "$1/wasp-$NEWVER/MANIFEST.sha256" | cut -d' ' -f1)" \
      > "$1/wasp-$NEWVER/MANIFEST.sha256.minisig"
  return 0
}
_mkrel "$T/rel" "$KEY"
REL="$T/rel/wasp-$NEWVER"
( cd "$T/rel" && tar czf "$T/release.tar.gz" "wasp-$NEWVER" )
# A tarball with a ../ member (GNU tar strips those when creating, so python writes it).
python3 -c 'import io,tarfile,sys
t=tarfile.open(sys.argv[1],"w:gz"); d=b"hi\n"; i=tarfile.TarInfo("wasp-x/../../escape"); i.size=len(d); t.addfile(i,io.BytesIO(d)); t.close()' "$T/evil.tar.gz"

_suite() { # label shell PATH
  L="$1"; SH="$2"; PP="$3"; W="$T/$L"; mkdir -p "$W/bin" "$W/hookbin"
  # A stand-in minisign: valid only for the key it was signed with and this exact manifest.
  cat > "$W/bin/minisign" <<EOF
#!$SH
while [ \$# -gt 0 ]; do case "\$1" in -Vqm|-Vm) m=\$2; shift ;; -P) k=\$2; shift ;; esac; shift; done
[ "\$(cat "\$m.minisig" 2>/dev/null)" = "testsig \$k \$(sha256sum "\$m" | cut -d' ' -f1)" ]
EOF
  printf '#!%s\necho "wp-hardening.sh $*" >> "%s/hooks.log"; [ "$1 $2" = "remoteip-fix --check" ] && exit 1; exit 0\n' "$SH" "$W" > "$W/hookbin/wp-hardening.sh"
  printf '#!%s\necho "wasp-alerts.sh $*" >> "%s/hooks.log"; exit 0\n' "$SH" "$W" > "$W/hookbin/wasp-alerts.sh"
  chmod +x "$W/bin/"* "$W/hookbin/"*

  # ── the VM at "10.14": every staged file edited a little ──
  V="$W/vm"; S="$V/etc/wp-install/payload"
  mkdir -p "$S" "$V/etc/wp-install/stages" "$V/usr/local/bin" "$V/etc/crontabs" "$V/etc/wp-install/malware" \
           "$V/home/wpuser/wp/html/wp-content/mu-plugins" "$V/home/wpuser/wp/secrets" "$V/usr/local/lib/wasp" "$V/etc/logrotate.d"
  for _p in "$REL"/payload/*/; do _n=$(basename "$_p"); [ "$_n" = stages ] && continue; cp -a "$_p" "$S/$_n"; done
  cp -a "$REL/payload/stages/." "$V/etc/wp-install/stages/"
  rm -rf "$S/upgrade" "$S/bin/wasp-upgrade.sh"                      # what 10.14 did not have
  echo "# 10.14" >> "$S/bin/wp-links.sh"; echo "# 10.14" >> "$S/mu-plugins/07-wasp-alerts.php"
  echo "# 10.14" >> "$S/malware/wp-malware.yar"; echo "# 10.14" >> "$S/apache-conf/wp-security-fallback.conf"
  printf '#!/bin/sh\necho legacy\n' > "$S/bin/wp-legacy.sh"
  grep -v 'wp-links.sh spam\|watch-site' "$REL/payload/cron/wordpress-vm.cron" \
    | sed 's#^30 4 \* \* 1 /usr/local/bin/wasp-alerts.sh watch-integrity .*#30 4 * * 1 /usr/local/bin/wp-plugins.sh verify >/dev/null 2>\&1#' \
    > "$S/cron/wordpress-vm.cron"
  for f in "$S"/bin/*.sh; do install -m 0755 "$f" "$V/usr/local/bin/"; done
  cp "$S/malware/"*.yar "$V/etc/wp-install/malware/"; cp "$S/lib/wasp-wpress-reader.php" "$V/usr/local/lib/wasp/"
  cp "$S/etc/logrotate.d/wordpress-vm" "$V/etc/logrotate.d/"
  M="$V/home/wpuser/wp/html/wp-content/mu-plugins"
  for f in "$S"/mu-plugins/*.php; do cp "$f" "$M/"; done
  sed -i 's|WPVM_SLUG_PLACEHOLDER|my-login|g' "$M/00-wpvm-login-slug.php"
  sed -i -e 's|WPVM_MFA_ENFORCE_PLACEHOLDER|1|g' -e 's|WPVM_MFA_GRACE_PLACEHOLDER|5|g' "$M/03-wpvm-mfa-enforce.php"
  printf '<?php // the site'"'"'s own\n' > "$M/zz-site.php"
  { echo '17 * * * * /usr/sbin/logrotate /etc/logrotate.conf 2>&1 | logger -t logrotate'
    grep -v '^#' "$S/cron/wordpress-vm.cron" | grep -v '^$'
    echo '0 1 * * * /root/my-own-job.sh'; } > "$V/etc/crontabs/root"
  printf "WASP_VERSION='10.14'\nWASP_RELEASE='10.14'\nWASP_VERSION_NOTE='old'\nWP_ADMIN_SLUG='other'\nMFA_ENFORCE='0'\nMFA_GRACE_DAYS='7'\nADMIN_USER='ops'\n" \
    > "$V/etc/wp-install/vars.sh"
  printf '%s\n' "$KEY" > "$V/etc/wp-install/release.pub"
  # Egress: an allowlist from before 10.26, and a commercial plugin that needs its server.
  mkdir -p "$V/opt/squid/config" "$V/home/wpuser/wp/html/wp-content/plugins/ultimate-elementor"
  printf '.wordpress.org\n.w.org\n' > "$V/opt/squid/config/allowlist-runtime.txt"
  # GeoIP setup before 10.20 rewrote one line of the installed update.sh; and Lynis's
  # cron file is installed, so the retired line is seen through two cron entries.
  sed -i 's|^PINNED_WP_VER=.*|PINNED_WP_VER="geoip-7.1-php8.4-apache"|' "$V/usr/local/bin/update.sh"
  grep -v '^#' "$S/cron/lynis-audit.cron" | grep -v '^$' | head -1 >> "$V/etc/crontabs/root"
  cp "$V/etc/crontabs/root" "$W/crontab.before"

  printf '#!%s\ncase "$*" in *"squid -k"*) echo "podman $*" >> "%s/podman.log" ;; esac\nexit 0\n' "$SH" "$W" > "$W/bin/podman"
  chmod +x "$W/bin/podman"
  _u() { env PATH="$W/bin:$PP" WASP_ROOT="$V" WASP_HOOK_BIN="$W/hookbin" WASP_UPGRADE_LINT="${LINT:-php -l}" \
           "$SH" "$TOOL" "$@" 2>&1 | sed 's/\x1b\[[0-9;]*m//g'; }
  _snap() { ( cd "$V" && find . -path ./var/lib/wasp-upgrade -prune -o -type f -print | LC_ALL=C sort | xargs sha256sum ); }
  _snap > "$W/s0"

  # ── verification ──
  _mkrel "$W/unsigned" ""
  out=$(_u check "$W/unsigned/wasp-$NEWVER"); rc=$?
  { printf '%s' "$out" | grep -q 'not signed'; } && _p "$L: an unsigned release is refused" || _f "$L: unsigned" "$out"
  printf '%s\n' "RWSotherkeyBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" > "$V/etc/wp-install/release.pub"
  out=$(_u check "$REL")
  printf '%s' "$out" | grep -q 'SIGNATURE INVALID' && _p "$L: a release signed with another key than the one pinned on the VM is refused" || _f "$L: wrong key" "$out"
  printf '%s\n' "$KEY" > "$V/etc/wp-install/release.pub"
  _mkrel "$W/tamper" "$KEY"; echo "# changed after signing" >> "$W/tamper/wasp-$NEWVER/payload/bin/wp-links.sh"
  out=$(_u check "$W/tamper/wasp-$NEWVER")
  printf '%s' "$out" | grep -q 'do not match the manifest' && _p "$L: a file changed after signing is refused" || _f "$L: tamper" "$out"
  _mkrel "$W/extra" "$KEY"; echo 'x' > "$W/extra/wasp-$NEWVER/payload/bin/evil.sh"
  out=$(_u check "$W/extra/wasp-$NEWVER")
  printf '%s' "$out" | grep -q 'does not list' && _p "$L: a file the signed manifest does not list is refused" || _f "$L: extra" "$out"
  out=$(_u check "$T/evil.tar.gz")
  # GNU tar lists the ../ member and is refused before extracting; BusyBox tar cleans the name
  # itself. Either way the release is refused and nothing lands outside the work directory.
  { printf '%s' "$out" | grep -qiE "absolute or ../ path|Expected one top-level" && [ ! -e "$V/var/lib/escape" ] \
    && [ ! -e "$V/escape" ]; } && _p "$L: a tarball holding a ../ path is refused, nothing written outside" || _f "$L: traversal" "$out"
  _snap > "$W/s1"; cmp -s "$W/s0" "$W/s1" && _p "$L: refused releases changed nothing" || _f "$L: refusal changed files" ""

  # ── no release named: the newest is fetched (file:// here, https on a VM) ──
  # The menu asked for a path; field operators had none. A fetched release must
  # get every check a copied one gets, and nothing may be changed by fetching.
  ln -sf "$(command -v curl)" "$W/bin/curl"
  out=$(export WASP_RELEASE_URL="file://$T/release.tar.gz"; _u check); rc=$?
  { [ "$rc" = 0 ] && printf '%s' "$out" | grep -q 'Fetching the newest release' && printf '%s' "$out" | grep -q 'Signature valid' \
    && printf '%s' "$out" | grep -q "Upgrade plan: 10.14 → $NEWVER" && printf '%s' "$out" | grep -q 'fetches the newest again'; } \
    && _p "$L: check with no release fetches the newest, then verifies and plans it like a copied one" || _f "$L: fetch check" "rc=$rc $out"
  _snap > "$W/s1"; cmp -s "$W/s0" "$W/s1" && _p "$L: ...and fetching changes nothing on the VM" || _f "$L: fetch changed files" ""
  out=$(export WASP_RELEASE_URL="file://$T/evil.tar.gz"; _u check); rc=$?
  # As for a copied tarball: GNU tar lists the ../ member and it is refused before
  # extracting; BusyBox tar strips it, and the result is refused as not a release.
  { [ "$rc" != 0 ] && printf '%s' "$out" | grep -qiE 'absolute or ../ path|Expected one top-level' \
    && [ ! -e "$V/var/lib/escape" ] && [ ! -e "$V/var/lib/wasp-upgrade/escape" ]; } \
    && _p "$L: a fetched release meets the same refusals (a ../ path), nothing written outside" || _f "$L: fetched evil" "rc=$rc $out"
  out=$(export WASP_RELEASE_URL="file://$T/no-such-release.tar.gz"; _u check); rc=$?
  [ "$rc" != 0 ] && printf '%s' "$out" | grep -q 'Could not download' && printf '%s' "$out" | grep -q 'name a release you have' \
    && _p "$L: a failed download says so and how to give a release instead" || _f "$L: fetch fail" "rc=$rc $out"
  out=$(export WASP_RELEASE_URL="http://releases.example/wasp.tar.gz"; _u check); rc=$?
  [ "$rc" != 0 ] && printf '%s' "$out" | grep -q 'must be https' && _p "$L: a plain-http release URL is refused" || _f "$L: http url" "rc=$rc $out"
  _snap > "$W/s1"; cmp -s "$W/s0" "$W/s1" && _p "$L: ...none of which changed anything" || _f "$L: refusals changed files" ""

  # ── check ──
  out=$(_u check "$T/release.tar.gz"); rc=$?
  _snap > "$W/s1"
  { [ "$rc" = 0 ] && cmp -s "$W/s0" "$W/s1"; } && _p "$L: check (from the tarball) verifies, plans and changes nothing" || _f "$L: check" "rc=$rc $out"
  printf '%s' "$out" | grep -q 'Signature valid' && printf '%s' "$out" | grep -q 'files match the signed manifest' \
    && _p "$L: ...signature and every file verified" || _f "$L: verify lines" "$out"
  { printf '%s' "$out" | grep -q '~ tool wp-links.sh' && printf '%s' "$out" | grep -q 'new, ' \
    && printf '%s' "$out" | grep -q '− tool wp-legacy.sh'; } \
    && _p "$L: ...names changed, new and removed tools" || _f "$L: tools" "$out"
  printf '%s' "$out" | grep -q '~ mu   07-wasp-alerts.php' && ! printf '%s' "$out" | grep -q 'mu   03-wpvm\|mu   00-wpvm' \
    && _p "$L: ...a changed mu-plugin; templated ones rendered with the VM's values show no change" || _f "$L: mu" "$out"
  { printf '%s' "$out" | grep -q '+ cron 40 4 \* \* 2 /usr/local/bin/wp-links.sh spam' \
    && printf '%s' "$out" | grep -q '− cron 30 4 \* \* 1 /usr/local/bin/wp-plugins.sh verify'; } \
    && _p "$L: ...cron lines to add and the retired one to remove" || _f "$L: cron plan" "$out"
  printf '%s' "$out" | grep -A3 'Configuration written' | grep -q 'apache-conf/wp-security-fallback.conf' \
    && _p "$L: ...build-time config that changed upstream is reported, not replaced" || _f "$L: cfg" "$out"
  printf '%s' "$out" | grep -q '+ egress support.brainstormforce.com  (Ultimate Addons for Elementor' \
    && ! printf '%s' "$out" | grep -q 'egress .wordpress.org' \
    && _p "$L: ...egress a plugin installed here needs and the VM lacks, and not what it has" || _f "$L: egress plan" "$out"
  printf '%s' "$out" | grep -q '10.15 upgrade step' && printf '%s' "$out" | grep -q '10.16 upgrade step' \
    && printf '%s' "$out" | grep -q '10.21 upgrade step' \
    && _p "$L: ...and the steps for each version passed" || _f "$L: hooks plan" "$out"
  { printf '%s' "$out" | grep -q '~ tool update.sh .*set by GeoIP setup before 10.20' && ! printf '%s' "$out" | grep -q 'update.sh: MODIFIED'; } \
    && _p "$L: update.sh with only GeoIP's old PINNED_WP_VER edit is replaced, not blocked as tampered" || _f "$L: geoip update.sh" "$out"
  [ "$(printf '%s' "$out" | grep -c '− cron 30 4 \* \* 1 /usr/local/bin/wp-plugins.sh verify')" = 1 ] \
    && _p "$L: a retired cron line is listed once, however many cron files are installed" || _f "$L: cron dup" "$out"
  out=$(_u check "$REL" --diff)
  printf '%s' "$out" | grep -q '^-# 10.14' && _p "$L: check --diff shows the changed lines" || _f "$L: diff" "$out"

  # ── a tool edited on the VM ──
  echo "# someone was here" >> "$V/usr/local/bin/wp-hardening.sh"
  out=$(_u apply "$REL" --yes); rc=$?
  { [ "$rc" = 1 ] && printf '%s' "$out" | grep -q 'wp-hardening.sh: MODIFIED since it was installed' \
    && grep -q 'someone was here' "$V/usr/local/bin/wp-hardening.sh"; } \
    && _p "$L: a tool edited on the VM blocks the upgrade and is left as evidence" || _f "$L: blocked" "rc=$rc $out"
  sed -i '/someone was here/d' "$V/usr/local/bin/wp-hardening.sh"

  # ── a new mu-plugin that PHP rejects ──
  out=$(LINT=false _u apply "$REL" --yes); rc=$?
  _snap > "$W/s1"
  { [ "$rc" != 0 ] && printf '%s' "$out" | grep -q "fails PHP's syntax check here. Nothing was changed" && cmp -s "$W/s0" "$W/s1"; } \
    && _p "$L: a mu-plugin that fails PHP's check stops the upgrade before any change" || _f "$L: lint gate" "rc=$rc $out"

  # ── apply ──
  out=$(_u apply "$REL" --yes); rc=$?
  [ "$rc" = 0 ] && printf '%s' "$out" | grep -q "now runs WASP $NEWVER" && _p "$L: apply succeeds" || _f "$L: apply" "rc=$rc $out"
  _same=1; for f in "$REL"/payload/bin/*.sh; do cmp -s "$f" "$V/usr/local/bin/$(basename "$f")" || _same=0; done
  [ "$_same" = 1 ] && [ ! -e "$V/usr/local/bin/wp-legacy.sh" ] && [ -x "$V/usr/local/bin/wasp-upgrade.sh" ] \
    && _p "$L: every tool is the release's, the new one included; the removed one is gone" || _f "$L: tools after" ""
  cmp -s "$REL/payload/malware/wp-malware.yar" "$V/etc/wp-install/malware/wp-malware.yar" \
    && cmp -s "$REL/payload/mu-plugins/07-wasp-alerts.php" "$M/07-wasp-alerts.php" \
    && _p "$L: rules and mu-plugins are the release's" || _f "$L: rules/mu after" ""
  { grep -q "'WPVM_LOGIN_SLUG', 'my-login'" "$M/00-wpvm-login-slug.php" && grep -q "'WPVM_MFA_ENFORCE', 1 )" "$M/03-wpvm-mfa-enforce.php" \
    && grep -q "'WPVM_MFA_GRACE_DAYS', 5 )" "$M/03-wpvm-mfa-enforce.php" && [ -f "$M/zz-site.php" ]; } \
    && _p "$L: mu-plugins keep the VM's own slug and two-factor settings; the site's own mu-plugin is untouched" \
    || _f "$L: rendered mu" "$(grep -h "define( 'WPVM" "$M/00-wpvm-login-slug.php" "$M/03-wpvm-mfa-enforce.php")"
  C="$V/etc/crontabs/root"
  { [ "$(grep -c 'wp-links.sh spam --notify' "$C")" = 1 ] && [ "$(grep -c 'watch-site' "$C")" = 1 ] \
    && ! grep -q 'wp-plugins.sh verify' "$C" && grep -q 'my-own-job' "$C" && grep -q 'logrotate' "$C"; } \
    && _p "$L: cron: new lines once, the retired line gone, the operator's and other stages' lines kept" || _f "$L: cron after" "$(cat "$C")"
  { diff -r "$REL/payload/bin" "$S/bin" >/dev/null && cmp -s "$REL/MANIFEST.sha256" "$V/etc/wp-install/MANIFEST.sha256" \
    && grep -q "^WASP_VERSION='$NEWVER'" "$V/etc/wp-install/vars.sh" && grep -q "^ADMIN_USER='ops'" "$V/etc/wp-install/vars.sh" \
    && [ ! -e "$S/stages" ] && [ -d "$S/upgrade" ]; } \
    && _p "$L: staged payload, manifest and version are the release's; the rest of vars.sh is kept" || _f "$L: staged" ""
  grep -q 'apache-conf' "$W/s0" && ! grep -q 'wp-security.conf' "$W/s0"; # (no installed apache conf in this root)
  # 10.15 and 10.21 both run the remoteip check (and, here, the repair); 10.16 the alerts setup.
  [ "$(grep -c 'remoteip-fix --check' "$W/hooks.log" 2>/dev/null)" = 2 ] && [ "$(grep -c '^wp-hardening.sh remoteip-fix$' "$W/hooks.log")" = 2 ] \
    && [ "$(grep -c 'wasp-alerts.sh setup --quiet' "$W/hooks.log")" = 1 ] \
    && _p "$L: the 10.15, 10.16 and 10.21 steps ran once each" || _f "$L: hooks ran" "$(cat "$W/hooks.log" 2>/dev/null)"
  { grep -qxF support.brainstormforce.com "$V/opt/squid/config/allowlist-runtime.txt" && grep -qxF .wordpress.org "$V/opt/squid/config/allowlist-runtime.txt" \
    && grep -q 'squid -k reconfigure' "$W/podman.log" 2>/dev/null && printf '%s' "$out" | grep -q 'Allowed: support.brainstormforce.com'; } \
    && _p "$L: the egress the plugin needs is added, nothing removed, and Squid reloaded" || _f "$L: egress apply" "$(cat "$V/opt/squid/config/allowlist-runtime.txt") $out"
  grep -q "upgrade 10.14 -> $NEWVER ok" "$V/var/lib/wasp-upgrade/history.log" && ls "$V/var/lib/wasp-upgrade/backups/"*-from-10.14.tar.gz >/dev/null 2>&1 \
    && _p "$L: recorded in the history, with a backup" || _f "$L: history" "$(cat "$V/var/lib/wasp-upgrade/history.log" 2>/dev/null)"
  _snap > "$W/s2"

  # ── again ──
  out=$(_u apply "$REL" --yes); rc=$?
  _snap > "$W/s3"
  { [ "$rc" = 0 ] && printf '%s' "$out" | grep -q 'Already up to date' && cmp -s "$W/s2" "$W/s3"; } \
    && _p "$L: a second apply changes nothing" || _f "$L: idempotent" "rc=$rc $out"

  # ── an operator who moved a job keeps their schedule ──
  sed -i 's#^40 4 \* \* 2 /usr/local/bin/wp-links.sh spam#10 6 * * 3 /usr/local/bin/wp-links.sh spam#' "$C"
  sed -i "s/^WASP_VERSION=.*/WASP_VERSION='10.17'/" "$V/etc/wp-install/vars.sh"
  out=$(_u check "$REL")
  printf '%s' "$out" | grep -q 'schedule changed on this VM, kept: 10 6 \* \* 3' && ! printf '%s' "$out" | grep -q '+ cron 40 4' \
    && _p "$L: a cron job whose schedule was changed on the VM is kept, not duplicated" || _f "$L: moved job" "$out"

  # ── rollback ──
  out=$(_u rollback --yes); rc=$?
  ls "$V/var/lib/wasp-upgrade/backups/" > /dev/null
  sed -i "s/^WASP_VERSION=.*/WASP_VERSION='10.14'/" "$V/etc/wp-install/vars.sh" 2>/dev/null
  _snap > "$W/s4"
  # The egress allowlist is not the upgrade's to take back (see below); everything else is.
  if [ "$rc" = 0 ] && diff <(grep -v ' ./opt/squid/' "$W/s0") <(grep -v ' ./opt/squid/' "$W/s4") >/dev/null; then
    _p "$L: rollback restores exactly what was there before the upgrade"
  else _f "$L: rollback" "rc=$rc $(diff "$W/s0" "$W/s4" | head -8) $out"; fi
  grep -qxF support.brainstormforce.com "$V/opt/squid/config/allowlist-runtime.txt" \
    && printf '%s' "$out" | grep -A1 'Egress that upgrade added is still allowed' | grep -q support.brainstormforce.com \
    && _p "$L: ...and says the egress it added stays, and how to remove it" || _f "$L: rollback egress" "$out"
  [ ! -e "$V/usr/local/bin/wasp-upgrade.sh" ] && grep -q 'wp-plugins.sh verify' "$C" \
    && _p "$L: ...removing what the upgrade added and restoring the old cron" || _f "$L: rollback detail" ""

  # ── downgrade ──
  sed -i "s/^WASP_VERSION=.*/WASP_VERSION='99.1'/" "$V/etc/wp-install/vars.sh"
  out=$(_u apply "$REL" --yes); rc=$?
  [ "$rc" = 1 ] && printf '%s' "$out" | grep -q 'Refusing to move this VM back' && _p "$L: a downgrade is refused" || _f "$L: downgrade" "rc=$rc $out"
  out=$(_u status)
  printf '%s' "$out" | grep -q 'rollback 10.14' || printf '%s' "$out" | grep -q 'rollback' && _p "$L: status shows the history and backups" || _f "$L: status" "$out"
}

_suite host /bin/sh "/usr/local/bin:/usr/bin:/bin"
if [ -n "$BB" ] && "$BB" --list >/dev/null 2>&1; then
  mkdir -p "$T/bb"; for _a in $("$BB" --list); do ln -sf "$BB" "$T/bb/$_a"; done
  ln -sf "$(command -v php)" "$T/bb/php"
  _suite busybox "$T/bb/sh" "$T/bb"
else
  _f "BusyBox not found: the Alpine-shell pass did not run" "set BUSYBOX=/path/to/busybox"
fi

echo ""
echo "  upgrade: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
