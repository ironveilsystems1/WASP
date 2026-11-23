#!/bin/sh
# step: add the opener-isolation header (Cross-Origin-Opener-Policy) to the site's security headers
#
# Run by wasp-upgrade.sh, once, when a VM passes 10.29, after the new tools are
# installed. wp-security.conf was written at build time and an upgrade does not
# replace it (it holds the VM's admin rules and the client's embeds). This asks
# wp-hardening.sh, now installed, to add its managed-headers block -- COOP on,
# hotlink protection off, unless /etc/wp-install/headers already says otherwise
# -- which keeps a copy of the file, asks Apache first, puts the old file back
# if Apache refuses, and restarts WordPress (10-20 seconds) so it applies.
# Safe to repeat: a file that already has the block is left alone.
R="${WASP_ROOT:-}"
CONF="${R}/home/wpuser/wp/apache-conf/wp-security.conf"
TOOL="${R}/usr/local/bin/wp-hardening.sh"
[ -f "$CONF" ] || { echo "no wp-security.conf here; skipped"; exit 0; }
if grep -q '^# BEGIN WASP managed headers' "$CONF"; then
  echo "the managed headers are already in place; nothing to do"
  exit 0
fi
[ -x "$TOOL" ] || { echo "wp-hardening.sh is not installed; skipped (run: doas wp-hardening.sh headers apply)"; exit 0; }
if WASP_APACHE_CONF="$CONF" WASP_HEADERS_STATE="${R}/etc/wp-install/headers" "$TOOL" headers apply; then
  echo "opener isolation is on; hotlink protection is a setting: wp-hardening.sh headers"
  exit 0
fi
echo "the headers were not applied; the site is unchanged. Run by hand: doas wp-hardening.sh headers apply"
exit 1
