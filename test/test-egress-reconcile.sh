#!/usr/bin/env bash
# =============================================================================
# test-egress-reconcile.sh — an upgrade adds the egress a VM needs, and only that
# =============================================================================
#
# `wasp-egress reconcile` (run by wasp-upgrade.sh apply) adds WordPress's own
# update servers and the licence server of each commercial plugin or theme
# INSTALLED here, when the allowlist lacks them. It never removes, never adds
# for a plugin that is not installed, never puts back what `deny` removed,
# never lists a parent beside a narrower entry (Squid refuses that file), and
# writes in place (the file is bind-mounted into Squid by inode).
#
# Drives the real wasp-egress.sh with podman stubbed; whether Squid honours the
# file is a live-VM question (`wasp-egress test`).
# =============================================================================
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
_p() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
_f() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n         %s\n' "$1" "${2:-}"; }

mkdir -p "$T/bin" "$T/etc" "$T/sq/config" "$T/sq/logs" "$T/wp/wp-content/plugins" "$T/wp/wp-content/themes"
: > "$T/etc/vars.sh"
R="$T/sq/config/allowlist-runtime.txt"; D="$T/sq/config/.denied"
sed -e '/^if \[ "\$(id -u)" -ne 0 \]; then$/,/^fi$/d' \
    -e "s#/etc/wp-install/vars.sh#$T/etc/vars.sh#g" \
    "$REPO/payload/bin/wasp-egress.sh" > "$T/wasp-egress.sh"
chmod +x "$T/wasp-egress.sh"
cat > "$T/bin/podman" <<STUB
#!/usr/bin/env bash
case "\$*" in
  *'squid -k parse'*) [ "\${PARSE_FAIL:-0}" = 1 ] && exit 1; exit 0 ;;
  *'squid -k reconfigure'*) echo x >> "$T/reconfigures"; exit 0 ;;
  *'grep -qxF'*) exit 1 ;;
esac
exit 0
STUB
printf '#!/bin/sh\nexit 0\n' > "$T/bin/logger"
chmod +x "$T/bin/"*

_eg() { PATH="$T/bin:${WASP_TEST_TOOLS:+$WASP_TEST_TOOLS:}$PATH" WASP_SQUID_DIR="$T/sq" WASP_WP_HTML="$T/wp" WASP_CLIENT_MAIL="$T/client-mail.ini" \
          ${WASP_TEST_SH:-sh} "$T/wasp-egress.sh" "$@" 2>&1; }
_has() { grep -qxF "$1" "$R"; }
_ino() { ls -i "$R" | awk '{print $1}'; }
_plug() { mkdir -p "$T/wp/wp-content/plugins/$1"; }

echo ""
echo "Egress reconcile"
echo ""
echo "── an older VM: WordPress's update servers missing, plugins needing theirs"
printf '# a VM from an older release\n.crowdsec.net\nwww.wordfence.com\n' > "$R"
_plug ultimate-elementor; _plug elementor; _plug wordfence; _plug contact-form-7
mkdir -p "$T/wp/wp-content/themes/Divi"
out=$(_eg reconcile --check)
for h in .wordpress.org .w.org support.brainstormforce.com noc1.wordfence.com .elegantthemes.com; do
  printf '%s\n' "$out" | grep -q "^add|${h}|" && _p "--check lists ${h}" || _f "--check ${h}" "$out"
done
printf '%s\n' "$out" | grep -q 'elementor\.com' && _f "free Elementor" "$out" || _p "free Elementor and other plugins need nothing"
printf '%s\n' "$out" | grep -q 'Ultimate Addons for Elementor.*plugin ultimate-elementor installed' \
  && _p "each says why: which installed plugin needs it" || _f "why" "$out"
cp "$R" "$T/before"
cmp -s "$R" "$T/before" && _p "--check changes nothing" || _f "--check" "changed the file"
i0=$(_ino)
out=$(_eg reconcile); rc=$?
[ "$rc" = 0 ] && _p "reconcile succeeds" || _f "reconcile rc" "$rc $out"
ok=1; for h in .wordpress.org .w.org support.brainstormforce.com noc1.wordfence.com .elegantthemes.com; do _has "$h" || ok=0; done
[ "$ok" = 1 ] && _p "every missing entry is added" || _f "added" "$(cat "$R")"
_has .crowdsec.net && _has www.wordfence.com && _p "nothing already there is removed" || _f "removed" "$(cat "$R")"
[ "$(_ino)" = "$i0" ] && _p "written in place (Squid reads the file by inode)" || _f "inode" "$i0 -> $(_ino)"
grep -q '^# Added by wasp-egress reconcile' "$R" && grep -q '^# Ultimate Addons for Elementor' "$R" \
  && _p "the file says when and why each was added" || _f "comments" "$(cat "$R")"
[ -s "$T/reconfigures" ] && _p "Squid is reloaded" || _f "reload" "none"
ls "$R".bak-* >/dev/null 2>&1 && _p "the previous list is kept" || _f "backup" "none"

echo ""
echo "── a second run, and what it must never do"
cp "$R" "$T/after1"; : > "$T/reconfigures"
out=$(_eg reconcile)
cmp -s "$R" "$T/after1" && [ ! -s "$T/reconfigures" ] && _p "a second run changes nothing" || _f "idempotent" "$(diff "$T/after1" "$R")"
printf '%s\n' "$out" | grep -q 'Everything WordPress and its installed plugins need' && _p "and says so" || _f "message" "$out"
[ -z "$(_eg reconcile --check)" ] && _p "--check prints nothing when nothing is missing" || _f "--check empty" "$(_eg reconcile --check)"
_eg deny noc1.wordfence.com >/dev/null
_has noc1.wordfence.com && _f "deny" "still listed" || _p "deny removes it"
grep -q ' noc1.wordfence.com ' "$D" && _p "and records the removal" || _f "ledger" "$(cat "$D" 2>/dev/null)"
_eg reconcile >/dev/null
_has noc1.wordfence.com && _f "reconcile" "put back what deny removed" || _p "reconcile does not put back what deny removed"
printf '%s\n' "$(_eg reconcile --check)" | grep -q '^skip|noc1.wordfence.com|.*removed with wasp-egress deny' \
  && _p "and says it was left out, and why" || _f "skip line" "$(_eg reconcile --check)"
_eg allow noc1.wordfence.com --permanent >/dev/null
_has noc1.wordfence.com && ! grep -q ' noc1.wordfence.com ' "$D" && _p "allow --permanent restores it and forgets the deny" || _f "re-allow" "$(cat "$D")"
rm -rf "$T/wp/wp-content/plugins/ultimate-elementor"
_eg reconcile >/dev/null
_has support.brainstormforce.com && _p "a plugin since removed: its entry stays (reconcile only adds)" || _f "removed entry" "$(cat "$R")"

echo ""
echo "── narrower entries, other vendors, and no egress filtering"
printf 'api.wordpress.org\ndownloads.wordpress.org\n.w.org\nmy.elementor.com\n' > "$R"; rm -f "$D"
rm -rf "$T/wp/wp-content/plugins/"* "$T/wp/wp-content/themes/"*; _plug elementor-pro
out=$(_eg reconcile --check)
printf '%s\n' "$out" | grep -q '^skip|.wordpress.org|.*api.wordpress.org downloads.wordpress.org is listed' \
  && _p "a parent is not added beside narrower entries (Squid refuses the file)" || _f "narrower" "$out"
printf '%s\n' "$out" | grep -q '^skip|.elementor.com|.*my.elementor.com' && _p "...the same for a vendor" || _f "narrower vendor" "$out"
printf '%s\n' "$out" | grep -q '^add|' && _f "narrower add" "$out" || _p "and nothing is added in their place"
printf '.wordfence.com\n.wordpress.org\n.w.org\n' > "$R"
rm -rf "$T/wp/wp-content/plugins/"* "$T/wp/wp-content/themes/"*; _plug wordfence
[ -z "$(_eg reconcile --check)" ] && _p "a dotted parent already listed covers the host" || _f "covered" "$(_eg reconcile --check)"
printf 'wordpress.org\n.w.org\n' > "$R"
printf '%s\n' "$(_eg reconcile --check)" | grep -q '^skip|.wordpress.org|' && _p "an exact entry does not count as its subdomains" || _f "exact" "$(_eg reconcile --check)"
for pair in "plugin js_composer .wpbakery.com" "plugin bb-plugin .beaverbuilder.com" "plugin gp-premium .generatepress.com" \
            "plugin kadence-blocks-pro .kadencewp.com" "plugin astra-addon support.brainstormforce.com" "theme Extra .elegantthemes.com" \
            "plugin wpvulnerability www.wpvulnerability.net"; do
  set -- $pair
  rm -rf "$T/wp/wp-content/plugins/"* "$T/wp/wp-content/themes/"*; mkdir -p "$T/wp/wp-content/$1s/$2"
  printf '%s\n' "$(_eg reconcile --check)" | grep -q "^add|$3|" && _p "$1 $2 needs $3" || _f "$2" "$(_eg reconcile --check)"
done
mv "$R" "$T/off"
out=$(_eg reconcile); rc=$?
[ "$rc" = 0 ] && [ ! -e "$R" ] && printf '%s' "$out" | grep -q 'not set up' && _p "no egress filtering: nothing created, said so" || _f "off" "$rc $out"
[ -z "$(_eg reconcile --check)" ] && _p "and --check is silent" || _f "off --check" "$(_eg reconcile --check)"
mv "$T/off" "$R"

echo ""
echo "── the client's mail through Microsoft 365 (10.27)"
printf '.wordpress.org\n.w.org\n' > "$R"; rm -f "$D"; rm -rf "$T/wp/wp-content/plugins/"* "$T/wp/wp-content/themes/"*
printf 'transport = m365\ntenant = contoso.example\nfrom = forms@client.example\n' > "$T/client-mail.ini"
out=$(_eg reconcile --check)
printf '%s\n' "$out" | grep -q "^add|login.microsoftonline.com|Microsoft 365 sign-in" && printf '%s\n' "$out" | grep -q '^add|graph.microsoft.com|' \
  && _p "Microsoft 365 for the client's mail needs sign-in and Graph" || _f "m365 egress" "$out"
printf 'transport = smtp\nhost = smtp.gmail.com\n' > "$T/client-mail.ini"
[ -z "$(_eg reconcile --check)" ] && _p "SMTP for the client's mail needs no web egress (it is a firewall pin)" || _f "smtp egress" "$(_eg reconcile --check)"
rm -f "$T/client-mail.ini"

echo ""
echo "── a list Squid refuses is put back"
printf '.w.org\n' > "$R"; cp "$R" "$T/good"
out=$(PARSE_FAIL=1 _eg reconcile); rc=$?
[ "$rc" = 1 ] && cmp -s "$R" "$T/good" && _p "Squid refusing it restores the previous list" || _f "restore" "$rc $(cat "$R")"

echo ""
echo "── discovery names what reconcile would add"
printf '%s\n' "1700000000.000 5 10.89.10.10 TCP_DENIED/403 0 CONNECT support.brainstormforce.com:443 - HIER_NONE/- -" \
              "1700000000.000 5 10.89.10.10 TCP_DENIED/403 0 CONNECT example.com:443 - HIER_NONE/- -" > "$T/sq/logs/access.log"
rm -rf "$T/wp/wp-content/plugins/"*; _plug ultimate-elementor
out=$(_eg discovery)
printf '%s\n' "$out" | grep -A2 'support.brainstormforce.com$' | grep -q 'plugin ultimate-elementor installed' \
  && printf '%s\n' "$out" | grep -q 'REQUIRED here:  doas wasp-egress.sh reconcile' \
  && _p "a denied host an installed plugin needs: named, with the fix" || _f "discovery vendor" "$out"
printf '%s\n' "$out" | grep -q 'probe by wasp-egress test' && _p "wasp-egress test's own probes are labelled" || _f "probe" "$out"

echo ""
printf '  passed %d   failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
