#!/usr/bin/env bash
# =============================================================================
# test-import-source.sh — an import source opens for one download, then closes
# =============================================================================
#
# The point of an import source is that it is NOT on the allowlist. So this
# asserts the window around the transfer, including when the transfer fails,
# with the real wp-import.sh and wasp-egress.sh and curl and podman stubbed.
# Whether Squid honours the window is a live-VM question, not answered here.
# =============================================================================
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
_p() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
_f() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n         %s\n' "$1" "${2:-}"; }

mkdir -p "$T/bin" "$T/inbox" "$T/staging" "$T/etc" "$T/sq/config" "$T/sq/logs"
: > "$T/etc/vars.sh"; printf 'wasp-placeholder.invalid\n' > "$T/sq/config/allowlist-maintenance.txt"
: > "$T/sq/config/allowlist-runtime.txt"

sed -e '/^if \[ "\$(id -u)" -ne 0 \]; then$/,/^fi$/d' \
    -e "s#/etc/wp-install/vars.sh#$T/etc/vars.sh#g" \
    -e "s#^IMPORT_SOURCES=.*#IMPORT_SOURCES=$T/etc/import-sources.txt#" \
    -e "s#^SQ=.*#SQ=$T/sq#" \
    "$REPO/payload/bin/wasp-egress.sh" > "$T/wasp-egress.sh"
sed -e '/^if \[ "\$(id -u)" -ne 0 \]; then$/,/^fi$/d' \
    -e "s#/etc/wp-install/vars.sh#$T/etc/vars.sh#g" \
    -e "s#^INBOX=.*#INBOX=$T/inbox#" \
    -e "s#^STAGING=.*#STAGING=$T/staging#" \
    -e "s#/usr/local/bin/wasp-egress.sh#$T/wasp-egress.sh#g" \
    "$REPO/payload/bin/wp-import.sh" > "$T/wp-import.sh"
chmod +x "$T/wasp-egress.sh"

cat > "$T/bin/podman" <<STUB
#!/usr/bin/env bash
case "\$*" in *'container exists squid'*) exit 0 ;; esac
exit 0
STUB
cat > "$T/bin/curl" <<STUB
#!/usr/bin/env bash
out=""; while [ \$# -gt 0 ]; do case "\$1" in -o) out="\$2"; shift ;; esac; shift; done
cp "$T/sq/config/allowlist-maintenance.txt" "$T/during"
[ "\${CURL_FAIL:-0}" = 1 ] && exit 22
printf 'PK\003\004 archive' > "\$out"
STUB
printf '#!/bin/sh\nexit 0\n' > "$T/bin/logger"; cp "$T/bin/logger" "$T/bin/sleep"
chmod +x "$T/bin/"*

_eg()  { PATH="$T/bin:${WASP_TEST_TOOLS:+$WASP_TEST_TOOLS:}$PATH" ${WASP_TEST_SH:-sh} "$T/wasp-egress.sh" "$@" 2>&1; }
_imp() { PATH="$T/bin:${WASP_TEST_TOOLS:+$WASP_TEST_TOOLS:}$PATH" ${WASP_TEST_SH:-sh} "$T/wp-import.sh" fetch url "$1" 2>&1; }
_closed() { ! grep -qx 'files.example.net' "$T/sq/config/allowlist-maintenance.txt"; }

echo ""
echo "Import sources"
echo ""
echo "── The list"
for bad in .example.net https://files.example.net/ files.example.net/path 'a b.example.net' nodots '*.example.net'; do
  _eg import-source add "$bad" >/dev/null; [ $? = 1 ] && _p "refuses '$bad'" || _f "accepted" "$bad"
done
_eg import-source add files.example.net >/dev/null
grep -qx files.example.net "$T/etc/import-sources.txt" && _p "an exact host is stored" || _f "add" ""
grep -q files "$T/sq/config/allowlist-runtime.txt" && _f "allowlist" "added at runtime" \
  || _p "adding one grants nothing on the runtime allowlist"
_eg import-source add FILES.example.net >/dev/null
[ "$(grep -c . "$T/etc/import-sources.txt")" = 1 ] && _p "case-folded and not duplicated" || _f "dupes" ""

echo ""
echo "── One download"
: > "$T/during"
_imp 'https://files.example.net/get/backup.zip' >/dev/null; rc=$?
[ "$rc" = 0 ] && _p "a listed host downloads" || _f "fetch" "exit $rc"
grep -qx files.example.net "$T/during" && _p "the host is open during the transfer" || _f "open" "$(cat "$T/during")"
_closed && _p "and closed after it" || _f "closed" "$(cat "$T/sq/config/allowlist-maintenance.txt")"

CURL_FAIL=1; export CURL_FAIL
_imp 'https://files.example.net/get/backup2.zip' >/dev/null; rc=$?
unset CURL_FAIL
[ "$rc" = 1 ] && _p "a failed download reports failure" || _f "fail rc" "exit $rc"
_closed && _p "and still closes the window" || _f "closed on failure" ""

: > "$T/during"
_imp 'https://other.example.org/backup3.zip' >/dev/null
grep -q other "$T/during" && _f "unlisted" "opened" || _p "an unlisted host opens nothing"

_eg maintenance enable --duration 30 --reason "operator window for test" --host updates.example.org >/dev/null
_imp 'https://files.example.net/get/backup4.zip' >/dev/null
grep -qx updates.example.org "$T/sq/config/allowlist-maintenance.txt" \
  && _p "an operator's open window is neither replaced nor closed" || _f "clobbered" "$(cat "$T/sq/config/allowlist-maintenance.txt")"

_eg import-source remove files.example.net >/dev/null
_eg import-source has files.example.net >/dev/null && _f "remove" "still listed" || _p "a removed host is gone"

echo ""
printf '  passed %d   failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
