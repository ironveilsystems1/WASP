#!/usr/bin/env bash
# =============================================================================
# test-tls-check.sh — the certificate check sees what a browser would
# =============================================================================
#
# 10.28: `wp-hardening.sh tls` checks the bare domain AND www, verifies the
# chain and the name as a browser does, and the daily `tls-check` mails a site
# it cannot reach (after one retry) instead of exiting 1 in silence. A www with
# no DNS record is skipped, said; the primary name with none is a problem.
#
# Real TLS: a throwaway CA, an intermediate and leaf certificates, served by
# Python's ssl module on local ports; the real openssl client checks them.
# =============================================================================
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
T=$(mktemp -d)
PIDS=""
trap 'for p in $PIDS; do kill "$p" 2>/dev/null; done; rm -rf "$T"' EXIT
PASS=0; FAIL=0
_p() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
_f() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n         %s\n' "$1" "${2:-}"; }
echo ""
echo "TLS check: both names, the chain, and an unreachable site"
command -v openssl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 \
  || { echo "  SKIPPED — needs openssl and python3"; exit 0; }

cd "$T" || exit 1
_cnf() { printf '[req]\ndistinguished_name=dn\n[dn]\n[ca]\nbasicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\n[leaf]\nbasicConstraints=CA:false\nsubjectAltName=%s\n' "$1" > "$T/x.cnf"; }
_cnf "DNS:x"
openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.pem -days 30 -subj "/CN=Test Root" -config x.cnf -extensions ca 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout int.key -out int.csr -subj "/CN=Test Intermediate R1" -config x.cnf 2>/dev/null
openssl x509 -req -in int.csr -CA root.pem -CAkey root.key -CAcreateserial -out int.pem -days 30 -extfile x.cnf -extensions ca 2>/dev/null
_leaf() {  # name days san
  _cnf "$3"
  openssl req -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=$1" -config x.cnf 2>/dev/null
  openssl x509 -req -in "$1.csr" -CA int.pem -CAkey int.key -CAcreateserial -out "$1.pem" -days "$2" -extfile x.cnf -extensions leaf 2>/dev/null
  cat "$1.pem" int.pem > "$1.chain.pem"
}
_leaf good 25 "DNS:site.example,DNS:www.site.example"
_leaf soon 5 "DNS:site.example,DNS:www.site.example"
_leaf apex 25 "DNS:site.example"
[ -s good.chain.pem ] && [ -s apex.chain.pem ] || { _f "could not make test certificates" ""; exit 1; }

cat > serve.py <<'PY'
import socket, ssl, sys, threading
port, chain, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(chain, key)
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", port)); s.listen(8)
print("ready", flush=True)
def h(c):
    try:
        t = ctx.wrap_socket(c, server_side=True); t.recv(1); t.close()
    except Exception:
        c.close()
while True:
    c, _ = s.accept(); threading.Thread(target=h, args=(c,), daemon=True).start()
PY
_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
_serve() {  # chain key -> port
  _pt=$(_port)
  python3 -I serve.py "$_pt" "$1" "$2" > "srv.$_pt" 2>&1 &
  PIDS="$PIDS $!"
  for _i in 1 2 3 4 5 6 7 8 9 10; do grep -q ready "srv.$_pt" 2>/dev/null && break; sleep 0.3; done
  echo "$_pt"
}
P_GOOD=$(_serve good.chain.pem good.key)
P_SOON=$(_serve soon.chain.pem soon.key)
P_LEAF=$(_serve good.pem good.key)
P_APEX=$(_serve apex.chain.pem apex.key)
P_DOWN=$(_port)

mkdir -p bin
cat > bin/wp-notify.sh <<STUB
#!/bin/sh
printf 'SUBJECT %s\n' "\$2" >> "$T/mail"; cat "\$3" >> "$T/mail"
STUB
printf '#!/bin/sh\nexit 0\n' > bin/logger
printf '#!/bin/sh\nexit 1\n' > bin/nslookup
chmod +x bin/*
sed -e '/^if \[ "\$(id -u)" -ne 0 \]; then$/,/^fi$/d' \
    -e "s#/etc/wp-install/vars.sh#$T/vars.sh#g" \
    -e "s#/usr/local/bin/wp-notify.sh#$T/bin/wp-notify.sh#g" \
    "$REPO/payload/bin/wp-hardening.sh" > hard.sh
: > vars.sh
_tls() {  # port cmd [args]
  _pt="$1"; shift
  env PATH="$T/bin:${WASP_TEST_TOOLS:+$WASP_TEST_TOOLS:}$PATH" WP_DOMAIN=site.example TLS_CHECK_ADDR=127.0.0.1 \
      TLS_CHECK_PORT="$_pt" TLS_CHECK_CAFILE="$T/root.pem" TLS_RETRY_WAIT=0 \
      ${WASP_TEST_SH:-sh} "$T/hard.sh" "$@" 2>&1
}

echo ""
echo "── a good certificate"
out=$(_tls "$P_GOOD" tls); rc=$?
[ "$rc" = 0 ] && _p "good chain, both names: exit 0" || _f "good rc" "rc=$rc $out"
printf '%s\n' "$out" | grep -q '^  site.example$' && printf '%s\n' "$out" | grep -q '^  www.site.example$' \
  && _p "both the bare domain and www are checked" || _f "names" "$out"
[ "$(printf '%s\n' "$out" | grep -c 'chain and name verified (Test Intermediate R1)')" = 2 ] \
  && _p "each says chain and name verified, and the issuer" || _f "verified" "$out"
: > mail; out=$(_tls "$P_GOOD" tls-check); rc=$?
[ "$rc" = 0 ] && [ ! -s mail ] && _p "the daily check is silent when all is well" || _f "quiet" "rc=$rc $(cat mail)"

echo ""
echo "── what a browser would refuse"
out=$(_tls "$P_LEAF" tls); rc=$?
[ "$rc" = 2 ] && printf '%s\n' "$out" | grep -q 'incomplete chain' && _p "a leaf without its intermediate: refused, 'incomplete chain'" || _f "chain" "rc=$rc $out"
out=$(_tls "$P_APEX" tls); rc=$?
printf '%s\n' "$out" | grep -A1 '^  site.example$' | grep -q 'verified' \
  && printf '%s\n' "$out" | grep -A1 '^  www.site.example$' | grep -q 'does not cover www.site.example' \
  && [ "$rc" = 2 ] && _p "a certificate without www: the apex passes, www fails, by name" || _f "www" "rc=$rc $out"
: > mail; _tls "$P_APEX" tls-check >/dev/null
grep -q '^SUBJECT TLS certificate for www.site.example is refused by browsers' mail && _p "and the daily check mails it" || _f "www mail" "$(cat mail)"
: > mail; out=$(_tls "$P_SOON" tls); rc=$?
[ "$rc" = 2 ] && printf '%s\n' "$out" | grep -q '⚠ [45] day(s) left' && _p "5 days left: warned, exit 2 (7 or fewer)" || _f "soon" "rc=$rc $out"
_tls "$P_SOON" tls-check >/dev/null
grep -q '^SUBJECT TLS certificate for site.example expires in [45] days' mail && _p "and mailed" || _f "soon mail" "$(cat mail)"
[ "$(grep -c '^SUBJECT' mail)" = 1 ] && grep -q 'www.site.example' mail && _p "one mail naming every affected name" || _f "one mail" "$(cat mail)"

echo ""
echo "── a site that cannot be reached"
: > mail; out=$(_tls "$P_DOWN" tls-check); rc=$?
[ "$rc" = 0 ] && grep -q '^SUBJECT site.example could not be reached over HTTPS' mail && _p "unreachable: mailed (it was exit 1 and silence)" || _f "down" "rc=$rc $(cat mail)"
grep -q 'tried twice' mail && _p "after a retry, and saying it may be this VM's own path" || _f "retry" "$(cat mail)"
out=$(_tls "$P_DOWN" tls); rc=$?
[ "$rc" = 2 ] && printf '%s\n' "$out" | grep -q 'could not connect to 127.0.0.1' && _p "interactively: could not connect, with the address" || _f "down tls" "rc=$rc $out"

echo ""
echo "── names and DNS"
out=$(env PATH="$T/bin:$PATH" WP_DOMAIN=www.site.example TLS_CHECK_PORT="$P_GOOD" TLS_CHECK_ADDR=127.0.0.1 TLS_CHECK_CAFILE="$T/root.pem" ${WASP_TEST_SH:-sh} "$T/hard.sh" tls 2>&1)
printf '%s\n' "$out" | grep -q '^  www.site.example$' && printf '%s\n' "$out" | grep -q '^  site.example$' \
  && _p "a WP_DOMAIN that is www: the bare name is checked too" || _f "www primary" "$out"
out=$(_tls "$P_GOOD" tls other.example); rc=$?
[ "$(printf '%s\n' "$out" | grep -c '^  [a-z]')" = 1 ] && [ "$rc" = 2 ] && _p "a name given checks only that name (and this one is not covered)" || _f "given" "rc=$rc $out"
printf '#!/bin/sh\ncase "$1" in\n  site.example) printf "Server:\\t10.0.0.1\\nAddress:\\t10.0.0.1:53\\n\\nName:\\tsite.example\\nAddress: 127.0.0.1\\n" ;;\n  *) exit 1 ;;\nesac\n' > bin/nslookup
: > mail
out=$(env PATH="$T/bin:$PATH" WP_DOMAIN=site.example TLS_CHECK_PORT="$P_GOOD" TLS_CHECK_CAFILE="$T/root.pem" TLS_RETRY_WAIT=0 ${WASP_TEST_SH:-sh} "$T/hard.sh" tls 2>&1); rc=$?
printf '%s\n' "$out" | grep -A1 '^  site.example$' | grep -q verified && printf '%s\n' "$out" | grep -A1 '^  www.site.example$' | grep -q 'no DNS record' \
  && [ "$rc" = 0 ] && _p "the address comes from DNS; a www with no record is skipped, said, exit 0" || _f "dns" "rc=$rc $out"
env PATH="$T/bin:$PATH" WP_DOMAIN=site.example TLS_CHECK_PORT="$P_GOOD" TLS_CHECK_CAFILE="$T/root.pem" TLS_RETRY_WAIT=0 ${WASP_TEST_SH:-sh} "$T/hard.sh" tls-check >/dev/null 2>&1
[ ! -s mail ] && _p "...and the daily check does not mail it" || _f "dns mail" "$(cat mail)"
printf '#!/bin/sh\nexit 1\n' > bin/nslookup
env PATH="$T/bin:$PATH" WP_DOMAIN=site.example TLS_CHECK_PORT="$P_GOOD" TLS_CHECK_CAFILE="$T/root.pem" TLS_RETRY_WAIT=0 ${WASP_TEST_SH:-sh} "$T/hard.sh" tls-check >/dev/null 2>&1
grep -q '^SUBJECT site.example could not be reached' mail && grep -q 'no DNS record' mail && _p "the site's own name with no DNS record is mailed" || _f "primary dns" "$(cat mail)"
grep -q '^127.0.0.1  site.example www.site.example$' "$REPO/lib/05-ssh-and-network-inject.sh" 2>/dev/null || \
  grep -q "127.0.0.1  %s www.%s" "$REPO/lib/05-ssh-and-network-inject.sh" && _p "(the loopback hosts entry this avoids is still written by the installer)" || _f "hosts" ""

echo ""
printf '  passed %d   failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
