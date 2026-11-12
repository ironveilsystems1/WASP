#!/usr/bin/env bash
# =============================================================================
# test-appsec.sh — the CrowdSec AppSec option: forwarder, tool, firewall rule
# =============================================================================
#
# 1. The REAL PHP forwarder (payload/php-conf/wasp-appsec.php), run by PHP's
#    built-in server as auto_prepend_file, against a stand-in AppSec listener
#    that records what it receives and answers as told. Checks the protocol
#    (headers, GET vs POST, the body), blocking, fail-open and fail-closed, the
#    timeout, a client trying to spoof X-Crowdsec-Appsec-Ip, the container's
#    proxy settings being ignored, and the max_body bound.
# 2. wasp-fw-rule.sh with a recording nft: rules are applied live AND
#    persisted, a rule that does not load is never kept, and output rules for
#    management and mail ports are refused.
# 3. wasp-appsec.sh with stubbed podman: the memory watchdog restarts CrowdSec
#    at its threshold and not below, memory sizes in every unit podman prints
#    are read correctly, a refused key rolls back, and an upstream VM is told
#    where to make its key.
#
# Not covered here: the real CrowdSec engine. Rule names and the light
# configuration are checked on a live VM by `wasp-appsec.sh test`.
# =============================================================================
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
T=$(mktemp -d); PIDS=""
trap 'for p in $PIDS; do kill "$p" 2>/dev/null; done; rm -rf "$T"' EXIT
PASS=0; FAIL=0
_p() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
_f() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n         %s\n' "$1" "${2:-}"; }
_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }

echo ""
echo "CrowdSec AppSec option"

# ── 1. The forwarder ─────────────────────────────────────────────────────────
if command -v php >/dev/null 2>&1 && php -m 2>/dev/null | grep -qi '^curl$'; then
  AP=$(_port); WP=$(_port)
  # Stand-in AppSec listener. Behaviour per request from $T/mode:
  #   allow | ban | error | sleep
  cat > "$T/fake_appsec.py" <<'PY'
import http.server, json, os, sys, time
D = sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def handle_error(self, *a): pass
    def _do(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        rec = {"method": self.command, "headers": {k.lower(): v for k, v in self.headers.items()},
               "body": body.decode("latin-1")}
        with open(os.path.join(D, "seen.jsonl"), "a") as fh:
            fh.write(json.dumps(rec) + "\n")
        mode = open(os.path.join(D, "mode")).read().strip()
        if mode == "sleep":
            time.sleep(1.5); code, out = 200, {"action": "allow"}
        elif mode == "ban":
            code, out = 403, {"action": "ban", "http_status": 403}
        elif mode == "error":
            code, out = 500, None
        else:
            code, out = 200, {"action": "allow"}
        b = json.dumps(out).encode()
        try:
            self.send_response(code); self.send_header("Content-Length", str(len(b))); self.end_headers()
            self.wfile.write(b)
        except OSError:
            pass   # the forwarder gave up waiting: that is the point of the sleep case
    do_GET = _do
    do_POST = _do
http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
  echo allow > "$T/mode"
  python3 "$T/fake_appsec.py" "$AP" "$T" & PIDS="$PIDS $!"
  mkdir -p "$T/docroot"
  # PHP's built-in server does not apply auto_prepend_file to a router
  # script, so the router does what auto_prepend_file does on the VM: the
  # forwarder first, then the site. Every path goes through it.
  printf '<?php\nrequire %s;\nrequire __DIR__ . "/index.php";\n' "'$REPO/payload/php-conf/wasp-appsec.php'" > "$T/docroot/router.php"
  cat > "$T/docroot/index.php" <<'PHP'
<?php
file_put_contents(getenv('RAN_MARK'), "ran\n", FILE_APPEND);
echo "site:" . strlen((string) file_get_contents('php://input'));
PHP
  _ini() { printf 'enabled = %s\nurl = http://127.0.0.1:%s/\nkey = testkey123\ntimeout_ms = %s\nmax_body = %s\nfailure_action = %s\n' \
             "${1:-1}" "${6:-$AP}" "${2:-200}" "${3:-1024}" "${4:-passthrough}" > "$T/appsec.ini"; }
  _ini
  # The container's proxy variables are set to a dead address: the forwarder
  # must not use them.
  mkdir -p "$T/tmp"
  ( cd "$T/docroot" && WASP_APPSEC_CONF="$T/appsec.ini" RAN_MARK="$T/ran" TMPDIR="$T/tmp" \
      http_proxy=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 \
      exec php -d variables_order=EGPCS -S "127.0.0.1:$WP" router.php >/dev/null 2>"$T/php.log" ) & PIDS="$PIDS $!"
  for _i in 1 2 3 4 5 6 7 8 9 10; do
    curl -s -o /dev/null "http://127.0.0.1:$AP/" 2>/dev/null && curl -s -o /dev/null "http://127.0.0.1:$WP/" 2>/dev/null && break
    sleep 0.3
  done
  : > "$T/seen.jsonl"; : > "$T/ran"
  _req() { curl -s -o "$T/out" -w '%{http_code}' --max-time 5 "$@"; }
  _last() { tail -1 "$T/seen.jsonl" | python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }

  _c=$(_req -A 'test-agent/1' -H 'X-Crowdsec-Appsec-Ip: 203.0.113.9' "http://127.0.0.1:$WP/shop/?q=1")
  if [ "$_c" = 200 ] && grep -q ran "$T/ran"; then _p "an allowed request reaches the site"; else _f "allowed request" "HTTP $_c"; fi
  _h=$(_last 'd["method"]+"|"+d["headers"].get("x-crowdsec-appsec-verb","")+"|"+d["headers"].get("x-crowdsec-appsec-uri","")+"|"+d["headers"].get("x-crowdsec-appsec-api-key","")+"|"+d["headers"].get("x-crowdsec-appsec-user-agent","")+"|"+d["headers"].get("x-crowdsec-appsec-http-version","")')
  [ "$_h" = "GET|GET|/shop/?q=1|testkey123|test-agent/1|11" ] \
    && _p "the protocol headers carry the method, URI, key, user agent and HTTP version" || _f "protocol headers" "$_h"
  [ "$(_last 'd["headers"].get("x-crowdsec-appsec-ip","")')" = "127.0.0.1" ] \
    && _p "a client cannot choose the address AppSec judges (its X-Crowdsec-Appsec-Ip is dropped)" \
    || _f "spoofed address forwarded" "$(_last 'd["headers"].get("x-crowdsec-appsec-ip")')"
  [ -n "$(_last 'd["headers"].get("x-crowdsec-appsec-host","")')" ] && _p "the Host is forwarded" || _f "host header" ""

  _c=$(_req -d 'log=admin&pwd=x%27+OR+1%3D1' "http://127.0.0.1:$WP/wp-login.php")
  [ "$_c" = 200 ] && [ "$(_last 'd["method"]+"|"+d["body"]')" = "POST|log=admin&pwd=x%27+OR+1%3D1" ] \
    && _p "a form body is forwarded unchanged, by POST" || _f "form body" "$(_last 'd["method"]+"|"+d["body"]')"
  _c=$(_req -H 'Content-Type: application/json' -d '{"a":"<script>"}' "http://127.0.0.1:$WP/wp-json/x")
  [ "$(_last 'd["body"]')" = '{"a":"<script>"}' ] && _p "a JSON body is forwarded" || _f "json body" "$(_last 'd["body"]')"
  : > "$T/ran"
  _c=$(_req -F 'title=hello' -F "file=@$T/appsec.ini" "http://127.0.0.1:$WP/upload.php")
  _b=$(_last 'd["body"]+"|"+d["headers"].get("content-type","")')
  [ "$_b" = "title=hello|application/x-www-form-urlencoded" ] \
    && _p "multipart: the fields are forwarded url-encoded, the file is not" || _f "multipart" "$_b"
  head -c 4096 /dev/zero | tr '\0' 'a' > "$T/big"
  _c=$(_req --data-binary @"$T/big" "http://127.0.0.1:$WP/big")
  [ "$_c" = 200 ] && [ "$(_last 'd["method"]+"|"+str(len(d["body"]))+"|"+d["headers"].get("x-crowdsec-appsec-verb","")')" = "GET|0|POST" ] \
    && _p "a body over max_body is not forwarded (the request still is, with its real verb)" \
    || _f "max_body" "$(_last 'd["method"]+"|"+str(len(d["body"]))')"

  echo ban > "$T/mode"; : > "$T/ran"
  _c=$(_req "http://127.0.0.1:$WP/wp-content/plugins/vuln/x.php?id=1")
  { [ "$_c" = 403 ] && ! grep -q ran "$T/ran"; } \
    && _p "a matched request gets 403 and the site's PHP never runs" || _f "ban" "HTTP $_c, ran=$(cat "$T/ran")"

  echo error > "$T/mode"; : > "$T/ran"
  _req "http://127.0.0.1:$WP/" >/dev/null; _req "http://127.0.0.1:$WP/" >/dev/null
  _c=$(_req "http://127.0.0.1:$WP/")
  [ "$_c" = 200 ] && grep -q ran "$T/ran" && _p "AppSec error (500): fail-open by default, the request passes" || _f "fail-open" "HTTP $_c"
  _ini 1 200 1024 ban
  _c=$(_req "http://127.0.0.1:$WP/")
  [ "$_c" = 503 ] && _p "AppSec error with failure_action = ban: refused (503), fail-closed" || _f "fail-closed" "HTTP $_c"
  _ini 1 200 1024 passthrough
  echo sleep > "$T/mode"
  _t0=$(date +%s%N); _c=$(_req "http://127.0.0.1:$WP/"); _t1=$(date +%s%N)
  _ms=$(( (_t1 - _t0) / 1000000 ))
  { [ "$_c" = 200 ] && [ "$_ms" -lt 1200 ]; } && _p "a slow AppSec costs at most the timeout (${_ms} ms), then passes" || _f "timeout" "HTTP $_c in ${_ms} ms"
  echo allow > "$T/mode"
  _ini 1 200 1024 passthrough "$(_port)"
  _c=$(_req "http://127.0.0.1:$WP/")
  [ "$_c" = 200 ] && _p "AppSec not listening: passes, and is logged" || _f "refused connection" "HTTP $_c"
  _ini 0
  : > "$T/seen.jsonl"
  _c=$(_req "http://127.0.0.1:$WP/")
  { [ "$_c" = 200 ] && [ ! -s "$T/seen.jsonl" ]; } && _p "enabled = 0: nothing is forwarded at all" || _f "disabled" "forwarded anyway"
  grep -q 'wasp-appsec' "$T/php.log" && _p "failures are logged under [wasp-appsec]" || _f "no log line" "$(tail -3 "$T/php.log")"
  [ "$(grep -c 'AppSec unavailable (500): requests pass' "$T/php.log")" = 1 ] && _p "three failures in a row are logged once (once a minute at most)" \
    || _f "log flood" "$(grep 'AppSec unavailable' "$T/php.log")"
else
  _f "php with the curl extension is needed for the forwarder tests" ""
fi

# ── 2. wasp-fw-rule.sh ──────────────────────────────────────────────────────
mkdir -p "$T/bin" "$T/etc"
cat > "$T/bin/nft" <<STUB
#!/bin/sh
printf '%s\n' "\$*" >> "$T/nft.log"
case "\$1" in
  -c) [ -e "$T/nft-bad" ] && { echo "Error: syntax error" >&2; exit 1; }; exit 0 ;;
  -a) printf '\tip saddr 10.89.10.3 tcp dport 7422 accept comment "wasp:appsec" # handle 42\n'; exit 0 ;;
esac
exit 0
STUB
chmod +x "$T/bin/nft"
printf 'flush ruleset\n' > "$T/etc/nftables.nft"
_fw() { env PATH="$T/bin:${WASP_TEST_TOOLS:+$WASP_TEST_TOOLS:}$PATH" WASP_RULES_FILE="$T/etc/wasp-rules.nft" NFT_MAIN="$T/etc/nftables.nft" \
        ${WASP_TEST_SH:-sh} "$REPO/payload/bin/wasp-fw-rule.sh" "$@" 2>&1; }
: > "$T/nft.log"
_o=$(_fw add appsec input ip saddr 10.89.10.3 ip daddr 10.89.10.1 tcp dport 7422 accept); _rc=$?
{ [ "$_rc" = 0 ] && grep -qx 'add rule inet filter input ip saddr 10.89.10.3 ip daddr 10.89.10.1 tcp dport 7422 accept comment "wasp:appsec"' "$T/etc/wasp-rules.nft" \
  && grep -q 'add rule inet filter input ip saddr 10.89.10.3' "$T/nft.log"; } \
  && _p "an input rule is applied live and persisted" || _f "add input" "$_o"
grep -qF 'include "'"$T/etc/wasp-rules.nft"'"' "$T/etc/nftables.nft" && _p "the persisted file is included by the ruleset" || _f "include" "$(cat "$T/etc/nftables.nft")"
_fw add appsec input ip saddr 10.89.10.3 ip daddr 10.89.10.1 tcp dport 7422 accept >/dev/null
[ "$(grep -c 'wasp:appsec' "$T/etc/wasp-rules.nft")" = 1 ] && _p "adding the same tag again replaces, never duplicates" || _f "duplicate" "$(cat "$T/etc/wasp-rules.nft")"
grep -q 'delete rule inet filter input handle 42' "$T/nft.log" && _p "the old live rule is found by its comment and removed" || _f "live replace" "$(cat "$T/nft.log")"
_fw add hive output ip daddr 192.0.2.5 tcp dport 8443 accept >/dev/null
grep -q '^insert rule inet filter output ip daddr 192.0.2.5 tcp dport 8443 accept comment "wasp:hive"' "$T/etc/wasp-rules.nft" \
  && _p "an output rule is inserted above the egress list's final drop" || _f "output insert" "$(cat "$T/etc/wasp-rules.nft")"
_o=$(_fw add hive output ip daddr 192.0.2.5 tcp dport 8006 accept); _rc=$?
[ "$_rc" != 0 ] && _p "an output rule for the Proxmox management port is refused" || _f "8006 allowed" "$_o"
_o=$(_fw add x output ip daddr 192.0.2.5 tcp dport 25 accept); _rc=$?
[ "$_rc" != 0 ] && _p "an output rule for mail (25) is refused" || _f "25 allowed" "$_o"
cp "$T/etc/wasp-rules.nft" "$T/before"; : > "$T/nft-bad"
_o=$(_fw add other input ip saddr 10.0.0.9 tcp dport 9999 accept); _rc=$?
rm -f "$T/nft-bad"
{ [ "$_rc" != 0 ] && cmp -s "$T/before" "$T/etc/wasp-rules.nft"; } \
  && _p "a rule that does not load with the ruleset is never kept for the next boot" || _f "bad rule kept" "$(cat "$T/etc/wasp-rules.nft")"
_o=$(_fw add evil input 'ip saddr 203.0.113.9 accept; flush ruleset'); _rc=$?
[ "$_rc" != 0 ] && _p "a rule smuggling a second statement is refused" || _f "injection" "$_o"
_fw del appsec >/dev/null
! grep -q 'wasp:appsec' "$T/etc/wasp-rules.nft" && _p "del removes it from disk (and live, by handle)" || _f "del" "$(cat "$T/etc/wasp-rules.nft")"

# ── 3. wasp-appsec.sh ───────────────────────────────────────────────────────
mkdir -p "$T/as/cs" "$T/as/secrets" "$T/as/phpconf" "$T/as/state" "$T/as/etc"
printf "WP_EXTRA_VOLS='-v /a:/b:ro'\n" > "$T/as/etc/wp-run-extra.env"
cat > "$T/bin/podman" <<STUB
#!/bin/sh
printf '%s\n' "\$*" >> "$T/podman.log"
case "\$1 \$2" in
  "inspect -f") case "\$*" in *Running*) echo true ;; *Pid*) echo 999999 ;; esac ;;
  "stats --no-stream") cat "$T/mem" ;;
  "restart crowdsec") : ;;
  "exec crowdsec") case "\$*" in *"bouncers add"*) echo "localkey123" ;; esac ;;
esac
exit 0
STUB
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "%s/logger.log"\n' "$T" > "$T/bin/logger"
printf '#!/bin/sh\nexit 0\n' > "$T/bin/rc-service"
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "%s/fw.log"\n' "$T" > "$T/bin/fwrule"
chmod +x "$T/bin/"*
_as() { env PATH="$T/bin:${WASP_TEST_TOOLS:+$WASP_TEST_TOOLS:}$PATH" WASP_ETC="$T/as/etc" CS_CONF_DIR="$T/as/cs" \
        WP_SECRETS_DIR="$T/as/secrets" WP_PHPCONF_DIR="$T/as/phpconf" APPSEC_STATE="$T/as/state" WASP_PAYLOAD="$REPO/payload" \
        FW_RULE="$T/bin/fwrule" APPSEC_PORT="${ASP:-1}" ${WASP_TEST_SH:-sh} "$REPO/payload/bin/wasp-appsec.sh" "$@" 2>&1; }

# A listener that answers (with 401 to any key): watchdog restarts wait for
# it, and `on` below must roll back when it refuses the key.
ASP=$(_port)
cat > "$T/fake401.py" <<'PY'
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(401); self.send_header("Content-Length", "4"); self.end_headers(); self.wfile.write(b"null")
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
python3 "$T/fake401.py" "$ASP" & PIDS="$PIDS $!"
export ASP
sleep 0.5
printf 'enabled = 1\nkey = k\n' > "$T/as/secrets/appsec.ini"
for _case in "480.2MB / 536.9MB:restart" "460.2MB / 536.9MB:none" "120.5MB / 536.9MB:none" "1.2GB / 2GB:restart" "300MiB / 512MiB:none" "470MiB / 512MiB:restart"; do
  printf '%s\n' "${_case%:*}" > "$T/mem"; : > "$T/podman.log"
  _as watchdog >/dev/null
  if grep -q 'restart crowdsec' "$T/podman.log"; then _got=restart; else _got=none; fi
  [ "$_got" = "${_case##*:}" ] && _p "watchdog at '${_case%% /*}': ${_got}" || _f "watchdog at '${_case%% /*}'" "expected ${_case##*:}, got ${_got}"
done
[ "$(grep -c . "$T/as/state/restarts")" = 3 ] && _p "every watchdog restart is recorded (for the Hive and status)" || _f "restarts recorded" "$(cat "$T/as/state/restarts")"
grep -q '#4797' "$T/logger.log" && _p "a watchdog restart is logged with the reason" || _f "restart reason" "$(cat "$T/logger.log")"
printf 'enabled = 0\n' > "$T/as/secrets/appsec.ini"; printf '470MiB / 512MiB\n' > "$T/mem"; : > "$T/podman.log"
_as watchdog >/dev/null
! grep -q restart "$T/podman.log" && _p "with AppSec off the watchdog does nothing" || _f "watchdog while off" ""

# The listener refuses the key: `on` must roll back and leave no AppSec files.
rm -f "$T/as/secrets/appsec.ini"; : > "$T/fw.log"
_o=$(_as on --yes); _rc=$?
{ [ "$_rc" != 0 ] && [ ! -e "$T/as/cs/acquis.d/wasp-appsec.yaml" ] && [ ! -e "$T/as/cs/appsec-configs/wasp-appsec-light.yaml" ] \
  && [ ! -e "$T/as/secrets/appsec.ini" ] && [ ! -s "$T/fw.log" ]; } \
  && _p "a refused API key rolls everything back: no listener config, no firewall rule, forwarder off" \
  || _f "rollback" "rc=$_rc $(printf '%s' "$_o" | tail -4)"
printf 'enforcement=upstream\n' > "$T/as/etc/crowdsec-topology"
_o=$(_as on --yes); _rc=$?
{ [ "$_rc" = 2 ] && printf '%s' "$_o" | grep -q 'cscli bouncers add'; } \
  && _p "on an upstream VM, it says where to make the key instead of guessing" || _f "upstream key" "rc=$_rc"
_o=$(_as on --yes --max-body 9999999); _rc=$?
[ "$_rc" = 2 ] && _p "max_body is capped at 1 MiB" || _f "max-body cap" "rc=$_rc"

# The two configuration files parse as YAML and say what the docs say.
if python3 -c 'import yaml' 2>/dev/null; then
  _y=$(python3 -c "import yaml,sys; a=yaml.safe_load(open(sys.argv[1])); c=yaml.safe_load(open(sys.argv[2])); print(a['source'], a['appsec_configs'], c['name'], 'outofband_rules' in c, any('crs' in r for r in c['inband_rules']))" \
        "$REPO/payload/crowdsec/appsec/wasp-appsec.yaml" "$REPO/payload/crowdsec/appsec/wasp-appsec-light.yaml")
  [ "$_y" = "appsec ['wasp/appsec-light'] wasp/appsec-light False False" ] \
    && _p "the listener points at the light config, which has no out-of-band rules and no CRS" || _f "yaml" "$_y"
fi

echo ""
printf '  passed %d   failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
