#!/usr/bin/env bash
# =============================================================================
# test-mail-wordpress.sh — operator and client mail paths on REAL WordPress
# =============================================================================
#
# 01-wpvm-smtp.php sends WASP's own alerts through the operator relay and the
# site's mail (contact forms, password resets) through the client's server:
# Microsoft 365 over Graph, or SMTP submission. This runs it inside a real
# WordPress, through wp_mail(), against two SMTP sinks that speak STARTTLS and
# AUTH like a real server, and a stand-in for Microsoft's two endpoints:
#
#   - no client settings: everything goes to the relay, From the relay's
#   - client SMTP: site mail to the client's server with the client's From and
#     the visitor's Reply-To; alerts and lockout notices still to the relay
#   - Microsoft 365: sign-in with the app's id and secret, then the whole MIME
#     message (attachment, Reply-To, Bcc) to /users/<mailbox>/sendMail; nothing
#     to the relay
#   - the client path failing (a dead server, Graph refusing, a message too big
#     for Graph): wp_mail() still succeeds, through the relay, Reply-To kept,
#     marked as a fallback, and the reason logged
#   - a half-written client file is ignored and logged, not a failure
#
# Needs: WASP_TEST_WP (a WordPress checkout), WASP_TEST_WPCLI (wp-cli.phar),
# mariadbd and mariadb, php with mysqli and openssl, python3, openssl. Without
# them it says SKIPPED and why.
# =============================================================================
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0; FAIL=0
_p() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
_f() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n         %s\n' "$1" "${2:-}"; }
echo ""
echo "Operator and client mail on real WordPress"
WPSRC="${WASP_TEST_WP:-}"; WPCLI="${WASP_TEST_WPCLI:-}"
if [ -z "$WPSRC" ] || [ ! -f "$WPSRC/wp-load.php" ] || [ -z "$WPCLI" ] || [ ! -f "$WPCLI" ] \
   || ! command -v mariadbd >/dev/null 2>&1 || ! php -m | grep -qi mysqli \
   || ! command -v python3 >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
  echo "  SKIPPED: set WASP_TEST_WP=<WordPress checkout> and WASP_TEST_WPCLI=<wp-cli.phar>; needs mariadbd, php-mysqli, python3, openssl"
  exit 0
fi
T=$(mktemp -d); PORT=$((36000 + RANDOM % 2000)); OP=$((PORT + 1)); CL=$((PORT + 2))
cleanup() {
  for p in ${DBPID:-} ${S1:-} ${S2:-}; do kill "$p" 2>/dev/null; done
  wait 2>/dev/null; rm -rf "$T"
}
trap cleanup EXIT

# ── two SMTP servers: STARTTLS, AUTH, each message saved to a file ──
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/key.pem" -out "$T/cert.pem" -days 2 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" >/dev/null 2>&1
cat > "$T/sink.py" <<'PY'
import socket, ssl, sys, os, base64, threading
port, outdir, cert, key = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH); ctx.load_cert_chain(cert, key)
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(8)
n = [0]
def serve(c):
    f = c.makefile("rb"); w = lambda s: c.sendall((s + "\r\n").encode())
    w("220 sink ESMTP"); user = ""; tls = False; rcpt = []
    while True:
        line = f.readline()
        if not line: return
        cmd = line.decode(errors="replace").strip(); up = cmd.upper()
        if up.startswith("EHLO") or up.startswith("HELO"):
            c.sendall(b"250-sink\r\n" + (b"250-AUTH PLAIN LOGIN\r\n" if tls else b"250-STARTTLS\r\n") + b"250 8BITMIME\r\n")
        elif up == "STARTTLS":
            w("220 go"); c = ctx.wrap_socket(c, server_side=True); f = c.makefile("rb"); tls = True
            w = (lambda cc: (lambda s: cc.sendall((s + "\r\n").encode())))(c)
        elif up.startswith("AUTH PLAIN"):
            parts = cmd.split(" ")
            if len(parts) < 3: w("334 "); parts.append(f.readline().decode().strip())
            user = base64.b64decode(parts[2]).split(b"\0")[1].decode(); w("235 ok")
        elif up.startswith("AUTH LOGIN"):
            w("334 VXNlcm5hbWU6"); user = base64.b64decode(f.readline().strip()).decode()
            w("334 UGFzc3dvcmQ6"); f.readline(); w("235 ok")
        elif up.startswith("MAIL FROM"):
            env = cmd[10:]; rcpt = []; w("250 ok")
        elif up.startswith("RCPT TO"):
            rcpt.append(cmd[8:]); w("250 ok")
        elif up == "DATA":
            w("354 go"); data = b""
            while True:
                l = f.readline()
                if l in (b".\r\n", b".\n", b""): break
                data += l
            n[0] += 1
            with open(os.path.join(outdir, "msg%d.eml" % n[0]), "wb") as o:
                o.write(("X-Sink-User: %s\r\nX-Sink-Envelope: %s\r\nX-Sink-Rcpt: %s\r\n" % (user, env, ",".join(rcpt))).encode() + data)
            w("250 queued")
        elif up == "QUIT":
            w("221 bye"); c.close(); return
        else:
            w("250 ok")
while True:
    c, _ = srv.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
mkdir -p "$T/op" "$T/cl"
python3 "$T/sink.py" "$OP" "$T/op" "$T/cert.pem" "$T/key.pem" >"$T/s1.log" 2>&1 & S1=$!
python3 "$T/sink.py" "$CL" "$T/cl" "$T/cert.pem" "$T/key.pem" >"$T/s2.log" 2>&1 & S2=$!

mariadb-install-db --no-defaults --datadir="$T/db" --user=root --auth-root-authentication-method=normal >/dev/null 2>&1
mariadbd --no-defaults --datadir="$T/db" --socket="$T/m.sock" --port="$PORT" --bind-address=127.0.0.1 --user=root >"$T/m.log" 2>&1 &
DBPID=$!
for _ in $(seq 1 30); do mariadb --no-defaults -S "$T/m.sock" -u root -e 'SELECT 1' >/dev/null 2>&1 && break; sleep 1; done
mariadb --no-defaults -S "$T/m.sock" -u root -e "CREATE DATABASE wp; CREATE USER 'wp'@'127.0.0.1' IDENTIFIED BY 'wp'; GRANT ALL ON wp.* TO 'wp'@'127.0.0.1';"
cp -a "$WPSRC" "$T/wp"; rm -f "$T/wp/wp-config.php"
# The sinks' certificate is trusted the way a real relay's would be: by CA.
W() { php -d openssl.cafile="$T/cert.pem" -d error_log= "$WPCLI" --allow-root --path="$T/wp" "$@"; }
W config create --dbname=wp --dbuser=wp --dbpass=wp --dbhost="127.0.0.1:$PORT" --skip-check >/dev/null 2>&1
W config set WPVM_SMTP_CONFIG "$T/private/smtp.ini" >/dev/null 2>&1
W config set WPVM_CLIENT_MAIL_CONFIG "$T/private/client-mail.ini" >/dev/null 2>&1
W core install --url=https://shop.example --title=Shop --admin_user=owner --admin_password="pw$RANDOM$RANDOM" \
  --admin_email=owner@shop.example --skip-email >/dev/null 2>&1 || { _f "WordPress did not install" "$(tail -5 "$T/m.log")"; exit 1; }
mkdir -p "$T/wp/wp-content/mu-plugins" "$T/private" "$T/graph"
cp "$REPO/payload/mu-plugins/01-wpvm-smtp.php" "$T/wp/wp-content/mu-plugins/"

# Microsoft's two endpoints, answered inside WordPress's own HTTP API.
cat > "$T/wp/wp-content/mu-plugins/zz-graph-standin.php" <<PHP
<?php
add_filter('pre_http_request', function (\$pre, \$args, \$url) {
    \$d = '$T/graph';
    if (strpos(\$url, 'https://login.microsoftonline.com/') === 0) {
        file_put_contents("\$d/token-url", \$url); file_put_contents("\$d/token-body", http_build_query(\$args['body']));
        if (file_exists("\$d/deny-signin")) {
            return array('headers' => array(), 'body' => '{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided.\r\nTrace ID: x"}', 'response' => array('code' => 401, 'message' => 'Unauthorized'), 'cookies' => array(), 'filename' => null);
        }
        return array('headers' => array(), 'body' => '{"access_token":"tok-123","expires_in":3599}', 'response' => array('code' => 200, 'message' => 'OK'), 'cookies' => array(), 'filename' => null);
    }
    if (strpos(\$url, 'https://graph.microsoft.com/') === 0) {
        file_put_contents("\$d/send-url", \$url); file_put_contents("\$d/send-auth", \$args['headers']['Authorization']);
        file_put_contents("\$d/send-type", \$args['headers']['Content-Type']); file_put_contents("\$d/send-body", \$args['body']);
        if (file_exists("\$d/deny-send")) {
            return array('headers' => array(), 'body' => '{"error":{"code":"ErrorAccessDenied","message":"Access is denied. Check credentials and try again."}}', 'response' => array('code' => 403, 'message' => 'Forbidden'), 'cookies' => array(), 'filename' => null);
        }
        return array('headers' => array(), 'body' => '', 'response' => array('code' => 202, 'message' => 'Accepted'), 'cookies' => array(), 'filename' => null);
    }
    return \$pre;
}, 10, 3);
PHP

b64() { printf '%s' "$1" | base64 | tr -d '\n'; }
cat > "$T/private/smtp.ini" <<INI
host = localhost
port = $OP
user = alerts@operator.example
pass_b64 = $(b64 'relay pass')
from = alerts@operator.example
from_name = Shop site
encryption = tls
timeout = 5
INI
client_smtp() {  # $1 = port
  cat > "$T/private/client-mail.ini" <<INI
transport = smtp
host = localhost
port = $1
user = forms@shop.example
pass_b64 = $(b64 'client app password')
from = forms@shop.example
from_name = Shop website
encryption = tls
timeout = 3
INI
}
client_m365() {
  cat > "$T/private/client-mail.ini" <<INI
transport = m365
tenant = shop.example
client_id = 3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90
secret_b64 = $(b64 'app~secret=value;with"odd')
from = forms@shop.example
from_name = Shop website
INI
}
reset() { rm -f "$T"/op/* "$T"/cl/* "$T"/graph/*; }
nop() { ls "$T/op" | wc -l | tr -d ' '; }
ncl() { ls "$T/cl" | wc -l | tr -d ' '; }
msg() { cat "$1"/*.eml 2>/dev/null | tr -d '\r'; }   # one message per case: reset empties the folder

# One wp_mail() as a plugin would call it. $1 = kind.
cat > "$T/send.php" <<'PHP'
<?php
$kind = getenv('KIND');
$h = array('Reply-To: Visitor <visitor@home.example>');
$att = array();
if ($kind === 'alert')    { $h = array('X-WASP-Alert: admin_created'); }
if ($kind === 'lockout')  { $h = array('X-WASP-Mail: operator'); }
if ($kind === 'force')    { $h[] = 'X-WASP-Mail: client'; }
if ($kind === 'bcc')      { $h[] = 'Bcc: archive@shop.example'; }
if ($kind === 'attach' || $kind === 'big') {
    $f = sys_get_temp_dir() . '/wasp-photo-' . getmypid() . '.jpg';
    file_put_contents($f, $kind === 'big' ? random_bytes(3200000) : 'JPEGDATA');
    $att[] = $f;
}
$ok = wp_mail('office@shop.example', 'New enquiry', "Name: Pat\nMessage: a new fence", $h, $att);
echo $ok ? "SENT\n" : "FAILED\n";
PHP
send() { KIND="$1" W eval-file "$T/send.php" 2>&1; }

echo ""
echo "── no client settings: one path, the relay"
reset; rm -f "$T/private/client-mail.ini"
out=$(send plain)
{ printf '%s' "$out" | grep -q SENT && [ "$(nop)" = 1 ] && [ "$(ncl)" = 0 ]; } && _p "site mail goes to the relay" || _f "relay only" "$out op=$(nop) cl=$(ncl)"
m=$(msg "$T/op")
printf '%s' "$m" | grep -q '^From: Shop site <alerts@operator.example>' && printf '%s' "$m" | grep -q '^X-Sink-User: alerts@operator.example' \
  && _p "...signed in as, and From, the relay's mailbox" || _f "relay From" "$m"
printf '%s' "$m" | grep -q '^Reply-To: Visitor <visitor@home.example>' && _p "...the visitor's Reply-To kept" || _f "reply-to" "$m"
reset; out=$(send force)
[ "$(nop)" = 1 ] && _p "asking for the client path with none set up uses the relay" || _f "force without client" "$out"

echo ""
echo "── client SMTP: site mail to the client, WASP's own mail to the relay"
client_smtp "$CL"
reset; out=$(send plain)
{ printf '%s' "$out" | grep -q SENT && [ "$(ncl)" = 1 ] && [ "$(nop)" = 0 ]; } && _p "a form's mail goes to the client's server, not the relay" || _f "client smtp" "$out op=$(nop) cl=$(ncl)"
m=$(msg "$T/cl")
printf '%s' "$m" | grep -q '^X-Sink-User: forms@shop.example' && printf '%s' "$m" | grep -q '^From: Shop website <forms@shop.example>' \
  && _p "...signed in as, and From, the client's mailbox" || _f "client From" "$m"
printf '%s' "$m" | grep -q '^X-Sink-Envelope: <forms@shop.example>' && _p "...envelope sender the client's too (SPF aligns)" || _f "envelope" "$m"
printf '%s' "$m" | grep -q '^Reply-To: Visitor <visitor@home.example>' && _p "...Reply-To the visitor" || _f "client reply-to" "$m"
reset; out=$(send alert)
{ [ "$(nop)" = 1 ] && [ "$(ncl)" = 0 ]; } && _p "a security alert (X-WASP-Alert) still goes to the relay" || _f "alert route" "op=$(nop) cl=$(ncl) $out"
msg "$T/op" | grep -q '^From: Shop site <alerts@operator.example>' && _p "...From the relay's mailbox" || _f "alert from" "$(msg "$T/op")"
reset; out=$(send lockout)
{ [ "$(nop)" = 1 ] && [ "$(ncl)" = 0 ]; } && _p "a lockout notice (X-WASP-Mail: operator) goes to the relay" || _f "lockout route" "op=$(nop) cl=$(ncl)"

echo ""
echo "── client SMTP down: the enquiry still arrives"
client_smtp 1
reset; out=$(send plain)
printf '%s' "$out" | grep -q SENT && _p "wp_mail() still reports success, so the form shows no error" || _f "fallback result" "$out"
m=$(msg "$T/op")
[ "$(nop)" = 1 ] && printf '%s' "$m" | grep -q '^X-WASP-Mail-Fallback: client mail failed' && _p "...sent through the relay, marked as a fallback" || _f "fallback relay" "$out op=$(nop) $m"
printf '%s' "$m" | grep -q '^From: Shop site <alerts@operator.example>' && printf '%s' "$m" | grep -q '^Reply-To: Visitor <visitor@home.example>' \
  && _p "...From the relay's mailbox (it would refuse the client's), Reply-To the visitor" || _f "fallback headers" "$m"
printf '%s' "$m" | grep -q '^X-Sink-Rcpt: <office@shop.example>$' && _p "...to the same recipient, once" || _f "fallback rcpt" "$m"
printf '%s' "$out" | grep -q '\[wpvm-smtp\] client mail failed (.*); sent through the operator relay instead' \
  && _p "...and the reason is logged" || _f "fallback log" "$out"

echo ""
echo "── Microsoft 365 through Graph: no SMTP at all"
client_m365
reset; out=$(send attach)
{ printf '%s' "$out" | grep -q SENT && [ "$(nop)" = 0 ] && [ "$(ncl)" = 0 ]; } && _p "sent, and neither SMTP server was contacted" || _f "graph route" "$out op=$(nop) cl=$(ncl)"
[ "$(cat "$T/graph/token-url" 2>/dev/null)" = "https://login.microsoftonline.com/shop.example/oauth2/v2.0/token" ] \
  && _p "signs in at the tenant's token endpoint" || _f "token url" "$(cat "$T/graph/token-url" 2>/dev/null)"
tb=$(cat "$T/graph/token-body" 2>/dev/null)
printf '%s' "$tb" | grep -q 'grant_type=client_credentials' && printf '%s' "$tb" | grep -q 'client_id=3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90' \
  && printf '%s' "$tb" | grep -q 'scope=https%3A%2F%2Fgraph.microsoft.com%2F.default' \
  && printf '%s' "$tb" | grep -q 'client_secret=app%7Esecret%3Dvalue%3Bwith%22odd' \
  && _p "...as the app: client credentials, Graph scope, the secret exactly as stored" || _f "token body" "$tb"
[ "$(cat "$T/graph/send-url")" = "https://graph.microsoft.com/v1.0/users/forms%40shop.example/sendMail" ] \
  && [ "$(cat "$T/graph/send-auth")" = "Bearer tok-123" ] && [ "$(cat "$T/graph/send-type")" = "text/plain" ] \
  && _p "sends as the client's mailbox, with the token, as base64 MIME" || _f "send request" "$(cat "$T"/graph/send-url "$T"/graph/send-auth 2>/dev/null)"
mime=$(base64 -d < "$T/graph/send-body" 2>/dev/null | tr -d '\r')
printf '%s' "$mime" | grep -q '^From: Shop website <forms@shop.example>' && printf '%s' "$mime" | grep -q '^To: office@shop.example' \
  && printf '%s' "$mime" | grep -q '^Subject: New enquiry' && printf '%s' "$mime" | grep -q '^Reply-To: Visitor <visitor@home.example>' \
  && _p "...the message as WordPress built it: From, To, Subject, Reply-To" || _f "mime headers" "$(printf '%s' "$mime" | head -20)"
printf '%s' "$mime" | grep -q 'filename=wasp-photo-[0-9]*.jpg' && printf '%s' "$mime" | grep -q "$(printf 'JPEGDATA' | base64)" \
  && _p "...with the uploaded photo attached" || _f "attachment" "$(printf '%s' "$mime" | grep -i filename)"
reset; send bcc >/dev/null
base64 -d < "$T/graph/send-body" 2>/dev/null | tr -d '\r' | grep -q '^Bcc: archive@shop.example' && _p "a Bcc goes in the message Graph reads its recipients from" || _f "bcc" "$(base64 -d < "$T/graph/send-body" | head -12)"
reset; out=$(send alert)
{ [ "$(nop)" = 1 ] && [ ! -e "$T/graph/send-url" ]; } && _p "a security alert still goes to the relay, not Microsoft" || _f "alert with m365" "op=$(nop) $out"

echo ""
echo "── Microsoft 365 refusing: the enquiry still arrives"
reset; touch "$T/graph/deny-send"; out=$(send plain)
{ printf '%s' "$out" | grep -q SENT && [ "$(nop)" = 1 ] && msg "$T/op" | grep -q '^X-WASP-Mail-Fallback'; } \
  && _p "Graph refusing to send: delivered through the relay" || _f "graph 403 fallback" "$out op=$(nop)"
printf '%s' "$out" | grep -q 'HTTP 403 ErrorAccessDenied.*may not send as forms@shop.example' && _p "...the log says the app may not send as that mailbox" || _f "403 log" "$out"
reset; touch "$T/graph/deny-signin"; out=$(send plain)
{ [ "$(nop)" = 1 ] && printf '%s' "$out" | grep -q 'Microsoft sign-in refused (HTTP 401): AADSTS7000215: Invalid client secret provided.'; } \
  && _p "an expired or wrong secret: delivered through the relay, the reason logged in one line" || _f "signin fallback" "$out"
printf '%s' "$out" | grep -q 'Trace ID' && _f "log line" "carries Microsoft's second line" || _p "...without Microsoft's trace lines"
printf '%s' "$out" | grep -q 'app~secret' && _f "secret" "the secret appeared in the output" || _p "...and the secret never appears"
reset; out=$(send big)
{ printf '%s' "$out" | grep -q SENT && [ "$(nop)" = 1 ] && [ ! -e "$T/graph/send-url" ] && printf '%s' "$out" | grep -q 'over what Microsoft Graph accepts'; } \
  && _p "a message too big for one Graph request goes through the relay instead" || _f "big" "$out op=$(nop)"

echo ""
echo "── a half-written client file"
printf 'transport = m365\ntenant = shop.example\nfrom = forms@shop.example\n' > "$T/private/client-mail.ini"
reset; out=$(send plain)
{ printf '%s' "$out" | grep -q SENT && [ "$(nop)" = 1 ] && printf '%s' "$out" | grep -q 'client-mail.ini (m365) needs tenant, client_id, secret_b64 and from'; } \
  && _p "is ignored with a logged reason; mail keeps going through the relay" || _f "invalid" "$out"
printf 'transport = carrier-pigeon\n' > "$T/private/client-mail.ini"
reset; out=$(send plain)
{ [ "$(nop)" = 1 ] && printf '%s' "$out" | grep -q 'unknown transport "carrier-pigeon"'; } && _p "an unknown transport too" || _f "unknown" "$out"

echo ""
printf '  passed %d   failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
