#!/usr/bin/env python3
"""
WASP Hive — a read-only fleet console for WASP VMs.

WATCH ONLY. WASP VMs push signed-in reports here (wasp-hive-report.sh); this
server never connects to them and holds no credential that could. Its only
outbound connection is optional and read-only: a Wazuh manager's API, to show
agent status, file-integrity events and SCA (CIS benchmark) results beside
WASP's own data.

Python standard library only. A console that sees the whole fleet's weak spots
should not also pull a dependency tree from a package registry at install time.

    hive_server.py [--config /etc/wasp-hive/hive.conf]

Everything an operator changes -- enrolling a VM, revoking one, adding a user --
is done with hive_admin.py on this VM's console or over SSH. The web interface
has no write path apart from logging in and out.
"""
import base64
import contextlib
import hashlib
import hmac
import http.server
import json
import os
import re
import secrets
import socketserver
import sqlite3
import ssl
import struct
import sys
import threading
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULTS = {
    "LISTEN_ADDR": "0.0.0.0",
    "LISTEN_PORT": "8443",
    "DATA_DIR": "/var/lib/wasp-hive",
    "CERT": "/etc/wasp-hive/hive.crt",
    "KEY": "/etc/wasp-hive/hive.key",
    "STATIC_DIR": os.path.join(HERE, "static"),
    "COMPLIANCE": os.path.join(HERE, "compliance.json"),
    "STALE_MINUTES": "45",
    "RETENTION_DAYS": "90",
    "SESSION_HOURS": "8",
    "MAX_REPORT_BYTES": "524288",
    "DASHBOARD_CIDRS": "",         # empty = anywhere the firewall allows
    "INGEST_CIDRS": "",
    "WAZUH_URL": "",               # e.g. https://wazuh.example:55000
    "WAZUH_USER": "",
    "WAZUH_PASSWORD_FILE": "",
    "WAZUH_CERT_SHA256": "",       # pin the manager's certificate
    "WAZUH_POLL_MINUTES": "10",
}

NODE_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


# ── Configuration ────────────────────────────────────────────────────────────
def load_config(path):
    """KEY=value lines. Parsed, never executed."""
    cfg = dict(DEFAULTS)
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                if k in DEFAULTS:
                    cfg[k] = v.strip().strip('"').strip("'")
    return cfg


# ── Storage ──────────────────────────────────────────────────────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
  name TEXT PRIMARY KEY, token_hash TEXT NOT NULL, client TEXT DEFAULT '',
  created INTEGER NOT NULL, revoked INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS reports (
  node TEXT NOT NULL, received_at INTEGER NOT NULL, sent_at INTEGER,
  source_ip TEXT, body TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS reports_node_time ON reports(node, received_at);
CREATE TABLE IF NOT EXISTS users (
  name TEXT PRIMARY KEY, pw_hash TEXT NOT NULL, totp_secret TEXT NOT NULL,
  totp_last_step INTEGER DEFAULT 0, created INTEGER NOT NULL, disabled INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions (
  id_hash TEXT PRIMARY KEY, user TEXT NOT NULL, created INTEGER NOT NULL,
  expires INTEGER NOT NULL, ip TEXT);
CREATE TABLE IF NOT EXISTS audit (
  at INTEGER NOT NULL, actor TEXT, action TEXT, detail TEXT, ip TEXT);
CREATE TABLE IF NOT EXISTS wazuh (
  node TEXT PRIMARY KEY, at INTEGER NOT NULL, body TEXT NOT NULL);
"""


class Store:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with self.conn() as c:
            c.executescript(SCHEMA)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    @contextlib.contextmanager
    def conn(self):
        """Commit on success, roll back on error, and always close: sqlite3's
        own context manager commits but leaves the connection open, which in
        a long-running server is a file descriptor per request."""
        c = sqlite3.connect(self.path, timeout=10)
        c.row_factory = sqlite3.Row
        try:
            yield c
            c.commit()
        except BaseException:
            c.rollback()
            raise
        finally:
            c.close()

    def audit(self, actor, action, detail="", ip=""):
        with self.lock, self.conn() as c:
            c.execute("INSERT INTO audit VALUES (?,?,?,?,?)",
                      (int(time.time()), actor, action, detail[:500], ip))


def sha256_hex(s):
    return hashlib.sha256(s.encode()).hexdigest()


# ── Passwords and TOTP ───────────────────────────────────────────────────────
PBKDF2_ITERS = 600000


def hash_password(pw, salt=None):
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ITERS)
    return "pbkdf2_sha256$%d$%s$%s" % (PBKDF2_ITERS, base64.b64encode(salt).decode(),
                                       base64.b64encode(dk).decode())


DUMMY_HASH = "pbkdf2_sha256$%d$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" % PBKDF2_ITERS


def check_password(pw, stored):
    try:
        algo, iters, salt, dk = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        got = hashlib.pbkdf2_hmac("sha256", pw.encode(), base64.b64decode(salt), int(iters))
        return hmac.compare_digest(got, base64.b64decode(dk))
    except (ValueError, TypeError):
        return False


def totp_at(secret_b32, step):
    key = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))
    mac = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % 1000000
    return "%06d" % code


def totp_verify(secret_b32, code, last_step, now=None):
    """Returns the matching time step, or None. A step at or before the last
    one accepted is refused, so a code seen over a shoulder cannot be replayed
    inside its 30 seconds."""
    if not re.fullmatch(r"\d{6}", code or ""):
        return None
    step = int((now or time.time()) // 30)
    for s in (step - 1, step, step + 1):
        if s > last_step and hmac.compare_digest(totp_at(secret_b32, s), code):
            return s
    return None


# ── Compliance ───────────────────────────────────────────────────────────────
def _get(d, path):
    cur = d
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def eval_check(check, report, now):
    """One evidence check against one report -> (ok: bool|None, observed: str).
    None means the report does not carry the evidence (an older WASP)."""
    op = check["op"]
    if op in ("all", "any"):
        results = [eval_check(c, report, now) for c in check["checks"]]
        oks = [r[0] for r in results]
        if None in oks:
            return None, "evidence missing"
        ok = all(oks) if op == "all" else any(oks)
        return ok, "; ".join(r[1] for r in results)
    val = _get(report, check["field"])
    if val is None:
        return None, "not reported"
    shown = ("yes" if val else "no") if isinstance(val, bool) else str(val)
    if op == "eq":
        return val == check["value"], shown
    if op == "in":
        return val in check["value"], shown
    if op == "lte":
        return isinstance(val, (int, float)) and val <= check["value"], str(val)
    if op == "fresh_hours":
        if not isinstance(val, (int, float)) or val <= 0:
            return False, "never"
        age = (now - val) / 3600.0
        return age <= check["value"], "%.0fh ago" % age
    if op == "none_with":
        if not isinstance(val, list):
            return None, "not reported"
        bad = [x for x in val if isinstance(x, dict) and x.get(check["key"]) in check["value"]]
        return not bad, "%d matching" % len(bad)
    if op == "empty":
        return (not val), "%d" % len(val) if isinstance(val, list) else str(val)
    raise ValueError("unknown op " + op)


def evaluate(compliance, report, now):
    """Every framework, every control -> status. Statuses:
       pass / partial / fail  -- WASP evidence decides
       unknown                -- the report lacks the evidence
       operator               -- outside a VM: the MSP's process or another system
       exempt                 -- does not apply to a WASP VM, with the reason"""
    checks = compliance["checks"]
    out = {}
    for fw in compliance["frameworks"]:
        rows, tally = [], {"pass": 0, "partial": 0, "fail": 0, "unknown": 0, "operator": 0, "exempt": 0}
        for ctl in fw["controls"]:
            row = {"id": ctl["id"], "title": ctl["title"], "evidence": []}
            if ctl.get("status") in ("operator", "exempt"):
                row["status"] = ctl["status"]
                row["reason"] = ctl.get("reason", "")
            else:
                oks = []
                for cid in ctl.get("checks", []):
                    ok, observed = eval_check(checks[cid], report, now)
                    oks.append(ok)
                    row["evidence"].append({"check": cid, "title": checks[cid]["title"],
                                            "ok": ok, "observed": observed})
                if not oks or None in oks:
                    row["status"] = "unknown"
                elif all(oks):
                    row["status"] = "pass"
                elif any(oks):
                    row["status"] = "partial"
                else:
                    row["status"] = "fail"
                if ctl.get("note"):
                    row["note"] = ctl["note"]
            tally[row["status"]] += 1
            rows.append(row)
        scored = tally["pass"] + tally["partial"] + tally["fail"] + tally["unknown"]
        score = round(100.0 * (tally["pass"] + 0.5 * tally["partial"]) / scored) if scored else None
        out[fw["id"]] = {"name": fw["name"], "score": score, "tally": tally, "controls": rows}
    return out


# ── Report summary ───────────────────────────────────────────────────────────
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def summarise(report, received_at, now, stale_minutes):
    v = report.get("vulns", {}) or {}
    vc = {s: 0 for s in SEV_ORDER}
    for f in v.get("findings", []) or []:
        if isinstance(f, dict) and f.get("severity") in vc:
            vc[f["severity"]] += 1
    m = report.get("malware", {}) or {}
    mc = {"CRITICAL": 0, "HIGH": 0, "SUSPICIOUS": 0}
    for f in m.get("findings", []) or []:
        if isinstance(f, dict) and f.get("severity") in mc:
            mc[f["severity"]] += 1
    health = (report.get("health") or {}).get("check_rc", 2)
    integ = report.get("integrity") or {}
    cs = report.get("crowdsec") or {}
    asx = cs.get("appsec") or {}
    age_min = (now - received_at) / 60.0
    # One overall state, worst first. Stale beats everything: an old report
    # describes a VM that may no longer exist in that state.
    if age_min > stale_minutes:
        state = "stale"
    elif health == 2 or mc["CRITICAL"] or integ.get("tooling") == "fail" or vc["CRITICAL"]:
        state = "critical"
    elif health == 1 or vc["HIGH"] or mc["HIGH"] or v.get("result") == "incomplete" \
            or integ.get("checksums") == "fail" or not cs.get("lapi_ok", True) \
            or (asx.get("enabled") and not asx.get("listening")):
        state = "warning"
    else:
        state = "ok"
    return {"state": state, "age_minutes": round(age_min, 1), "vulns": vc, "malware": mc,
            "vuln_result": v.get("result", "unknown"),
            "integrity": integ.get("tooling", "unknown"), "checksums": integ.get("checksums", "unknown"),
            "crowdsec": {"decisions": cs.get("decisions", 0), "alerts_24h": cs.get("alerts_24h", 0),
                         "mode": cs.get("mode", "?"), "lapi_ok": cs.get("lapi_ok"),
                         "appsec": bool(asx.get("enabled")), "appsec_listening": bool(asx.get("listening"))},
            "health": (report.get("health") or {}).get("check", ""),
            "release": report.get("wasp_release", "?"),
            "domain": report.get("domain", ""),
            "versions": report.get("versions", {})}


def with_hive_facts(rep, wazuh_row, now, poll_minutes):
    """Evidence the Hive holds and the VM does not, under the reserved "_hive"
    key. A VM cannot assert these: ingest drops any "_hive" a report carries.
    Central logging counts only when the Wazuh manager itself says the agent
    is active, recently -- not because the VM says it has an agent."""
    rep = dict(rep)
    active = False
    if wazuh_row:
        try:
            agent = (json.loads(wazuh_row["body"]) or {}).get("agent") or {}
        except ValueError:
            agent = {}
        fresh = now - wazuh_row["at"] <= max(3 * poll_minutes * 60, 1800)
        active = fresh and agent.get("status") == "active"
    rep["_hive"] = {"wazuh_active": active}
    return rep


def validate_report(rep):
    """Shape checks on what a VM sent. Content is data, shown escaped by the
    dashboard; this keeps a malformed or hostile report from breaking the page
    or the database, not from lying -- a compromised VM can always lie about
    itself, and the console says so."""
    if not isinstance(rep, dict) or rep.get("schema") != 1:
        return "schema must be 1"
    for k in ("health", "vulns", "malware", "integrity", "crowdsec", "backups", "controls"):
        if k in rep and not isinstance(rep[k], dict):
            return "%s must be an object" % k
    for k in ("findings",):
        for sec in ("vulns", "malware"):
            if k in rep.get(sec, {}) and not isinstance(rep[sec][k], list):
                return "%s.%s must be a list" % (sec, k)
    return None


# ── Wazuh (optional, read-only) ──────────────────────────────────────────────
class Wazuh:
    """Polls a Wazuh manager's API with a read-only user and caches what it
    finds per agent name. An agent whose name matches an enrolled node is shown
    on that node's page. The manager's certificate is pinned by SHA-256 when
    WAZUH_CERT_SHA256 is set; without a pin the connection is still encrypted
    but not authenticated, and the dashboard says so."""

    def __init__(self, cfg, store):
        self.cfg, self.store = cfg, store
        self.url = cfg["WAZUH_URL"].rstrip("/")
        self.status = {"configured": bool(self.url), "ok": None, "error": "", "at": 0,
                       "pinned": bool(cfg["WAZUH_CERT_SHA256"])}

    def _req(self, method, path, token=None, auth=None):
        """One request on a connection whose certificate is checked BEFORE
        anything -- the Basic credentials above all -- is sent on it."""
        import http.client
        u = urllib.parse.urlsplit(self.url)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE   # authenticated by the pin below, when set
        conn = http.client.HTTPSConnection(u.hostname, u.port or 55000, timeout=20, context=ctx)
        try:
            conn.connect()
            pin = self.cfg["WAZUH_CERT_SHA256"].replace(":", "").lower()
            if pin:
                der = conn.sock.getpeercert(binary_form=True)
                if hashlib.sha256(der).hexdigest() != pin:
                    raise ssl.SSLError("Wazuh certificate does not match WAZUH_CERT_SHA256")
            headers = {"Accept": "application/json"}
            if token:
                headers["Authorization"] = "Bearer " + token
            if auth:
                headers["Authorization"] = "Basic " + base64.b64encode(auth.encode()).decode()
            conn.request(method, (u.path.rstrip("/") or "") + path, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            if resp.status >= 400:
                raise RuntimeError("Wazuh API %s %s -> HTTP %d" % (method, path, resp.status))
            return json.loads(data.decode())
        finally:
            conn.close()

    def poll_once(self):
        pwfile = self.cfg["WAZUH_PASSWORD_FILE"]
        password = open(pwfile, encoding="utf-8").read().strip() if pwfile else ""
        tok = self._req("POST", "/security/user/authenticate",
                        auth="%s:%s" % (self.cfg["WAZUH_USER"], password))["data"]["token"]
        agents = self._req("GET", "/agents?limit=500&select=id,name,status,version,lastKeepAlive,os.name",
                           token=tok)["data"]["affected_items"]
        with self.store.conn() as c:
            names = {r["name"] for r in c.execute("SELECT name FROM nodes WHERE revoked=0")}
        found = 0
        for a in agents:
            if a.get("name") not in names:
                continue
            found += 1
            aid = a["id"]
            body = {"agent": a}
            try:
                body["fim"] = self._req("GET", "/syscheck/%s?limit=20&sort=-date" % aid,
                                        token=tok)["data"]["affected_items"]
            except Exception as e:  # noqa: BLE001 -- one missing module is not a failed poll
                body["fim_error"] = str(e)[:200]
            try:
                body["sca"] = self._req("GET", "/sca/%s" % aid, token=tok)["data"]["affected_items"]
            except Exception as e:  # noqa: BLE001
                body["sca_error"] = str(e)[:200]
            with self.store.lock, self.store.conn() as c:
                c.execute("INSERT OR REPLACE INTO wazuh VALUES (?,?,?)",
                          (a["name"], int(time.time()), json.dumps(body)))
        self.status.update(ok=True, error="", at=int(time.time()), agents=len(agents), matched=found)

    def run(self):
        while True:
            try:
                self.poll_once()
            except Exception as e:  # noqa: BLE001 -- shown on the dashboard, retried next cycle
                self.status.update(ok=False, error=str(e)[:300], at=int(time.time()))
            time.sleep(max(1, int(self.cfg["WAZUH_POLL_MINUTES"])) * 60)


# ── HTTP ─────────────────────────────────────────────────────────────────────
def ip_allowed(ip, cidrs):
    if not cidrs.strip():
        return True
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs.split(","):
        c = c.strip()
        if c and addr in ipaddress.ip_network(c, strict=False):
            return True
    return False


class Hive:
    def __init__(self, cfg):
        self.cfg = cfg
        self.store = Store(os.path.join(cfg["DATA_DIR"], "hive.db"))
        with open(cfg["COMPLIANCE"], encoding="utf-8") as fh:
            self.compliance = json.load(fh)
        self.wazuh = Wazuh(cfg, self.store)
        self.fails = {}   # ip -> [count, first_at]
        self.fails_lock = threading.Lock()

    # Login throttling: five failures from one address in 15 minutes locks it
    # out for the rest of the window.
    def throttled(self, ip):
        with self.fails_lock:
            n, first = self.fails.get(ip, (0, 0))
            if time.time() - first > 900:
                self.fails.pop(ip, None)
                return False
            return n >= 5

    def failed(self, ip):
        with self.fails_lock:
            n, first = self.fails.get(ip, (0, time.time()))
            self.fails[ip] = (n + 1, first)

    def latest(self, c, node):
        return c.execute("SELECT * FROM reports WHERE node=? ORDER BY received_at DESC LIMIT 1",
                         (node,)).fetchone()

    def prune(self):
        cut = int(time.time()) - int(self.cfg["RETENTION_DAYS"]) * 86400
        with self.store.lock, self.store.conn() as c:
            c.execute("DELETE FROM reports WHERE received_at < ?", (cut,))
            c.execute("DELETE FROM sessions WHERE expires < ?", (int(time.time()),))


SEC_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; "
                               "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
                               "base-uri 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Strict-Transport-Security": "max-age=31536000",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "application/javascript; charset=utf-8"),
          "/app.css": ("app.css", "text/css; charset=utf-8"),
          "/favicon.svg": ("favicon.svg", "image/svg+xml")}


def make_handler(hive):
    cfg = hive.cfg

    class H(http.server.BaseHTTPRequestHandler):
        server_version = "WASP-Hive"
        sys_version = ""
        timeout = 30          # a client that stops talking is dropped

        def log_message(self, fmt, *args):  # one line per request, no bodies
            sys.stderr.write("%s %s\n" % (self.client_address[0], fmt % args))

        def _drain(self):
            """Read a request body nobody consumed (a refused or unused POST)
            before answering. Closing a TLS socket with unread input sends a
            reset, and the client loses the answer -- a 401 becomes a
            "connection reset" in the VM's log."""
            if getattr(self, "_consumed", False) or self.command not in ("POST", "PUT"):
                return
            self._consumed = True
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                n = 0
            if 0 < n <= 4 * int(cfg["MAX_REPORT_BYTES"]):
                try:
                    self.rfile.read(n)
                except OSError:
                    pass
            elif n:
                self.close_connection = True

        def _send(self, code, body=b"", ctype="application/json", extra=None):
            self._drain()
            if isinstance(body, (dict, list)):
                body = json.dumps(body).encode()
            elif isinstance(body, str):
                body = body.encode()
            self.send_response(code)
            for k, v in SEC_HEADERS.items():
                self.send_header(k, v)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if body and self.command != "HEAD":
                self.wfile.write(body)

        def _ip(self):
            return self.client_address[0]

        def _session(self):
            raw = self.headers.get("Cookie", "")
            m = re.search(r"(?:^|;\s*)hive_session=([A-Za-z0-9_-]{20,})", raw)
            if not m:
                return None
            with hive.store.conn() as c:
                r = c.execute("SELECT * FROM sessions WHERE id_hash=? AND expires>?",
                              (sha256_hex(m.group(1)), int(time.time()))).fetchone()
            return r["user"] if r else None

        def _body(self, limit):
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return None
            if n <= 0 or n > limit:
                return None
            self._consumed = True
            return self.rfile.read(n)

        # ── GET ──────────────────────────────────────────────────────────
        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path
            if path == "/api/v1/ping":
                return self._send(200, {"ok": True, "service": "wasp-hive"})
            if path in STATIC:
                if not ip_allowed(self._ip(), cfg["DASHBOARD_CIDRS"]):
                    return self._send(403, {"error": "forbidden"})
                fn, ctype = STATIC[path]
                try:
                    with open(os.path.join(cfg["STATIC_DIR"], fn), "rb") as fh:
                        return self._send(200, fh.read(), ctype)
                except OSError:
                    return self._send(404, {"error": "not found"})
            if not path.startswith("/api/v1/"):
                return self._send(404, {"error": "not found"})
            if not ip_allowed(self._ip(), cfg["DASHBOARD_CIDRS"]):
                return self._send(403, {"error": "forbidden"})
            user = self._session()
            if not user:
                return self._send(401, {"error": "login required"})
            now = time.time()
            if path == "/api/v1/me":
                return self._send(200, {"user": user})
            if path == "/api/v1/fleet":
                return self._send(200, self.fleet(now))
            if path == "/api/v1/frameworks":
                return self._send(200, {"disclaimer": hive.compliance.get("disclaimer", ""),
                                    "frameworks": [{"id": f["id"], "name": f["name"], "scope": f.get("scope", "")}
                                                   for f in hive.compliance["frameworks"]]})
            m = re.fullmatch(r"/api/v1/node/([A-Za-z0-9._-]{1,64})", path)
            if m:
                return self.node(m.group(1), now)
            m = re.fullmatch(r"/api/v1/compliance/([a-z0-9]{1,16})", path)
            if m:
                return self.matrix(m.group(1), now)
            return self._send(404, {"error": "not found"})

        def fleet(self, now):
            stale = int(cfg["STALE_MINUTES"])
            out = []
            with hive.store.conn() as c:
                for n in c.execute("SELECT * FROM nodes WHERE revoked=0 ORDER BY client, name"):
                    r = hive.latest(c, n["name"])
                    item = {"node": n["name"], "client": n["client"]}
                    if r:
                        wz = c.execute("SELECT * FROM wazuh WHERE node=?", (n["name"],)).fetchone()
                        rep = with_hive_facts(json.loads(r["body"]), wz, now, int(cfg["WAZUH_POLL_MINUTES"]))
                        item.update(summarise(rep, r["received_at"], now, stale))
                        ev = evaluate(hive.compliance, rep, now)
                        item["compliance"] = {k: v["score"] for k, v in ev.items()}
                    else:
                        item.update({"state": "never", "compliance": {}})
                    out.append(item)
            return {"generated_at": int(now), "nodes": out, "wazuh": hive.wazuh.status,
                    "stale_minutes": stale}

        def matrix(self, fwid, now):
            """One framework across the fleet: controls down, nodes across."""
            fw = next((f for f in hive.compliance["frameworks"] if f["id"] == fwid), None)
            if not fw:
                return self._send(404, {"error": "no such framework"})
            cols = []
            with hive.store.conn() as c:
                for n in c.execute("SELECT * FROM nodes WHERE revoked=0 ORDER BY client, name"):
                    r = hive.latest(c, n["name"])
                    col = {"node": n["name"], "client": n["client"]}
                    if r:
                        wz = c.execute("SELECT * FROM wazuh WHERE node=?", (n["name"],)).fetchone()
                        rep = with_hive_facts(json.loads(r["body"]), wz, now, int(cfg["WAZUH_POLL_MINUTES"]))
                        ev = evaluate(hive.compliance, rep, now)[fwid]
                        col.update(state=summarise(rep, r["received_at"], now, int(cfg["STALE_MINUTES"]))["state"],
                                   score=ev["score"], statuses=[row["status"] for row in ev["controls"]])
                    else:
                        col.update(state="never", score=None, statuses=[])
                    cols.append(col)
            return self._send(200, {
                "disclaimer": hive.compliance.get("disclaimer", ""),
                "framework": {"id": fw["id"], "name": fw["name"], "scope": fw.get("scope", ""),
                              "controls": [{k: ctl[k] for k in ("id", "title", "status", "reason", "note", "checks")
                                            if k in ctl} for ctl in fw["controls"]]},
                "checks": {k: v["title"] for k, v in hive.compliance["checks"].items()},
                "nodes": cols})

        def node(self, name, now):
            with hive.store.conn() as c:
                n = c.execute("SELECT * FROM nodes WHERE name=? AND revoked=0", (name,)).fetchone()
                if not n:
                    return self._send(404, {"error": "no such node"})
                r = hive.latest(c, name)
                hist = c.execute(
                    "SELECT received_at, body FROM reports WHERE node=? AND received_at>? ORDER BY received_at",
                    (name, int(now) - 30 * 86400)).fetchall()
                wz = c.execute("SELECT * FROM wazuh WHERE node=?", (name,)).fetchone()
            if not r:
                return self._send(200, {"node": name, "client": n["client"], "state": "never"})
            rep = with_hive_facts(json.loads(r["body"]), wz, now, int(cfg["WAZUH_POLL_MINUTES"]))
            # History thinned to at most one point per hour: 30 days of
            # 15-minute reports is 2,880 rows, and a sparkline needs 720.
            series, last_hour = [], None
            for h in hist:
                hr = h["received_at"] // 3600
                if hr == last_hour:
                    continue
                last_hour = hr
                s = summarise(json.loads(h["body"]), h["received_at"], h["received_at"], 10 ** 9)
                series.append({"t": h["received_at"], "vuln": sum(s["vulns"].values()),
                               "malware": s["malware"]["CRITICAL"] + s["malware"]["HIGH"],
                               "decisions": s["crowdsec"]["decisions"] or 0,
                               "alerts": s["crowdsec"]["alerts_24h"] or 0,
                               "disk": (json.loads(h["body"]).get("health") or {}).get("disk_used_pct", 0)})
            return self._send(200, {
                "node": name, "client": n["client"], "received_at": r["received_at"],
                "source_ip": r["source_ip"],
                "summary": summarise(rep, r["received_at"], now, int(cfg["STALE_MINUTES"])),
                "report": rep, "compliance": evaluate(hive.compliance, rep, now),
                "history": series,
                "wazuh": json.loads(wz["body"]) if wz else None,
                "wazuh_at": wz["at"] if wz else None,
                "wazuh_status": hive.wazuh.status})

        # ── POST ─────────────────────────────────────────────────────────
        def do_POST(self):
            path = urllib.parse.urlsplit(self.path).path
            if path == "/api/v1/report":
                return self.ingest()
            if not ip_allowed(self._ip(), cfg["DASHBOARD_CIDRS"]):
                return self._send(403, {"error": "forbidden"})
            # Same-origin only. The session cookie is SameSite=Strict as well;
            # this is the second lock on the same door.
            origin = self.headers.get("Origin")
            host = self.headers.get("Host", "")
            if origin and urllib.parse.urlsplit(origin).netloc != host:
                return self._send(403, {"error": "cross-origin request refused"})
            if path == "/api/v1/login":
                return self.login()
            if path == "/api/v1/logout":
                return self.logout()
            return self._send(404, {"error": "not found"})

        def ingest(self):
            ip = self._ip()
            if not ip_allowed(ip, cfg["INGEST_CIDRS"]):
                return self._send(403, {"error": "forbidden"})
            node = self.headers.get("X-Hive-Node", "")
            auth = self.headers.get("Authorization", "")
            if not NODE_RE.match(node) or not auth.startswith("Bearer "):
                return self._send(401, {"error": "unauthorised"})
            token = auth[7:].strip()
            with hive.store.conn() as c:
                n = c.execute("SELECT token_hash FROM nodes WHERE name=? AND revoked=0", (node,)).fetchone()
            # Compared as hashes, constant-time. An unknown node and a wrong
            # token give the same answer.
            if not n or not hmac.compare_digest(n["token_hash"], sha256_hex(token)):
                hive.store.audit(node, "ingest-refused", "bad token", ip)
                return self._send(401, {"error": "unauthorised"})
            raw = self._body(int(cfg["MAX_REPORT_BYTES"]))
            if raw is None:
                return self._send(413, {"error": "missing or too large"})
            try:
                rep = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return self._send(400, {"error": "not JSON"})
            err = validate_report(rep)
            if err:
                return self._send(400, {"error": err})
            # The token decides which row this is, not the body. A VM cannot
            # write another VM's report by naming it.
            rep["node"] = node
            rep.pop("_hive", None)
            with hive.store.lock, hive.store.conn() as c:
                c.execute("INSERT INTO reports VALUES (?,?,?,?,?)",
                          (node, int(time.time()), rep.get("sent_at"), ip, json.dumps(rep)))
            return self._send(204)

        def login(self):
            ip = self._ip()
            if hive.throttled(ip):
                return self._send(429, {"error": "too many failed logins; wait 15 minutes"})
            raw = self._body(4096)
            try:
                d = json.loads(raw.decode()) if raw else {}
            except ValueError:
                d = {}
            user, pw, code = str(d.get("user", "")), str(d.get("password", "")), str(d.get("totp", ""))
            with hive.store.conn() as c:
                u = c.execute("SELECT * FROM users WHERE name=? AND disabled=0", (user,)).fetchone()
            # Password and code both checked, then one answer. Which one was
            # wrong is not said.
            step = None
            # An unknown user costs the same PBKDF2 as a known one, so the
            # response time does not say which names exist.
            if not u:
                check_password(pw, DUMMY_HASH)
            elif check_password(pw, u["pw_hash"]):
                step = totp_verify(u["totp_secret"], code, u["totp_last_step"])
            if step is None:
                hive.failed(ip)
                hive.store.audit(user[:64], "login-failed", "", ip)
                return self._send(401, {"error": "invalid login"})
            sid = secrets.token_urlsafe(32)
            exp = int(time.time()) + int(cfg["SESSION_HOURS"]) * 3600
            with hive.store.lock, hive.store.conn() as c:
                c.execute("UPDATE users SET totp_last_step=? WHERE name=?", (step, user))
                c.execute("INSERT INTO sessions VALUES (?,?,?,?,?)",
                          (sha256_hex(sid), user, int(time.time()), exp, ip))
            hive.store.audit(user, "login", "", ip)
            cookie = ("hive_session=%s; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=%d"
                      % (sid, int(cfg["SESSION_HOURS"]) * 3600))
            return self._send(200, {"user": user}, extra={"Set-Cookie": cookie})

        def logout(self):
            raw = self.headers.get("Cookie", "")
            m = re.search(r"(?:^|;\s*)hive_session=([A-Za-z0-9_-]{20,})", raw)
            if m:
                with hive.store.lock, hive.store.conn() as c:
                    c.execute("DELETE FROM sessions WHERE id_hash=?", (sha256_hex(m.group(1)),))
            return self._send(200, {"ok": True},
                              extra={"Set-Cookie": "hive_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"})

        def do_HEAD(self):
            return self.do_GET()

    return H


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """TLS is negotiated in each connection's own thread, not in accept():
    wrapping the listening socket would let one client that opens a
    connection and never finishes the handshake stall every other one."""
    daemon_threads = True
    allow_reuse_address = True
    tls = None

    def finish_request(self, request, client_address):
        request.settimeout(15)
        try:
            request = self.tls.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            request.close()
            return
        try:
            super().finish_request(request, client_address)
        finally:
            try:
                request.close()
            except OSError:
                pass


def main(argv):
    cfg_path = "/etc/wasp-hive/hive.conf"
    if len(argv) > 2 and argv[1] == "--config":
        cfg_path = argv[2]
    cfg = load_config(cfg_path)
    hive = Hive(cfg)
    srv = Server((cfg["LISTEN_ADDR"], int(cfg["LISTEN_PORT"])), make_handler(hive))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cfg["CERT"], cfg["KEY"])
    srv.tls = ctx
    if hive.wazuh.url:
        threading.Thread(target=hive.wazuh.run, daemon=True).start()

    def pruner():
        while True:
            try:
                hive.prune()
            except sqlite3.Error:
                pass
            time.sleep(3600)
    threading.Thread(target=pruner, daemon=True).start()
    sys.stderr.write("WASP Hive listening on %s:%s\n" % (cfg["LISTEN_ADDR"], cfg["LISTEN_PORT"]))
    srv.serve_forever()


if __name__ == "__main__":
    main(sys.argv)
