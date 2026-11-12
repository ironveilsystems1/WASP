#!/usr/bin/env python3
"""test-hive.py — WASP Hive server: authentication, ingest, compliance engine.

Standard library only, like the server. Starts the real server on localhost
with a throwaway key for the HTTP tests.

    python3 test/test-hive.py
"""
import http.client
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "hive"))
sys.path.insert(0, HERE)
import hive_server as hs  # noqa: E402
import hive_fixtures as fx  # noqa: E402

COMPLIANCE = json.load(open(os.path.join(REPO, "hive", "compliance.json"), encoding="utf-8"))
SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"


class Crypto(unittest.TestCase):
    def test_password_roundtrip(self):
        h = hs.hash_password("correct horse battery")
        self.assertTrue(h.startswith("pbkdf2_sha256$600000$"))
        self.assertTrue(hs.check_password("correct horse battery", h))
        self.assertFalse(hs.check_password("correct horse batterY", h))
        self.assertFalse(hs.check_password("x", "garbage"))
        self.assertFalse(hs.check_password("x", hs.DUMMY_HASH))

    def test_totp_rfc6238_vector(self):
        # RFC 6238 appendix B, SHA-1, T=59 -> 94287082 (8 digits); 6 digits = 287082
        secret = __import__("base64").b32encode(b"12345678901234567890").decode()
        self.assertEqual(hs.totp_at(secret, 59 // 30), "287082")

    def test_totp_window_and_replay(self):
        now = 1_800_000_000
        step = now // 30
        code = hs.totp_at(SECRET, step)
        self.assertEqual(hs.totp_verify(SECRET, code, 0, now), step)
        self.assertEqual(hs.totp_verify(SECRET, hs.totp_at(SECRET, step - 1), 0, now), step - 1)
        self.assertIsNone(hs.totp_verify(SECRET, hs.totp_at(SECRET, step - 2), 0, now), "outside +-1 step")
        self.assertIsNone(hs.totp_verify(SECRET, code, step, now), "the same code twice is a replay")
        self.assertIsNone(hs.totp_verify(SECRET, "12345", 0, now))
        self.assertIsNone(hs.totp_verify(SECRET, "abcdef", 0, now))


class Engine(unittest.TestCase):
    def setUp(self):
        self.now = time.time()
        self.rep = fx.report("n1", "www.example.com", {}, self.now)

    def test_every_check_has_evidence_in_a_report(self):
        """A check whose field no report carries is a control that can only
        ever be 'unknown'. _hive.* is added by the Hive itself."""
        rep = hs.with_hive_facts(self.rep, None, self.now, 10)
        for cid, chk in COMPLIANCE["checks"].items():
            subs = chk["checks"] if chk["op"] in ("any", "all") else [chk]
            for sub in subs:
                self.assertIsNotNone(hs._get(rep, sub["field"]), "%s: %s not in a report" % (cid, sub["field"]))

    def test_compliance_file_is_consistent(self):
        for fw in COMPLIANCE["frameworks"]:
            seen = set()
            for ctl in fw["controls"]:
                self.assertNotIn(ctl["id"], seen, fw["id"])
                seen.add(ctl["id"])
                if ctl.get("status"):
                    self.assertIn(ctl["status"], ("operator", "exempt"))
                    self.assertTrue(ctl.get("reason"), "%s %s needs a reason" % (fw["id"], ctl["id"]))
                else:
                    self.assertTrue(ctl.get("checks"), "%s %s has no evidence" % (fw["id"], ctl["id"]))
                    for k in ctl["checks"]:
                        self.assertIn(k, COMPLIANCE["checks"])

    def test_clean_report_scores(self):
        ev = hs.evaluate(COMPLIANCE, hs.with_hive_facts(self.rep, None, self.now, 10), self.now)
        self.assertEqual(set(ev), {f["id"] for f in COMPLIANCE["frameworks"]})
        cis = {c["id"]: c for c in ev["cis8"]["controls"]}
        self.assertEqual(cis["6.3"]["status"], "pass")
        self.assertEqual(cis["8.9"]["status"], "fail", "no Wazuh means no central logs")
        self.assertEqual(cis["14"]["status"], "operator")
        self.assertEqual(cis["10.2"]["status"], "exempt")
        t = ev["cis8"]["tally"]
        scored = t["pass"] + t["partial"] + t["fail"] + t["unknown"]
        self.assertEqual(ev["cis8"]["score"], round(100.0 * (t["pass"] + 0.5 * t["partial"]) / scored))

    def test_findings_move_controls(self):
        self.rep["vulns"]["findings"] = [{"severity": "CRITICAL", "component": "x 1", "title": "t", "cve": ""}]
        self.rep["controls"]["mfa_enforce"] = False
        ev = hs.evaluate(COMPLIANCE, self.rep, self.now)
        cis = {c["id"]: c for c in ev["cis8"]["controls"]}
        self.assertEqual(cis["7.4"]["status"], "partial")
        self.assertEqual(cis["6.3"]["status"], "fail")
        self.assertEqual(cis["6.3"]["evidence"][0]["observed"], "no")

    def test_older_wasp_is_unknown_not_fail(self):
        del self.rep["controls"]
        ev = hs.evaluate(COMPLIANCE, self.rep, self.now)
        cis = {c["id"]: c for c in ev["cis8"]["controls"]}
        self.assertEqual(cis["6.3"]["status"], "unknown")

    def test_wazuh_evidence_comes_from_the_manager(self):
        row = {"at": int(self.now), "body": json.dumps({"agent": {"status": "active"}})}
        self.assertTrue(hs.with_hive_facts(self.rep, row, self.now, 10)["_hive"]["wazuh_active"])
        row_old = {"at": int(self.now) - 7200, "body": row["body"]}
        self.assertFalse(hs.with_hive_facts(self.rep, row_old, self.now, 10)["_hive"]["wazuh_active"])
        row_dis = {"at": int(self.now), "body": json.dumps({"agent": {"status": "disconnected"}})}
        self.assertFalse(hs.with_hive_facts(self.rep, row_dis, self.now, 10)["_hive"]["wazuh_active"])

    def test_summarise_states(self):
        s = lambda r, age=60: hs.summarise(r, self.now - age, self.now, 45)["state"]  # noqa: E731
        self.assertEqual(s(self.rep), "ok")
        self.assertEqual(s(self.rep, age=46 * 60), "stale")
        r = json.loads(json.dumps(self.rep)); r["vulns"]["result"] = "incomplete"
        self.assertEqual(s(r), "warning")
        r = json.loads(json.dumps(self.rep)); r["malware"]["findings"] = [{"severity": "CRITICAL"}]
        self.assertEqual(s(r), "critical")
        r = json.loads(json.dumps(self.rep)); r["integrity"]["tooling"] = "fail"
        self.assertEqual(s(r), "critical")
        r = json.loads(json.dumps(self.rep)); r["crowdsec"]["lapi_ok"] = False
        self.assertEqual(s(r), "warning")

    def test_appsec_evidence(self):
        cis = lambda r: {c["id"]: c for c in hs.evaluate(COMPLIANCE, r, self.now)["cis8"]["controls"]}  # noqa: E731
        self.assertEqual(cis(self.rep)["13.10"]["status"], "partial", "log-only CrowdSec is filtering after the fact")
        r = json.loads(json.dumps(self.rep))
        r["crowdsec"]["appsec"].update(enabled=True, listening=True)
        self.assertEqual(cis(r)["13.10"]["status"], "pass")
        r["crowdsec"]["appsec"]["listening"] = False
        self.assertEqual(cis(r)["13.10"]["status"], "partial")
        self.assertEqual(hs.summarise(r, self.now - 60, self.now, 45)["state"], "warning",
                         "AppSec on but not listening means requests pass uninspected")

    def test_validate_report(self):
        self.assertIsNone(hs.validate_report(self.rep))
        self.assertTrue(hs.validate_report({"schema": 2}))
        self.assertTrue(hs.validate_report([]))
        self.assertTrue(hs.validate_report({"schema": 1, "health": "x"}))
        self.assertTrue(hs.validate_report({"schema": 1, "vulns": {"findings": "x"}}))


class Http(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                        "-days", "2", "-keyout", cls.d + "/k", "-out", cls.d + "/c", "-subj", "/CN=t"],
                       check=True, capture_output=True)
        cfg = dict(hs.DEFAULTS)
        cfg.update(LISTEN_ADDR="127.0.0.1", LISTEN_PORT="0", DATA_DIR=cls.d + "/data", CERT=cls.d + "/c",
                   KEY=cls.d + "/k", MAX_REPORT_BYTES="4096")
        cls.hive = hs.Hive(cfg)
        handler = hs.make_handler(cls.hive)
        handler.log_message = lambda *a: None
        cls.srv = hs.Server(("127.0.0.1", 0), handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cfg["CERT"], cfg["KEY"])
        cls.srv.tls = ctx
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        with cls.hive.store.conn() as c:
            c.execute("INSERT INTO nodes VALUES ('n1', ?, '', 0, 0)", (hs.sha256_hex("tok1"),))
            c.execute("INSERT INTO users VALUES ('ops', ?, ?, 0, 0, 0)", (hs.hash_password("pw-long-enough"), SECRET))

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        shutil.rmtree(cls.d, ignore_errors=True)

    def req(self, method, path, body=None, headers=None):
        c = http.client.HTTPSConnection("127.0.0.1", self.port, context=ssl._create_unverified_context(), timeout=10)
        h = dict(headers or {})
        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            h.setdefault("Content-Type", "application/json")
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        out = r.read()
        c.close()
        return r, out

    def ingest(self, body, token="tok1", node="n1"):
        return self.req("POST", "/api/v1/report", body, {"Authorization": "Bearer " + token, "X-Hive-Node": node})

    def login(self, code=None, pw="pw-long-enough", ip_reset=True):
        if ip_reset:
            self.hive.fails.clear()
            with self.hive.store.conn() as c:
                c.execute("UPDATE users SET totp_last_step=0")
        code = code or hs.totp_at(SECRET, int(time.time() // 30))
        return self.req("POST", "/api/v1/login", {"user": "ops", "password": pw, "totp": code},
                        {"Origin": "https://127.0.0.1:%d" % self.port, "Host": "127.0.0.1:%d" % self.port})

    def test_ingest(self):
        rep = fx.report("n1", "www.example.com", {}, time.time())
        self.assertEqual(self.ingest(rep, token="wrong")[0].status, 401)
        self.assertEqual(self.ingest(rep, node="nope")[0].status, 401)
        self.assertEqual(self.ingest(b"x" * 5000)[0].status, 413)
        self.assertEqual(self.ingest(b"{not json")[0].status, 400)
        self.assertEqual(self.ingest({"schema": 9})[0].status, 400)
        small = {"schema": 1, "sent_at": int(time.time())}
        self.assertEqual(self.ingest(small)[0].status, 204)

    def test_api_needs_a_session(self):
        for p in ("/api/v1/fleet", "/api/v1/node/n1", "/api/v1/compliance/cis8", "/api/v1/me"):
            self.assertEqual(self.req("GET", p)[0].status, 401, p)

    def test_static_has_security_headers(self):
        r, body = self.req("GET", "/")
        self.assertEqual(r.status, 200)
        csp = r.getheader("Content-Security-Policy")
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
        self.assertNotIn(b"<script>", body, "no inline script in the page")

    def test_login_flow(self):
        r, _ = self.login(code="000000")
        self.assertEqual(r.status, 401)
        r, _ = self.login(pw="wrong")
        self.assertEqual(r.status, 401)
        r, _ = self.login()
        self.assertEqual(r.status, 200)
        ck = r.getheader("Set-Cookie")
        for attr in ("HttpOnly", "Secure", "SameSite=Strict"):
            self.assertIn(attr, ck)
        sid = ck.split(";")[0]
        r, body = self.req("GET", "/api/v1/fleet", headers={"Cookie": sid})
        self.assertEqual(r.status, 200)
        self.assertIn("nodes", json.loads(body))
        r, body = self.req("GET", "/api/v1/compliance/pci4", headers={"Cookie": sid})
        self.assertEqual(json.loads(body)["framework"]["id"], "pci4")
        # The same code again is a replay.
        with self.hive.store.conn() as c:
            last = c.execute("SELECT totp_last_step FROM users").fetchone()[0]
        r, _ = self.login(code=hs.totp_at(SECRET, last), ip_reset=False)
        self.hive.fails.clear()
        self.assertEqual(r.status, 401)
        # Logout ends the session server-side.
        self.req("POST", "/api/v1/logout", {}, {"Cookie": sid})
        self.assertEqual(self.req("GET", "/api/v1/fleet", headers={"Cookie": sid})[0].status, 401)

    def test_cross_origin_post_refused(self):
        r, _ = self.req("POST", "/api/v1/login", {"user": "ops", "password": "x", "totp": "1"},
                        {"Origin": "https://evil.example", "Host": "127.0.0.1:%d" % self.port})
        self.assertEqual(r.status, 403)

    def test_login_throttle(self):
        self.hive.fails.clear()
        for _ in range(5):
            self.login(code="000000", ip_reset=False)
        r, _ = self.login(ip_reset=False)
        self.assertEqual(r.status, 429, "a sixth try in the window is refused even with the right code")
        self.hive.fails.clear()

    def test_slow_handshake_does_not_block(self):
        import socket
        s = socket.create_connection(("127.0.0.1", self.port))   # opens, never speaks TLS
        try:
            t0 = time.time()
            r, _ = self.req("GET", "/api/v1/ping")
            self.assertEqual(r.status, 200)
            self.assertLess(time.time() - t0, 5)
        finally:
            s.close()


class WazuhConnector(unittest.TestCase):
    """Against a stand-in manager speaking the documented 4.x shapes. Not a
    substitute for a real manager (docs/HIVE.md says so); it does prove the
    pin is checked before the password is sent."""

    @classmethod
    def setUpClass(cls):
        import http.server
        cls.d = tempfile.mkdtemp()
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                        "-days", "2", "-keyout", cls.d + "/k", "-out", cls.d + "/c", "-subj", "/CN=wazuh"],
                       check=True, capture_output=True)
        cls.seen_auth = []
        seen = cls.seen_auth

        class W(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _j(self, obj):
                b = json.dumps(obj).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def do_POST(self):
                seen.append(self.headers.get("Authorization", ""))
                self._j({"data": {"token": "jwt-x"}})

            def do_GET(self):
                assert self.headers.get("Authorization") == "Bearer jwt-x"
                if self.path.startswith("/agents"):
                    return self._j({"data": {"affected_items": [
                        {"id": "003", "name": "n1", "status": "active", "version": "Wazuh v4.12.0"},
                        {"id": "004", "name": "not-enrolled", "status": "active"}]}})
                if self.path.startswith("/syscheck/003"):
                    return self._j({"data": {"affected_items": [{"file": "/etc/passwd", "date": "2026-11-10T01:00:00Z"}]}})
                if self.path.startswith("/sca/003"):
                    return self._j({"data": {"affected_items": [{"policy_id": "cis_alpine", "pass": 40, "fail": 3, "score": 93}]}})
                self.send_response(404)
                self.end_headers()

        cls.srv = http.server.HTTPServer(("127.0.0.1", 0), W)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cls.d + "/c", cls.d + "/k")
        cls.srv.socket = ctx.wrap_socket(cls.srv.socket, server_side=True)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        der = subprocess.run(["openssl", "x509", "-in", cls.d + "/c", "-outform", "der"],
                             check=True, capture_output=True).stdout
        cls.pin = __import__("hashlib").sha256(der).hexdigest()
        open(cls.d + "/pw", "w").write("secret-pw\n")

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        shutil.rmtree(cls.d, ignore_errors=True)

    def connector(self, pin):
        cfg = dict(hs.DEFAULTS)
        cfg.update(WAZUH_URL="https://127.0.0.1:%d" % self.srv.server_address[1], WAZUH_USER="hive-ro",
                   WAZUH_PASSWORD_FILE=self.d + "/pw", WAZUH_CERT_SHA256=pin)
        store = hs.Store(tempfile.mkdtemp(dir=self.d) + "/h.db")
        with store.conn() as c:
            c.execute("INSERT INTO nodes VALUES ('n1', 'x', '', 0, 0)")
        return hs.Wazuh(cfg, store), store

    def test_poll_stores_matching_agents(self):
        w, store = self.connector(self.pin)
        w.poll_once()
        self.assertEqual((w.status["ok"], w.status["agents"], w.status["matched"]), (True, 2, 1))
        with store.conn() as c:
            rows = c.execute("SELECT node, body FROM wazuh").fetchall()
        self.assertEqual([r["node"] for r in rows], ["n1"])
        body = json.loads(rows[0]["body"])
        self.assertEqual(body["sca"][0]["score"], 93)
        self.assertEqual(body["fim"][0]["file"], "/etc/passwd")

    def test_wrong_pin_sends_no_password(self):
        del self.seen_auth[:]
        w, _ = self.connector("00" * 32)
        with self.assertRaises(ssl.SSLError):
            w.poll_once()
        self.assertEqual(self.seen_auth, [], "credentials went to an unpinned server")


if __name__ == "__main__":
    unittest.main(verbosity=1)
