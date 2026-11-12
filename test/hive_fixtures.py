"""Sample WASP Hive reports, shaped exactly like wasp-hive-report.sh's output.

Fictional clients and example.com domains only. Used by test-hive.py and by
the dashboard screenshot in docs/VALIDATION.md.
"""
import copy
import json
import random
import time

BASE = {
    "schema": 1, "wasp_release": "10.12",
    "health": {"check_rc": 0, "check": "OK wordpress up, db up, crowdsec up", "disk_used_pct": 31, "uptime_s": 1209600},
    "versions": {"wordpress": "6.8.3", "php": "8.3.27", "mariadb": "11.4.8"},
    "vulns": {"result": "complete", "sources": "Wordfence + WPVulnerability", "findings": []},
    "malware": {"findings": []},
    "integrity": {"tooling": "pass", "tooling_modified": 0, "checksums": "pass", "checksums_modified": 0},
    "crowdsec": {"mode": "upstream", "lapi_ok": True, "decisions": 14, "alerts_24h": 9, "bouncer": "n/a",
                 "top_scenarios": [{"scenario": "crowdsecurity/http-probing", "count": 5},
                                   {"scenario": "crowdsecurity/http-wordpress-scan", "count": 3},
                                   {"scenario": "crowdsecurity/http-bad-user-agent", "count": 1}],
                 "appsec": {"enabled": False, "listening": False, "failure_action": "passthrough", "mem_mb": 0,
                            "watchdog_restarts_24h": 0, "blocked_24h": 0}},
    "backups": {"offsite_error": False, "offsite_configured": True},
    "egress": {"temporary": []},
    "controls": {"mfa_enforce": True, "mfa_grace_days": 7, "egress_proxy": True, "restrict_egress": True,
                 "deployment_profile": "production", "geoip": False, "login_slug": True,
                 "admin_ip_restricted": True, "clamav": False, "wpvulnerability": True,
                 "wordfence_feed": True, "smtp_alerts": True, "heartbeat": True, "release_signature": "verified"},
}

# (node, client, domain, tweaks)
FLEET = [
    ("wp-acme-www", "Acme Dental", "acme-dental.example.com", {
        "crowdsec.appsec": {"enabled": True, "listening": True, "failure_action": "passthrough", "mem_mb": 212,
                            "watchdog_restarts_24h": 1, "blocked_24h": 37}}),
    ("wp-acme-shop", "Acme Dental", "shop.acme-dental.example.com", {"vulns.findings": [
        {"severity": "HIGH", "component": "plugin contact-form-x 5.2.1", "title": "Unauthenticated stored XSS", "cve": "CVE-2026-10001"},
        {"severity": "MEDIUM", "component": "plugin gallery-lite 2.0.4", "title": "Missing authorization on settings export", "cve": "CVE-2026-10002"}]}),
    ("wp-northfield-cpa", "Northfield CPA", "northfield-cpa.example.com", {"controls.wordfence_feed": False}),
    ("wp-northfield-portal", "Northfield CPA", "portal.northfield-cpa.example.com", {
        "malware.findings": [{"severity": "CRITICAL", "finding": "obfuscated-php", "detail": "wp-content/uploads/2026/10/cache.php (48% escapes)"},
                             {"severity": "HIGH", "finding": "suspect-user", "detail": "wp_svc_sync: created at midnight, backdated, role-stripped"}],
        "health.check_rc": 1, "health.check": "WARN wp-cron overdue"}),
    ("wp-riverside-fd", "Riverside Fire", "riverside-fire.example.com", {"egress.temporary": "OPEN"}),
    ("wp-riverside-donate", "Riverside Fire", "donate.riverside-fire.example.com", {
        "vulns.result": "incomplete", "crowdsec.lapi_ok": False, "backups.offsite_configured": False}),
    ("wp-harbor-law", "Harbor Law", "harbor-law.example.com", {"integrity.checksums": "fail", "integrity.checksums_modified": 2}),
    ("wp-harbor-intake", "Harbor Law", "intake.harbor-law.example.com", {"STALE": True}),
]


def _set(d, path, val):
    parts = path.split(".")
    for p in parts[:-1]:
        d = d.setdefault(p, {})
    d[parts[-1]] = val


def report(node, domain, tweaks, now):
    r = copy.deepcopy(BASE)
    r.update(node=node, hostname=node, domain=domain, sent_at=int(now))
    r["vulns"]["at"] = int(now - 5 * 3600)
    r["malware"]["at"] = int(now - 8 * 3600)
    r["integrity"]["checksums_at"] = int(now - 3 * 86400)
    r["backups"]["local_at"] = int(now - 6 * 3600)
    r["backups"]["offsite_at"] = int(now - 6 * 3600)
    for k, v in tweaks.items():
        if k == "STALE":
            continue
        if k == "egress.temporary" and v == "OPEN":
            v = [{"until": int(now + 38 * 60), "tag": "fileshare", "domain": ".dropbox.com"}]
        _set(r, k, v)
    return r


def seed_history(db_path, now, days=7):
    """Hourly history straight into the database, for the trend sparklines.
    The ingest API stamps received_at itself, so the past cannot be posted."""
    import sqlite3
    rng = random.Random(7)
    c = sqlite3.connect(db_path)
    for node, _client, domain, tweaks in FLEET:
        if tweaks.get("STALE"):
            t_end = now - 5 * 3600
        else:
            t_end = now - 3600
        t = now - days * 86400
        dec = 10
        while t <= t_end:
            r = report(node, domain, tweaks, t)
            dec = max(0, dec + rng.randint(-3, 4))
            r["crowdsec"]["decisions"] = dec
            r["crowdsec"]["alerts_24h"] = max(0, dec + rng.randint(-4, 6))
            r["health"]["disk_used_pct"] = 30 + int((t - (now - days * 86400)) / 86400)
            c.execute("INSERT INTO reports VALUES (?,?,?,?,?)", (node, int(t), int(t), "192.0.2.10", json.dumps(r)))
            t += 3600
    c.commit()
    c.close()


if __name__ == "__main__":
    print(json.dumps(report("wp-sample", "www.example.com", {}, time.time()), indent=2))
