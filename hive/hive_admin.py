#!/usr/bin/env python3
"""
hive-admin — the only way to change anything on a WASP Hive.

    hive-admin enroll <node> [--client NAME]   create a node; prints the line to run on the VM
    hive-admin rotate <node>                   new token for a node (the old one stops working)
    hive-admin revoke <node>                   stop accepting reports from a node
    hive-admin nodes                           list nodes and when each last reported
    hive-admin user-add <name>                 add a dashboard user (password + authenticator)
    hive-admin user-reset <name>               new password and authenticator for a user
    hive-admin user-disable <name>
    hive-admin users
    hive-admin audit [N]                       the last N logins, refusals and changes
    hive-admin pin                             this Hive's certificate pin

Run as root on the Hive VM. The web dashboard deliberately has no way to do any
of this: a console that can enroll nodes or add users over HTTP is a console
whose login page is worth attacking.
"""
import base64
import getpass
import hashlib
import os
import secrets
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hive_server as hs  # noqa: E402

CONF = os.environ.get("HIVE_CONF", "/etc/wasp-hive/hive.conf")


def store_and_cfg():
    cfg = hs.load_config(CONF)
    store = hs.Store(os.path.join(cfg["DATA_DIR"], "hive.db"))
    _own_like_dir(cfg["DATA_DIR"])
    return store, cfg


def _own_like_dir(d):
    """Run as root, this tool may be the first to create the database; the
    service runs as "hive" and must still be able to write it."""
    if os.geteuid() != 0:
        return
    st = os.stat(d)
    for fn in os.listdir(d):
        p = os.path.join(d, fn)
        try:
            os.chown(p, st.st_uid, st.st_gid)
        except OSError:
            pass


def cert_pin(cfg):
    """sha256 of the certificate's public key, base64 -- curl's
    --pinnedpubkey format. The key, not the certificate, so renewing the
    certificate with the same key does not break every VM's pin."""
    pub = subprocess.run(["openssl", "x509", "-in", cfg["CERT"], "-noout", "-pubkey"],
                         check=True, capture_output=True).stdout
    der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "der"],
                         input=pub, check=True, capture_output=True).stdout
    return base64.b64encode(hashlib.sha256(der).digest()).decode()


def hive_url():
    return os.environ.get("HIVE_PUBLIC_URL") or "https://%s" % _primary_ip()


def _primary_ip():
    try:
        out = subprocess.run(["ip", "-4", "route", "get", "1.1.1.1"], capture_output=True, text=True).stdout
        parts = out.split()
        return parts[parts.index("src") + 1]
    except (ValueError, IndexError, OSError):
        return "<hive-address>"


def _ask_password():
    while True:
        p1 = getpass.getpass("  Password (12+ characters): ")
        if len(p1) < 12:
            print("  Too short.")
            continue
        if p1 != getpass.getpass("  Again: "):
            print("  They do not match.")
            continue
        return p1


def _new_totp(store, name):
    secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
    uri = "otpauth://totp/WASP%%20Hive:%s?secret=%s&issuer=WASP%%20Hive&digits=6&period=30" % (name, secret)
    print("")
    print("  Add this to an authenticator app (Aegis, 2FAS, 1Password, Google Authenticator):")
    print("    secret : %s" % secret)
    print("    or URI : %s" % uri)
    try:
        q = subprocess.run(["qrencode", "-t", "ANSIUTF8", uri], capture_output=True, text=True)
        if q.returncode == 0:
            print(q.stdout)
    except OSError:
        pass
    # Proven before it is saved: an authenticator set up wrong is a locked-out
    # user discovered at the worst moment.
    for _ in range(3):
        code = input("  Enter the 6-digit code it shows now: ").strip()
        if hs.totp_verify(secret, code, 0) is not None:
            return secret
        print("  That code does not match. Check the device clock.")
    sys.exit("  Not saved.")


def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help", "help"):
        print(__doc__.strip())
        return 0
    cmd, args = argv[1], argv[2:]
    if cmd in ("revoke", "user-disable") and not args:
        sys.exit("  Usage: hive-admin %s <name>" % cmd)
    if cmd in ("enroll", "rotate") and "--client" in args and args.index("--client") + 1 >= len(args):
        sys.exit("  --client needs a name.")
    store, cfg = store_and_cfg()
    who = os.environ.get("SUDO_USER") or os.environ.get("DOAS_USER") or getpass.getuser()

    if cmd in ("enroll", "rotate"):
        if not args or not hs.NODE_RE.match(args[0]):
            sys.exit("  Node names: letters, digits, . _ - (the VM's hostname is a good choice).")
        node = args[0]
        client = ""
        if "--client" in args:
            client = args[args.index("--client") + 1]
        token = secrets.token_urlsafe(32)
        with store.lock, store.conn() as c:
            exists = c.execute("SELECT 1 FROM nodes WHERE name=?", (node,)).fetchone()
            if cmd == "enroll" and exists:
                sys.exit("  %s already exists. New token: hive-admin rotate %s" % (node, node))
            if cmd == "rotate" and not exists:
                sys.exit("  No node %s." % node)
            if cmd == "enroll":
                c.execute("INSERT INTO nodes VALUES (?,?,?,?,0)",
                          (node, hs.sha256_hex(token), client, int(time.time())))
            else:
                c.execute("UPDATE nodes SET token_hash=?, revoked=0 WHERE name=?", (hs.sha256_hex(token), node))
        store.audit(who, cmd, node)
        print("")
        print("  %s %s. On that WASP VM, run this once:" % (node, "enrolled" if cmd == "enroll" else "re-keyed"))
        print("")
        print("    doas wasp-hive-report.sh enroll %s %s %s %s" % (hive_url(), node, token, cert_pin(cfg)))
        print("")
        print("  The token is shown once and stored here only as a hash. It lets that VM")
        print("  replace its own report and nothing else.")
        return 0

    if cmd == "revoke":
        with store.lock, store.conn() as c:
            n = c.execute("UPDATE nodes SET revoked=1 WHERE name=?", (args[0],)).rowcount
        store.audit(who, "revoke", args[0])
        print("  Revoked." if n else "  No such node.")
        return 0

    if cmd == "nodes":
        now = time.time()
        with store.conn() as c:
            rows = c.execute("""SELECT n.name, n.client, n.revoked, MAX(r.received_at) AS last
                                FROM nodes n LEFT JOIN reports r ON r.node=n.name
                                GROUP BY n.name ORDER BY n.client, n.name""").fetchall()
        print("  %-28s %-20s %s" % ("NODE", "CLIENT", "LAST REPORT"))
        for r in rows:
            last = "never" if not r["last"] else "%d min ago" % ((now - r["last"]) // 60)
            print("  %-28s %-20s %s%s" % (r["name"], r["client"] or "-", last, "  (revoked)" if r["revoked"] else ""))
        return 0

    if cmd in ("user-add", "user-reset"):
        if not args:
            sys.exit("  Usage: hive-admin %s <name>" % cmd)
        name = args[0]
        with store.conn() as c:
            exists = c.execute("SELECT 1 FROM users WHERE name=?", (name,)).fetchone()
        if cmd == "user-add" and exists:
            sys.exit("  %s exists. hive-admin user-reset %s" % (name, name))
        if cmd == "user-reset" and not exists:
            sys.exit("  No user %s." % name)
        pw = _ask_password()
        secret = _new_totp(store, name)
        with store.lock, store.conn() as c:
            if cmd == "user-add":
                c.execute("INSERT INTO users VALUES (?,?,?,0,?,0)", (name, hs.hash_password(pw), secret, int(time.time())))
            else:
                c.execute("UPDATE users SET pw_hash=?, totp_secret=?, totp_last_step=0, disabled=0 WHERE name=?",
                          (hs.hash_password(pw), secret, name))
                c.execute("DELETE FROM sessions WHERE user=?", (name,))
        store.audit(who, cmd, name)
        print("  Saved. Every login needs the password and a code.")
        return 0

    if cmd == "user-disable":
        with store.lock, store.conn() as c:
            c.execute("UPDATE users SET disabled=1 WHERE name=?", (args[0],))
            c.execute("DELETE FROM sessions WHERE user=?", (args[0],))
        store.audit(who, "user-disable", args[0])
        print("  Disabled, and signed out everywhere.")
        return 0

    if cmd == "users":
        with store.conn() as c:
            for r in c.execute("SELECT name, disabled, created FROM users ORDER BY name"):
                print("  %-24s %s" % (r["name"], "disabled" if r["disabled"] else "active"))
        return 0

    if cmd == "audit":
        n = int(args[0]) if args else 40
        with store.conn() as c:
            for r in c.execute("SELECT * FROM audit ORDER BY at DESC LIMIT ?", (n,)):
                print("  %s  %-16s %-14s %-20s %s" % (time.strftime("%Y-%m-%d %H:%M", time.gmtime(r["at"])),
                                                      r["actor"], r["action"], r["detail"], r["ip"] or ""))
        return 0

    if cmd == "pin":
        print("  sha256//%s" % cert_pin(cfg))
        return 0

    sys.exit("  Unknown command. hive-admin help")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
