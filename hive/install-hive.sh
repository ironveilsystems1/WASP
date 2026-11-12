#!/bin/sh
# install-hive.sh — set up WASP Hive on a fresh Alpine VM.
#
#   doas sh hive/install-hive.sh [--admin-cidr 10.0.0.0/24] [--name hive.example.lan]
#                                [--ssh-cidr L] [--dashboard-cidr L] [--ingest-cidr L]
#                                [--pubkey RW...] [--unverified]
#
#   --admin-cidr      SSH and the dashboard, from these addresses
#   --ssh-cidr        SSH only (overrides --admin-cidr for SSH)
#   --dashboard-cidr  the dashboard only (overrides --admin-cidr for it)
#   --ingest-cidr     the networks the WASP VMs report from
#   Each takes one CIDR or a comma-separated list. With both a dashboard and an
#   ingest list, the service port is closed to everything else at the firewall
#   as well as in the service.
#
# Run from the unpacked WASP release, or let install.sh (role "WASP Hive")
# run it on the new VM's first boot. What it does:
#   1. Verifies the release signature and the hive/ files against the signed
#      manifest (refuses on a mismatch; --unverified only for a test build).
#   2. apk: python3, openssl, nftables, minisign; qrencode if available.
#   3. Installs to /opt/wasp-hive, runs as the unprivileged user "hive".
#   4. Generates the Hive's TLS key and a self-signed certificate. VMs pin the
#      KEY, so the certificate never needs a public CA and can be renewed.
#   5. Firewall: 443 redirected to the service on 8443; SSH only from
#      --admin-cidr when given; nothing else in.
#   6. OpenRC service wasp-hive, supervised.
#
# Re-running is safe: the key, the database and hive.conf are kept.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REL=$(cd "$HERE/.." && pwd)
OPT=/opt/wasp-hive
ETC=/etc/wasp-hive
DATA=/var/lib/wasp-hive
ADMIN_CIDR=""
SSH_CIDR=""
DASH_CIDR=""
INGEST_CIDR=""
PUBKEY_ARG=""
NAME=$(hostname -f 2>/dev/null || hostname)
UNVERIFIED=0

while [ $# -gt 0 ]; do
  case "$1" in
    --admin-cidr) ADMIN_CIDR="$2"; shift 2 ;;
    --ssh-cidr) SSH_CIDR="$2"; shift 2 ;;
    --dashboard-cidr) DASH_CIDR="$2"; shift 2 ;;
    --ingest-cidr) INGEST_CIDR="$2"; shift 2 ;;
    --pubkey) PUBKEY_ARG="$2"; shift 2 ;;
    --name) NAME="$2"; shift 2 ;;
    --unverified) UNVERIFIED=1; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

# Each list: CIDRs (or single addresses), comma-separated, nothing else --
# they are written into the nftables ruleset and hive.conf.
_cidrs_ok() {
  [ -z "$1" ] && return 0
  _l=$(printf '%s' "$1" | tr -d ' ')
  case "$_l" in *[!0-9./,]*|,*|*,|*,,*) return 1 ;; esac   # IPv4, as everywhere in WASP
  return 0
}
for _pair in "admin-cidr:$ADMIN_CIDR" "ssh-cidr:$SSH_CIDR" "dashboard-cidr:$DASH_CIDR" "ingest-cidr:$INGEST_CIDR"; do
  _cidrs_ok "${_pair#*:}" || { echo "--${_pair%%:*}: not a CIDR list: ${_pair#*:}" >&2; exit 2; }
done
SSH_CIDR=$(printf '%s' "${SSH_CIDR:-$ADMIN_CIDR}" | tr -d ' ')
DASH_CIDR=$(printf '%s' "${DASH_CIDR:-$ADMIN_CIDR}" | tr -d ' ')
INGEST_CIDR=$(printf '%s' "$INGEST_CIDR" | tr -d ' ')
case "$PUBKEY_ARG" in *[!A-Za-z0-9+/=]*) echo "--pubkey: not a minisign public key" >&2; exit 2 ;; ''|RW*) : ;; *) echo "--pubkey: a minisign public key starts with RW" >&2; exit 2 ;; esac
case "$NAME" in *[!A-Za-z0-9.-]*) echo "--name: letters, digits, dots and dashes only" >&2; exit 2 ;; esac

[ "$(id -u)" = 0 ] || { echo "Run as root (doas sh $0)." >&2; exit 1; }
[ -r /etc/alpine-release ] || { echo "WASP Hive is installed on Alpine Linux." >&2; exit 1; }
say() { printf '  %s\n' "$*"; }

# ── 1. Packages ──────────────────────────────────────────────────────────────
say "Installing packages…"
apk add --no-cache python3 openssl nftables minisign >/dev/null
apk add --no-cache qrencode >/dev/null 2>&1 || say "(qrencode unavailable: authenticator setup will show the secret as text)"
python3 -c 'import sqlite3, ssl' || { echo "python3 lacks sqlite3 or ssl." >&2; exit 1; }

# ── 2. Verify what is about to be installed ──────────────────────────────────
# The same key install.sh uses; read from it so there is one place to change.
PUBKEY=${PUBKEY_ARG:-$(sed -n 's/^WASP_PUBKEY="\${WASP_PUBKEY:-\([^}]*\)}".*/\1/p' "$REL/install.sh" 2>/dev/null | head -1)}
if [ -r "$REL/MANIFEST.sha256" ] && [ -r "$REL/MANIFEST.sha256.minisig" ] && [ -n "$PUBKEY" ]; then
  minisign -Vqm "$REL/MANIFEST.sha256" -P "$PUBKEY" \
    || { echo "  RELEASE SIGNATURE INVALID. Not installing." >&2; exit 1; }
  ( cd "$REL" && grep '  hive/' MANIFEST.sha256 | sha256sum -c --quiet ) \
    || { echo "  hive/ files do not match the signed manifest. Not installing." >&2; exit 1; }
  grep -q '  hive/hive_server.py$' "$REL/MANIFEST.sha256" \
    || { echo "  The signed manifest does not cover hive/. Not installing." >&2; exit 1; }
  say "✔ Release signature and hive/ files verified."
elif [ "$UNVERIFIED" = 1 ]; then
  say "WARNING: installing an UNVERIFIED build (--unverified)."
else
  echo "  No signed manifest (MANIFEST.sha256 + .minisig) next to this script." >&2
  echo "  Use a signed release, or --unverified for a test build." >&2
  exit 1
fi

# ── 3. User and files ────────────────────────────────────────────────────────
getent group hive >/dev/null 2>&1 || addgroup -S hive
getent passwd hive >/dev/null 2>&1 || adduser -S -D -H -h "$DATA" -s /sbin/nologin -G hive hive
install -d -m 0755 "$OPT" "$OPT/static"
install -m 0644 "$HERE/hive_server.py" "$HERE/hive_admin.py" "$HERE/compliance.json" "$OPT/"
install -m 0644 "$HERE"/static/* "$OPT/static/"
install -d -m 0750 -o root -g hive "$ETC"
install -d -m 0700 -o hive -g hive "$DATA"
cat > /usr/local/bin/hive-admin <<'EOF'
#!/bin/sh
exec /usr/bin/python3 /opt/wasp-hive/hive_admin.py "$@"
EOF
chmod 0755 /usr/local/bin/hive-admin

if [ ! -e "$ETC/hive.conf" ]; then
  cat > "$ETC/hive.conf" <<EOF
# WASP Hive. KEY=value; read, never executed. Restart after a change:
#   doas rc-service wasp-hive restart
LISTEN_ADDR=0.0.0.0
LISTEN_PORT=8443
DATA_DIR=$DATA
CERT=$ETC/hive.crt
KEY=$ETC/hive.key
# Who may open the dashboard / who may send reports. Comma-separated CIDRs;
# empty means whoever the firewall lets in.
DASHBOARD_CIDRS=${DASH_CIDR}
INGEST_CIDRS=${INGEST_CIDR}
# A VM is "stale" after this long without a report (they send every 15 min).
STALE_MINUTES=45
RETENTION_DAYS=90
SESSION_HOURS=8
# Optional, read-only Wazuh manager API. See docs/HIVE.md.
WAZUH_URL=
WAZUH_USER=
WAZUH_PASSWORD_FILE=$ETC/wazuh.password
WAZUH_CERT_SHA256=
WAZUH_POLL_MINUTES=10
EOF
  chown root:hive "$ETC/hive.conf"; chmod 0640 "$ETC/hive.conf"
fi

# ── 4. TLS key ───────────────────────────────────────────────────────────────
if [ ! -s "$ETC/hive.key" ]; then
  say "Generating the Hive's TLS key…"
  IP=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')
  SAN="DNS:${NAME}"; [ -n "$IP" ] && SAN="${SAN},IP:${IP}"
  ( umask 077
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
      -keyout "$ETC/hive.key" -out "$ETC/hive.crt" -subj "/CN=${NAME}" \
      -addext "subjectAltName=${SAN}" >/dev/null 2>&1 )
  chown root:hive "$ETC/hive.key"; chmod 0640 "$ETC/hive.key"; chmod 0644 "$ETC/hive.crt"
fi

# ── 5. Firewall ──────────────────────────────────────────────────────────────
[ -e /etc/nftables.nft ] && [ ! -e /etc/nftables.nft.pre-hive ] && cp -p /etc/nftables.nft /etc/nftables.nft.pre-hive
_set() { printf '%s' "$1" | sed 's/,/, /g'; }
if [ -n "$SSH_CIDR" ]; then SSH_RULE="ip saddr { $(_set "$SSH_CIDR") } tcp dport 22 accept"
else SSH_RULE="tcp dport 22 accept"; fi
# The same rule install.sh writes for a Hive VM: closed to everything but the
# dashboard and WASP VM networks when both are known. The service checks both
# again itself.
if [ -n "$DASH_CIDR" ] && [ -n "$INGEST_CIDR" ]; then
  WEB_RULE="ip saddr { $(_set "$DASH_CIDR,$INGEST_CIDR") } tcp dport 8443 accept"
else
  WEB_RULE="tcp dport 8443 accept"
fi
cat > /etc/nftables.nft <<EOF
#!/usr/sbin/nft -f
# WASP Hive. Written by install-hive.sh; the previous file is nftables.nft.pre-hive.
flush ruleset

table inet hive {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    # VMs with restricted egress may reach tcp/443 only; the service runs
    # unprivileged on 8443.
    tcp dport 443 redirect to :8443
  }
  chain input {
    type filter hook input priority filter; policy drop;
    ct state established,related accept
    ct state invalid drop
    iif lo accept
    meta l4proto { icmp, ipv6-icmp } accept
    $SSH_RULE
    $WEB_RULE
  }
  chain forward { type filter hook forward priority filter; policy drop; }
}
EOF
nft -c -f /etc/nftables.nft
rc-update add nftables default >/dev/null 2>&1 || true
rc-service nftables restart >/dev/null

# ── 6. Service ───────────────────────────────────────────────────────────────
install -m 0755 "$HERE/hive.initd" /etc/init.d/wasp-hive
touch /var/log/wasp-hive.log
chown hive:hive /var/log/wasp-hive.log; chmod 0640 /var/log/wasp-hive.log
rc-update add wasp-hive default >/dev/null
rc-service wasp-hive restart >/dev/null

sleep 1
if wget -qO- --no-check-certificate https://127.0.0.1:8443/api/v1/ping 2>/dev/null | grep -q wasp-hive; then
  say "✔ WASP Hive is running."
else
  say "The service did not answer. See /var/log/wasp-hive.log"
  exit 1
fi

PIN=$(/usr/local/bin/hive-admin pin | sed 's/^ *//')
cat <<EOF

  Certificate pin: ${PIN}

  Next:
    1. A dashboard user (password + authenticator app):
         doas hive-admin user-add <name>
    2. Each WASP VM, one at a time:
         doas hive-admin enroll <vm-hostname> --client "<client name>"
       and run the line it prints on that VM.
    3. Open https://${NAME}/  (the browser will warn: the certificate is
       self-signed. Compare its key with the pin above, then accept it.)

EOF
