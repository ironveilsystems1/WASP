#!/usr/bin/env bash
# 05-ssh-and-network-inject.sh — part of install.sh (host-side, runs on the Proxmox VE host).
# Injects hostname, SSH hardening config, admin credentials file, nftables.nft, and /etc/network/interfaces onto the mounted disk.
# Sourced by install.sh in order -- do not run this file directly; it
# depends on variables and functions (msg_*, TMPDIR, REPO_DIR, MNT, etc.)
# that install.sh and earlier lib files set up.

echo "$HN" > "$MNT/etc/hostname"
grep -q "$HN" "$MNT/etc/hosts" 2>/dev/null || echo "127.0.1.1  $HN" >> "$MNT/etc/hosts"

# ─ Split-horizon loopback (optional; lib/01 asks) ─────────────────────────────
# Behind a reverse proxy with split-horizon DNS, the site's own name resolves to
# the proxy. WordPress calls that name for WP-Cron, Site Health and parts of the
# REST API, so those calls leave the VM and need a permitted path back to the
# proxy on 80/443. Where the segment is firewalled east-west -- which is the
# point of putting each site on its own VLAN -- that path does not exist by
# default, the calls are dropped, and the operator sees "scheduled posts
# stopped" with nothing naming DNS or the firewall.
#
# This entry keeps the call inside the VM. Written here, before first boot, so
# WP-Cron works on day one rather than after someone correlates two unrelated
# symptoms. The trade-off (loopback no longer exercises the real proxy path) is
# stated at the prompt, not buried here.
#
# Both names: the bare domain and www. A hosts entry for one does nothing for
# the other, and which one WordPress calls depends on siteurl, which is set
# later in the browser wizard and is not knowable here.
if [[ "${LOOPBACK_HOSTS:-0}" = "1" && -n "${WP_DOMAIN:-}" ]]; then
  if ! grep -q "[[:space:]]${WP_DOMAIN}\$" "$MNT/etc/hosts" 2>/dev/null; then
    printf '127.0.0.1  %s www.%s\n' "$WP_DOMAIN" "${WP_DOMAIN#www.}" >> "$MNT/etc/hosts"
    msg_ok "Loopback: ${WP_DOMAIN} → 127.0.0.1 (WP-Cron needs no path to the proxy)"
  fi
fi

# ─ SSH hardening ──────────────────────────────────────────────────────────────
SSHCFG="$MNT/etc/ssh/sshd_config"; mkdir -p "$MNT/etc/ssh"
[[ $DISABLE_PW_AUTH -eq 1 ]] && _PWAUTH="no" || _PWAUTH="yes"

# FORENSIC FIX (new-audit Critical finding, confirmed accurate): root SSH
# login used to re-enable itself as a "fallback" when admin-account
# creation failed (ADMIN_USER_CREATED=0). Removed: PermitRootLogin is now
# unconditionally "no". Recovery when the admin account is missing is via
# the Proxmox console (`qm terminal <vmid>`, which uses the ROOT_PASS set
# unconditionally in 04-nbd-mount-and-chroot.sh) — not by exposing root
# over the network, which is a worse trade for a rare failure case.
_ROOTLOGIN="no"

if [[ "$ADMIN_USER_CREATED" -eq 1 ]]; then
  # Normal path: the admin account (wheel + doas, created in the chroot
  # above) is the only way in.
  ADMIN_HASHED=$(openssl passwd -6 "$ADMIN_PASS")
  sed -i "s|^${ADMIN_USER}:[^:]*:|${ADMIN_USER}:${ADMIN_HASHED}:|" "$MNT/etc/shadow"
  if [[ -n "$SSH_KEYS" ]]; then
    # Re-validated here, at the point of use, rather than trusted from the
    # prompt that collected it — the same reasoning as the TRUST-COUNT
    # assertions in lib/03 and lib/06. lib/01 validates every key it accepts,
    # so in the normal path this changes nothing. It exists because this is the
    # only place the value becomes a login decision, and because password auth
    # is switched off on the strength of this file: a future preset path, an
    # answer file, or an edit to lib/01 that loosened a check would reach this
    # line without having passed one.
    #
    # Written line by line rather than as one blob so a single bad line is
    # dropped instead of poisoning the file, and so the count that goes into
    # the install log is the count that is actually on disk.
    mkdir -p "$MNT/home/${ADMIN_USER}/.ssh"
    _AK="$MNT/home/${ADMIN_USER}/.ssh/authorized_keys"
    : > "$_AK"
    _written=0; _skipped=0
    while IFS= read -r _kl || [[ -n "$_kl" ]]; do
      [[ -z "$_kl" ]] && continue
      case "$(_ssh_key_kind "$_kl")" in
        ok) printf '%s\n' "$_kl" >> "$_AK"; _written=$((_written+1)) ;;
        private)
          # Refused rather than written, even this late. A private key in
          # authorized_keys gives no login AND leaves the private half on the
          # VM's disk; dropping the line keeps at least the second from being
          # true of a file we created.
          msg_warn "A PRIVATE key reached the key-injection stage and was NOT written."
          msg_warn "  Treat that keypair as compromised and generate a new one."
          _skipped=$((_skipped+1)) ;;
        *) msg_warn "Unusable SSH key line skipped: $(printf '%.40s' "$_kl")…"
           _skipped=$((_skipped+1)) ;;
      esac
    done <<< "$SSH_KEYS"
    chmod 700 "$MNT/home/${ADMIN_USER}/.ssh"
    chmod 600 "$_AK"
    chown -R "${ADMIN_UID}:${ADMIN_GID}" "$MNT/home/${ADMIN_USER}"

    # Nothing usable, with password auth about to be off, is a VM that cannot
    # be reached over the network at all. Refuse to build it rather than hand
    # back something only the Proxmox console can rescue.
    if [[ "$_written" -eq 0 ]]; then
      msg_warn "No usable SSH key was written to authorized_keys, and password"
      msg_warn "  authentication is disabled for this VM. It would come up with"
      msg_warn "  no network login path at all — reachable only from the"
      msg_warn "  Proxmox console via 'qm terminal ${VMID}'."
      msg_error "Refusing to build a VM with no way in. Re-run and supply a valid public key."
    fi
    msg_ok "authorized_keys written: ${_written} key(s)$([[ "$_skipped" -gt 0 ]] && printf ', %s skipped' "$_skipped")"
    [[ "$_written" -gt 1 ]] && msg_info "  Any of the ${_written} can log in; each is equally privileged."
    unset _AK _kl _written _skipped
  fi
else
  # FALLBACK — should be rare, adduser is a simple local-filesystem
  # operation with no network dependency. Root SSH stays disabled either
  # way now, so there's nothing useful to do with an operator-supplied SSH
  # key here — it would sit on an account (root) that SSH can never reach.
  # This is a degraded state, not a final one — flagged loudly here and
  # again in the closing summary; fix by hand after boot via the console
  # (`qm terminal <vmid>`): adduser, addgroup <user> wheel, apk add doas,
  # echo 'permit persist :wheel' > /etc/doas.d/doas.conf, then copy the
  # intended key into that account's ~/.ssh/authorized_keys yourself.
  :
fi

cat > "$SSHCFG" << SSHEOF
PermitRootLogin ${_ROOTLOGIN}
PasswordAuthentication ${_PWAUTH}
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 6
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
IgnoreRhosts yes
HostbasedAuthentication no
AllowUsers ${ADMIN_USER}
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
SSHEOF
chmod 600 "$SSHCFG"

if [[ "$ADMIN_USER_CREATED" -eq 1 ]]; then
  msg_ok "SSH: ${ADMIN_USER} ($([[ $DISABLE_PW_AUTH -eq 1 ]] && echo 'key-only' || echo 'password')), root login disabled"
else
  msg_warn "SSH: no admin account — SSH has no usable login until you create one (root login stays disabled; see console-recovery instructions above)"
fi

# ─ Admin credentials note (only what the operator doesn't already know) ──────
# ROOT_PASS is never written to disk in plaintext (the operator typed it, no
# need to also leave a copy lying around) — same treatment here. The
# operator-chosen admin password (no-key path) is likewise never written.
# The AUTO-GENERATED admin password (key-provided path, used only by doas —
# see the SSH access prompt) is the one exception: nobody typed it, so
# without writing it down it would be permanently unusable, exactly like the
# openssl-rand DB passwords already documented in /root/.wp-credentials.
if [[ "$ADMIN_USER_CREATED" -eq 1 ]]; then
  if [[ -n "$SSH_KEYS" ]]; then
    cat > "$MNT/root/.wp-admin-credentials" << ADMINCREDS
# ============================================================
# Admin account — generated by create-wordpress-vm.sh
# chmod 600 /root/.wp-admin-credentials
# ============================================================
# Username : ${ADMIN_USER}
# SSH      : key-only (the public key supplied during provisioning)
# Password : ${ADMIN_PASS}
#   Not used for SSH (password login is disabled) — only for 'doas'
#   once logged in, or as a local-console recovery password.
# doas     : any command as root, e.g.  doas -s   (interactive root shell)
# ============================================================
ADMINCREDS
  else
    cat > "$MNT/root/.wp-admin-credentials" << ADMINCREDS
# ============================================================
# Admin account — generated by create-wordpress-vm.sh
# chmod 600 /root/.wp-admin-credentials
# ============================================================
# Username : ${ADMIN_USER}
# SSH      : password (the one set during provisioning)
# doas     : any command as root, e.g.  doas -s   (interactive root shell)
# ============================================================
ADMINCREDS
  fi
  chmod 600 "$MNT/root/.wp-admin-credentials"
  msg_ok "/root/.wp-admin-credentials written (chmod 600)"
fi

# ─ nftables ───────────────────────────────────────────────────────────────────
echo "$NFT_CONF" > "$MNT/etc/nftables.nft"; chmod 600 "$MNT/etc/nftables.nft"

# Persistence for operator-added egress ports. `wp-hardening.sh egress-allow`
# applies a port to the LIVE ruleset and appends an `add element` line here;
# this include is what makes it survive a reboot. Created empty (comments
# only) at install because nftables treats a missing include as a fatal
# error -- and a fatal error loading nftables means the VM boots with NO
# firewall at all, which is a far worse outcome than the feature not working.
mkdir -p "$MNT/etc/wp-install"
cat > "$MNT/etc/wp-install/egress-extra.nft" << 'EGRESSEXTRA'
# Operator-added egress ports, managed by:
#   wp-hardening.sh egress-allow <port> [tcp|udp]
#   wp-hardening.sh egress-deny  <port> [tcp|udp]
# Included from /etc/nftables.nft. Do not delete this file — an empty one is
# valid and expected; a missing one makes the whole ruleset fail to load.
EGRESSEXTRA
chmod 644 "$MNT/etc/wp-install/egress-extra.nft"
printf '\ninclude "/etc/wp-install/egress-extra.nft"\n' >> "$MNT/etc/nftables.nft"
msg_ok "nftables.nft injected (with egress-extra include)"

# ─ Network addressing (DHCP or static) ────────────────────────────────────────
# Alpine's cloud image reads /etc/network/interfaces via the OpenRC "networking"
# service (already enabled below). We overwrite it unconditionally so behaviour
# is deterministic regardless of what the base image shipped with.
mkdir -p "$MNT/etc/network"
if [[ "$NET_MODE" == "static" ]]; then
  IFS=' ' read -r -a _dns_arr <<< "$VM_DNS"
  cat > "$MNT/etc/network/interfaces" << IFACEEOF
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
    address ${VM_STATIC_IP}
    netmask ${VM_NETMASK}
    gateway ${VM_GATEWAY}
    dns-nameservers ${_dns_arr[*]}
IFACEEOF
  msg_ok "Static network config injected: ${VM_STATIC_IP}/${VM_PREFIX} via ${VM_GATEWAY}"
else
  cat > "$MNT/etc/network/interfaces" << 'IFACEEOF'
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
IFACEEOF
  msg_ok "DHCP network config injected"
fi

# ── Shell-safe serialization for vars.sh (BUG FIX v7-12, #10) ──────────────
