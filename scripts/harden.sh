#!/usr/bin/env bash
# Manual/idempotent version of the hardening cloud-init already applies on
# first boot. Re-run safely any time; useful if you provisioned the box
# by hand instead of via terraform, or want to double check drift.
#
# Usage: sudo ./harden.sh <admin_ssh_port>
set -euo pipefail

ADMIN_PORT="${1:?Usage: harden.sh <admin_ssh_port>}"

echo "==> Configuring sshd (real admin daemon) on port ${ADMIN_PORT}, key-only"
install -d /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/99-honeypot-hardening.conf <<EOF
Port ${ADMIN_PORT}
PasswordAuthentication no
PermitRootLogin prohibit-password
X11Forwarding no
AllowTcpForwarding no
EOF
systemctl restart ssh

echo "==> Installing unattended-upgrades, fail2ban, ufw, docker"
apt-get update -y
apt-get install -y ufw unattended-upgrades fail2ban docker.io docker-compose-plugin

cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
systemctl enable --now unattended-upgrades
systemctl enable --now fail2ban
systemctl enable --now docker

echo "==> Firewall: admin port (${ADMIN_PORT}) + honeypot ports 22/23 only"
ufw default deny incoming
ufw default allow outgoing
ufw allow "${ADMIN_PORT}"/tcp
ufw allow 22/tcp
ufw allow 23/tcp
ufw --force enable

echo "==> Done. Verify with: ufw status verbose && systemctl status ssh"
