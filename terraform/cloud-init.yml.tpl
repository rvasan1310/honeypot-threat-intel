#cloud-config
# First-boot hardening: real sshd moves off 22 and goes key-only BEFORE
# any honeypot container is deployed. Port 22 is left free for Cowrie later.

package_update: true
package_upgrade: true

packages:
  - ufw
  - unattended-upgrades
  - fail2ban
  - docker.io
  - docker-compose-plugin

write_files:
  - path: /etc/ssh/sshd_config.d/99-honeypot-hardening.conf
    content: |
      Port ${admin_ssh_port}
      PasswordAuthentication no
      PermitRootLogin prohibit-password
      X11Forwarding no
      AllowTcpForwarding no

  - path: /etc/apt/apt.conf.d/20auto-upgrades
    content: |
      APT::Periodic::Update-Package-Lists "1";
      APT::Periodic::Unattended-Upgrade "1";

runcmd:
  # Restart sshd on the new port before touching the firewall so we never
  # lock ourselves out mid-boot.
  - systemctl restart ssh
  - ufw default deny incoming
  - ufw default allow outgoing
  - ufw allow ${admin_ssh_port}/tcp
  - ufw allow 22/tcp
  - ufw allow 23/tcp
  - ufw --force enable
  - systemctl enable --now unattended-upgrades
  - systemctl enable --now fail2ban
  - systemctl enable --now docker
  - usermod -aG docker $(logname 2>/dev/null || echo root)
