terraform {
  required_version = ">= 1.5.0"
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.34"
    }
  }
}

provider "digitalocean" {
  token = var.do_token
}

# Dedicated project SSH key -- upload the PUBLIC half only.
resource "digitalocean_ssh_key" "honeypot_key" {
  name       = "honeypot-project-key"
  public_key = file(var.ssh_public_key_path)
}

# Cloud-init handles first-boot hardening (Phase 2) so the box never has an
# open window with default sshd config before we can lock it down. A single
# text/cloud-config document doesn't need the hashicorp/cloudinit provider's
# MIME-multipart machinery -- the builtin templatefile() is enough.
resource "digitalocean_droplet" "honeypot" {
  image  = "ubuntu-22-04-x64"
  name   = var.droplet_name
  region = var.region
  size   = var.droplet_size
  ssh_keys = [digitalocean_ssh_key.honeypot_key.fingerprint]
  user_data = templatefile("${path.module}/cloud-init.yml.tpl", {
    admin_ssh_port = var.admin_ssh_port
  })

  tags = ["honeypot", "threat-intel"]
}

# Firewall managed as code -- this is the point of the exercise.
# Only the admin SSH port (real sshd) and port 22 (Cowrie, pretending to be sshd) are open.
resource "digitalocean_firewall" "honeypot_fw" {
  name        = "honeypot-firewall"
  droplet_ids = [digitalocean_droplet.honeypot.id]

  inbound_rule {
    protocol         = "tcp"
    port_range       = var.admin_ssh_port
    source_addresses = [var.admin_ip_cidr]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Optional: Cowrie telnet honeypot (2223->23). Comment out if you only want SSH.
  inbound_rule {
    protocol         = "tcp"
    port_range       = "23"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}
