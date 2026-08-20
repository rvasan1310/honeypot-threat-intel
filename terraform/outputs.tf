output "droplet_ip" {
  description = "Public IP of the honeypot VPS."
  value       = digitalocean_droplet.honeypot.ipv4_address
}

output "admin_ssh_command" {
  description = "How to reach the REAL sshd (not the honeypot)."
  value       = "ssh -i ~/.ssh/honeypot_project -p ${var.admin_ssh_port} root@${digitalocean_droplet.honeypot.ipv4_address}"
}
