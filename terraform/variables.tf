variable "do_token" {
  description = "DigitalOcean API token. Set via TF_VAR_do_token env var or terraform.tfvars (gitignored)."
  type        = string
  sensitive   = true
}

variable "ssh_public_key_path" {
  description = "Path to the PUBLIC half of the dedicated project SSH key (never the private key)."
  type        = string
  default     = "~/.ssh/honeypot_project.pub"
}

variable "admin_ssh_port" {
  description = "Non-standard port the REAL sshd will listen on. Port 22 is reserved for Cowrie."
  type        = number
  default     = 2201
}

variable "admin_ip_cidr" {
  description = "Your home/admin IP in CIDR form (e.g. 203.0.113.5/32). Restricts real SSH access. Use 0.0.0.0/0 only temporarily if your IP is dynamic, then tighten it."
  type        = string
}

variable "region" {
  description = "DigitalOcean region slug."
  type        = string
  default     = "nyc3"
}

variable "droplet_size" {
  description = "Droplet size slug. s-1vcpu-1gb is plenty for Cowrie."
  type        = string
  default     = "s-1vcpu-1gb"
}

variable "droplet_name" {
  type    = string
  default = "honeypot-01"
}
