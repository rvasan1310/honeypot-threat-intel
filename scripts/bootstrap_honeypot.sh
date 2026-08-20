#!/usr/bin/env bash
# Run once on the VPS after Terraform apply + harden.sh, to lay down the
# directories docker-compose.yml expects and do the first deploy.
# Usage: ./bootstrap_honeypot.sh
set -euo pipefail

sudo mkdir -p /opt/honeypot/logs /opt/honeypot/downloads
sudo chown -R "$(whoami)":"$(whoami)" /opt/honeypot

echo "==> Directories ready at /opt/honeypot. Now clone the repo and run:"
echo "    cd docker && docker compose up -d"
