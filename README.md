# honeypot-threat-intel

A real internet-facing SSH/Telnet honeypot (Cowrie), provisioned via
Terraform, deployed via Docker Compose, redeployed via GitHub Actions.
Collects real attacker telemetry for a short threat-intel writeup, with
findings mapped to MITRE ATT&CK.

Repo layout:

```
terraform/        # DigitalOcean droplet + firewall + first-boot hardening (cloud-init)
docker/           # docker-compose.yml + Cowrie config (cowrie.cfg, userdb.txt)
scripts/          # harden.sh, bootstrap_honeypot.sh, ship_logs.sh (log exfil off-box)
.github/workflows/ # deploy.yml (CI/CD redeploy), healthcheck.yml (daily spot-check)
analysis/         # parse_logs.py, report_template.md
```

Everything in this repo is generated and ready to run, but the steps below
that touch a real cloud account, real money, or a live internet-facing
box are yours to execute and confirm — provisioning infrastructure and
exposing a port to the internet isn't something to do on autopilot.

---

## Phase 0 — Prerequisites (you do this)

1. Create a DigitalOcean account and an API token (`API` → `Generate New
   Token`, read+write). This repo's Terraform is written for DigitalOcean;
   swapping to Linode/Vultr means swapping the provider block in
   `terraform/main.tf` and adjusting resource names.
2. Generate a **dedicated** SSH key for this project only:
   ```bash
   ssh-keygen -t ed25519 -f ~/.ssh/honeypot_project -C "honeypot-vps"
   ```
3. Push this repo to GitHub as `honeypot-threat-intel` (private is fine
   while iterating, make it public before you link it in the report).

## Phase 1 — Provision with Terraform (you run this)

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars: do_token, ssh_public_key_path
terraform init
terraform plan
terraform apply
```

`main.tf` defines the droplet, uploads your public key, and creates a
DigitalOcean Cloud Firewall (`digitalocean_firewall.honeypot_fw`) as code
— that firewall resource is the thing worth pointing to in an interview,
not a screenshot of a dashboard toggle.

**Never commit `terraform.tfvars`** — it's gitignored, and holds your API
token. Set `TF_VAR_do_token` as an env var instead if you'd rather not
keep it in a file at all.

## Phase 2 — Hardening (already automated, verify it)

`terraform/cloud-init.yml.tpl` runs on first boot, before Terraform even
returns: moves real sshd to `admin_ssh_port`, disables password auth,
enables `ufw` (deny-by-default, allow only the admin port + 22 + 23),
turns on `unattended-upgrades` and `fail2ban`, installs Docker.

Verify after `terraform apply` finishes (wait ~60s for cloud-init):

```bash
ssh -i ~/.ssh/honeypot_project -p <admin_ssh_port> root@<droplet_ip>
sudo ufw status verbose
systemctl status ssh unattended-upgrades fail2ban docker
```

If you provisioned by hand instead of trusting cloud-init, `scripts/harden.sh
<admin_ssh_port>` does the same thing idempotently.

## Phase 3 — Deploy Cowrie (you run this, on the VPS)

```bash
# on the VPS, as the admin user:
sudo mkdir -p /opt/honeypot/repo
sudo chown -R $(whoami) /opt/honeypot
git clone <your-repo-url> /opt/honeypot/repo
./scripts/bootstrap_honeypot.sh   # creates /opt/honeypot/logs + /downloads

cd /opt/honeypot/repo/docker
docker compose up -d
docker compose ps
```

`docker/docker-compose.yml` maps host port 22 → container 2222 (and 23 →
2223 for telnet), and bind-mounts logs/downloads straight to
`/opt/honeypot/logs` and `/opt/honeypot/downloads` on the host so
`scripts/ship_logs.sh` can read them regardless of container state.
`docker/cowrie/cowrie.cfg` sets a plausible fake hostname
(`srv-prod-04`), enables `output_jsonlog` (`cowrie.json`), and
`docker/cowrie/userdb.txt` accepts most brute-forced creds (except
`root`/`root`) so you capture post-login command activity, not just a
wall of failed logins.

**Test from your laptop, not the VPS itself:**

```bash
ssh root@<droplet_ip>          # should land in a FAKE shell
whoami; ls; uname -a           # confirm harmless commands work
```

Then confirm it landed in the log:

```bash
ssh -i ~/.ssh/honeypot_project -p <admin_ssh_port> root@<droplet_ip> \
  'tail -5 /opt/honeypot/logs/cowrie.json'
```

## Phase 4 — CI/CD (you configure the secrets, once)

The admin SSH port (`admin_ssh_port`) is open to `0.0.0.0/0` in the
firewall, not scoped to a single IP — GitHub's hosted runners connect from
GitHub's own dynamic IP ranges, which aren't practical to allowlist.
Security here rests on key-only auth (`PasswordAuthentication no`),
`fail2ban`, and a non-default port, not on restricting the source IP.

In the GitHub repo: **Settings → Secrets and variables → Actions**, add:

| Secret | Value |
|---|---|
| `VPS_HOST` | droplet IP |
| `VPS_ADMIN_PORT` | your `admin_ssh_port` |
| `VPS_USER` | e.g. `root` |
| `VPS_DEPLOY_SSH_KEY` | private half of a **deploy-only** key (generate a separate one from your personal admin key; add its public half to the VPS's `authorized_keys`) |

`.github/workflows/deploy.yml` triggers on push to `main` touching
`docker/**`, SSHes in via `appleboy/ssh-action`, `git reset --hard
origin/main`, and does `docker compose down && up -d --build`.
`.github/workflows/healthcheck.yml` runs daily, fails (→ GitHub emails
you) if the container isn't running or `cowrie.json` hasn't grown in 48h
— this automates the Phase 6 "spot check" so you don't have to remember.

Test it: tweak a comment in `docker/docker-compose.yml`, push to `main`,
watch the Action run, confirm `docker compose ps` shows a fresh container
start time.

## Phase 5 — Log shipping (you set up the cron job)

On the VPS:

```bash
crontab -e
# add:
17 3 * * * /opt/honeypot/repo/scripts/ship_logs.sh >> /var/log/ship_logs.log 2>&1
```

`scripts/ship_logs.sh` commits a dated snapshot of `cowrie.json` to a
`logs` branch of this repo. Use a **separate write-capable deploy key**
from the CI one if you want defense in depth (CI key stays read-only,
shipping key can push but can't redeploy).

**GeoIP (optional):** download MaxMind's free GeoLite2-Country database
(requires a free MaxMind account) and pass its path to
`analysis/parse_logs.py --geoip`.

## Phase 6 — Let it run (1-2 weeks, do nothing)

- Don't restart or tune the containers.
- Don't SSH into the honeypot from your real IP to "test" it again — it
  pollutes the dataset. Use the healthcheck workflow instead of manual
  pokes.
- Check in on `healthcheck.yml` runs in the Actions tab.

## Phase 7 — Analyze

```bash
cd analysis
python -m venv .venv && source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements.txt

# pull the shipped logs down first:
git fetch origin logs
git checkout origin/logs -- raw/

python parse_logs.py --input "raw/**/cowrie.json" --outdir output \
  --geoip /path/to/GeoLite2-Country.mmdb   # omit --geoip to skip country stats
```

Produces `output/summary.json` (all the headline numbers) plus PNG charts:
top credentials, top countries, connections/day, command categories
(malware-staging / recon / crypto-mining / other, via simple keyword
matching in `classify_command()` — sanity-check a sample by hand before
trusting it for the report).

## Phase 8 — Write the report

Fill in `analysis/report_template.md` using `output/summary.json` and the
charts. Pick 2-3 individual sessions to narrate by hand — the automated
categorization tells you *where* to look, not the story itself. Publish
as this repo's root README (replace this file) or a separate post, and
link back to the repo.

---

## Pre-flight checklist before going live

- [ ] Dedicated SSH key for this project only, not personal (`Phase 0`)
- [ ] Real admin sshd off port 22, key-only (`cloud-init.yml.tpl` / `harden.sh`)
- [ ] Firewall allows only admin port + honeypot ports (`digitalocean_firewall.honeypot_fw`)
- [ ] `terraform.tfvars` gitignored, never committed
- [ ] CI deploy key is read-only-ish (scoped to redeploy, not god-mode); log-shipping key is separate if used
- [ ] Logs shipped off-box daily (`scripts/ship_logs.sh` + cron)
- [ ] No personal data, credentials, or reused passwords anywhere on this VPS, ever
