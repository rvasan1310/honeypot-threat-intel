# [I ran a real SSH honeypot on the open internet for two weeks. Here's what attacked it.]

*Fill in dates once collection is done, e.g. "Aug 20 - Sep 3, 2026".*

## What I built

Provisioned a VPS via Terraform (DigitalOcean, firewall managed as code),
deployed [Cowrie](https://github.com/cowrie/cowrie) (fake SSH/Telnet) via
Docker Compose, and wired a GitHub Actions pipeline that redeploys the
honeypot config on every push to `main`. Logs are shipped off-box daily to
a private git branch so a compromised container can't destroy its own
evidence. Repo: `[link]`.

## The numbers

*Pull these straight from `analysis/output/summary.json` after running
`parse_logs.py`.*

- Total connection attempts: **N**
- Unique source IPs: **N**
- Unique countries: **N**
- Top credential pairs tried: *(see chart)*

![Top credentials](../output/top_credentials.png)
![Top countries](../output/top_countries.png)
![Connections per day](../output/connections_per_day.png)
![Command categories](../output/command_categories.png)

## Concrete stories

*Pick 2-3 individual sessions from `analysis/output/summary.json`'s
`top_15_commands` or by grepping specific `session` IDs out of the raw
JSON. For each: what they tried, in what order, and what it maps to.*

### Story 1: [e.g. "Cryptominer staging via wget"]

Session `[session_id]` from `[ip]` (`[country]`) logged in with
`[user]/[pass]`, then ran:

```
[command 1]
[command 2]
[command 3]
```

This is consistent with **[malware staging / recon / miner drop]**, mapped
to MITRE ATT&CK **[T1105 Ingress Tool Transfer / T1496 Resource Hijacking]**.

### Story 2: [...]

### Story 3: [...]

## MITRE ATT&CK mapping observed

| Behavior | Technique |
|---|---|
| Password brute forcing | T1110 Brute Force |
| Successful login w/ guessed creds | T1078 Valid Accounts |
| Commands run post-login | T1059 Command and Scripting Interpreter |
| File download attempts (wget/curl) | T1105 Ingress Tool Transfer |
| Recon commands (uname, whoami, etc) | T1082 System Information Discovery |
| Cryptominer indicators | T1496 Resource Hijacking |

## What I'd do differently / next steps

- [ ] Add a second honeypot type (Conpot for ICS/SCADA flavor)
- [ ] Correlate source IPs against known botnet / C2 IP lists
- [ ] Longer collection window to see if credential lists rotate over time
- [ ] [your own findings here]

## Repo

Terraform, Compose config, CI/CD pipeline, and analysis scripts (logs and
secrets scrubbed): `[link]`
