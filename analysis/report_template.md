# I ran a real SSH/Telnet honeypot on the open internet for 12 days. Here's what attacked it.

*Collection window: Aug 20 - Sep 1, 2026 (12 days).*

## What I built

Provisioned a VPS via Terraform (DigitalOcean, firewall managed as code),
deployed [Cowrie](https://github.com/cowrie/cowrie) (fake SSH/Telnet) via
Docker Compose, and wired a GitHub Actions pipeline that redeploys the
honeypot config on every push to `main`. Logs are shipped off-box daily to
a private git branch so a compromised container can't destroy its own
evidence. Repo: [`rvasan1310/honeypot-threat-intel`](https://github.com/rvasan1310/honeypot-threat-intel).

## Known limitation: no post-auth command data for this window

A misconfiguration in `cowrie.cfg` (three keys pointed at bundled-resource
paths that don't exist in the `cowrie/cowrie:latest` image) crashed every
single session immediately after a successful login, before the attacker
ever reached a shell. That means the numbers below are solid for
connection volume and credential-stuffing behavior, but there is **zero
post-auth command data** for the full Aug 20 - Sep 1 window — no malware
staging, no recon commands, no miner drops observed, because none were
ever captured, not because attackers didn't attempt them. This was found
and fixed on 2026-09-01 (see repo commit `a638b86`); a follow-up collection
window is needed to fill in the "concrete stories" and command-category
sections below with real data.

## The numbers

Pulled from `analysis/output/summary.json`:

- Total events logged: **103,967**
- Total connection attempts: **21,943**
- Unique sessions: **21,965**
- Unique source IPs: **1,596**
- Successful logins: **13,093** (all crashed pre-shell, see limitation above)
- Failed logins: **12,795**
- Top credential pairs tried: *(see chart)*

![Top credentials](../output/top_credentials.png)
![Connections per day](../output/connections_per_day.png)

*Country breakdown and command-category chart are not included this round:
country requires a MaxMind GeoLite2 DB (`--geoip` flag, not yet wired up),
and command categories are empty for the reason above.*

The two most-tried pairs — `enable\x00`/`linuxshell\x00` (2,787 attempts)
and `system\x00`/`shell\x00` (2,739 attempts) — dwarf everything else and
carry trailing null bytes, a fingerprint of raw Telnet-negotiation scanner
tools rather than manual attempts; this is almost certainly one or two
automated botnet scanners hammering the telnet listener. Further down the
list, `root/xc3511` (272) and `root/vizxv` (205) are the original Mirai
botnet's hardcoded default-credential list for IP cameras and DVRs —
nearly a decade old and still in active use by scanners today. The rest
(`admin/admin`, `root/admin`, `support/support`, `root/default`) are
generic router/appliance default-credential guesses, consistent with
broad, untargeted IoT credential stuffing rather than anything aimed at
this host specifically.

## Concrete stories

Blocked on the post-auth data gap above — none of this window's ~13k
successful logins produced command data to tell a story from. This section
is intentionally left out of this round; revisit after the next collection
window using `analysis/output/summary.json`'s `top_15_commands` or by
grepping specific `session` IDs out of the raw JSON.

## MITRE ATT&CK mapping observed

| Behavior | Technique | Observed this window? |
|---|---|---|
| Password brute forcing | T1110 Brute Force | Yes (12,795 failed attempts) |
| Successful login w/ guessed creds | T1078 Valid Accounts | Yes (13,093, but see limitation) |
| Commands run post-login | T1059 Command and Scripting Interpreter | No — capture bug, see above |
| File download attempts (wget/curl) | T1105 Ingress Tool Transfer | No — capture bug, see above |
| Recon commands (uname, whoami, etc) | T1082 System Information Discovery | No — capture bug, see above |
| Cryptominer indicators | T1496 Resource Hijacking | No — capture bug, see above |

## What I'd do differently / next steps

- [ ] Re-run collection now that the post-auth capture bug is fixed, to
      actually fill in the command-behavior sections above
- [ ] Wire up `--geoip` with a MaxMind GeoLite2 DB for the country breakdown
- [ ] Add a health check that catches "container up but every session
      dying pre-shell" — the Docker healthcheck only checked the port was
      listening, which stayed true throughout this entire bug
- [ ] Add a second honeypot type (Conpot for ICS/SCADA flavor)
- [ ] Correlate source IPs against known botnet / C2 IP lists
- [ ] Longer collection window to see if credential lists rotate over time

## Repo

Terraform, Compose config, CI/CD pipeline, and analysis scripts (logs and
secrets scrubbed): [`rvasan1310/honeypot-threat-intel`](https://github.com/rvasan1310/honeypot-threat-intel)
