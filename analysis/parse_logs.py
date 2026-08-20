#!/usr/bin/env python3
"""
Parse Cowrie's cowrie.json (one JSON object per line) into the numbers and
charts used in the Phase 8 report: connection counts, top credentials,
post-auth commands, and MITRE ATT&CK tagging.

Usage:
    python parse_logs.py --input raw/*.json --outdir output \
        --geoip GeoLite2-Country.mmdb   # optional

If --geoip is omitted, country enrichment is skipped and the country chart
is left out (everything else still runs).
"""
import argparse
import glob
import json
from collections import Counter
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt

# Cowrie eventid -> rough MITRE ATT&CK technique used for post-hoc tagging in
# the report. This is intentionally coarse -- refine per-session by hand for
# the "concrete stories" section rather than trusting this mapping blindly.
MITRE_MAP = {
    "cowrie.login.failed": "T1110 (Brute Force)",
    "cowrie.login.success": "T1078 (Valid Accounts)",
    "cowrie.command.input": "T1059 (Command and Scripting Interpreter)",
    "cowrie.session.file_download": "T1105 (Ingress Tool Transfer)",
    "cowrie.session.file_upload": "T1105 (Ingress Tool Transfer)",
}

MALWARE_STAGING_HINTS = ("wget", "curl", "tftp", "scp ", "base64 -d", "chmod +x")
RECON_HINTS = ("uname", "whoami", "id", "cat /proc/cpuinfo", "cat /etc/issue", "ps aux")
MINER_HINTS = ("xmrig", "stratum+tcp", "minerd", "cpuminer")


def load_events(patterns):
    events = []
    for pattern in patterns:
        for path in glob.glob(pattern, recursive=True):
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    return pd.DataFrame(events)


def enrich_geoip(df, mmdb_path):
    import geoip2.database

    reader = geoip2.database.Reader(mmdb_path)

    def lookup(ip):
        try:
            return reader.country(ip).country.name or "Unknown"
        except Exception:
            return "Unknown"

    df["country"] = df["src_ip"].apply(lookup)
    reader.close()
    return df


def classify_command(cmd: str) -> str:
    low = cmd.lower()
    if any(h in low for h in MINER_HINTS):
        return "crypto-mining"
    if any(h in low for h in MALWARE_STAGING_HINTS):
        return "malware-staging"
    if any(h in low for h in RECON_HINTS):
        return "recon"
    return "other"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", nargs="+", default=["raw/**/cowrie.json"],
                     help="glob pattern(s) for cowrie.json files")
    ap.add_argument("--outdir", default="output")
    ap.add_argument("--geoip", default=None,
                     help="path to GeoLite2-Country.mmdb (optional)")
    args = ap.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    df = load_events(args.input)
    if df.empty:
        print("No events loaded -- check --input glob pattern.")
        return

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["mitre"] = df["eventid"].map(MITRE_MAP)

    if args.geoip and "src_ip" in df.columns:
        df = enrich_geoip(df, args.geoip)

    summary = {
        "total_events": len(df),
        "unique_sessions": df["session"].nunique() if "session" in df else None,
        "unique_source_ips": df["src_ip"].nunique() if "src_ip" in df else None,
        "date_range": [
            str(df["timestamp"].min()),
            str(df["timestamp"].max()),
        ],
    }
    if "country" in df.columns:
        summary["unique_countries"] = df["country"].nunique()

    # --- Top credential pairs -------------------------------------------------
    creds = df[df["eventid"].isin(["cowrie.login.failed", "cowrie.login.success"])]
    if not creds.empty:
        top_creds = (
            creds.groupby(["username", "password"]).size()
            .sort_values(ascending=False).head(10)
        )
        summary["top_10_credentials"] = [
            {"username": u, "password": p, "count": int(c)}
            for (u, p), c in top_creds.items()
        ]

        fig, ax = plt.subplots(figsize=(8, 5))
        labels = [f"{u}/{p}" for u, p in top_creds.index]
        ax.barh(labels[::-1], top_creds.values[::-1])
        ax.set_xlabel("Attempts")
        ax.set_title("Top 10 username/password combinations")
        fig.tight_layout()
        fig.savefig(outdir / "top_credentials.png", dpi=150)
        plt.close(fig)

    # --- Commands after login --------------------------------------------------
    cmds = df[df["eventid"] == "cowrie.command.input"].copy()
    if not cmds.empty:
        cmds["category"] = cmds["input"].fillna("").apply(classify_command)
        cat_counts = cmds["category"].value_counts()
        summary["command_categories"] = cat_counts.to_dict()

        top_cmds = cmds["input"].value_counts().head(15)
        summary["top_15_commands"] = top_cmds.to_dict()

        fig, ax = plt.subplots(figsize=(6, 5))
        ax.bar(cat_counts.index, cat_counts.values)
        ax.set_ylabel("Count")
        ax.set_title("Post-login commands by category")
        fig.tight_layout()
        fig.savefig(outdir / "command_categories.png", dpi=150)
        plt.close(fig)

    # --- Countries ---------------------------------------------------------
    if "country" in df.columns:
        top_countries = df.drop_duplicates("src_ip")["country"].value_counts().head(10)
        summary["top_10_countries_by_unique_ip"] = top_countries.to_dict()

        fig, ax = plt.subplots(figsize=(8, 5))
        ax.barh(top_countries.index[::-1], top_countries.values[::-1])
        ax.set_xlabel("Unique source IPs")
        ax.set_title("Top source countries")
        fig.tight_layout()
        fig.savefig(outdir / "top_countries.png", dpi=150)
        plt.close(fig)

    # --- Connections over time ----------------------------------------------
    connects = df[df["eventid"] == "cowrie.session.connect"]
    if not connects.empty:
        daily = connects.set_index("timestamp").resample("D").size()
        fig, ax = plt.subplots(figsize=(9, 4))
        daily.plot(ax=ax, marker="o")
        ax.set_ylabel("Connections")
        ax.set_title("Connection attempts per day")
        fig.tight_layout()
        fig.savefig(outdir / "connections_per_day.png", dpi=150)
        plt.close(fig)

    (outdir / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
    print(json.dumps(summary, indent=2, default=str))
    print(f"\nCharts + summary.json written to {outdir}/")


if __name__ == "__main__":
    main()
