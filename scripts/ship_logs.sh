#!/usr/bin/env bash
# Runs ON THE VPS via cron. Ships cowrie.json off-box daily so a compromised
# box can't be used to destroy its own evidence.
#
# Default strategy: commit a dated snapshot to a "logs" branch of this repo
# using a dedicated deploy key with write access (separate from the CI
# read-only key if you want defense in depth -- see README).
#
# Alternative: swap the git block below for `rclone sync` / `s3cmd put` to
# push straight to a DigitalOcean Spaces / S3 bucket instead.
#
# Suggested crontab (run `crontab -e` on the VPS):
#   17 3 * * * /opt/honeypot/repo/scripts/ship_logs.sh >> /var/log/ship_logs.log 2>&1
set -euo pipefail

REPO_DIR="${REPO_DIR:-/opt/honeypot/repo}"
LOG_SRC="/opt/honeypot/logs/cowrie.json"
LOGS_BRANCH="logs"
DATE_TAG="$(date -u +%F)"

cd "$REPO_DIR"

git fetch origin "$LOGS_BRANCH" 2>/dev/null || true
git checkout -B "$LOGS_BRANCH" "origin/$LOGS_BRANCH" 2>/dev/null || git checkout -B "$LOGS_BRANCH"

mkdir -p "raw/${DATE_TAG}"
cp "$LOG_SRC" "raw/${DATE_TAG}/cowrie.json"

git add "raw/${DATE_TAG}/cowrie.json"
if ! git diff --cached --quiet; then
  git -c user.name="honeypot-bot" -c user.email="honeypot-bot@localhost" \
    commit -m "logs: ${DATE_TAG} snapshot"
  git push origin "$LOGS_BRANCH"
  echo "Shipped ${DATE_TAG} snapshot."
else
  echo "No log changes to ship for ${DATE_TAG}."
fi

git checkout main
