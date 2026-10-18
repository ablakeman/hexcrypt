#!/bin/bash
# Loads new hexcrypt access-log lines from the shared nginx container into the telemetry
# DB, and keeps them in a permanent log the DB can be rebuilt from. Cron, every 15 minutes:
#   */15 * * * * /srv/www/hexcrypt/deploy/telemetry/collect.sh
# Lines logged between the last run and an nginx container recreate are lost.
set -euo pipefail

HERE=$(dirname "$(readlink -f "$0")")
DIR=${TELEMETRY_DIR:-/srv/www/hexcrypt-telemetry}
NGINX=celebratingbrentcom-nginx-1
mkdir -p "$DIR/db"
cd "$DIR"

# [since, until) window, so each line is collected exactly once. last-run only
# advances after the import succeeds, so a failed run is retried next time.
now=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
since=$(cat last-run 2>/dev/null || echo 1970-01-01T00:00:00Z)
docker logs --since "$since" --until "$now" "$NGINX" 2>/dev/null | sed -n 's/^hexcrypt //p' > new.log
"$HERE/import.py" db/telemetry.db < new.log
cat new.log >> access.log
echo "$now" > last-run
