#!/bin/bash
# Appends new hexcrypt access-log lines from the shared nginx container to a permanent
# log, then rebuilds the GoAccess report and a daily CSV. Cron, every 15 minutes:
#   */15 * * * * /srv/www/hexcrypt/deploy/telemetry/collect.sh
# Lines logged between the last run and an nginx container recreate are lost.
set -euo pipefail

DIR=${TELEMETRY_DIR:-/srv/www/hexcrypt-telemetry}
NGINX=celebratingbrentcom-nginx-1
mkdir -p "$DIR/public"
cd "$DIR"

# [since, until) window, so each line is collected exactly once.
now=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
since=$(cat last-run 2>/dev/null || echo 1970-01-01T00:00:00Z)
docker logs --since "$since" --until "$now" "$NGINX" 2>/dev/null | sed -n 's/^hexcrypt //p' >> access.log
echo "$now" > last-run

goaccess access.log --log-format=COMBINED --html-report-title="hexcrypt" --no-global-config \
    -o public/index.html.tmp >/dev/null 2>&1 && mv public/index.html.tmp public/index.html

# One row per day. The CLI sends no User-Agent, so nginx logs "-".
awk -F'"' '
BEGIN { split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m, " "); for (i in m) mon[m[i]] = sprintf("%02d", i) }
{
    ip = substr($1, 1, index($1, " ") - 1)
    match($1, /\[[^:]+/); split(substr($1, RSTART + 1, RLENGTH - 1), a, "/"); day = a[3] "-" mon[a[2]] "-" a[1]
    split($2, r, " "); split($3, s, " "); req = r[1] " " r[2]; st = s[1]; cli = ($6 == "-")
    days[day] = 1
    if (r[1] == "GET" && (r[2] == "/" || r[2] == "/:id") && st == 200) { views[day]++; if (!seen[day, ip]++) visitors[day]++ }
    if (req == "GET /:id" && st == 200) opened[day]++
    if (req == "PUT /api/v1/secrets/:id" && st == 201) { created[day]++; if (cli) created_cli[day]++ }
    if (req == "GET /api/v1/secrets/:id" && st == 200) { revealed[day]++; if (cli) revealed_cli[day]++ }
    if (req == "GET /api/v1/secrets/:id" && st == 404) missing[day]++
    if (st == 429) limited[day]++
    if (st == 507) full[day]++
}
END {
    print "date,page_views,visitors,links_opened,created,created_cli,revealed,revealed_cli,not_found,rate_limited,server_full"; fflush()
    for (d in days) printf "%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n", d, views[d], visitors[d], opened[d], created[d], created_cli[d], revealed[d], revealed_cli[d], missing[d], limited[d], full[d] | "sort"
}' access.log > public/daily.csv
cp access.log public/access.log
