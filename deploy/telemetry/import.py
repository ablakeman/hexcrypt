#!/usr/bin/env python3
"""Append trimmed nginx log lines (stdin, combined format) to the telemetry DB (argv[1]).

Rebuild from the permanent log: rm telemetry.db && import.py telemetry.db < access.log
"""
import re
import sqlite3
import sys
from datetime import datetime, timezone

LINE = re.compile(r'(\S+) - - \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3}) (\d+) "([^"]*)" "([^"]*)"')

SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    ts TEXT NOT NULL,     -- UTC, ISO 8601
    network TEXT,         -- client IPv4 /24 or IPv6 /48
    method TEXT,
    route TEXT,           -- secret ids are replaced with :id
    status INTEGER,
    bytes INTEGER,
    referer TEXT,
    user_agent TEXT,
    via TEXT,             -- cli (no User-Agent) or web
    event TEXT            -- home_view, link_opened, created, revealed, not_found, rate_limited, server_full
);
CREATE INDEX IF NOT EXISTS requests_ts ON requests(ts);
CREATE INDEX IF NOT EXISTS requests_event ON requests(event);
DROP VIEW IF EXISTS daily;
CREATE VIEW daily AS
SELECT date(ts) AS day,
    count(DISTINCT CASE WHEN event IN ('home_view', 'link_opened') THEN network END) AS visitors,
    sum(event = 'home_view') AS home_views,
    sum(event = 'link_opened') AS links_opened,
    sum(event = 'created') AS created,
    sum(event = 'created' AND via = 'cli') AS created_cli,
    sum(event = 'revealed') AS revealed,
    sum(event = 'revealed' AND via = 'cli') AS revealed_cli,
    sum(event = 'not_found') AS not_found,
    sum(event = 'rate_limited') AS rate_limited,
    sum(event = 'server_full') AS server_full,
    count(*) AS requests
FROM requests GROUP BY day ORDER BY day DESC;
"""

EVENTS = {
    ("GET", "/", 200): "home_view",
    ("GET", "/:id", 200): "link_opened",
    ("PUT", "/api/v1/secrets/:id", 201): "created",
    ("GET", "/api/v1/secrets/:id", 200): "revealed",
    ("GET", "/api/v1/secrets/:id", 404): "not_found",
}


def rows(lines):
    for line in lines:
        m = LINE.match(line)
        if not m:
            continue
        network, ts, method, route, status, size, referer, ua = m.groups()
        ts = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
        status = int(status)
        event = {429: "rate_limited", 507: "server_full"}.get(status) or EVENTS.get((method, route, status))
        yield (ts.strftime("%Y-%m-%dT%H:%M:%SZ"), network, method, route, status, int(size),
               None if referer == "-" else referer, None if ua == "-" else ua, "cli" if ua == "-" else "web", event)


db = sqlite3.connect(sys.argv[1])
db.executescript(SCHEMA)
with db:
    db.executemany("INSERT INTO requests VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows(sys.stdin))
