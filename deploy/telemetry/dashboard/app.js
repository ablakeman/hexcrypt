// Dashboard over the telemetry DB, read through Datasette's JSON API (same origin, behind
// the nginx allowlist and basic auth). Paths, referrers and user agents come from strangers,
// so they only ever reach the page as text nodes, never as markup.

const nf = new Intl.NumberFormat().format;
const dayFmt = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" }).format;
const longDayFmt = new Intl.DateTimeFormat(undefined, { weekday: "short", month: "short", day: "numeric" }).format;
const RANGES = { "7d": 7, "30d": 30, "90d": 90, all: 0 };
// ponytail: one UTC offset for the whole range, so days on the far side of a DST change are off by an hour.
const TZ = `${-new Date().getTimezoneOffset()} minutes`;

// A network is people on a day it loaded the app (only a browser running the page fetches
// the wasm) or used the CLI to send or read. Everything else is automated.
const BASE = `WITH r AS (SELECT date(ts, :tz) AS d, * FROM requests WHERE ts >= :since),
human AS (SELECT * FROM r WHERE route LIKE '/assets/%.wasm' OR (via = 'cli' AND event IN ('created', 'revealed'))),
people AS (SELECT DISTINCT d, network FROM human) `;
const APP_ROUTES = `('/', '/favicon.svg', '/robots.txt', '/api/v1/config')`;
const SQL = {
  totals: `${BASE} SELECT (SELECT count(DISTINCT network) FROM human) AS people, count(*) AS requests,
    count(DISTINCT network) AS networks, total(event = 'created') AS created, total(event = 'created' AND via = 'cli') AS created_cli,
    total(event = 'link_opened') AS opened, total(event = 'revealed') AS revealed FROM r`,
  daily: `${BASE} SELECT r.d AS day, count(DISTINCT CASE WHEN p.network IS NOT NULL THEN r.network END) AS people,
    count(DISTINCT CASE WHEN p.network IS NULL THEN r.network END) AS automated, count(*) AS requests,
    total(event = 'created') AS created, total(event = 'revealed') AS revealed, total(event = 'not_found') AS not_found,
    total(event = 'rate_limited') AS rate_limited, total(event = 'server_full') AS server_full
    FROM r LEFT JOIN people p ON p.d = r.d AND p.network = r.network GROUP BY r.d`,
  hours: `${BASE} SELECT CAST(strftime('%w', ts, :tz) AS INTEGER) AS dow, CAST(strftime('%H', ts, :tz) AS INTEGER) AS hour,
    count(*) AS n FROM human GROUP BY 1, 2`,
  clients: `${BASE} SELECT user_agent AS ua, count(DISTINCT d || network) AS n FROM human GROUP BY 1`,
  referrers: `${BASE} SELECT referer, count(*) AS n FROM r WHERE event IN ('home_view', 'link_opened')
    AND referer IS NOT NULL AND referer NOT LIKE 'http%://hexcrypt.com%' AND referer NOT LIKE 'http%://www.hexcrypt.com%'
    GROUP BY 1 ORDER BY n DESC LIMIT 50`,
  probes: `${BASE} SELECT route, count(*) AS n, count(DISTINCT network) AS networks FROM r
    WHERE event IS NULL AND status NOT IN (301, 304) AND route NOT LIKE '/assets/%' AND route NOT IN ${APP_ROUTES}
    GROUP BY 1 ORDER BY n DESC LIMIT 10`,
};

async function query(sql, params = {}) {
  const res = await fetch(`/telemetry.json?${new URLSearchParams({ sql, _shape: "array", ...params })}`);
  const body = await res.json().catch(() => ({}));
  if (!res.ok || !Array.isArray(body)) throw new Error(body.error || `HTTP ${res.status}`);
  return body;
}

function el(tag, attrs = {}, ...kids) {
  const e = tag.startsWith("svg:") ? document.createElementNS("http://www.w3.org/2000/svg", tag.slice(4)) : document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  e.append(...kids.flat().filter((k) => k != null && k !== false));
  return e;
}
const $ = (id) => document.getElementById(id);
const num = (n) => el("span", { class: "num" }, nf(n));
const plural = (n, one, many) => [num(n), ` ${n === 1 ? one : many}`];
const pct = (a, b) => (b ? `${Math.round((100 * a) / b)}%` : "–");
const ymd = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
const parseDay = (s) => new Date(`${s}T12:00:00`);

// Every local day from `first` to today, so quiet days show as gaps instead of disappearing.
function dayList(first) {
  const out = [];
  for (const d = parseDay(first), end = ymd(new Date()); ymd(d) <= end; d.setDate(d.getDate() + 1)) out.push(ymd(d));
  return out;
}

function niceMax(v) {
  if (v <= 4) return 4;
  const p = 10 ** Math.floor(Math.log10(v));
  return [1, 2, 5, 10].map((m) => m * p).find((m) => m >= v);
}

// Daily columns, stacked or side by side. Pointer or arrow keys pick a day for the readout.
function columns(box, rows, series, { height = 220, stack = true, axis = true, readout } = {}) {
  const width = Math.max(box.clientWidth, 240);
  const left = axis ? 34 : 0, bottom = axis ? 22 : 0, plotW = width - left, plotH = height - bottom;
  const total = (r) => (stack ? series.reduce((a, s) => a + r[s.key], 0) : Math.max(...series.map((s) => r[s.key])));
  const max = niceMax(Math.max(0, ...rows.map(total)));
  const slot = plotW / rows.length, barW = Math.min(56, Math.max(1, slot * (rows.length > 60 ? 0.86 : 0.7)));
  const y = (v) => (v / max) * plotH;
  const svg = el("svg:svg", { width, height, viewBox: `0 0 ${width} ${height}`, class: "cols" });
  svg.append(el("svg:defs", {}, el("svg:pattern", { id: `hatch-${box.id}`, width: 5, height: 5, patternUnits: "userSpaceOnUse", patternTransform: "rotate(45)" },
    el("svg:rect", { width: 5, height: 5, class: "hatch-bg" }), el("svg:line", { x1: 0, y1: 0, x2: 0, y2: 5, class: "hatch-line" }))));
  if (axis) {
    for (const t of [0, max / 2, max]) {
      const ty = plotH - y(t);
      svg.append(el("svg:line", { x1: left, x2: width, y1: ty, y2: ty, class: t ? "grid" : "base" }));
      svg.append(el("svg:text", { x: left - 8, y: ty + 4, "text-anchor": "end" }, nf(t)));
    }
    const every = Math.ceil(rows.length / Math.max(2, Math.floor(plotW / 70)));
    rows.forEach((r, i) => {
      if ((rows.length - 1 - i) % every) return;
      svg.append(el("svg:text", { x: left + slot * i + slot / 2, y: height - 4, "text-anchor": "middle" }, dayFmt(parseDay(r.day))));
    });
  }
  const groups = rows.map((r, i) => {
    const g = el("svg:g", {});
    let base = plotH;
    series.forEach((s, j) => {
      const h = y(r[s.key]);
      if (!h) return;
      const w = stack ? barW : barW / series.length;
      const x = left + slot * i + (slot - barW) / 2 + (stack ? 0 : w * j);
      const top = stack ? base - h : plotH - h;
      const rect = el("svg:rect", { x, y: top, width: w, height: h, class: s.cls });
      if (s.cls === "automated") rect.setAttribute("fill", `url(#hatch-${box.id})`);
      g.append(rect);
      if (stack) base -= h;
    });
    svg.append(g);
    return g;
  });
  box.replaceChildren(svg);
  if (!readout) return;

  // Defaults to the latest day; hover or arrow keys move it.
  let cur = rows.length - 1;
  const show = (i, mark) => {
    cur = Math.min(rows.length - 1, Math.max(0, i));
    groups.forEach((g, j) => g.classList.toggle("on", mark && j === cur));
    readout.el.replaceChildren(el("b", {}, longDayFmt(parseDay(rows[cur].day))), ": ", ...readout.text(rows[cur]));
  };
  show(cur, false);
  svg.setAttribute("tabindex", "0");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", `${readout.label}, one column per day. Use the arrow keys to read each day.`);
  svg.addEventListener("pointermove", (e) => show(Math.floor((e.offsetX - left) / slot), true));
  svg.addEventListener("pointerleave", () => show(rows.length - 1, false));
  svg.addEventListener("keydown", (e) => {
    const step = { ArrowLeft: -1, ArrowRight: 1 }[e.key];
    if (step) { e.preventDefault(); show(cur + step, true); }
  });
}

function bars(list, rows, empty, { mono = false } = {}) {
  if (!rows.length) return list.replaceChildren(el("li", { class: "empty" }, empty));
  const max = Math.max(...rows.map((r) => r.n));
  list.replaceChildren(...rows.map((r) => {
    const bar = el("i");
    bar.style.width = `${(100 * r.n) / max}%`;
    return el("li", { title: r.title || r.label }, el("span", { class: mono ? "label mono" : "label" }, r.label), el("span", { class: "num" }, nf(r.n)), bar);
  }));
}

// Sums rows that map to the same label, largest first.
function tally(rows, label, limit = 8) {
  const m = new Map();
  for (const r of rows) { const k = label(r); m.set(k, (m.get(k) || 0) + r.n); }
  return [...m].map(([label, n]) => ({ label, n })).sort((a, b) => b.n - a.n).slice(0, limit);
}

function client(ua) {
  if (!ua) return "hexcrypt CLI";
  if (/bot|crawl|spider|headless|curl|python|go-http|wget/i.test(ua)) return "Bots and scripts";
  const browser = /Edg\//.test(ua) ? "Edge" : /Firefox\/|FxiOS/.test(ua) ? "Firefox" : /Chrome\/|CriOS/.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Other";
  const os = /iPhone|iPad/.test(ua) ? "iOS" : /Android/.test(ua) ? "Android" : /Mac OS X/.test(ua) ? "macOS" : /Windows/.test(ua) ? "Windows" : /Linux/.test(ua) ? "Linux" : "";
  return os ? `${browser} on ${os}` : browser;
}

function host(ref) {
  try { return new URL(ref).host.replace(/^www\./, ""); } catch { return ref; }
}

function heat(box, rows) {
  const counts = new Map(rows.map((r) => [`${r.dow}:${r.hour}`, r.n]));
  const max = Math.max(1, ...rows.map((r) => r.n));
  const names = [1, 2, 3, 4, 5, 6, 0].map((d) => [d, new Intl.DateTimeFormat(undefined, { weekday: "short" }).format(new Date(2024, 0, 7 + d))]);
  const cells = [];
  for (const [d, name] of names) {
    cells.push(el("span", { class: "day" }, name));
    for (let h = 0; h < 24; h++) {
      const n = counts.get(`${d}:${h}`) || 0;
      const c = el("i", { title: `${name} ${String(h).padStart(2, "0")}:00, ${nf(n)} ${n === 1 ? "visit" : "visits"}` });
      if (n) c.style.setProperty("--a", (0.15 + (0.85 * n) / max).toFixed(3));
      cells.push(c);
    }
  }
  cells.push(el("span"), ...Array.from({ length: 24 }, (_, h) => el("span", { class: "hour" }, h % 6 ? "" : String(h).padStart(2, "0"))));
  box.replaceChildren(...cells);
}

function lead(t, first, range) {
  const when = range === "all" ? `Since ${dayFmt(parseDay(first))}` : `In the last ${RANGES[range]} days`;
  $("headline").replaceChildren(when, ", ", ...plural(t.people, "person", "people"), " opened hexcrypt",
    ...(t.created ? [" and sent ", ...plural(t.created, "secret", "secrets"), "."] : [". Nobody sent a secret."]));
  $("subline").replaceChildren(...plural(t.requests, "request", "requests"), " came from ", ...plural(t.networks, "network", "networks"), ". ",
    num(t.networks - t.people), " of those networks never loaded the app, so they count as automated.");
  const stage = (value, label, note, cls = "") => el("div", { class: cls }, el("dt", {}, label), el("dd", {}, num(value), el("small", {}, note)));
  $("flow").replaceChildren(
    stage(t.people, "People", "loaded the app or used the CLI"),
    stage(t.created, "Secrets sent", t.created ? `${nf(t.created - t.created_cli)} web, ${nf(t.created_cli)} CLI` : "none yet"),
    stage(t.opened, "Links opened", `${pct(t.opened, t.created)} of sent, in a browser`),
    stage(t.revealed, "Secrets read", `${pct(t.revealed, t.created)} of sent, ${nf(Math.max(0, t.created - t.revealed))} unread or expired`, "read"),
  );
}

let meta, token = 0, last;

async function load() {
  const range = location.hash.slice(1) in RANGES ? location.hash.slice(1) : "30d";
  for (const a of document.querySelectorAll(".tabs a")) a.toggleAttribute("aria-current", a.hash === `#${range}`);
  document.body.setAttribute("aria-busy", "true");
  const mine = ++token;
  try {
    meta ??= (await query("SELECT min(ts) AS first, max(ts) AS last FROM requests"))[0];
    if (!meta.first) throw new Error("the requests table is empty; the collector hasn't run yet");
    const firstLocal = ymd(new Date(meta.first));
    let first = firstLocal;
    if (RANGES[range]) { const d = new Date(); d.setDate(d.getDate() - RANGES[range] + 1); first = ymd(d); }
    const since = new Date(`${first}T00:00:00`).toISOString().slice(0, 19) + "Z";
    const params = { tz: TZ, since };
    const [[totals], daily, hours, clients, referrers, probes] = await Promise.all(
      ["totals", "daily", "hours", "clients", "referrers", "probes"].map((k) => query(SQL[k], params)));
    if (mine !== token) return;
    last = { totals, daily, hours, clients, referrers, probes, first: first < firstLocal ? firstLocal : first, range };
    render();
  } catch (e) {
    $("headline").textContent = "The telemetry database couldn't be read.";
    $("subline").textContent = `${e.message}. Reload the page to try again, or check the hexcrypt-telemetry container.`;
  } finally {
    if (mine === token) document.body.removeAttribute("aria-busy");
  }
}

function render() {
  if (!last) return;
  const { totals, daily, hours, clients, referrers, probes, first, range } = last;
  lead(totals, first, range);
  const byDay = new Map(daily.map((r) => [r.day, r]));
  const zero = { people: 0, automated: 0, requests: 0, created: 0, revealed: 0, not_found: 0, rate_limited: 0, server_full: 0 };
  const rows = dayList(first).map((day) => ({ ...zero, ...byDay.get(day), day }));

  columns($("traffic"), rows, [{ key: "people", cls: "people" }, { key: "automated", cls: "automated" }], {
    readout: { el: $("traffic-readout"), label: "People and automated networks per day",
      text: (r) => [...plural(r.people, "person", "people"), ", ", ...plural(r.automated, "automated network", "automated networks"), ", ", ...plural(r.requests, "request", "requests")] },
  });
  columns($("secrets"), rows, [{ key: "created", cls: "sent" }, { key: "revealed", cls: "read" }], {
    height: 160, stack: false,
    readout: { el: $("secrets-readout"), label: "Secrets sent and read per day", text: (r) => [num(r.created), " sent, ", num(r.revealed), " read"] },
  });
  heat($("heat"), hours);
  bars($("referrers"), tally(referrers, (r) => host(r.referer)), "No other site has linked here yet. Every visit so far came in directly.");
  bars($("clients"), tally(clients, (r) => client(r.ua)), "Nobody has loaded the app in this range.");
  bars($("probes"), probes.map((r) => ({ label: r.route, n: r.n, title: `${r.route}, from ${nf(r.networks)} ${r.networks === 1 ? "network" : "networks"}` })),
    "No scanner traffic in this range.", { mono: true });

  const trouble = [
    ["not_found", "Opened a link that was already used or expired"],
    ["rate_limited", "Were slowed down by the rate limit"],
    ["server_full", "Were turned away because storage was full"],
  ];
  $("trouble").replaceChildren(...trouble.map(([key, label]) => {
    const spark = el("div", { class: "spark", id: `spark-${key}` });
    const item = el("div", {}, el("p", {}, num(rows.reduce((a, r) => a + r[key], 0)), " ", label), spark);
    queueMicrotask(() => columns(spark, rows, [{ key, cls: "trouble" }], { height: 36, axis: false }));
    return item;
  }));

  $("updated").replaceChildren("Last request logged ", new Date(meta.last).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }),
    ". New requests arrive every 15 minutes.");
}

addEventListener("hashchange", load);
let resizeTimer;
addEventListener("resize", () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(render, 120); });
load();
