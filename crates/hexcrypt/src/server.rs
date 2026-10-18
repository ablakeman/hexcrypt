//! `hexcrypt serve`: stores ciphertext blobs, burns them on first read, serves the web UI.
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{header, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::Router;
use rusqlite::{params, Connection, OptionalExtension};
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::KeyExtractor;
use tower_governor::{GovernorError, GovernorLayer};
use tower_http::set_header::SetResponseHeaderLayer;

#[derive(clap::Args, Clone)]
pub struct Opts {
    #[arg(long, env = "HEXCRYPT_BIND", default_value = "127.0.0.1:8080")]
    pub bind: SocketAddr,
    /// SQLite path. The default keeps secrets in memory only, so a restart purges them
    /// and ciphertext never reaches disk. Give a file path to keep secrets across restarts.
    #[arg(long, env = "HEXCRYPT_DB", default_value = ":memory:")]
    pub db: String,
    /// Maximum ciphertext size in bytes.
    #[arg(long, env = "HEXCRYPT_MAX_SIZE", default_value_t = 1024 * 1024)]
    pub max_size: usize,
    /// Maximum lifetime in seconds.
    #[arg(long, env = "HEXCRYPT_MAX_EXPIRY", default_value_t = 86400)]
    pub max_expiry: u64,
    /// Bytes one client (IPv4 address or IPv6 /64) may upload per UTC day.
    #[arg(long, env = "HEXCRYPT_DAILY_QUOTA", default_value_t = 20 * 1024 * 1024)]
    pub daily_quota: u64,
    /// Bytes stored across all secrets (in memory by default). Uploads past this get 507.
    #[arg(long, env = "HEXCRYPT_MAX_TOTAL_BYTES", default_value_t = 256 * 1024 * 1024)]
    pub max_total_bytes: u64,
    /// Take the client address from `X-Real-IP` instead of the TCP peer. Set this only
    /// behind a proxy that overwrites that header and is the only way in.
    #[arg(long, env = "HEXCRYPT_TRUST_PROXY", value_parser = clap::builder::BoolishValueParser::new())]
    pub trust_proxy: bool,
}

#[derive(Clone)]
struct App {
    // ponytail: one connection behind a mutex; move to a pool if writes contend.
    db: Arc<Mutex<Connection>>,
    quota: Arc<Mutex<Quota>>,
    opts: Opts,
}

/// Rate-limit key: the client IP, with IPv6 collapsed to its /64 so one host
/// cannot rotate through its own subnet to dodge the limits. That is the TCP peer
/// unless `trust_proxy` is set; a client can put anything in a header.
#[derive(Clone)]
struct ClientIp {
    trust_proxy: bool,
}

impl KeyExtractor for ClientIp {
    type Key = IpAddr;
    fn extract<T>(&self, req: &axum::http::Request<T>) -> Result<IpAddr, GovernorError> {
        let peer = || req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip());
        let header = || req.headers().get("x-real-ip")?.to_str().ok()?.trim().parse().ok();
        let ip = if self.trust_proxy { header().or_else(peer) } else { peer() };
        match ip.ok_or(GovernorError::UnableToExtractKey)?.to_canonical() {
            IpAddr::V6(v6) => Ok(IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (!0u128 << 64)))),
            v4 => Ok(v4),
        }
    }
}

/// Upload bytes per client for the current UTC day.
// ponytail: fixed daily window, so a client can spend 2x the quota across midnight; use a token bucket if that matters.
#[derive(Default)]
struct Quota {
    day: i64,
    used: HashMap<IpAddr, u64>,
}

impl Quota {
    fn charge(&mut self, ip: IpAddr, n: u64, limit: u64) -> bool {
        let day = now() / 86400;
        if day != self.day {
            self.day = day;
            self.used.clear();
        }
        let used = self.used.entry(ip).or_default();
        if *used + n > limit {
            return false;
        }
        *used += n;
        true
    }

    /// Give back a charge for an upload that was not stored.
    fn refund(&mut self, ip: IpAddr, n: u64) {
        if let Some(used) = self.used.get_mut(&ip) {
            *used = used.saturating_sub(n);
        }
    }
}

/// Run `f` on a blocking thread so a slow disk cannot stall the async workers.
/// A poisoned lock is reused: no call leaves a transaction open, so the connection is fine.
async fn with_db<T: Send + 'static>(
    db: &Arc<Mutex<Connection>>,
    f: impl FnOnce(&Connection) -> T + Send + 'static,
) -> T {
    let db = db.clone();
    tokio::task::spawn_blocking(move || f(&db.lock().unwrap_or_else(PoisonError::into_inner)))
        .await
        .expect("db task panicked")
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

pub fn open_db(path: &str) -> anyhow::Result<Connection> {
    if let Some(dir) = std::path::Path::new(path).parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }
    }
    let db = Connection::open(path)?;
    db.execute_batch(
        // secure_delete zeroes burned blobs instead of leaving them in free pages.
        "PRAGMA journal_mode=WAL;
         PRAGMA secure_delete=ON;
         CREATE TABLE IF NOT EXISTS secrets (
           id TEXT PRIMARY KEY,
           blob BLOB NOT NULL,
           expires_at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS secrets_expires ON secrets(expires_at);",
    )?;
    Ok(db)
}

pub fn router(db: Arc<Mutex<Connection>>, opts: Opts) -> Router {
    let ip = ClientIp { trust_proxy: opts.trust_proxy };
    let state = App { db, quota: Default::default(), opts };

    // One token back per `period`, up to `burst` saved.
    let limit = |period: Duration, burst: u32| {
        let cfg = Arc::new(
            GovernorConfigBuilder::default()
                .key_extractor(ip.clone())
                .period(period)
                .burst_size(burst)
                .finish()
                .unwrap(),
        );
        let limiter = cfg.limiter().clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                limiter.retain_recent();
            }
        });
        GovernorLayer::new(cfg)
    };

    let api = Router::new()
        .route("/config", get(config))
        .route("/secrets/{id}", get(fetch).merge(put(store).layer(limit(Duration::from_secs(10), 10))))
        .layer(limit(Duration::from_secs(2), 30))
        .with_state(state);

    let hdr =
        |k: header::HeaderName, v: &'static str| SetResponseHeaderLayer::overriding(k, HeaderValue::from_static(v));
    Router::new()
        .nest("/api/v1", api)
        .fallback(static_file)
        .layer(hdr(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; \
             connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        ))
        .layer(hdr(header::REFERRER_POLICY, "no-referrer"))
        .layer(hdr(header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .layer(hdr(header::X_FRAME_OPTIONS, "DENY"))
        .layer(hdr(header::HeaderName::from_static("x-robots-tag"), "noindex, nofollow"))
}

pub async fn run(opts: Opts) -> anyhow::Result<()> {
    let db = Arc::new(Mutex::new(open_db(&opts.db)?));
    let sweeper = db.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let r: rusqlite::Result<usize> = with_db(&sweeper, |db| {
                let n = db.execute("DELETE FROM secrets WHERE expires_at < ?1", params![now()])?;
                // With a file --db: truncating the WAL drops its copies of burned blobs. A no-op in memory.
                db.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
                Ok(n)
            })
            .await;
            match r {
                Ok(0) => {}
                Ok(n) => eprintln!("swept {n} expired"),
                Err(e) => eprintln!("sweep: {e}"),
            }
        }
    });
    let listener = tokio::net::TcpListener::bind(opts.bind).await?;
    eprintln!("hexcrypt listening on http://{}", opts.bind);
    axum::serve(listener, router(db, opts).into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

fn json(status: StatusCode, body: String) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

async fn config(State(app): State<App>) -> Response {
    json(StatusCode::OK, format!(r#"{{"max_size":{},"max_expiry":{}}}"#, app.opts.max_size, app.opts.max_expiry))
}

async fn store(State(app): State<App>, Path(id): Path<String>, req: Request) -> Response {
    if !hexcrypt_core::is_valid_id(&id) {
        return (StatusCode::BAD_REQUEST, "bad id").into_response();
    }
    let ttl: u64 =
        match req.headers().get("x-expires-seconds").and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok()) {
            Some(t) if t >= 60 && t <= app.opts.max_expiry => t,
            _ => {
                let msg = format!("x-expires-seconds must be 60..={}", app.opts.max_expiry);
                return (StatusCode::BAD_REQUEST, msg).into_response();
            }
        };
    // The governor layer in front already rejected requests without a key.
    let Ok(ip) = (ClientIp { trust_proxy: app.opts.trust_proxy }).extract(&req) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(body) = axum::body::to_bytes(req.into_body(), app.opts.max_size).await else {
        return (StatusCode::PAYLOAD_TOO_LARGE, "too large").into_response();
    };
    if body.len() < 1 + hexcrypt_core::NONCE_LEN + 16 {
        return (StatusCode::BAD_REQUEST, "blob too short").into_response();
    }
    let n = body.len() as u64;
    if !app.quota.lock().unwrap().charge(ip, n, app.opts.daily_quota) {
        return (StatusCode::TOO_MANY_REQUESTS, "daily upload quota exceeded").into_response();
    }
    let expires_at = now() + ttl as i64;
    let (max_total, row_id) = (app.opts.max_total_bytes, id.clone());
    // Both statements run under one lock, so concurrent uploads cannot overshoot the cap.
    let r = with_db(&app.db, move |db| {
        // ponytail: sums every row per upload; keep a running total if the table gets large.
        let total: i64 = db.query_row("SELECT COALESCE(SUM(length(blob)), 0) FROM secrets", [], |r| r.get(0))?;
        if total as u64 + n > max_total {
            return Ok(None);
        }
        db.execute(
            "INSERT INTO secrets (id, blob, expires_at) VALUES (?1, ?2, ?3)",
            params![row_id, body.as_ref(), expires_at],
        )
        .map(Some)
    })
    .await;
    if !matches!(r, Ok(Some(_))) {
        app.quota.lock().unwrap().refund(ip, n);
    }
    match r {
        // id is validated hex, so no JSON escaping is needed.
        Ok(Some(_)) => json(StatusCode::CREATED, format!(r#"{{"id":"{id}","expires_at":{expires_at}}}"#)),
        Ok(None) => (StatusCode::INSUFFICIENT_STORAGE, "server is full; try later").into_response(),
        Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::ConstraintViolation => {
            (StatusCode::CONFLICT, "id taken").into_response()
        }
        Err(e) => {
            eprintln!("db error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Burn-on-read: a single DELETE ... RETURNING is atomic, so two racing readers
/// cannot both get the blob.
async fn fetch(State(app): State<App>, Path(id): Path<String>) -> Response {
    if !hexcrypt_core::is_valid_id(&id) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let r: rusqlite::Result<Option<Vec<u8>>> = with_db(&app.db, move |db| {
        db.query_row(
            "DELETE FROM secrets WHERE id = ?1 AND expires_at > ?2 RETURNING blob",
            params![id, now()],
            |row| row.get(0),
        )
        .optional()
    })
    .await;
    match r {
        Ok(Some(blob)) => {
            ([(header::CONTENT_TYPE, "application/octet-stream"), (header::CACHE_CONTROL, "no-store")], blob)
                .into_response()
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            eprintln!("db error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(rust_embed::Embed)]
#[folder = "dist"]
struct Dist;

async fn static_file(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let (file, cache) = match Dist::get(path) {
        // Only Vite's content-hashed assets can be cached forever; favicon.svg keeps its name.
        Some(f) if path.starts_with("assets/") => (f, "public, max-age=31536000, immutable"),
        Some(f) if !path.is_empty() => (f, "no-cache"),
        // Everything else (including /<id>) is the SPA shell.
        _ => match Dist::get("index.html") {
            Some(f) => (f, "no-store"),
            None => return (StatusCode::NOT_FOUND, "web UI not built").into_response(),
        },
    };
    (
        [(header::CONTENT_TYPE, file.metadata.mimetype().to_string()), (header::CACHE_CONTROL, cache.to_string())],
        file.data.into_owned(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn app_with(f: impl FnOnce(&mut Opts)) -> Router {
        let mut opts = Opts {
            bind: "127.0.0.1:0".parse().unwrap(),
            db: ":memory:".into(),
            max_size: 1024,
            max_expiry: 86400,
            daily_quota: 2500,
            max_total_bytes: 1 << 20,
            trust_proxy: true,
        };
        f(&mut opts);
        router(Arc::new(Mutex::new(open_db(":memory:").unwrap())), opts)
    }

    fn app() -> Router {
        app_with(|_| {})
    }

    async fn put(app: &Router, id: &str, ttl: &str, body: Vec<u8>) -> StatusCode {
        put_from(app, "10.0.0.1", id, ttl, body).await
    }

    async fn put_from(app: &Router, ip: &str, id: &str, ttl: &str, body: Vec<u8>) -> StatusCode {
        let mut req = Request::put(format!("/api/v1/secrets/{id}"))
            .header("x-real-ip", ip)
            .header("x-forwarded-for", ip)
            .header("x-expires-seconds", ttl)
            .body(Body::from(body))
            .unwrap();
        // Every test request arrives from the same TCP peer.
        req.extensions_mut().insert(ConnectInfo(SocketAddr::from(([192, 0, 2, 1], 4000))));
        app.clone().oneshot(req).await.unwrap().status()
    }

    async fn get_status(app: &Router, id: &str) -> (StatusCode, Vec<u8>) {
        let res = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/secrets/{id}"))
                    .header("x-real-ip", "10.0.0.1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let st = res.status();
        let b = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap().to_vec();
        (st, b)
    }

    #[tokio::test]
    async fn store_fetch_burn() {
        let app = app();
        let blob = vec![1u8; 64];
        assert_eq!(put(&app, "3fa9c2e17b04", "3600", blob.clone()).await, StatusCode::CREATED);
        assert_eq!(put(&app, "3fa9c2e17b04", "3600", blob.clone()).await, StatusCode::CONFLICT);
        assert_eq!(get_status(&app, "3fa9c2e17b04").await, (StatusCode::OK, blob));
        assert_eq!(get_status(&app, "3fa9c2e17b04").await.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn validation() {
        let app = app();
        assert_eq!(put(&app, "nothex", "3600", vec![1; 64]).await, StatusCode::BAD_REQUEST);
        assert_eq!(put(&app, "3fa9c2e17b04", "999999999", vec![1; 64]).await, StatusCode::BAD_REQUEST);
        assert_eq!(put(&app, "3fa9c2e17b04", "3600", vec![1; 5]).await, StatusCode::BAD_REQUEST);
        assert_eq!(put(&app, "3fa9c2e17b04", "3600", vec![1; 2000]).await, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(get_status(&app, "000000000000").await.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn daily_quota_per_v6_subnet() {
        let app = app();
        // Same /64, different hosts: they share one 2500-byte quota.
        assert_eq!(put_from(&app, "2001:db8::1", "000000000001", "3600", vec![1; 1000]).await, StatusCode::CREATED);
        assert_eq!(put_from(&app, "2001:db8::2", "000000000002", "3600", vec![1; 1000]).await, StatusCode::CREATED);
        assert_eq!(
            put_from(&app, "2001:db8::3", "000000000003", "3600", vec![1; 1000]).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        // Another /64 has its own.
        assert_eq!(put_from(&app, "2001:db8:0:1::1", "000000000003", "3600", vec![1; 1000]).await, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn put_rate_limit() {
        let app = app();
        for i in 0..10 {
            assert_eq!(put(&app, &format!("{i:012x}"), "3600", vec![1; 64]).await, StatusCode::CREATED);
        }
        assert_eq!(put(&app, "00000000000a", "3600", vec![1; 64]).await, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn spoofed_headers_ignored_without_trust_proxy() {
        let app = app_with(|o| o.trust_proxy = false);
        for i in 0..10 {
            let ip = format!("10.9.{i}.1");
            assert_eq!(put_from(&app, &ip, &format!("{i:012x}"), "3600", vec![1; 64]).await, StatusCode::CREATED);
        }
        assert_eq!(
            put_from(&app, "10.9.99.1", "00000000000a", "3600", vec![1; 64]).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn global_cap() {
        let app = app_with(|o| o.max_total_bytes = 1500);
        assert_eq!(put_from(&app, "10.0.0.1", "000000000001", "3600", vec![1; 1000]).await, StatusCode::CREATED);
        assert_eq!(
            put_from(&app, "10.0.0.2", "000000000002", "3600", vec![1; 1000]).await,
            StatusCode::INSUFFICIENT_STORAGE
        );
        // Reading frees the space.
        assert_eq!(get_status(&app, "000000000001").await.0, StatusCode::OK);
        assert_eq!(put_from(&app, "10.0.0.2", "000000000002", "3600", vec![1; 1000]).await, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn failed_upload_refunds_quota() {
        let app = app();
        assert_eq!(put(&app, "000000000001", "3600", vec![1; 1000]).await, StatusCode::CREATED);
        assert_eq!(put(&app, "000000000001", "3600", vec![1; 1000]).await, StatusCode::CONFLICT);
        // Without the refund this would be 3000 bytes against a 2500-byte quota.
        assert_eq!(put(&app, "000000000002", "3600", vec![1; 1000]).await, StatusCode::CREATED);
    }
}
