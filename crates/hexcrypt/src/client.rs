use std::borrow::Cow;
use std::io::{IsTerminal, Read, Write};
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context};
use hexcrypt_core::{Envelope, Kind};

pub fn parse_expires(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    let (num, mult) = [('s', 1), ('m', 60), ('h', 3600), ('d', 86400)]
        .into_iter()
        .find_map(|(unit, mult)| s.strip_suffix(unit).map(|n| (n, mult)))
        .unwrap_or((s, 1));
    let n: u64 = num.parse().with_context(|| format!("bad --expires {s:?}; use e.g. 1h, 1d"))?;
    n.checked_mul(mult).with_context(|| format!("--expires {s:?} is too long"))
}

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(300))
        .build()
        .expect("reqwest client")
}

/// Drop control characters so a hostile sender cannot drive the terminal.
fn sanitize(data: &[u8]) -> Vec<u8> {
    String::from_utf8_lossy(data)
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .collect::<String>()
        .into_bytes()
}

pub async fn send(file: Option<String>, expires: &str, server: &str) -> anyhow::Result<()> {
    let expires = parse_expires(expires)?;
    let env = match file.as_deref() {
        None | Some("-") => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            match String::from_utf8(buf) {
                Ok(s) => Envelope::text(&s),
                Err(e) => Envelope::file("stdin", e.into_bytes()),
            }
        }
        Some(p) => {
            let name = Path::new(p).file_name().and_then(|n| n.to_str()).unwrap_or("file");
            Envelope::file(name, std::fs::read(p).with_context(|| format!("read {p}"))?)
        }
    };
    let pt = env.to_bytes();
    let base = server.trim_end_matches('/');
    let http = http();
    // The id is random, so retry once if it is already taken.
    for attempt in 0..2 {
        let id = hexcrypt_core::new_id()?;
        let key = hexcrypt_core::new_key()?;
        let blob = hexcrypt_core::encrypt(&id, &key, &pt)?;
        let res = http
            .put(format!("{base}/api/v1/secrets/{id}"))
            .header("x-expires-seconds", expires)
            .body(blob)
            .send()
            .await?;
        if res.status() == reqwest::StatusCode::CONFLICT && attempt == 0 {
            continue;
        }
        if !res.status().is_success() {
            bail!("server returned {}: {}", res.status(), res.text().await.unwrap_or_default());
        }
        println!("{}", hexcrypt_core::build_url(base, &id, &key));
        return Ok(());
    }
    unreachable!()
}

pub async fn get(url: &str, output: Option<String>) -> anyhow::Result<()> {
    let (base, id, key) = hexcrypt_core::parse_url(url)?;
    let res = http().get(format!("{base}/api/v1/secrets/{id}")).send().await?;
    if res.status() == reqwest::StatusCode::NOT_FOUND {
        bail!("secret not found: already read, expired, or never existed");
    }
    if !res.status().is_success() {
        bail!("server returned {}", res.status());
    }
    let blob = res.bytes().await?;
    let pt = hexcrypt_core::decrypt(&id, &key, &blob)?;
    let env = Envelope::from_bytes(&pt)?;

    let stdout = std::io::stdout();
    let data = if stdout.is_terminal() { Cow::Owned(sanitize(&env.data)) } else { Cow::Borrowed(&env.data[..]) };
    match (env.kind, output) {
        (Kind::Text, None) => {
            let mut out = stdout.lock();
            out.write_all(&data)?;
            if !data.ends_with(b"\n") {
                out.write_all(b"\n")?;
            }
        }
        (_, Some(p)) if p == "-" => stdout.lock().write_all(&data)?,
        (_, out) => {
            // Sender controls the name: keep only the final path component. {name:?} escapes control chars.
            let name = out.unwrap_or_else(|| {
                Path::new(&env.name).file_name().and_then(|n| n.to_str()).unwrap_or("secret").to_string()
            });
            // create_new is O_EXCL: no check-then-write race, and it won't follow a planted symlink.
            let mut f = match std::fs::OpenOptions::new().write(true).create_new(true).open(&name) {
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    bail!("{name:?} already exists; pass -o to choose another path")
                }
                r => r.with_context(|| format!("create {name:?}"))?,
            };
            f.write_all(&env.data)?;
            eprintln!("wrote {name:?} ({} bytes)", env.data.len());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn expires() {
        assert_eq!(super::parse_expires("1h").unwrap(), 3600);
        assert_eq!(super::parse_expires("7d").unwrap(), 604800);
        assert_eq!(super::parse_expires("90").unwrap(), 90);
        assert!(super::parse_expires("soon").is_err());
        assert!(super::parse_expires("5µ").is_err());
        assert!(super::parse_expires("999999999999999999d").is_err());
    }

    #[test]
    fn sanitize_strips_escapes() {
        assert_eq!(super::sanitize(b"a\x1b]0;pwned\x07b\r\n\tc"), b"a]0;pwnedb\n\tc");
    }
}
