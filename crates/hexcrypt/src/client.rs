use std::io::{Read, Write};
use std::path::Path;

use anyhow::{bail, Context};
use hexcrypt_core::{Envelope, Kind};

pub fn parse_expires(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.len().saturating_sub(1));
    let (num, mult) = match unit {
        "s" => (num, 1),
        "m" => (num, 60),
        "h" => (num, 3600),
        "d" => (num, 86400),
        _ => (s, 1),
    };
    let n: u64 = num.parse().with_context(|| format!("bad --expires {s:?}; use e.g. 1h, 1d, 7d"))?;
    Ok(n * mult)
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
    let id = hexcrypt_core::new_id()?;
    let key = hexcrypt_core::new_key()?;
    let blob = hexcrypt_core::encrypt(&id, &key, &env.to_bytes())?;

    let base = server.trim_end_matches('/');
    let res = reqwest::Client::new()
        .put(format!("{base}/api/v1/secrets/{id}"))
        .header("x-expires-seconds", expires)
        .body(blob)
        .send()
        .await?;
    if !res.status().is_success() {
        bail!("server returned {}: {}", res.status(), res.text().await.unwrap_or_default());
    }
    println!("{}", hexcrypt_core::build_url(base, &id, &key));
    Ok(())
}

pub async fn get(url: &str, output: Option<String>) -> anyhow::Result<()> {
    let (base, id, key) = hexcrypt_core::parse_url(url)?;
    let res = reqwest::get(format!("{base}/api/v1/secrets/{id}")).await?;
    if res.status() == reqwest::StatusCode::NOT_FOUND {
        bail!("secret not found: already read, expired, or never existed");
    }
    if !res.status().is_success() {
        bail!("server returned {}", res.status());
    }
    let blob = res.bytes().await?;
    let pt = hexcrypt_core::decrypt(&id, &key, &blob)?;
    let env = Envelope::from_bytes(&pt)?;

    match (env.kind, output) {
        (Kind::Text, None) => {
            let mut out = std::io::stdout().lock();
            out.write_all(&env.data)?;
            if !env.data.ends_with(b"\n") {
                out.write_all(b"\n")?;
            }
        }
        (_, Some(p)) if p == "-" => std::io::stdout().lock().write_all(&env.data)?,
        (_, out) => {
            // Sender controls the name: keep only the final path component.
            let name = out.unwrap_or_else(|| {
                Path::new(&env.name).file_name().and_then(|n| n.to_str()).unwrap_or("secret").to_string()
            });
            if Path::new(&name).exists() {
                bail!("{name} already exists; pass -o to choose another path");
            }
            std::fs::write(&name, &env.data)?;
            eprintln!("wrote {name} ({} bytes)", env.data.len());
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
    }
}
