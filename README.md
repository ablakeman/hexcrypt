# hexcrypt

Share a secret once. Encrypted in your browser or terminal, the key never leaves the link, and the first read burns it.

**https://hexcrypt.com**

```
$ echo "db_password=hunter2" | hexcrypt send --expires 1h
https://hexcrypt.com/3fa9c2e17b04#Xq9k…

$ hexcrypt send .env
$ hexcrypt get https://hexcrypt.com/3fa9c2e17b04#Xq9k…
```

## How it works

1. The client generates a random 256-bit key and a random 12-hex-character id.
2. The payload (text or file, with its name) is encrypted with XChaCha20-Poly1305. The id is bound in as associated data, so a blob cannot be re-homed under another id.
3. Only the ciphertext is uploaded. The key goes after the `#` in the URL. Browsers never send the fragment to any server, and the CLI never sends it either.
4. The first `GET` deletes the row in the same SQL statement that returns it (`DELETE … RETURNING`), so two racing readers cannot both succeed. Unread secrets are purged when they expire (1 hour, 1 day or 7 days).
5. The web page does not fetch on load. A human has to click **Reveal**, so chat link previews do not burn the secret.

What the server can see: ciphertext, its size, the id, timing, and the client's IP. What it cannot see: the key, the plaintext, the filename.

The same Rust crate (`hexcrypt-core`) runs natively in the CLI and as WebAssembly in the browser, so both clients share one wire format.

## Install the CLI

```
cargo install hexcrypt
```

`hexcrypt send` defaults to https://hexcrypt.com. Point it elsewhere with `--server` or `HEXCRYPT_SERVER`.

## Self-host

The same binary is the server:

```
hexcrypt serve --bind 0.0.0.0:8080 --db /data/hexcrypt.db --max-size 10485760 --max-expiry 604800
```

or with Docker:

```
docker compose up -d --build
```

Put a TLS-terminating proxy in front and forward `X-Forwarded-For` (per-IP rate limiting keys on it). Every flag has an env var equivalent: `HEXCRYPT_BIND`, `HEXCRYPT_DB`, `HEXCRYPT_MAX_SIZE`, `HEXCRYPT_MAX_EXPIRY`.

## API

| Method | Path | Notes |
|---|---|---|
| `PUT` | `/api/v1/secrets/{id}` | body: raw ciphertext; header `X-Expires-Seconds: 60…604800`. `201` with `{"id","expires_at"}`, `409` if the id exists. |
| `GET` | `/api/v1/secrets/{id}` | returns the ciphertext once, then `404`. |
| `GET` | `/api/v1/config` | `{"max_size","max_expiry"}` |

Blob format: `0x01 || nonce[24] || ciphertext+tag`. Plaintext envelope: `kind(1: 0=text,1=file) || name_len(u16 LE) || name || data`.

## Develop

```
cargo test                         # core + server tests
cd web && npm install && npm run wasm && npm run build   # outputs to crates/hexcrypt/dist
cargo run -- serve --bind 127.0.0.1:8080
cd web && npm run dev               # Vite dev server proxies /api to :8080
```

## License

MIT or Apache-2.0, at your option.
