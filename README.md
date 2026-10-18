# hexcrypt

Share a secret once. Your browser or your terminal encrypts the secret. The key stays in the link. The first read deletes the secret.

**https://hexcrypt.com**

```
$ echo "db_password=hunter2" | hexcrypt send --expires 1h
https://hexcrypt.com/3fa9c2e17b04#Xq9k…

$ hexcrypt send .env
$ hexcrypt get https://hexcrypt.com/3fa9c2e17b04#Xq9k…
```

## How it works

1. The client makes a random 256-bit key and a random id of 12 hex characters.
2. The client encrypts the payload with XChaCha20-Poly1305. The payload is the text or the file, with its name. The id is the associated data, so no one can store the blob under a different id.
3. The client uploads only the ciphertext. The key goes after the `#` in the URL. Browsers do not send the fragment to a server. The command-line interface (CLI) does not send the fragment either.
4. The first `GET` deletes the row with the same SQL statement that returns it, `DELETE … RETURNING`. If two readers race, only one gets the secret. The server deletes unread secrets when they expire, after 1 hour or 1 day.
5. The web page does not fetch the secret when it loads. A person must click **Reveal**. Link previews in chat tools do not delete the secret.

The server can see:

- the ciphertext and its size
- the id
- the time of each request
- the IP address of the client

The server cannot see:

- the key
- the plaintext
- the file name

The CLI and the browser use the same Rust crate, `hexcrypt-core`. The CLI runs it natively. The browser runs it as WebAssembly. Both clients use one wire format.

## Install the CLI

```
cargo install hexcrypt-cli
```

`hexcrypt send` uses https://hexcrypt.com by default. To use a different server, set `--server` or `HEXCRYPT_SERVER`.

## Self-host

The same binary is the server:

```
hexcrypt serve --bind 0.0.0.0:8080 --db /data/hexcrypt.db --max-size 1048576 --max-expiry 86400 --daily-quota 20971520
```

Or use Docker:

```
docker compose up -d --build
```

Put a proxy that terminates TLS in front of the server. Make the proxy forward `X-Forwarded-For`. The rate limits use this header to find the client address.

The limits apply to each IPv4 address or to each IPv6 /64 prefix:

- 1 request per 2 s, with a burst of 30.
- 1 upload per 10 s, with a burst of 10.
- `--daily-quota` bytes per UTC day.

Each flag has an environment variable: `HEXCRYPT_BIND`, `HEXCRYPT_DB`, `HEXCRYPT_MAX_SIZE`, `HEXCRYPT_MAX_EXPIRY`, and `HEXCRYPT_DAILY_QUOTA`.

## API

| Method | Path | Notes |
|---|---|---|
| `PUT` | `/api/v1/secrets/{id}` | The body is the raw ciphertext. Set the header `X-Expires-Seconds` to a value from 60 to `max_expiry`. The server returns `201` with `{"id","expires_at"}`. It returns `409` if the id exists. It returns `429` if the client is over the rate limit or over the daily quota. |
| `GET` | `/api/v1/secrets/{id}` | Returns the ciphertext once. After that, it returns `404`. |
| `GET` | `/api/v1/config` | Returns `{"max_size","max_expiry"}`. |

The blob format is `0x01 || nonce[24] || ciphertext+tag`. The plaintext envelope is `kind(1: 0=text,1=file) || name_len(u16 LE) || name || data`.

## Develop

```
cargo test                         # core + server tests
cd web && npm install && npm run wasm && npm run build   # outputs to crates/hexcrypt/dist
cargo run -- serve --bind 127.0.0.1:8080
cd web && npm run dev               # Vite dev server proxies /api to :8080
```

## License

MIT.
