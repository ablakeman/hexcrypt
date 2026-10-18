# syntax=docker/dockerfile:1
# Stage 1: web UI (wasm-pack + vite)
FROM rust:1.95-bookworm AS web
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm && rm -rf /var/lib/apt/lists/*
RUN rustup target add wasm32-unknown-unknown && cargo install wasm-pack --locked
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY web ./web
RUN cd web && npm ci && npm run wasm && npm run build

# Stage 2: server binary (embeds web/dist)
FROM rust:1.95-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY --from=web /src/crates/hexcrypt/dist ./crates/hexcrypt/dist
RUN cargo build --release --locked -p hexcrypt-cli && mkdir /data

# Stage 3: runtime
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/hexcrypt /hexcrypt
# nonroot is uid 65532; the volume inherits this ownership on first mount.
COPY --from=build --chown=65532:65532 /data /data
VOLUME ["/data"]
ENV HEXCRYPT_BIND=0.0.0.0:8080 HEXCRYPT_DB=/data/hexcrypt.db
EXPOSE 8080
ENTRYPOINT ["/hexcrypt"]
CMD ["serve"]
