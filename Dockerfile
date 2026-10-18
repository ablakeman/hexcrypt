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
RUN cargo build --release --locked -p hexcrypt-cli

# Stage 3: runtime
# Secrets live in memory only (the HEXCRYPT_DB default), so a container restart purges them.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/hexcrypt /hexcrypt
ENV HEXCRYPT_BIND=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/hexcrypt"]
CMD ["serve"]
