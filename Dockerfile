# tproxy-rs — Telegram WEB proxy relay (Rust)
FROM rust:alpine AS build
RUN apk add --no-cache musl-dev openssl-dev pkgconfig
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src/ src/
RUN cargo build --release

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=build /app/target/release/tproxy-rs /usr/local/bin/tproxy-rs
COPY public/ public/
EXPOSE 8091
CMD ["tproxy-rs", "-c", "/app/config.json"]
