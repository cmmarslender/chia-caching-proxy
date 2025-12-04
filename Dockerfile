FROM rust:bookworm AS builder
WORKDIR /app

RUN apt update && \
    apt-get install -y libclang-dev && \
    rm -rf /var/lib/apt/lists/*

COPY . .
RUN cargo build --release

WORKDIR /app/target/release
CMD ["/app/target/release/chia-caching-proxy"]
