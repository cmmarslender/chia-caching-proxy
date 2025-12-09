FROM rust:1-trixie AS chef

RUN apt update && \
    apt install -y --no-install-recommends cmake libclang-dev && \
    rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare  --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json
# Build application
COPY . .
RUN cargo build --release

FROM gcr.io/distroless/cc-debian13:debug AS runtime
WORKDIR /app
COPY --from=builder /app/target/release/chia-caching-proxy /usr/local/bin/chia-caching-proxy
ENTRYPOINT ["/usr/local/bin/chia-caching-proxy"]
