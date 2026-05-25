# syntax=docker/dockerfile:1.6

FROM rust:1.95-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --bin honey \
 && cp /build/target/release/honey /honey

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /honey /usr/local/bin/honey
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/honey"]
