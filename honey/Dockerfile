# syntax=docker/dockerfile:1.6

# Multi-stage Rust build using cargo-chef so dependency compilation is cached
# across source changes. First-time build: ~8-10 min. Subsequent source-only
# rebuilds: ~15-30 s.

FROM rust:1.95-bookworm AS chef
RUN cargo install cargo-chef --locked --version ^0.1
WORKDIR /build

# ── recipe planner ────────────────────────────────────────────────────────────
# Output: recipe.json describing every dep + workspace crate. Source content
# doesn't matter at this stage — only Cargo.toml / Cargo.lock are read.
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo chef prepare --recipe-path recipe.json

# ── deps cook ─────────────────────────────────────────────────────────────────
# Build only what recipe.json says — gives us a layer with every dep compiled,
# cached in the image. Source changes don't invalidate this layer.
FROM chef AS deps
COPY --from=planner /build/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo chef cook --release --recipe-path recipe.json

# ── final binary ──────────────────────────────────────────────────────────────
FROM deps AS builder
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --release --bin honey \
 && cp /build/target/release/honey /honey

# ── runtime ───────────────────────────────────────────────────────────────────
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /honey /usr/local/bin/honey
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/honey"]
