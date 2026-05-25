# syntax=docker/dockerfile:1.6

# Multi-stage Rust build using cargo-chef so dependency compilation is cached
# across source changes. First-time build: ~8-10 min. Subsequent source-only
# rebuilds: ~15-30 s.

FROM lukemathwalker/cargo-chef:latest-rust-1.95-bookworm AS chef
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
    cargo chef cook --release --bin honey --recipe-path recipe.json

# ── final binary ──────────────────────────────────────────────────────────────
FROM deps AS builder
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --release --bin honey \
 && cp /build/target/release/honey /honey \
 && mkdir -p /dirs/bloom /dirs/wordlists /dirs/stats /dirs/data/honey /dirs/geoip

# ── runtime ───────────────────────────────────────────────────────────────────
# Pre-create writable dirs with nonroot ownership. When docker mounts a named
# volume onto a path that exists in the image, it inherits the path's ownership;
# otherwise the freshly created mount point is owned by root and writes fail.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /honey /usr/local/bin/honey
COPY --from=builder --chown=nonroot:nonroot /dirs/bloom     /bloom
COPY --from=builder --chown=nonroot:nonroot /dirs/wordlists /wordlists
COPY --from=builder --chown=nonroot:nonroot /dirs/stats     /stats
COPY --from=builder --chown=nonroot:nonroot /dirs/data      /data
COPY --from=builder --chown=nonroot:nonroot /dirs/geoip     /geoip
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/honey"]
