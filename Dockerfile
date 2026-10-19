FROM rust:1.96-bookworm AS builder

WORKDIR /usr/src/veridag
COPY . .

# Docker Desktop's Hyper-V backend can default to a small VM. Keep the Rust
# build inside that envelope instead of running one compiler process per CPU.
ENV CARGO_BUILD_JOBS=1

RUN --mount=type=cache,id=veridag-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=veridag-target,target=/usr/src/veridag/target,sharing=locked \
    cargo build --release --locked --bin veridag-node -p veridag-node \
    && cp target/release/veridag-node /tmp/veridag-node

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates curl \
    && groupadd --system veridag \
    && useradd --system --gid veridag --home-dir /var/lib/veridag veridag \
    && mkdir -p /var/lib/veridag \
    && chown veridag:veridag /var/lib/veridag \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder --chown=veridag:veridag /tmp/veridag-node /usr/local/bin/veridag-node

USER veridag
WORKDIR /var/lib/veridag

HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=5 \
  CMD curl -sf http://localhost:8080/v1/health || exit 1

ENTRYPOINT ["veridag-node"]
