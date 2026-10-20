set shell := ["bash", "-Eeuo", "pipefail", "-c"]
set windows-shell := ["powershell.exe", "-ExecutionPolicy", "Bypass", "-NoLogo", "-NoProfile", "-Command"]

forge := if os_family() == "windows" { "& '" + env_var("USERPROFILE") + "/.foundry/bin/forge.exe'" } else { "forge" }
slither := if os_family() == "windows" { "$env:PATH = '" + env_var("USERPROFILE") + "/.foundry/bin;' + $env:PATH; & '" + env_var("USERPROFILE") + "/.local/bin/slither.exe'" } else { "slither" }
python := if os_family() == "windows" { "uv run python" } else { "python3" }

default:
    @just --list

# Install rust components used by CI
setup:
    rustup component add rustfmt clippy rust-src
    cargo install cargo-deny cargo-audit
    @echo "setup: ok"

# Full local verification (fast subset used pre-push)
check:
    cargo fmt --check
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo test --workspace --all-features
    cargo doc --workspace --no-deps

# Security audit (advisory + license + banned deps)
audit:
    cargo deny check --warn unmaintained --warn unsound
    cargo audit

# Protocol conformance: regenerate and validate golden vectors
vectors:
    cargo run -p veridag-testkit --bin veridag-vector-gen
    cargo test -p veridag-testkit --test vectors

# Quint formal model (uses the pinned local npm toolchain)
formal:
    cd formal/quint; npm ci
    cd formal/quint; npm exec -- quint typecheck consensus.qnt
    cd formal/quint; npm exec -- quint typecheck instance4.qnt
    cd formal/quint; npm exec -- quint test consensus_test.qnt
    cd formal/quint; npm exec -- quint run instance4.qnt --invariant=Agreement --max-steps=30 --max-samples=200
    cd formal/quint; npm exec -- quint run instance4.qnt --invariant=Finality --max-steps=30 --max-samples=200
    cd formal/quint; npm exec -- quint run instance4.qnt --invariant=Integrity --max-steps=30 --max-samples=200

# In-process 4-validator consensus demo
demo:
    cargo run -p veridag-node -- demo

# 4-validator multi-process QUIC network devnet
devnet:
    cargo test -p veridag-net --test devnet -- --nocapture

# Deterministic simulation harness (agreement & causal ordering)
sim:
    cargo test -p veridag-consensus --test simulation -- --nocapture

# Validator node health probe (checks agreement & emits status)
health:
    cargo run -p veridag-node -- health

# Launch a single daemon node for local dev (seed 1, RPC on :8080)
daemon:
    cargo run -p veridag-node -- daemon --seed 1 --rpc 0.0.0.0:8080

# Spin up 4-validator Docker Compose mesh
docker-up:
    docker compose up -d
    @echo "Nodes starting — wait ~10s then: curl http://localhost:8081/v1/health"

# Tear down Docker Compose mesh
docker-down:
    docker compose down

# Verify health, agreement, progress, and single-validator restart recovery.
docker-soak duration="300":
    {{python}} scripts/devnet-soak.py --duration {{duration}} --restart-service node4 --output artifacts/devnet-soak.json

# Solidity format, unit, fuzz, and invariant campaign.
solidity:
    {{forge}} fmt --check
    {{forge}} test -vvv

# Solidity static analysis (requires slither-analyzer).
slither:
    {{slither}} . --config-file slither.config.json

# Validate all versioned industry adapter manifests.
industry:
    {{python}} scripts/validate-industry-packs.py

# Test and verify Revenue OS synchronization
revenue:
    {{python}} scripts/revenue-sync.py --test

# Hot-path benchmark suite
bench:
    cargo bench -p veridag-qa

# Run the canonical decoder fuzz campaign in a memory-bounded nightly container.
fuzz duration="60":
    docker run --rm --cpus 2 --memory 1800m -e CARGO_BUILD_JOBS=1 -e CARGO_TARGET_DIR=/tmp/veridag-target -e RUSTUP_TOOLCHAIN=nightly -e PATH=/cargo-cache/bin:/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin -v veridag-fuzz-cargo:/cargo-cache -v "${PWD}:/work" -w /work rustlang/rust:nightly-bookworm bash -c 'command -v cargo-fuzz >/dev/null || cargo install --root /cargo-cache cargo-fuzz --locked; cargo fuzz run canonical-decoders --fuzz-dir fuzz -- -max_total_time={{duration}} -timeout=5'

# Developer CLI help
cli:
    cargo run -p veridag-cli -- --help

# Run web portal documentation app locally
site-dev:
    cd site; npm run dev

# Build static production bundle for web portal
site-build:
    cd site; npm run build

# Run TypeScript SDK conformance tests and verify packaging
ts-test:
    cd sdks/typescript; npm test
    cd sdks/typescript; npm run build
    cd sdks/typescript; npm run verify-package

# Run Python SDK conformance tests and verify packaging
py-test:
    cd sdks/python; uv run python -m unittest discover -s tests
    cd sdks/python; uv build

# Full local pre-release gate. Docker soak and fuzz remain explicit because they are long-running.
release-gate: check vectors audit formal solidity slither industry revenue ts-test py-test site-build
    @echo "release-gate: all checks passed"
