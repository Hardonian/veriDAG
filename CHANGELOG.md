# Changelog

All notable changes to this project are documented here. The format follows
Keep a Changelog; versions follow SemVer. Protocol version is distinct from
software version (see `protocol/specification/17-upgrades.md`).

## [Unreleased]

## [1.0.0] - 2026-10-14

Stable reference implementation release covering the numbered protocol milestones, production Next.js site portal, and full multi-language SDK distribution.
This version number is governed by `docs/capability-matrix.md` and `docs/release-readiness.md`.

### Added

- Docker devnet agreement/progress soak with single-validator restart evidence.
- CI gates for the container devnet, Foundry fuzz/invariant tests, Slither, the
  Quint model, industry manifests, SDKs, and the production site build.
- An explicit release-readiness checklist separating executable software gates
  from independent audit, multi-region operations, and regulatory approvals.
- A seeded canonical-decoder libFuzzer corpus and a memory-bounded Docker fuzz
  command matching the nightly CI campaign.
- Structured logging via `tracing-subscriber` with `RUST_LOG` env filter and
  optional JSON output (`VERIDAG_LOG_JSON=1`).
- Graceful shutdown handler (Ctrl+C / SIGTERM) for clean daemon termination.
- Prometheus metrics endpoint (`/v1/metrics`) wired to `PrometheusExporter`
  with counters for vertices proposed, waves committed, txs executed, and
  checkpoints produced, plus gauges for highest wave and max round.
- Readiness probe endpoint (`/v1/ready`) returning 200 when consensus is
  progressing (highest_wave > 0) and 503 otherwise.
- Release profile in workspace `Cargo.toml` (`opt-level=3`, thin LTO,
  `codegen-units=1`, `panic=abort`, `strip=true`).
- Docker healthcheck in `Dockerfile` and `docker-compose.yml` with
  `restart: unless-stopped` policy.
- CI jobs for TypeScript SDK, Python SDK conformance, and site build
  verification on every PR.
- Dependabot coverage for npm (site, TypeScript SDK) and pip (Python SDK).
- Production portal deployment on Vercel (`https://veridag.vercel.app`) with preview deployment automation.

### Changed

- Container builds now use a bounded build context, cached Rust compilation,
  and a single build job to remain reliable under Docker Desktop resource caps.
- Validator recovery re-advertises its persisted frontier and performs bounded,
  overlapping DAG catch-up after restart.
- The real-QUIC devnet test now waits for a target-round quorum instead of the
  first target-round vertex, eliminating a timing-dependent checkpoint race.
- Solidity bridge and checkpoint paths use reentrancy protection, checked token
  results, replay protection, and checks-effects-interactions ordering.
- Rust workspace packages now publish in dependency order without requiring
  unpublished internal dev-dependencies. Release bundles retain SHA-256
  manifests, SPDX SBOMs, and tag-bound provenance attestations.
- `just` recipes now run through native PowerShell on Windows and Bash on Unix,
  including the containerized fuzz and complete release-gate entry points.
- Formal verification now uses a repository-pinned Quint npm toolchain in both
  local release gates and CI instead of an implicit global installation.
- Version bumped from `0.1.0-alpha` to `1.0.0` across workspace, SDKs, and documentation site.
- Docker Compose migrated to V2 format (removed deprecated `version:` key).
- `cargo deny` CI runs from workspace root where `deny.toml` lives.
- Architecture docs updated to reflect all 24 shipped crates and 3 binaries.
- README CLI example fixed (`daemon --seed` instead of `run --validator-seed`).

### Safety & Conformance

- All 24 Rust crates `#![forbid(unsafe_code)]`.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean (0 warnings).
- Full workspace test suite green across all test targets.
- TypeScript SDK conformance verified with 100% bit-for-bit equivalence against canonical Rust golden vectors.
- Python SDK conformance test suite green.
- Quint formal specifications verify Agreement, Finality, and Integrity invariants.

## [0.1.0-alpha] - 2026-08-17

First reference-implementation alpha. The full consensus + execution +
persistence + networking + smart contract + cross-chain + institutional
settlement pipeline is complete and tested across Phases 0–26.

### Added

- Phase 0: normative protocol specification 00–22.
- Phase 1: Quint formal model (`consensus.qnt`, `invariants.qnt`) with
  Agreement/Finality/Integrity invariants.
- Phase 2: golden and malformed test vectors.
- Phase 3: Rust protocol foundation crates (`protocol-types`, `codec`, `crypto`,
  `merkle`, `transaction`, `capabilities`, `object-state`, `storage`).
- Phase 4: sequential deterministic state machine (`veridag-execution`).
- Phase 5: `veridag-net` — QUIC authenticated validator links + vertex/batch
  gossip. Multi-process devnet test reaches consensus over real sockets.
- Phase 6: `veridag-dag` — VCE-1 vertex wire form, validity, equivocation,
  quorum progression.
- Phase 7: `veridag-consensus` — BaselineDagBft pure-function commit rule,
  deterministic simulation (Agreement + order-independence).
- Phase 8: vertical slice — tx → batch → vertex → commit → order → execute →
  state root; 4 validators derive identical state.
- Phase 9: `veridag-storage` — trait-based stores + `MemoryStore`/`SledStore`.
  Crash-injection harness proves restart-safe recovery (identical state root).
- Phase 10: `veridag-execution` — conflict-aware parallel scheduler;
  parallel == sequential property-tested.
- Phase 11: `veridag-net` — Public libp2p discovery plane over Floodsub/Noise/Yamux with strict consensus DAG QUIC mesh isolation.
- Phase 12: `veridag-wasm-runtime` — Deterministic Wasm runtime with capability-scoped host ABI, fuel metering, and Wasmtime v48 engine.
- Phase 13: Developer SDKs — Idiomatic Rust, TypeScript, and Python SDKs with bit-for-bit wire serialization and signing conformance.
- Phase 14: `veridag-light-client` — 2f+1 quorum checkpoint verification, epoch tracking, and BMH-1 Merkle inclusion proofs.
- Phase 15: `veridag-zkvm` — Pluggable zkVM state validity proofs (Mock, SP1, RiscZero).
- Phase 16: `veridag-da` — 2D Reed-Solomon tensor erasure coding with iterative recovery and validator replication schemes.
- Phase 17: `veridag-da::hw_accel` — Chunk-unrolled SIMD vector XOR and batch GF(2^8) acceleration hooks.
- Phase 18: `veridag-stablecoin` — USMCA & G8 multilateral sovereign digital dollar (USDV), Proof-of-Reserves, and OFAC sanctions compliance.
- Phase 19: `veridag-ethereum` — Experimental EVM JSON-RPC compatibility types,
  BMH-1 Merkle inclusion proofs, and pre-audit Solidity contracts
  (`USDV.sol`, `VeridagBridge.sol`, `VeridagLightClient.sol`).
- Phase 20: `veridag-consensus` — Dynamic committee reconfiguration with weighted stakes (2W/3 + 1) and seamless epoch handovers.
- Phase 21: `veridag-metrics` — Enterprise OpenMetrics/Prometheus exposition exporter with DAG throughput and TPS telemetry.
- Phase 22: `veridag-storage` — State snapshotting, archival pruning policies, and institutional fast sync protocol.
- Phase 23: `veridag-crypto` — Pluggable `KeySigner` boundary with a local
  signer. AWS KMS, GCP KMS, Azure Key Vault, and PKCS#11 providers are not
  implemented in this release.
- Phase 24: `veridag-execution` — Native multi-chain asset typing (`Usdv`, `Btc`, `Eth`, `Sol`) and speculative parallel batch compaction.
- Phase 25: `veridag-bitcoin` — Bitcoin SPV client with canonical 80-byte header parser, nBits PoW validation, and UTXO bridge codecs.
- Phase 26: Hardonian Stack & Settler Native Layer — Deep integration with Settler reconciliation engine, proofpack anchors, and sovereign AI stack.
- `veridag-node`, `veridag-cli`, `veridag-genesis` binaries.
- Governance docs, ADRs 0001–0015, CI.
- Release profile: `opt-level=3`, thin LTO, `panic=abort`, `strip=true`
  (low-latency, low-energy, small binary).
- Docs: `docs/quickstart.md` (universal onboarding), updated
  `docs/architecture.md`, ROADMAP phase status.

### Safety

- All crates `#![forbid(unsafe_code)]`.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
- Full workspace test suite green.
