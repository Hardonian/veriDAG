# Roadmap

The protocol is built phase by phase, always keeping the tree green. We do not
claim a phase is done until its Definition of Done is met with real artifacts.

## Phase 0 — Specification skeleton (DONE in this tree)

Normative spec 00–13, scoped drafts 14–18. Terminology, identifiers, VCE-1
canonical encoding, transactions, object model, capabilities, DAG, BaselineDagBft,
ordering, execution, state (BMH-1), checkpoints, membership, upgrades.

## Phase 1 — Formal consensus model (DONE in this tree)

`formal/quint/consensus.qnt`, `instance4.qnt`, and `consensus_test.qnt`:
validators, rounds, vertices, parents, equivocation, quorum commit rule, and
Agreement/Finality/Integrity invariants. Checked with `quint typecheck`,
`quint test`, and `quint run --invariant`.

## Phase 2 — Protocol vectors (DONE in this tree)

`protocol/test-vectors/`: encoding, hash, signature, transaction, genesis golden
vectors. `conformance/malformed/`: must-reject byte strings. Generated and
re-validated by the Rust workspace.

## Phase 3 — Rust protocol foundation (DONE in this tree)

Crates: `veridag-protocol-types`, `veridag-codec`, `veridag-crypto`,
`veridag-merkle`, `veridag-transaction`, `veridag-capabilities`,
`veridag-object-state`, `veridag-storage`. All `#![forbid(unsafe_code)]`, all
pass golden + malformed vectors.

## Phase 4 — Sequential state machine (DONE in this tree)

`veridag-execution`: native transfer, create/update/delete, capabilities,
resource accounting, state roots, receipts. Deterministic state tests.

## Phase 5 — Validator networking (DONE in this tree)

`veridag-net`: QUIC validator links with self-signed Ed25519 certs and a
domain-separated verifier (no MITM, no plaintext). `gossip` module broadcasts
tagged messages (vertices + batches) over authenticated uni-streams.
`tests/devnet.rs`: four OS-process validators reach consensus over **real
QUIC sockets** — identical state roots and checkpoints across the network.

## Phase 6 — DAG (DONE in this tree)

`veridag-dag`: VCE-1 vertex wire form, domain-separated ids/signatures,
validity rules, equivocation detection, quorum round progression, causal
traversal. 14 unit tests. `Dag::iter_vertex_ids()` added for recovery.

## Phase 7 — Baseline consensus (DONE in this tree)

`veridag-consensus`: StaticCommittee leader schedule, pure-function commit rule
with Shoal-style pipelining, deterministic causal ordering. Validated by
deterministic simulation (`tests/simulation.rs`): n=4/f=1 Agreement +
delivery-order independence.

## Phase 8 — Vertical slice (DONE in this tree)

`tests/vertical_slice.rs`: client tx → batch commitment → DAG vertex →
BaselineDagBft commit → canonical ordering → sequential execution → state root.
Four validators derive identical committed ordering and identical final state;
committed double-spend resolves deterministically.

## Phase 9 — Crash recovery (DONE in this tree)

`veridag-storage`: trait-based `StateStore`/`DagStore`/`CheckpointStore` with
`MemoryStore` and `SledStore` (feature `persistent`). `sled_tests`:
crash-injection harness builds a 4-validator DAG through a committed wave,
persists every vertex + final state to sled, **drops all in-memory state**
(simulated crash), reopens, rebuilds the DAG from persisted bytes in round
order, re-runs the commit rule, and re-executes — asserting identical state
root + balances. The commit → checkpoint boundary is restart-safe.

## Phase 10 — Parallel execution (DONE in this tree)

`veridag-execution`: conflict-aware scheduler partitions the committed ordering
into a non-conflicting parallel prefix + sequential suffix; the sequential
executor is the oracle. `tests/parallel.rs` property-tests
parallel == sequential across randomized workloads.

## Phase 11 — Public P2P Plane (DONE in this tree)

`veridag-net`: selective libp2p discovery (`DiscoveryPolicy::Open`, `DiscoveryPolicy::Allowlist`)
over Floodsub/TCP/Noise/Yamux without altering consensus security semantics. Consensus DAG
strictly isolated on authenticated QUIC mesh; public gossip plane handles ingress and relay.

## Phase 12 — Deterministic Wasm Runtime (DONE in this tree)

`veridag-wasm-runtime`: `ComponentLoader` validates Wasm bytecode and `WasmComponentManifest`,
rejecting non-deterministic imports (WASI/time/random/sockets) and enforcing capability-scoped
host ABI (`host_read`, `host_write`, `host_spend`, `host_epoch`, `host_log`) and deterministic
fuel metering. Native and Wasmtime backends.

## Phase 13 — Developer SDKs (DONE in this tree)

Idiomatic developer SDKs in Rust (`veridag-sdk`), TypeScript (`sdks/typescript`), and Python
(`sdks/python`). All three languages validated for bit-for-bit wire serialization, Ed25519 signing,
and transaction hashing against `protocol/test-vectors/sdk_conformance.json`.

## Phase 14 — Light Client Protocol (DONE in this tree)

`veridag-light-client`: 2f+1 quorum checkpoint verification, continuous epoch state tracking
(`LightClientTracker`), and BMH-1 Merkle object inclusion proofs. Matched on EVM L1 by
`contracts/VeridagLightClient.sol`.

## Phase 15 — Zero-Knowledge Proof Adapters (DONE in this tree)

`veridag-zkvm`: pluggable `ZkvmAdapter` trait with `MockZkvmAdapter`, `Sp1Adapter`, and
`RiscZeroAdapter` behind feature flags. Proving is decoupled from the critical consensus path
and utilized for L1 settlement compression and fast light client sync.

## Phase 16 — Advanced Data Availability (DONE in this tree)

`veridag-da`: 2D Reed-Solomon tensor erasure coding (`Da2DConfig`, `encode_2d`, `reconstruct_2d`)
with alternating row/column iterative recovery under scattered erasures, independent row/col
Merkle commitments, and deterministic validator replication assignment (`ValidatorReplicationScheme`).

## Phase 17 — Hardware Acceleration (DONE in this tree)

`veridag-da::hw_accel`: `HwAccelEngine` with chunk-unrolled SIMD vector XOR, batch GF(2^8)
multiplication, and C/Zig foreign acceleration hooks under strict `#![forbid(unsafe_code)]`.

## Phase 18 — USMCA & G8 Sovereign Multilateral Settlement (USDV) (DONE in this tree)

`veridag-stablecoin`: US-aligned sovereign digital dollar for USMCA trade corridor clearing
and G8 economic forum multilateral treasury settlement. 100% reserve-backed (US Treasuries,
FDIC cash deposits, Reverse Repo), cryptographically verified Proof-of-Reserves (PoR) in
state roots, capability-gated mint/burn/pause, and hooks for operator-supplied sanctions
screening. Normative spec 19. Mathematical conservation-of-value invariant checked across
all transitions.

## Phase 19 — Ethereum Interoperability Substrate (EXPERIMENTAL)

`veridag-ethereum`: EVM JSON-RPC compatibility types (`eth_chainId`, `eth_blockNumber`,
`eth_getBalance`), BMH-1 proof generation, and cross-chain bridge primitives.
Pre-audit Solidity prototypes: `USDV.sol`, `VeridagLightClient.sol`, and
`VeridagBridge.sol`. This is not an EVM implementation or trustless light client.

## Phase 20 — Dynamic Validator Membership & Reconfiguration (DONE in this tree)

`veridag-consensus`: Dynamic committee reconfiguration (`DynamicCommittee`, `WeightedValidator`,
`EpochHandoverTracker`), threshold stake calculation (2W/3 + 1), and seamless epoch transitions
without liveness interruption. Normative spec 16 upgraded from draft to normative.

## Phase 21 — Enterprise Prometheus Observability (DONE in this tree)

`veridag-metrics`: Standard OpenMetrics/Prometheus exposition format exporter (`PrometheusExporter`),
delivering sorted `# HELP` / `# TYPE` metric definitions, counter, gauge, and histogram telemetry
for validator node operations, consensus round timing, commit rates, and DAG throughput.

## Phase 22 — State Archival & Fast Snapshot Synchronization (DONE in this tree)

`veridag-storage`: State snapshotting engine (`StateSnapshot`, `PruningPolicy`), state serialization
and deserialization, and state sync primitives enabling newly onboarded institutional validators
to bootstrap to consensus height without replaying historical DAG waves.

## Phase 23 — Cloud KMS & HSM Signer Boundary (INTERFACE ONLY)

`veridag-crypto`: Pluggable key management abstraction (`KeySigner` trait) with local software
implementation (`LocalKeySigner`). `RemoteKmsSigner` is a fail-closed integration
boundary; AWS, Google Cloud, Azure, and PKCS#11 providers remain future work.

## Phase 24 — Multi-Chain Asset Integration & Speculative Batch Compactor (DONE in this tree)

`veridag-execution`: Native multi-chain asset typing (`AssetType`: `Usdv`, `Btc`, `Eth`, `Sol`),
disjoint transaction read/write dependency partitioning, and parallel batch compaction
(`BatchCompactor`) optimizing block throughput for high-concurrency cross-chain operations.

## Phase 25 — Bitcoin Native Substrate & Cross-Chain SPV (DONE in this tree)

`veridag-bitcoin`: Bitcoin SPV client with canonical 80-byte header parsing, compact nBits PoW
validation, Double-SHA256 (`hash256`), Merkle inclusion proof verification (`BitcoinMerkleProof`),
continuous header tracker (`BtcSpvHeaderTracker`), and bidirectional UTXO deposit/withdrawal
codecs (`CrossChainBtcDeposit`, `CrossChainBtcWithdrawal`). Normative spec 21.

## Phase 26 — Hardonian Sovereign AI Stack & Settler Native Layer (DONE in this tree)

`veridag-stablecoin`, `veridag-protocol-types`, `veridag-cli`: Deep bidirectional integration with
the Hardonian Sovereign AI Stack and Settler reconciliation engine. Native object types
`SETTLER_ANCHOR` and `CONSORTIUM_TENANT`, atomic batch settlement execution (`execute_settler_batch`),
reconciliation proofpack state anchoring, and cross-repo interoperability with MissionLedger,
ReadyLayer, nlsqlc, mcpwall, and TokenGoblin. Normative spec 22.

## Phase 27 — Commercial Revenue Operations & Enterprise Settlement (v1.1.0 — IN PROGRESS)

`veridag-node`, `veridag-cli`, `revenue-os`: Direct monetization and enterprise cash-flow generation:
1. **Revenue OS Live Connective Pipeline**: Real-time SQLite telemetry sync emitting transaction settlement fees, validator license subscriptions, and float yield directly into `/home/scott/ai-lab/revenue-os/revenue-os.db`.
2. **USMCA Commercial Trade Pilot**: Activation of the 90-day freight invoice clearing pilot clearing $5M–$15M USDV via Settler dual-leg reconciliation (`SETTLER_ANCHOR = 5`) with a 1 bps protocol surcharge.
3. **Hardonian AI Agent Compute Metering**: Real-time micro-metering ($10⁻⁶ USDV) across TokenGoblin, Settler, and MissionLedger for autonomous agent swarm missions and tool call settlements.
4. **Phase 23 Production Cloud KMS/HSM**: AWS KMS, GCP Cloud KMS, and PKCS#11 hardware security module signers graduating Phase 23 for institutional bank validator deployments.
5. **Consortium Member Licensing ($250k/yr)**: Onboarding initial 4 to 8 institutional member nodes with dynamic weighted committee governance and staking yield distribution.

## Release status

Pre-GA. The numbered phases above record protocol and reference-implementation
milestones; `DONE in this tree` does not by itself mean production-ready or
independently audited. The workspace tests and strict Clippy gate pass, and the
four-validator development network reaches agreement over QUIC. Production
promotion additionally requires the runtime, security, packaging, recovery,
benchmark, and external-review gates tracked in
[`docs/capability-matrix.md`](docs/capability-matrix.md).
