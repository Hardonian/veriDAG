# ⚡ VeriDAG

## Deterministic shared state for multi-party systems

[![Status](https://img.shields.io/badge/status-pre--GA-orange?style=for-the-badge)](docs/capability-matrix.md)
[![Rust](https://img.shields.io/badge/Rust-1.95%2B-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org)
[![Safety](https://img.shields.io/badge/unsafe-FORBIDDEN-blueviolet?style=for-the-badge&logo=shield)](Cargo.toml)
[![Formal Verification](https://img.shields.io/badge/Formal%20Model-Quint%20Verified-cyan?style=for-the-badge&logo=probot)](formal/quint/)
[![License](https://img.shields.io/badge/License-Apache_2.0_|_MIT-blue?style=for-the-badge)](LICENSE-APACHE)
[![Transport](https://img.shields.io/badge/Transport-QUIC_%2B_TLS_1.3-informational?style=for-the-badge)](implementations/rust/crates/net)
[![Storage](https://img.shields.io/badge/Storage-Embedded_Sled-success?style=for-the-badge)](implementations/rust/crates/storage)

[Quickstart](#quickstart-in-under-3-minutes) • [Why Veridag](#why-veridag) • [Capability Matrix](docs/capability-matrix.md) • [Enterprise APIs](#enterprise-infrastructure--apis) • [SDKs](#multi-language-sdks) • [Industry Packs](industry-packs/) • [Security](#security-and-control-mapping) • [Crate Map](#crate-ecosystem) • [Docs](docs/)

---

## What is VeriDAG?

**Veridag** is an implementation-independent protocol and Rust reference engine for **deterministic, Byzantine-resilient, capability-secured distributed computation**.

> **Release status:** pre-GA. The protocol core and conformance suites are
> functional; several integrations remain experimental or interface-only. See
> the [capability matrix](docs/capability-matrix.md) before evaluating or
> deploying the software.

> **Portfolio signal:** VeriDAG is the distributed-systems flagship: a Rust reference engine for deterministic, Byzantine-resilient computation with capability security, formal models, and cryptographic auditability.

Within its documented committee and fault assumptions, it gives mutually distrustful parties—autonomous AI agents, organizations, microservices, cloud nodes, and edge devices—a shared state machine with deterministic agreement and cryptographic auditability.

```text
┌────────────────┐     ┌────────────────┐     ┌────────────────┐
│   Consensus    │  +  │   Verifiable   │  +  │ Deterministic  │
│  (DAG-BFT)     │     │     State      │     │  Computation   │
└───────┬────────┘     └───────┬────────┘     └───────┬────────┘
        │                      │                      │
        ▼                      ▼                      ▼
┌────────────────┐     ┌────────────────┐     ┌────────────────┐
│   Capability   │  +  │      Data      │  +  │ Cryptographic  │
│    Security    │     │  Availability  │     │     Proofs     │
└───────┬────────┘     └───────┬────────┘     └───────┬────────┘
        │                      │                      │
        └──────────────────────┼──────────────────────┘
                               │
                               ▼
        ================================================
        🛡️   V E R I D A G   T R U S T   F A B R I C   🛡️
        ================================================
```

### What Veridag Is NOT

- ❌ **Not a speculative cryptocurrency or token casino** — No gas volatility, no speculative hype tokens required to run consensus.
- ❌ **Not a bloated blockchain clone** — No 500GB ledger bloat, no complex node mining rigs.
- ❌ **Not a fragile cloud framework** — Zero runtime dependencies; no Kubernetes, Postgres, Redis, or Kafka sidecars needed.

### Flagship integration targets

- 🏛️ **Regulated settlement pilots** — USDV object types, reserve-attestation commitments, capability-gated mint/burn/pause controls, and ISO 20022 parsing are implemented as experimental building blocks. Issuance, custody, sanctions screening, and regulatory operation require an authorized operator and independent review.
- ⛓️ **Ethereum interoperability** — Solidity contracts, BMH-1 inclusion proofs, and an EVM JSON-RPC compatibility facade are available for testing. The light client is threshold-relayed, not trustless, and the contracts have not completed an external audit.
- 🌐 **Cross-industry evidence anchoring** — Versioned adapters for CloudEvents, GS1 EPCIS, HL7 FHIR, OPC UA, W3C Verifiable Credentials, and ISO 20022 validate bounded envelopes and commit hashes without placing source records on-chain.

---

## Why Veridag?

| Property | What It Means for You |
| :--- | :--- |
| **Pure-Function DAG-BFT** | Consensus is an invariant pure function over a causal DAG. Given identical inputs, every node resolves the identical commit point and wave ordering. |
| **Zero-Unsafe Core** | The entire consensus, execution, and state engine enforces `#![forbid(unsafe_code)]`. Memory safety vulnerabilities cannot corrupt state. |
| **Object-Centric Capabilities** | Fine-grained object capabilities replace blunt permissions. Access is scoped, verifiable, and strictly sandboxed. |
| **Instant Crash Recovery** | Append-friendly embedded `sled` storage. If a node crashes mid-commit, it reboots, replays durable bytes, and recovers byte-identical state. |
| **Self-Contained Deployment** | A validator uses embedded storage and does not require a database sidecar. Release workflows publish checksums, SBOMs, and build provenance. Measure binary size and platform performance for each release artifact. |
| **Authenticated QUIC Fast Path** | Low-latency 1-RTT gossip over authenticated QUIC with self-signed Ed25519 TLS certificates and domain-separated preimages. |

---

## Quickstart (In Under 3 Minutes)

### 1. Prerequisites

Veridag requires standard **Rust 1.95+** (edition 2021):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default stable
```

### 2. Clone & Build

```bash
git clone https://github.com/Hardonian/veridag.git
cd veridag
```

### 3. Run the In-Process 4-Validator Consensus Demo

Witness 4 independent validator nodes reach cryptographic agreement on state roots and checkpoint IDs in a single command:

```bash
cargo run -p veridag-node -- demo
```

**Output:**

```text
veridag-node demo: 4-validator committee, in-process
submitted transfer alice->bob 40 to all mempools
round 1..11: max round reached 11
validator 0: state_root=0xac049e6fdadc2840ff5d3a9ee9e4598a4eebf86e68861bccedcab8f46942cb4e checkpoints=1
  checkpoint seq=1 id=0x3a875556df63e5ff02303aa0971018d2a69e3d1bd344b50cbb459b160daade40
...
AGREEMENT OK: identical state root across 4 validators
bob balance: 40 (expected 40)
```

---

## Enterprise Infrastructure & APIs

### Built-in HTTP / JSON-RPC Daemon

Launch a local development validator with explicit development credentials and genesis state:

```bash
# Launch validator node daemon with HTTP RPC enabled
cargo run -p veridag-node -- daemon --seed 1 --dev-genesis --rpc 127.0.0.1:8080 --data-dir ./data/node-1

# Query node health
curl http://127.0.0.1:8080/v1/health

# Query cryptographic Sparse Merkle Tree state root
curl http://127.0.0.1:8080/v1/state/root

# Query latest finalized checkpoint certificate
curl http://127.0.0.1:8080/v1/checkpoints/latest
```

### Multi-Validator Docker Compose Mesh

Launch 4 independent validator nodes communicating over an authenticated QUIC mesh with mapped RPC ports:

```bash
docker compose up -d
curl http://localhost:8081/v1/health
```

---

## Multi-Language SDKs

Veridag maintains first-class, bit-for-bit conformant client libraries across Rust, TypeScript, and Python:

### TypeScript SDK (`@veridag/sdk`)

```typescript
import { VeridagClient, Keypair, TxBuilder } from "@veridag/sdk";

const client = new VeridagClient("http://127.0.0.1:8080");
const health = await client.health();
console.log("Connected to DAG:", health.status, "State Root:", health.state_root);

const sender = Keypair.fromSeed(new Uint8Array(32).fill(1));
const recipient = Keypair.fromSeed(new Uint8Array(32).fill(2)).address();
const stx = new TxBuilder(sender).nonce(0).transfer(recipient, 500n);
const receipt = await client.submitTransaction(stx, sender.public);
console.log("Tx admitted into DAG:", receipt.tx_id);
```

### Python SDK (`veridag`)

```python
from veridag import VeridagClient, Keypair, TxBuilder

client = VeridagClient("http://127.0.0.1:8080")
h = client.health()
print(f"Connected: chain={h['chain_id']} root={h['state_root'][:16]}...")

sender = Keypair.from_seed(b"\x01" * 32)
recipient = Keypair.from_seed(b"\x02" * 32).address()
stx = TxBuilder(sender).nonce(0).transfer(recipient, 500)
res = client.submit_transaction(stx, sender.public())
print("Tx admitted:", res["tx_id"])
```

---

## ISO 20022 Banking Bridge

Veridag provides native parsing and atomic DAG execution of ISO 20022 `pacs.008.001.08` credit transfer instructions with automatic 1 bps clearing surcharge splits (80% validator pool, 20% insurance reserve) and cryptographic `pacs.002.001.10` execution receipts:

```bash
cargo test -p veridag-stablecoin iso20022
```

---

## Security and control mapping

The repository includes an engineering control mapping to selected **AICPA Trust Services Criteria**. This is not a SOC 2 audit, report, or certification.

- **CC6 Logical Access**: Ed25519 asymmetric signatures, domain separation tags, consortium multi-tenancy.
- **CC7 Operations**: Causal DAG audit log, SMT inclusion proofs, automated `/v1/health` monitoring.
- **A1 Availability**: Bullshark $3f+1$ Byzantine Fault Tolerance with asynchronous fallback.
- **PI1 Processing Integrity**: Canonical VCE-1 non-malleable encoding, metered WebAssembly runtime.
- **C1 Confidentiality**: TLS 1.3 / Noise transport encryption, zero hardcoded credentials.

For details, review [`compliance/SOC2_TYPE2_CONTROLS.md`](compliance/SOC2_TYPE2_CONTROLS.md), [`docs/threat-model.md`](docs/threat-model.md), and the [capability matrix](docs/capability-matrix.md).

---

## Crate Ecosystem

```text
implementations/rust/
├── bins/
│   ├── veridag-node/       # Full Validator Daemon & HTTP/JSON RPC Server
│   ├── veridag-cli/        # Universal Operator & Developer CLI
│   └── veridag-genesis/    # Committee Genesis Bootstrap Tool
└── crates/
    ├── protocol-types/     # Canonical IDs, hash types, version tags
    ├── codec/              # VCE-1 canonical non-malleable binary codec
    ├── crypto/             # Ed25519, SHA-512/256 domain separation
    ├── merkle/             # Sparse Merkle Trees (SMT) & inclusion proofs
    ├── capabilities/       # Object-capability authorization tokens
    ├── transaction/        # Transaction wire format & replay protection
    ├── object-state/       # Version-disciplined object ledger
    ├── dag/                # DAG structure, equivocation detection
    ├── consensus/          # Bullshark DAG-BFT commit rule & wave ordering
    ├── execution/          # Conflict-aware parallel scheduler
    ├── checkpoint/         # Quorum finality proofs (2f+1)
    ├── wasm-runtime/       # Metered Wasmtime smart contract sandbox
    ├── zkvm/               # Experimental proof-system adapter interfaces
    ├── da/                 # 2D Reed-Solomon data availability
    ├── light-client/       # Quorum-checkpoint and inclusion verification
    ├── bitcoin/            # Bitcoin native SPV header & PoW client
    ├── ethereum/           # Experimental Ethereum proof/RPC compatibility types
    ├── stablecoin/         # USDV sovereign dollar, ISO 20022 engine & PoR
    ├── storage/            # Sled durable persistence and snapshot validation
    ├── net/                # Authenticated QUIC + TLS 1.3 mesh transport
    ├── sdk/                # Native Rust client SDK
    ├── metrics/            # Zero-overhead Prometheus probes
    ├── industry/           # Versioned cross-industry evidence adapters
    └── testkit/            # Golden vectors & cross-language harness
```

---

## Developer Cheatsheet

```bash
# Setup & Linting
just check             # Format check, zero-warning clippy gate, full test suite

# Multi-Language SDK Conformance (Rust, TS, Python)
pwsh -File scripts/publish-sdks.ps1   # Windows PowerShell
bash scripts/publish-sdks.sh          # Linux / macOS

# Execution & Demos
cargo run -p veridag-node -- demo    # Run in-process 4-node consensus demo
docker compose up -d                 # Spin up 4-node container cluster
python3 scripts/devnet-soak.py --duration 300 --restart-service node4

# Web Portal & Economics
just site-build        # Build Next.js documentation, explorer & pricing portal
```

See the [release-readiness checklist](docs/release-readiness.md) for the exact
automated, independent-audit, multi-region, and regulatory promotion evidence.

---

## Security & Verification Invariants

Veridag enforces non-negotiable core invariants:

1. **Agreement:** Non-faulty nodes commit identical state anchors.
2. **Finality:** Committed waves are immutable and cannot be rolled back.
3. **Integrity:** Only validly signed, structurally sound vertices enter the DAG.
4. **Determinism:** State transitions are pure functions independent of machine architecture, memory layout, CPU count, or wall-clock timestamps.

For vulnerability disclosure and security policies, see [SECURITY.md](SECURITY.md).

---

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
