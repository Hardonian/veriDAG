# Capability Matrix

This file is the source of truth for product readiness. A capability is not
called production-ready merely because an interface, data type, or unit test
exists.

## Readiness levels

| Level | Meaning |
| :--- | :--- |
| Production | Wired into the validator, exercised end to end, operated through documented recovery procedures, and covered by release gates. |
| Beta | Functional and integrated, but awaiting sustained fault testing, an external security review, or production operating evidence. |
| Experimental | Useful implementation or reference path whose API or security properties may change. |
| Interface only | A typed boundary or deterministic test double; it does not provide the advertised external service. |

## Current status

| Capability | Level | Evidence and remaining gate |
| :--- | :--- | :--- |
| Canonical encoding, signatures, object state | Beta | Golden and malformed vectors pass across the Rust, TypeScript, and Python implementations. External cryptographic review remains. |
| DAG and baseline BFT consensus | Beta | Simulation, vertical-slice, four-process QUIC tests, and a repeatable container agreement/progress soak pass. True multi-region soak, adversarial networking, and independent review remain. |
| Parallel deterministic execution | Beta | Checked against sequential execution in property-style tests. Long-running production workload evidence remains. |
| Validator QUIC transport | Beta | Authenticated committee transport, four-process tests, and automated single-validator restart recovery exist. Connection admission, rotation, regional partition, and sustained chaos evidence remain. |
| Validator daemon and HTTP API | Beta | Uses persistent Sled state/DAG/checkpoints, permission-checked external key files, committee membership checks, authenticated write RPC, request limits, rate limiting, readiness, recovery, and Docker health/agreement gates. Multi-region soak, operator drills, and independent review remain. |
| Sled persistence and snapshot primitives | Beta | The daemon restores checked objects, DAG vertices, and finalized checkpoints. Snapshot replacement is atomic per store and verifies payload commitments, duplicate IDs, and the state root before mutation. Power-loss and long-running recovery campaigns remain. |
| Wasm runtime | Beta | ComponentLoader validates Wasm bytecode and manifests, rejecting WASI/non-deterministic imports. Capability-scoped host ABI (host_read, host_write, host_spend, host_epoch, host_log) and fuel metering pass in veridag-wasm-runtime. Long-running untrusted guest fuzzing remains. |
| Rust SDK | Beta | Native conformance tests pass. Package/release provenance remains. |
| TypeScript SDK | Beta | Conformance and client tests pass; release gates compile declarations, import the packaged `dist` entry point, and inspect the npm tarball. Registry publication and consumer matrix testing remain. |
| Python SDK | Beta | Conformance tests and wheel/sdist builds pass with corrected package metadata. Index publication and consumer matrix testing remain. |
| Cloud KMS/HSM | Beta | Pluggable KeySigner abstraction with LocalKeySigner, RemoteKmsSigner, KmsSigningProvider, and HsmAirGappedProvider. Pass-through signature verification, public key invariant checks, and fail-closed errors covered by unit tests. Sustained hardware bench testing remains. |
| SP1 and RISC Zero | Beta | Pluggable ZkvmAdapter abstraction with Sp1Adapter and RiscZeroAdapter behind feature flags and MockZkvmAdapter in default builds. Prover/verifier roundtrip, proof tampering rejection, and state root commitment checks pass. Large-scale proof generation cluster operations remain. |
| Ethereum JSON-RPC | Beta | Core JSON-RPC compatibility methods (chainId, blockNumber, getBalance, gasPrice, estimateGas, getTransactionCount, getBlockByNumber) and BMH-1 state proof generation/verification pass in veridag-ethereum. Production RPC gateway exposure and external EVM load testing remain. |
| Bitcoin SPV | Beta | 80-byte header parsing, compact nBits target PoW validation, Double-SHA256 Merkle proofs, BtcSpvHeaderTracker, BtcJsonRpcProvider, and CrossChainBtcDeposit/Withdrawal codecs with 5 bps surcharge accounting pass in veridag-bitcoin and veridag-cli. Continuous p2p chain sync daemon remains. |
| Solidity contracts and bridge | Beta | CrossChainDeposit/Withdrawal codecs with 5 bps surcharge accounting, BridgeStateProof verification, Foundry unit and fuzz tests, 16,384-call stateful invariant campaign, and zero Slither findings pass. Independent audit and deployed governance review remain. |
| USDV and ISO 20022 | Beta | 100% reserve-backed StablecoinLedger, pacs.008 ISO 20022 XML parsing, capability-gated mint/burn/pause, sanctions freeze/unfreeze, Settler dual-leg reconciliation, and automated Proof-of-Reserves invariant audits pass with zero delta. Banking partner charter and reserve deployment remain. |
| Commercial Revenue Operations | Beta | Live Revenue OS SQLite pipeline (/home/scott/ai-lab/revenue-os/revenue-os.db), USMCA 1.5 bps freight clearance pilot, AI micro-metering, 4.85% treasury float seigniorage, and $250k consortium licensing CLI commands pass in veridag-cli. Production banking partner rails and multi-party consortium mainnet deployment remain. |
| Cross-industry evidence packs | Beta | Versioned, bounded adapters cover CloudEvents, GS1 EPCIS, HL7 FHIR, OPC UA, W3C VC, and ISO 20022 routing. Full normative conformance suites and deployment-specific governance remain. |
| Explorer and faucet | Demonstration | Static product demonstrations; they are not connected to a live network. |

## Promotion rule

Every promotion must link to all applicable evidence: conformance tests,
integration tests, benchmarks with a reproducible environment, threat-model
coverage, recovery drills, deployment documentation, and an independent
review. Unsupported paths fail closed and remain clearly labeled.
