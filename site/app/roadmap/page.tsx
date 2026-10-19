const phases = [
  { n: "0–4", t: "Protocol foundation", d: "Specification, canonical encoding, cryptography, object state, and sequential execution.", status: "Beta" },
  { n: "5–11", t: "Network and consensus", d: "Authenticated QUIC, causal DAG, static-committee consensus, crash recovery, and development-network integration.", status: "Beta" },
  { n: "12–14", t: "Runtime, SDKs, and light clients", d: "Metered Wasm, packaged Rust/TypeScript/Python clients, checkpoint verification, and inclusion proofs.", status: "Beta" },
  { n: "15", t: "Zero-knowledge adapters", d: "Proof-system integration boundary and deterministic mock verifier; real prover/verifier integrations remain experimental.", status: "Interface only" },
  { n: "16–17", t: "Data availability and acceleration", d: "Erasure coding and acceleration primitives with tests; sustained multi-node operational evidence remains.", status: "Experimental" },
  { n: "18", t: "Regulated asset controls", d: "USDV object model, ISO 20022 parsing, reserve commitments, and policy hooks. Issuance and regulatory operation are external.", status: "Experimental" },
  { n: "19", t: "Ethereum interoperability", d: "RPC compatibility types and pre-audit federated-relay contracts; not an EVM or trustless bridge.", status: "Experimental" },
  { n: "20–22", t: "Membership, observability, and recovery", d: "Reconfiguration types, Prometheus output, persistent state, verified snapshots, and checkpoint recovery.", status: "Beta" },
  { n: "23", t: "Cloud KMS and HSM", d: "Fail-closed signer interface. Reviewed AWS, GCP, Azure, and PKCS#11 provider implementations remain future work.", status: "Interface only" },
  { n: "24–26", t: "Assets, Bitcoin, and application adapters", d: "Multi-asset types, Bitcoin verification primitives, and application-specific codecs. Production chain operations remain experimental.", status: "Experimental" },
  { n: "27", t: "Cross-industry evidence packs", d: "Bounded adapters for CloudEvents, GS1 EPCIS, HL7 FHIR, OPC UA, W3C VC, and ISO 20022 with privacy-preserving anchors.", status: "Beta" },
  { n: "v1.1", t: "Commercial Revenue Operations", d: "Direct Revenue OS sync, USMCA invoice clearing pilot ($5M–$15M), AI agent micro-metering, and consortium validator seat licensing.", status: "In progress" },
  { n: "GA gates", t: "Independent assurance and operations", d: "External security audit, multi-region fault campaign, recovery drills, performance envelopes, support ownership, and deployment-specific compliance approval.", status: "Required" },
];

const colorByStatus: Record<string, string> = {
  Beta: "var(--accent-emerald-bright)",
  Experimental: "#fbbf24",
  "Interface only": "var(--accent-violet-bright)",
  "In progress": "var(--accent-cyan-bright)",
  Required: "#fb7185",
};

export default function Roadmap() {
  return (
    <div>
      <h1>Capability Roadmap</h1>
      <p className="tagline">
        Veridag is pre-GA. Milestone completion records that an artifact exists in the tree; capability status records whether it is ready to operate.
      </p>

      <div className="alert" style={{ border: "1px solid rgba(251, 191, 36, 0.4)", background: "rgba(251, 191, 36, 0.08)" }}>
        <div className="alert-title" style={{ color: "#fbbf24" }}>Pre-GA release discipline</div>
        <p style={{ margin: 0, fontSize: "14px", color: "#c7d2e0" }}>
          Core protocol functions are integrated and tested, while external audits, production operating evidence, and several provider integrations remain release gates. See the repository capability matrix for exact evidence and limitations.
        </p>
      </div>

      <h2>Capability Breakdown</h2>
      <div>
        {phases.map((p) => (
          <div className="phase-card" key={p.n}>
            <div className="phase-header">
              <div>
                <span className="phase-num">{p.n}</span> — <span className="phase-title">{p.t}</span>
              </div>
              <span style={{ fontSize: "12px", color: colorByStatus[p.status], fontFamily: "var(--font-mono)", fontWeight: 700 }}>
                {p.status.toUpperCase()}
              </span>
            </div>
            <p style={{ margin: 0, fontSize: "13.5px", color: "var(--text-muted)" }}>{p.d}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
