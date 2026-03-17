# Primust Developer Documentation

Prove what your system did. Mathematically.

---

## What is Primust

You already have checks — access control, schema validation, model evaluation, bias audits, policy enforcement. Primust does not replace them. **Primust makes them provable.**

The flow is simple:

1. **Input** — your system receives a request, data, or event.
2. **Checks** — your existing governance logic executes: OPA policies, Cedar rules, LLM evaluations, schema validators, anything.
3. **Output** — Primust captures the execution trace, binds it cryptographically, and produces a credential.
4. **Verify** — anyone with the credential can verify it independently. No phone calls. No network access. No trust required.

The credential is called a **VPEC** — a Verifiable Process Execution Credential. It is portable JSON. It is verifiable offline. It contains commitment hashes, never raw content. It is the cryptographic receipt for what your system actually did.

Primust is not an AI governance tool. AI governance is the first market. The primitive works for any governed process — software build systems, financial data pipelines, clinical data delivery, insurance claims, legal research. Any process where a party needs proof without trusting the runner.

---

## What is a VPEC

**Verifiable Process Execution Credential.**

- **Verifiable** — any party can independently confirm the credential is valid, without contacting the issuer.
- **Process** — it binds to a specific execution: the checks that ran, the inputs they consumed, the outputs they produced.
- **Execution** — it captures what actually happened at runtime, not what was supposed to happen.
- **Credential** — it is a portable, self-contained JSON object that travels with the artifact it describes.

A VPEC is cryptographically signed JSON. It contains commitment hashes — SHA-256 or Poseidon2 digests of inputs, outputs, and check results — never the raw content. This makes VPECs **content-blind**: a verifier can confirm a bias audit passed without ever seeing the model weights or training data.

VPECs are **offline-verifiable**. Verification requires only the credential and a trust root. No network calls after the first public key fetch. Works forever regardless of Primust's existence.

> A VPEC proves *what happened*, not *what should have happened*. It is a receipt, not a policy.

---

## Proof Levels

Not all evidence is equal. Primust assigns every check a **proof level** based on the cryptographic strength of its binding. Five levels, from strongest to weakest:

| Level | Enum | Mechanism | Trust Required | Examples |
|---|---|---|---|---|
| Mathematical | `mathematical` | Noir ZK circuit (UltraHonk, Modal CPU) | None — math proves it | Regex, allowlist, threshold, OPA (local eval), Cedar eval(), Drools eval(), Ed25519 verify |
| Verifiable Inference | `verifiable_inference` | ONNX-to-circuit (EZKL/Bionetta, Modal GPU) | Trust model weights | XGBoost, Isolation Forest, scikit-learn classification |
| Execution | `execution` | Model-hash-binding circuit | Trust the model (public, auditable) | Named ML model with version hash, pinned LLM API version, custom code (hash-bound) |
| Witnessed | `witnessed` | Two RFC 3161 timestamps + Ed25519 sig | Trust the reviewer identity | Human review, pharmacist approval, CISO sign-off |
| Attestation | `attestation` | Invocation-binding circuit | Trust the process owner's word | OTEL records, opaque processes, external REST API wrappers |

**Weakest-link rule:** A VPEC's `proof_level_floor` is the lowest proof level across all checks it contains. One Attestation check makes the floor Attestation. This is by design and cannot be faked upward.

**upstream_vpec_verify ceiling: Mathematical.** Ed25519 verification is deterministic — always the same result for the same inputs.

---

## Provable Surface

The `provable_surface` is the share of your governance that is cryptographically provable — a float from 0.0 to 1.0. It answers: of all the governance checks in this process, what fraction produce verifiable evidence?

```
provable_surface: 0.73
provable_surface_breakdown: {
  mathematical:        0.62,   # 62% of checks — deterministically proven
  verifiable_inference: 0.00,
  execution:           0.11,   # 11% — named model, auditable identity
  witnessed:           0.00,
  attestation:         0.00
}
provable_surface_ungoverned: 0.27   # manifest checks with no record this run
```

**`proof_level_floor` is the compliance gate.** It is the weakest-link scalar — use it to enforce a minimum guarantee.

**`provable_surface` is the hero metric.** It shows the full picture. Lead with this in auditor conversations:

> "62% of your governance is mathematically proven."

Not: "Your proof level floor is attestation." That's honest technical disclosure, not the opening pitch.

---

## Policy Bundles

Policy bundles are pre-built collections of checks mapped to compliance frameworks. Each bundle declares which checks are required and what the expected provable surface looks like.

| Bundle ID | Description | Framework Mappings |
|---|---|---|
| `ai_agent_general_v1` | General AI agent governance | — |
| `eu_ai_act_art12_v1` | EU AI Act Article 12 transparency and logging | eu_ai_act_art12, eu_ai_act_art9 |
| `hipaa_safeguards_v1` | HIPAA technical safeguards | hipaa_164312 |
| `soc2_cc_v1` | SOC 2 common criteria | soc2_cc71, soc2_cc81 |
| `coding_agent_v1` | Code-generating agent governance | — |
| `supply_chain_governance_v1` | Software supply chain integrity | — |
| `financial_data_governance_v1` | Financial data processing controls | — |

Bundles are composable. Apply multiple bundles to cover overlapping frameworks.

---

## Open Source

Two packages are Apache-2.0 and free forever — no account required:

**`primust-verify`** — offline VPEC verifier. Verify any VPEC with no Primust involvement. Works forever.
```bash
pip install primust-verify
primust verify vpec.json
primust verify vpec.json --trust-root key.pem   # zero network
```

**`primust-checks`** — open source check harness. Run governance checks with or without a Primust account. Without an API key: observability only, no VPECs issued. With an API key: identical checks, VPECs issued.
```bash
pip install primust-checks
```

---

## Regulated Industry Connectors

`primust-connectors` (Apache-2.0) provides governance adapters for regulated enterprise platforms. Each connector wraps a decisioning platform with VPEC issuance — proving governance ran without disclosing the data it ran on.

**7 Python REST connectors built (321 tests):**

| Connector | Platform | Proof Ceiling | Verifier |
|---|---|---|---|
| ComplyAdvantage | AML entity screening | Attestation | FinCEN, FCA, AUSTRAC |
| NICE Actimize | AML transaction monitoring + SAR | Witnessed (SAR), Attestation (scoring) | FinCEN, OCC, FCA |
| FICO Blaze | Credit decisioning BRMS | Attestation | CFPB, state AGs |
| IBM ODM | Enterprise BRMS / underwriting | Attestation | CFPB, OCC |
| FICO Falcon | Card fraud detection | Attestation | OCC, Visa/MC |
| Pega CDH | Next-best-action / regulated NBA | Attestation | OCC, CFPB, GDPR Art 22 |
| Wolters Kluwer UpToDate | Clinical decision support | Attestation | CMS, Joint Commission |

All REST connectors are Attestation ceiling — the vendor's internal logic is a black box at the REST API boundary. Mathematical ceiling is achievable with Java/C# in-process SDKs running inside the vendor's runtime — these are spec-only and require vendor SDK licenses.

```bash
pip install primust-connectors
```

---

*Primust Developer Documentation · docs.primust.com*
*Canonical sources: DECISIONS_v13, MASTER_v9, TECH_SPEC_v8*
