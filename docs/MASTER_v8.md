# PRIMUST MASTER
## Consolidated Working Document · All Amendments Applied
### v8.0 · March 15, 2026 · Supersedes MASTER v7.0 and all prior versions

> **CRITICAL: THIS DOCUMENT WINS ALL CONFLICTS alongside DECISIONS_v12.**
> GEP · VPEC · Company: Primust · TrustScope: TABLED
> New in v8: Cross-org verification. Audit Report artifact. Domain-neutral markets. Relying party pattern. AIUC-1 schema additions. Unstructured check handling. Gap taxonomy 30 types. Full package inventory updated to shipped state March 15, 2026.

---

## 1. WHAT PRIMUST IS

A standalone cryptographic primitive and SDK that proves any defined process executed correctly on specific data. Portable. Verifiable offline by anyone. No trust in the issuer required.

> **"Run whatever checks you run. We make the proof that they ran."**

**Four-word product explanation: Input → Checks → Output → Verify**

AI governance is the first market. Not the defining frame. The product is a universal primitive — any governed process, any industry, any check: AI pipelines, software build systems, financial data pipelines, clinical data, manufacturing QC, legal research.

**Named capabilities:**
- VPEC issuance
- Evidence Pack assembly
- Cross-org verification
- Audit Report (signed PDF, offline-verifiable)

**TrustScope is TABLED.** Primust ships first, alone.

---

## 2. THE THREE-PLANE BOUNDARY

Company-formation decision. Every feature evaluated against these planes.

| Plane | What It Does | Who Owns It |
|---|---|---|
| Execution Plane | Checks run. Enforcement. Content lives here. Never crosses to Primust. | TrustScope (future) |
| Credential Plane | Manifests. Commitments. Signatures. Timestamps. VPEC issuance. Gap records. | Primust |
| Reliance Plane | Verification. Evidence Packs. Selective disclosure. External acceptance. Audit Reports. | Primust |

**Critical:** Primust never makes enforcement decisions. Records that a decision was made. Never makes it.

---

## 3. THREE ENTRY POINTS

All converge at the same proof layer. All produce the same VPEC.

### Entry Point 1 — Pure SDK (Design Partner Motion)
```python
pip install primust primust-ai
p = primust.Pipeline(api_key="pk_live_xxx")
primust_ai.autoinstrument(pipeline=p)
```
Three lines. Works today. The design partner motion.

### Entry Point 2 — CLI Discovery
```bash
primust discover ./my_agent/
# AST parsing, fully local, zero content access
# Scaffolds ./primust_manifests/
# Add API key → VPECs flow
```
**Status:** P15-A — not yet built.

### Entry Point 3 — Policy Center UI
`app.primust.com/policy` — security analyst configures governance, engineering gets generated instrumentation code.

**All three paths:** content never transits Primust, only hashes reach signing endpoint, pay per VPEC.

---

## 4. PROOF LEVELS — FIVE LEVELS (CANONICAL)

| Level | Enum | How Proven | Trust Required | Examples |
|---|---|---|---|---|
| Mathematical | mathematical | Noir, UltraHonk, Modal CPU | None — math | Regex, allowlist, threshold, OPA/Cedar/Drools, Ed25519 verify |
| Verifiable Inference | verifiable_inference | ONNX-to-circuit, Modal GPU | Trust model weights | XGBoost, Isolation Forest, scikit-learn |
| Execution | execution | Model-hash-binding circuit | Trust the model (public, auditable) | Named ML model, pinned LLM API, custom code (hash-bound) |
| Witnessed | witnessed | Two RFC 3161 + Ed25519 sig | Trust reviewer identity | Human review, pharmacist approval, CISO sign-off |
| Attestation | attestation | Invocation-binding circuit | Trust process owner's word | Opaque process, OTEL records |

**Weakest-link rule:** proof_level_floor = minimum across all records. DERIVED. Never set manually.

**Sales narrative:** Lead with provable_surface_breakdown, not floor.
- Wrong: "Your proof level floor is attestation."
- Right: "62% of your governance is mathematically proven."

---

## 5. OPEN SOURCE HARNESS — primust.checks (SHIPPED)

Apache-2.0. Customer environment only. Zero content transits Primust. **Live on PyPI 1.0.0.**

**Motion:** Free harness = distribution. API key = proof layer activates = revenue. Same code, one line change.

**8 built-in checks (shipped):**
- AI-focused: secrets_scanner, pii_regex, cost_bounds, command_patterns (Mathematical, CPU)
- Domain-neutral: upstream_vpec_verify, schema_validation, reconciliation_check, dependency_hash_check (Mathematical)

**ZK checks:** enforcement_rate, pii_non_detection, cost_bound_zk (Mathematical, Noir)

**BYOC:**
```python
@harness.check
def my_existing_check(input, output) -> CheckResult:
    return CheckResult(passed=your_logic(input), evidence="...")
```

**7 preconfigured bundles:** ai_agent_general_v1, eu_ai_act_art12_v1, hipaa_safeguards_v1, soc2_cc_v1, coding_agent_v1, supply_chain_governance_v1, financial_data_governance_v1

Without API key: governance observability, "Proof: Not issued" column = silent conversion prompt.
With API key: VPECs issued, no other change.

---

## 6. SIGNING KEY ARCHITECTURE (CANONICAL)

**Standard tier:** Primust GCP KMS Ed25519, HSM-backed, dual-region. Trust anchor: `primust.com/.well-known/primust-pubkey.pem`

**Enterprise tier (BYOK):** Customer's own signing key. Primust = issuance orchestration only. Customer private key never leaves their environment. Trust anchor: `customer.com/.well-known/primust-pubkey.pem`

**Failure modes:**
- GCP KMS downtime: signing stops, pipelines continue (fail-open), queue flushes on recovery
- Key compromise: revoke <4h, new key <4h, re-issue <72h — CCR patent covers hybrid Ed25519 + ML-DSA-65
- Primust going dark: BYOK VPECs verifiable forever; standard-tier VPECs verifiable while public key cached

**Post-quantum:** Hybrid Ed25519 + ML-DSA-65 when GCP KMS supports it. Not v1.0.

---

## 7. FOUR VERIFICATION PATHS (UPDATED — v8)

Verification must not depend on Primust infrastructure.

**Path 0 — primust-verify embedded (HIGHEST FREQUENCY — relying party)**
The B2B integration pattern. A downstream system embeds primust-verify as a function call before processing upstream output. This is also what upstream_vpec_verify does internally.
```python
from primust_verify import verify
result = verify(vpec_json)
if not result.valid: raise GovernanceVerificationError(result.failure_reason)
```
Zero Primust infrastructure involvement in the verification path. Java/C# gap: demand-gate primust-verify-java.

**Path 1 — primust-verify (Apache-2.0, THE real answer)**
```bash
pip install primust-verify
primust verify vpec.json
primust verify vpec.json --trust-root key.pem  # zero network
```
Works forever. Primust offline = irrelevant.

**Path 2 — primust verify CLI**
Ships with main SDK. Same library.

**Path 3 — verify.primust.com**
Human front door. Convenience only. Page MUST display: "You don't need this website."

---

## 8. AUDIT ALIGNMENT — HOW IT WORKS (CANONICAL)

**Primust is an evidence producer. Not a control mapping engine. Customers declare their own controls and attach Evidence Packs.**

### Four mechanisms:

**Mechanism 1 — Bundle framework tags**
Each policy bundle declares framework mappings embedded in the VPEC:
- `eu_ai_act_art12_v1` → ["eu_ai_act_art12", "eu_ai_act_art9"]
- `hipaa_safeguards_v1` → ["hipaa_164312"]
- `soc2_cc_v1` → ["soc2_cc71", "soc2_cc81"]

**Mechanism 2 — Evidence Pack framework view**
Evidence Packs include `framework_view` section: per framework, which VPEC claims satisfy which controls.

**Mechanism 3 — verify.primust.com/pack/{pack_id}**
Auditor-facing view shows framework alignment. No login. Math checks out or it doesn't.

**Mechanism 4 — Audit Report**
Evidence Pack → signed PDF → `primust verify-report` confirms tamper-evidence. Human-readable rendering for auditors who will not run Python. Coverage basis gating: P1 watermarked, P2/P3 fully exportable.

**What Primust does NOT do:**
- Assert that a framework is satisfied (claims are mathematical; compliance is the customer's conclusion)
- Replace a compliance officer's judgment

---

## 9. PACKAGE INVENTORY — CONFIRMED SHIPPED (MARCH 15, 2026)

| Registry | Packages | Status |
|---|---|---|
| PyPI | primust, primust-verify, primust-checks, primust-langgraph, primust-openai-agents, primust-google-adk, primust-otel | Live 1.0.0 |
| npm | @primust/sdk, @primust/otel, @primust/artifact-core | Live 1.0.0 |
| Maven Central | primust-cedar, primust-drools, primust-odm, sdk-java | Published 1.0.0 |
| Go | primust-opa, rules-core-go | Tagged. GREEN. |
| app.primust.com | Dashboard + Policy Center + onboarding | Live |
| GitHub | primust-dev/primust | Public |

**Still to build / blocked:**
- verify.primust.com: GCP KMS + service account deploy to Fly.io
- Migrations 005–008 applied. 009 written.
- primust discover (P15-A), autoinstrument() runtime discovery (P15-B)
- Archetype inference engine (depends on P15-A)
- primust-verify-java (first Java relying-party design partner)
- Domain packs (first FSI/Insurance/CI-CD design partner)

---

## 10. BUILD ORDER (CURRENT STATE)

**Immediate (no new code, infrastructure actions):**
- Deploy GCP KMS to Fly.io → verify.primust.com live
- Apply migration 009 to Neon US + EU

**Shipped (since v8.0 draft):**
- Migrations 005–008 applied to Neon US + EU
- JSX extension fixed in dashboard + verify-site
- primust-opa go.mod fixed
- Migration 009 written (AIUC-1 schema additions)
- P29-A: primust-hook built (AMDT-16 resolved, Go binary, 31 tests)

**Next build:**
- P15-A: primust discover CLI (gates archetype inference, check candidates)
- P15-B: autoinstrument() runtime discovery
- primust verify-report CLI (part of audit report surface)

**Demand-driven:**
- CrewAI (P11-E), Pydantic AI (P11-G), Semantic Kernel (P11-F)
- Domain packs (first design partner per domain)
- primust-verify-java (first Java relying-party design partner)

---

## 11. GTM — FIRST THREE CUSTOMERS

| Customer | Validates | Success |
|---|---|---|
| 1 — Time to value | Production pipeline, LangGraph, Mode 2 policy | Integration under 1 week. "I could hand this to compliance without a briefing." |
| 2 — Remediation loop | Gap Inbox, waiver (with risk_treatment), re-run, Resolution VPEC | At least one waiver and one resolved gap with signed Resolution VPEC. |
| 3 — External acceptance | Evidence Pack + Audit Report in real security review | Reduced follow-up questions. Shortened review time. |

**Second GTM track (hook attachment):** CISO/IT buyer, MDM deployment, developers never see it. primust-hook required.

**Insurance underwriter story:** `blocked_count > 0` proves control effectiveness. 99.7% governance rate over 90 days = measurably different risk profile. Primust = measurement instrument for AI liability underwriting.

**Non-AI GTM wedges:**
- OPA/CI-CD: primust-opa + supply_chain_governance_v1 for software supply chain buyers
- FSI: primust-finance pack + reconciliation_check + upstream_vpec_verify for financial data pipeline buyers

---

## 12. PRICING

- Per-VPEC issued. Surface-agnostic.
- Sandbox = trial motion. No free tier.
- Enterprise: flat annual $75–250K/yr. Never metered.
- primust.checks harness: Apache-2.0, free forever. Distribution engine.
- **Principle:** Never create incentive to sample, suppress, or narrow scope.

---

## 13. TECH STACK

| Service | Purpose |
|---|---|
| Fly.io | Always-on FastAPI, dual-region |
| Modal | Noir ZK proving (CPU) + EZKL Verifiable Inference (GPU) |
| Neon Postgres | DATABASE_URL_US + DATABASE_URL_EU |
| GCP KMS Ed25519 | HSM signing — PRIMUST_KMS_KEY_US + PRIMUST_KMS_KEY_EU |
| DigiCert TSA | RFC 3161 timestamping (~$0.002–0.005/check, dominant COGS) |
| Sigstore Rekor | Key transparency + rotation log |
| Cloudflare R2 | ZK artifact storage — R2_BUCKET_US + R2_BUCKET_EU |
| Vercel | app.primust.com, verify.primust.com, primust.com |
| Mintlify | docs.primust.com |
| Clerk | Auth + SAML SSO |

**Bootstrap API key deprecation: 2026-06-01.**

---

## 14. PATENTS — 15 PROVISIONALS

TrustScope-branded (9): MAX, AGB, SMI, ZKP, AIG, AGD, CAG, CLAG, PEC
Primust-branded (6): OVG, TDZ, GLP, CCR, PVP, CMB
PCT deadline: July 2026. Witnessed continuation claim on PEC required before PCT.
Cross-org verification chain composition: not in any existing provisional — review before PCT.

---

## 15. CROSS-ORG VERIFICATION (CANONICAL)

upstream_vpec_verify is a built-in check in primust-checks (shipped) that treats a received VPEC as the subject of governance. Proof ceiling: Mathematical (Ed25519 is deterministic). Domain-neutral — works for AI outputs, financial data deliveries, software artifacts, clinical data, any VPEC-bearing upstream.

Result: the downstream org's VPEC contains a Mathematical claim that they verified their upstream's governance before processing their output. Chains compose across any number of org boundaries. No Primust infrastructure in the verification path.

Use cases (highest value first): platform/marketplace governance mandate, FSI regulated AI acceptance, EU AI Act Article 25 deployer obligations, software supply chain acceptance, enterprise vendor due diligence, healthcare clinical AI, legal tech malpractice evidence, government/defense NDAA supply chain.

See DECISIONS_v12 §26 for full spec including trust root modes, gap taxonomy, composition diagram.

---

## 16. DOMAIN-NEUTRAL MARKETS (CANONICAL)

The GEP primitive is not AI-specific.

| Market | Trigger Check | Regulatory Driver |
|---|---|---|
| Software supply chain | dependency_hash_check, upstream_vpec_verify | SLSA, NIST SSDF, 2026 NDAA AI supply chain |
| Financial data pipelines | reconciliation_check, schema_validation, upstream_vpec_verify | OCC/FCA model risk, SEC audit trails |
| Clinical trial data | upstream_vpec_verify + data integrity checks | FDA 21 CFR Part 11 |
| Manufacturing QC | threshold_check, upstream_vpec_verify | ISO 9001, GMP, AS9100 |
| Legal research | upstream_vpec_verify + source_citation_verified | Malpractice, bar association AI guidelines |
| Government / defense | upstream_vpec_verify + provenance checks | 2026 NDAA AI supply chain |

Entry point for non-AI buyers: primust-checks Apache-2.0 + supply_chain_governance_v1 bundle. OPA wedge for CI/CD buyers.

---

## 17. GAP TAXONOMY — 30 TYPES (CANONICAL)

Core (22) + archetype_unmapped (1) + cross-org (7) = 30 total.

See DECISIONS_v12 §22 for full list with severities. check_candidate findings are NOT gap types — they are scan advisories.

---

*PRIMUST MASTER v8.0 · March 15, 2026 · Supersedes MASTER v7.0 and all prior versions.*
