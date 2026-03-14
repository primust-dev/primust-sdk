# DECISIONS
## Primust, Inc. · Canonical Locked Decisions
### v11.0 · March 13, 2026 · Supersedes DECISIONS v10.0 and all prior versions

> ⚠ CRITICAL: THIS DOCUMENT WINS ALL CONFLICTS. Every engineering, product, patent, and GTM decision flows from what is written here. When this document conflicts with any other, this document is correct.
>
> DECISIONS_v11 incorporates: DECISIONS_v10.docx + DECISIONS_v10_AMENDMENT_2026-03-13.md + all decisions from March 13 strategy session.

---

## 1. WHAT PRIMUST IS

A standalone cryptographic primitive and SDK that proves any defined process executed correctly on specific data. Portable. Verifiable offline by anyone. No trust in the issuer required.

> **"Run whatever checks you run. We make the proof that they ran."**

**Four-word product explanation: Input → Checks → Output → Verify**

**Core Naming (No Exceptions)**

| Term | Name | Definition |
|---|---|---|
| Company / Product | Primust | Coined word. Trademarkable. primust.com. pip install primust. |
| Cryptographic Primitive | GEP | Governed Execution Proof. VC proves a computation correct; GEP proves a defined governed process ran correctly. |
| Credential Artifact | VPEC | Verifiable Process Execution Credential. Portable, signed, offline-verifiable JSON artifact. |

> ⚠ Do NOT use: PEC, PGC, byollm, proof_profile, TrustScope branding in any Primust code, doc, or customer-facing material.

**TrustScope Status**

> ⚠ CRITICAL: TrustScope is TABLED. Primust ships first, alone. Do not build TrustScope infrastructure. Do not reference TrustScope in customer-facing materials.

---

## 2. THE THREE-PLANE BOUNDARY (COMPANY-FORMATION DECISION)

This is not a product preference. Every feature must be evaluated against these three planes. Any feature in the execution plane belongs in TrustScope — even if technically easy to build.

| Plane | What It Does | Who Owns It | Examples |
|---|---|---|---|
| Execution Plane | Checks run. Policies enforced. Runtime integrations fire. Enforcement-adjacent behavior. | TrustScope (future) | Detection engines, PII scan runtime, tool allowlist enforcement, capability demotion, blocking |
| Credential Plane | Manifests. Policy snapshots. Poseidon2 commitments. Ed25519 signatures. RFC 3161 timestamps. VPEC issuance. Gap records. | Primust | GEP primitive, p.record(), p.close(), VPEC schema, check manifest registry, policy snapshot binding, gap taxonomy |
| Reliance Plane | Verification. Reviewer UX. Evidence Packs. Selective disclosure. External acceptance. | Primust | verify.primust.com, primust-verify (open source), Evidence Pack assembler, Coverage basis labels |

**Critical implication:** Primust never makes enforcement decisions. Primust records that a decision was made and what it was. Never makes it.

---

## 3. PRIMARY SDK SURFACE (CANONICAL)

> ⚠ CRITICAL: `primust.instrument()` / `primust_ai.autoinstrument()` is the primary SDK surface. `p.record()` is the custom check escape hatch only. Any documentation or quickstart leading with `p.record()` is wrong.

```python
# Full integration — two lines, governed run in under 5 minutes
p = primust.Pipeline(api_key="pk_sb_xxx", policy="ai_agent_customer_support_v1")
primust_ai.autoinstrument(pipeline=p)

# Custom check only — escape hatch
@p.record_check("custom_bias_monitor")
def run_bias_check(text):
    return my_proprietary_model.score(text)
```

`p.record()` is Advanced Usage. Not the primary path. Docs must reflect this.

---

## 4. THREE ENTRY POINTS (NEW — v11)

Three distinct entry points. All converge at the same proof layer. All produce the same VPEC.

### Entry Point 1 — Pure SDK (Design Partner Motion, Technical Users)
```python
pip install primust primust-ai
p = primust.Pipeline(api_key="pk_live_xxx")
primust_ai.autoinstrument(pipeline=p)
```
No dashboard required. Works today. Zero CAC.

### Entry Point 2 — CLI Discovery (Technical Teams with Existing Checks)
```bash
primust discover ./my_agent/
# AST parsing. Fully offline. Zero API calls. Zero content access.
# Finds LLM calls, ML models, validators, human approval patterns.
# Classifies by proof level ceiling.
# Outputs ./primust_manifests/ stub files.
# Add API key → VPECs flow.
```

### Entry Point 3 — Policy Center UI (Security Analyst / Compliance)
- app.primust.com — configure required checks, pick policy bundle
- Security analyst owns governance declaration
- Engineering receives generated instrumentation code, no manifest decisions required
- Manifest registered from UI configuration

**All three entry points:** checks run in customer environment, content never transits Primust, only hashes reach signing endpoint, pay per VPEC.

---

## 5. PROOF LEVELS — FIVE LEVELS (CANONICAL)

> ⚠ FIVE levels. "Verifiable Inference" replaces "Execution+ZKML" everywhere. human_review → Witnessed NOT Attestation.

| Level | Enum | How Proven | Trust Required | Example Checks | Status |
|---|---|---|---|---|---|
| Mathematical | mathematical | Noir, UltraHonk, Modal CPU | None — math | Regex, allowlist, threshold, GARCH, OLS, policy rules (OPA/Cedar/Drools) | Built |
| Verifiable Inference | verifiable_inference | ONNX-to-circuit (EZKL/Bionetta), Modal GPU, proof_pending: true | Trust model weights | XGBoost, Isolation Forest, scikit-learn | Tier 2 — design partner trigger |
| Execution | execution | Model-hash-binding circuit | Trust the model (public, auditable) | Named ML model, pinned LLM API, versioned tool, custom code (hash-bound) | Built |
| Witnessed | witnessed | Two RFC 3161 timestamps + Ed25519 sig | Trust reviewer identity (key in org JWKS) | Human review, pharmacist approval, CISO sign-off | Tier A — build now |
| Attestation | attestation | Invocation-binding circuit | Trust process owner's word | Opaque process, OTEL records | Built |

**Weakest-link rule:** proof_level_floor = minimum across all records. Cannot be faked upward. Applies to proof_level_floor only — not provable_surface.

---

## 6. VPEC SCHEMA — CANONICAL

> ⚠ proof_level as single field REMOVED. Two fields, two jobs.

| Field | Type | Job |
|---|---|---|
| proof_level_floor | enum | Technical minimum. Weakest-link scalar. DERIVED — never set manually. |
| provable_surface | float 0.0–1.0 | Distribution of proof levels across records. Hero metric. |
| provable_surface_breakdown | object | Per-level shares. Sum = provable_surface ±0.0001. |
| provable_surface_pending | float | Share where proof_pending: true at issuance. |
| provable_surface_ungoverned | float | Share of manifest_checks with no CheckExecutionRecord. |
| provable_surface_basis | enum | executed_records OR manifest_checks |
| provable_surface_suppressed | boolean | True if org suppressed distribution disclosure. |

**PS-INV-1 through PS-INV-4 required. VPEC issuance rejected server-side on violation.**

---

## 7. SIGNING KEY ARCHITECTURE (NEW — v11)

### Primary: GCP KMS Ed25519, dual-region
- PRIMUST_KMS_KEY_US — aws-us-east-1
- PRIMUST_KMS_KEY_EU — aws-eu-central-1 Frankfurt
- HSM-backed. Primust-operated.

### Single Trust Anchor Problem — Resolved via BYOK
At Enterprise tier, customers bring their own signing key. Auditor verifies against customer's `/.well-known/primust-pubkey.pem`. Primust role = issuance orchestration, not trust anchor.

| Tier | Signing Key | Trust Anchor |
|---|---|---|
| Developer / Growth | Primust GCP KMS (dual-region) | primust.com/.well-known/primust-pubkey.pem |
| Enterprise | Customer BYOK | customer.com/.well-known/primust-pubkey.pem |

### Failure Modes
- **GCP KMS downtime:** signing stops, pipelines continue (fail-open), queue flushes on recovery, issued VPECs unaffected
- **Key compromise:** revoke <4h, new key <4h, impact audit <24h, re-issue <72h — CCR patent covers hybrid Ed25519 + ML-DSA-65
- **Primust going dark:** BYOK Enterprise VPECs verifiable forever; standard-tier VPECs verifiable while public key cached

### Post-Quantum
Hybrid Ed25519 + ML-DSA-65 covered by CCR patent. Blocked on GCP KMS ML-DSA support. Not v1.0. Formal decision: migrate when HSM-backed ML-DSA available in GCP KMS.

---

## 8. THREE VERIFICATION PATHS (NEW — v11)

Verification must not depend on Primust infrastructure. Three paths in priority order:

### Path 1 — primust-verify library (THE real answer)
```bash
pip install primust-verify  # Apache-2.0, free forever
primust verify vpec.json
primust verify vpec.json --trust-root key.pem  # zero network calls
primust pack verify pack.json
```
Runs locally. No network calls after first public key fetch. Works forever regardless of Primust's existence.

### Path 2 — primust verify CLI
Ships with main SDK. Same library underneath.

### Path 3 — verify.primust.com
Human front door for auditors who won't run Python. Convenience only. Not the trust anchor.

> ⚠ verify.primust.com MUST display: "You don't need this website. pip install primust-verify — works offline, forever."

**Exit codes:** 0 = valid, 1 = invalid, 2 = valid SANDBOX, 3 = valid but key expired/revoked

---

## 9. PACKAGE INVENTORY — CANONICAL (CONFIRMED BUILT, MARCH 13 2026)

### Deployable Apps (3)
| App | Status |
|---|---|
| API (FastAPI/asyncpg) | Built. 16 files, 61 tests. Fly.io dual-region. |
| Dashboard (Next.js 15 / React 19) | Built. 12 components, 6 tests. app.primust.com |
| Verify Site (Next.js 15) | Built. 3 components. verify.primust.com |

### Customer SDKs — READY TO PUBLISH
| Package | Lang | Status |
|---|---|---|
| primust (sdk-python) | Python | 12 files, 26 tests, discovery module |
| primust-verify | Python | 6 files, 3 tests, Apache-2.0 |
| @primust/sdk (sdk-js) | TypeScript | Pipeline API, CheckSession, ReviewSession |
| sdk-java | Java | 13 files |
| sdk-csharp | C# | 7 files, early |

### AI Adapters — READY TO PUBLISH (all 14 tests each)
primust-langgraph, primust-google-adk, primust-openai-agents, primust-otel, @primust/otel

### Rule Engine Adapters — READY TO PUBLISH (Mathematical ceiling)
primust-cedar (Java), primust-drools (Java), primust-odm (Java), primust-opa (Go)

### Cryptographic Primitives (Built)
artifact-core (TS), artifact-core-py, zk-core (TS), zk-core-py (stub), runtime-core (TS), runtime-core-py, policy-engine (TS), policy-engine-py (early), registry (TS), evidence-pack (TS), evidence-pack-py (stub), verifier (TS)

### Infrastructure (Built)
zk-worker (Modal Python), db (4 migrations), rules-core (Java)

### Regulated Connectors
primust-connectors: Guidewire BUILT (38 tests). All others: p.record() wrap or deferred.

### Schemas (Frozen v4.0.0)
11 JSON schemas. Golden test vectors. PROVISIONAL_FREEZE.md. SIGNER_TRUST_POLICY.md.

**Total: 3 apps, 31 packages, 5 languages (TS, Python, Java, Go, C#), ~200+ source files, ~150+ test files.**

---

## 10. WHAT SHIPS THIS WEEK (NO NEW BUILD REQUIRED)

| Deliverable | Action |
|---|---|
| primust | Publish to PyPI |
| primust-verify | Publish to PyPI, Apache-2.0 |
| @primust/sdk | Publish to npm |
| primust-langgraph | Publish to PyPI |
| primust-openai-agents | Publish to PyPI |
| primust-google-adk | Publish to PyPI |
| primust-otel | Publish to PyPI |
| @primust/otel | Publish to npm |
| primust-opa | Publish to pkg.go.dev |
| primust-cedar, primust-drools, primust-odm | Publish to Maven Central |
| verify.primust.com | Make public and live |
| app.primust.com | Sign-up flow live |

---

## 11. WHAT NEEDS TO BE BUILT

| Item | Priority | Notes |
|---|---|---|
| primust discover (P15-A) | 1 | Standalone CLI, no dependencies |
| autoinstrument() runtime discovery (P15-B) | 1 | Depends on P15-A |
| Policy center UI — manifest management | 2 | Dashboard shell exists |
| Preconfigured policy bundles as runnable checks | 2 | Depends on policy center |
| primust.checks harness | 2 | Apache-2.0, BYOC |
| primust-hook binary | 3 | AMDT-16 spec, open questions remain |
| BYOK signing key support | 3 | Enterprise tier |
| Witnessed stage type full implementation | 3 | RFC 3161 dual timestamp, PCT claim |
| CrewAI adapter (P11-E) | 2 | — |
| Pydantic AI adapter (P11-G) | 2 | No OTEL coverage |

---

## 12. OPEN SOURCE HARNESS — primust.checks (NEW — v11)

Apache-2.0. Runs entirely in customer environment. No content transits Primust.

**Includes:**
- Preconfigured policy bundles: EU AI Act, HIPAA, SOC 2, General AI, Coding Agent
- Light built-in checks: secrets scanner, PII regex, cost bounds, command patterns (CPU only)
- Mathematical checks: deterministic ZK-provable ones already built
- BYOC wrapper interface: `@primust.check` decorator

**Motion:** Free harness = distribution. Proof layer activates with one line = revenue. Zero re-instrumentation on conversion.

**BYOC principle:** Customer wraps their Lakera, OPA, Guardrails, or homegrown check. Primust proves it ran. No replacement required.

---

## 13. POLICY/MANIFEST CENTER — app.primust.com (NEW — v11)

Three sections in one dashboard:

**Policy:** browse bundles, configure required checks, thresholds, proof level targets, register custom manifests, generate instrumentation code for engineering

**Runs:** VPEC history, provable surface breakdown, gap inbox, waiver workflow

**Verify:** Evidence Pack assembly, share link generation, audit-ready export

Security analyst works in Policy. Engineering uses generated code. No terminal required for policy declaration.

---

## 14. MANIFEST LIVES ON CUSTOMER SIDE (ARCHITECTURAL INVARIANT — v11)

Customer repo holds manifest. Customer environment runs checks. Customer infrastructure holds results. Primust receives commitment hash only at VPEC issuance.

**Required disclosure (Quickstart + Audit Guide + Evidence Pack observation_summary):**
> "Primust proves what the manifest says ran. Primust does not guarantee what should have been in the manifest."

---

## 15. ONBOARDING FLOW — CANONICAL (v11)

```
Sign up at primust.com
  → Sandbox API key (pk_sb_xxx), free, no credit card
  → Choose entry point:
      A) pip install primust primust-ai → 3 lines → VPEC < 5min
      B) primust discover ./path/ → review → add API key → VPECs flow
      C) Policy center → configure → generated code → hand to engineering
  → First VPEC in dashboard (test: true, environment: "sandbox")
  → Review provable surface breakdown
  → Promote to production key (no re-instrumentation)
  → Assemble Evidence Pack
  → verify.primust.com/{pack_id} — auditor front door
```

**Time targets:** First VPEC <5min | First governed production run <1 day | Mode 2 policy <7 days | First Evidence Pack <30 days

---

## 16. DOMAIN PACK PACKAGING (CANONICAL, FROM AMDT-1)

| Package | Ships When |
|---|---|
| primust | v1.0 |
| primust-ai | v1.0 |
| primust-rules-core (JAR) | v1.0 |
| primust-finance | First FSI design partner |
| primust-insurance | First Insurance/Clinical design partner |
| primust-cicd | First CI/CD design partner |

Do NOT build domain packs before design partner trigger.

---

## 17. ACTIVITY CHAIN (AI DOMAIN PACK, CANONICAL)

- AgentActivityRecord: APPEND-ONLY. No update(). No delete().
- Runs entirely in customer infrastructure.
- chain_root (single hash) ONLY value transiting Primust.
- Zero AgentActivityRecords transit Primust. Hard stop.
- Three backends: SQLite (dev), PostgreSQL (production), S3 + Object Lock COMPLIANCE 7yr (regulated)

---

## 18. CODING AGENT HOOK ATTACHMENT (FROM AMDT-16)

**Primust role:** evidence layer only. Records, commits, signs, issues. Never blocks. Never allows.

**primust-hook binary:** single binary, Claude Code + Cursor, IT MDM deployment. Developer installs nothing.

**Open questions before build:** binary distribution URL, policy delivery (pull vs bundled), Windsurf surface confirmation.

---

## 19. ADAPTER STATUS (CANONICAL)

| Adapter | Status |
|---|---|
| LangGraph | BUILT — primust-langgraph, 14 tests |
| Google ADK | BUILT — primust-google-adk, 14 tests |
| OTEL (three surfaces) | BUILT — primust-otel, 14 tests |
| OpenAI Agents SDK | BUILT — primust-openai-agents, 14 tests |
| Cedar/Drools/ODM/OPA | BUILT — rule engine adapters |
| Guidewire | BUILT — 38 tests, first enterprise connector |
| CrewAI | P11-E — build next |
| Pydantic AI | P11-G — build, no OTEL coverage |
| Semantic Kernel | P11-F — .NET-first |
| Vertex AI / Bedrock | demand-driven — design partner trigger |

MCP Proxy: PERMANENTLY DROPPED. OTEL covers MCP ecosystem.
AutoGen/MS Agent: DROPPED. OTEL covers via P11-C.
LangChain chains: DROPPED. LangGraph covers via P11-A.

---

## 20. PROOF LEVEL SALES NARRATIVE (CANONICAL)

Lead with provable_surface_breakdown, not proof_level_floor.

**Wrong:** "Your proof level floor is attestation."
**Right:** "62% of your governance is mathematically proven."

Floor is honest technical disclosure. Not the opening pitch.

---

## 21. PRICING (CANONICAL)

- Per-VPEC issued. Surface-agnostic.
- Sandbox = trial motion. No free tier.
- Sandbox VPEC: environment: "sandbox", primust-verify returns SANDBOX flag, not audit-acceptable.
- Conversion: same key upgrades, no re-instrumentation.
- Enterprise: flat annual $75–250K/yr, never metered.
- **Locked principle:** Never create incentive to sample, suppress, or narrow scope.

---

## 22. GAP TAXONOMY — 21 TYPES (CANONICAL)

check_not_executed (High), enforcement_override (Critical), engine_error (High), check_degraded (Medium), external_boundary_traversal (High), lineage_token_missing (High), admission_gate_override (Critical), check_timing_suspect (Medium), reviewer_credential_invalid (Critical), witnessed_display_missing (High), witnessed_rationale_missing (High), witnessed_timestamp_invalid (High), deterministic_consistency_violation (Critical), skip_rationale_missing (High), policy_config_drift (Medium), proof_level_floor_breach (Critical), zkml_proof_pending_timeout (Medium), zkml_proof_failed (High), system_error (High), sla_breach (Medium), explanation_missing (Medium), bias_audit_missing (Medium)

---

## 23. INFRASTRUCTURE STACK (CANONICAL — PRIMUST_PROVIDERS_v1.0 WINS)

| Component | Provider |
|---|---|
| API hosting | Fly.io (always-on, replaces Render permanently) |
| Database | Neon Postgres — DATABASE_URL_US (aws-us-east-1) + DATABASE_URL_EU (aws-eu-central-1) |
| Signing | GCP KMS Ed25519 — PRIMUST_KMS_KEY_US + PRIMUST_KMS_KEY_EU |
| ZK proving | Modal (CPU Noir/nargo + GPU EZKL Tier 2) |
| Artifact storage | Cloudflare R2 — R2_BUCKET_US + R2_BUCKET_EU |
| Front-end | Vercel — app.primust.com, verify.primust.com, primust.com |
| Docs | Mintlify — docs.primust.com |

**Bootstrap API key deprecation hardcoded: 2026-06-01.**

---

## 24. PATENT PORTFOLIO — 15 PROVISIONALS

**TrustScope-branded (9):** MAX, AGB, SMI, ZKP, AIG, AGD, CAG, CLAG, PEC
**Primust-branded (6):** OVG, TDZ, GLP, CCR, PVP, CMB

PCT filing deadline: July 2026.
Witnessed proof level requires continuation claim on PEC patent before PCT filing.

---

## 25. FORBIDDEN TERMS

| Banned | Use Instead |
|---|---|
| PEC | VPEC |
| PGC | VPEC |
| byollm | llm_api |
| proof_profile | provable_surface_breakdown |
| coverage_pct | provable_surface |
| Execution+ZKML | verifiable_inference |
| TrustScope (in Primust materials) | — |

---

*DECISIONS_v11.0 · March 13, 2026 · Primust, Inc.*
*Supersedes DECISIONS_v10.docx + all prior versions and amendments.*
*This document wins all conflicts.*
