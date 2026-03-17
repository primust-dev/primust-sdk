# DECISIONS
## Primust, Inc. · Canonical Locked Decisions
### v13.0 · March 16, 2026 · Supersedes DECISIONS v12 and all prior versions

> ⚠ CRITICAL: THIS DOCUMENT WINS ALL CONFLICTS. Every engineering, product, patent, and GTM decision flows from what is written here. When this document conflicts with any other, this document is correct.
>
> DECISIONS_v13 incorporates: DECISIONS_v12 + CANONICAL_AMENDMENT_v13_v9_v8 (March 16, 2026): VPEC field renames, gap taxonomy 30→47, connector build status, visibility field, pk_sb_ canonical, system_unavailable gap type.

---

## 1. WHAT PRIMUST IS

A standalone cryptographic primitive and SDK that proves any defined process executed correctly on specific data. Portable. Verifiable offline by anyone. No trust in the issuer required.

> **"Run whatever checks you run. We make the proof that they ran."**

**Four-word product explanation: Input → Checks → Output → Verify**

AI governance is the first market. Not the defining frame. The product is a universal primitive — any governed process, any industry, any check: AI pipelines, software build systems, financial data pipelines, clinical data delivery, manufacturing QC, legal research workflows.

**Named capabilities:**
- VPEC issuance — cryptographic proof that declared checks ran on committed data
- Evidence Pack assembly — aggregate VPEC collections for audit periods
- Cross-org verification — downstream verification of upstream VPECs as a first-class check
- Audit Report — signed PDF artifact derived from an Evidence Pack, verifiable offline

**Core Naming (No Exceptions)**

| Term | Name | Definition |
|---|---|---|
| Company / Product | Primust | Coined word. Trademarkable. primust.com. pip install primust. |
| Cryptographic Primitive | GEP | Governed Execution Proof. VC proves a computation correct; GEP proves a defined governed process ran correctly. |
| Credential Artifact | VPEC | Verifiable Process Execution Credential. Portable, signed, offline-verifiable JSON artifact. |

> ⚠ Do NOT use: PEC, PGC, byollm, proof_profile, coverage_pct, Execution+ZKML, TrustScope branding, pk_test_xxx, proof_level (VPEC-level), proof_distribution, proof_level_breakdown, coverage_verified_pct, governance_gaps in any Primust code, doc, or customer-facing material.

**TrustScope is TABLED.** Primust ships first, alone. Do not build TrustScope infrastructure.

---

## 2. THE THREE-PLANE BOUNDARY (COMPANY-FORMATION DECISION)

This is not a product preference. Every feature must be evaluated against these three planes.

| Plane | What It Does | Who Owns It | Examples |
|---|---|---|---|
| Execution Plane | Checks run. Policies enforced. Runtime integrations fire. Enforcement-adjacent behavior. | TrustScope (future) | Detection engines, PII scan runtime, tool allowlist enforcement, capability demotion, blocking |
| Credential Plane | Manifests. Policy snapshots. Poseidon2 commitments. Ed25519 signatures. RFC 3161 timestamps. VPEC issuance. Gap records. | Primust | GEP primitive, p.record(), p.close(), VPEC schema, check manifest registry, policy snapshot binding, gap taxonomy |
| Reliance Plane | Verification. Reviewer UX. Evidence Packs. Selective disclosure. External acceptance. | Primust | verify.primust.com, primust-verify (open source), Evidence Pack assembler, Coverage basis labels, Audit Reports |

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

## 4. THREE ENTRY POINTS (CANONICAL)

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
**Status:** P15-A — not yet built. Demand-gated on first design partner who needs it.

### Entry Point 3 — Policy Center UI (Security Analyst / Compliance)
- app.primust.com — configure required checks, pick policy bundle
- Security analyst owns governance declaration
- Engineering receives generated instrumentation code, no manifest decisions required

**All three entry points:** checks run in customer environment, content never transits Primust, only hashes reach signing endpoint, pay per VPEC.

---

## 5. PROOF LEVELS — FIVE LEVELS (CANONICAL)

> ⚠ FIVE levels. "Verifiable Inference" replaces "Execution+ZKML" everywhere. human_review → Witnessed NOT Attestation.

| Level | Enum | How Proven | Trust Required | Example Checks | Status |
|---|---|---|---|---|---|
| Mathematical | mathematical | Noir, UltraHonk, Modal CPU | None — math | Regex, allowlist, threshold, GARCH, OLS, policy rules (OPA local / Cedar eval() / Drools eval() with Map facts / ODM eval() via IlrSessionFactory), Ed25519 verify | Built |
| Verifiable Inference | verifiable_inference | ONNX-to-circuit (EZKL/Bionetta), Modal GPU, proof_pending: true | Trust model weights | XGBoost, Isolation Forest, scikit-learn | Tier 2 — design partner trigger |
| Execution | execution | Model-hash-binding circuit | Trust the model (public, auditable) | Named ML model, pinned LLM API, versioned tool, custom code (hash-bound) | Built |
| Witnessed | witnessed | Two RFC 3161 timestamps + Ed25519 sig | Trust reviewer identity (key in org JWKS) | Human review, pharmacist approval, CISO sign-off | Built |
| Attestation | attestation | Invocation-binding circuit | Trust process owner's word | Opaque process, OTEL records | Built |

**Weakest-link rule:** proof_level_floor = minimum across all records. Cannot be faked upward. DERIVED — never set manually.

**upstream_vpec_verify proof ceiling: Mathematical.** Ed25519 signature verification is deterministic. Same inputs always yield same result. No LLM judgment, no heuristic.

---

## 6. VPEC SCHEMA — CANONICAL

> ⚠ proof_level as single field REMOVED. Two fields, two jobs.

| Field | Type | Job |
|---|---|---|
| `proof_level_floor` | enum | Technical minimum. Weakest-link scalar. DERIVED — never set manually. |
| `provable_surface` | float 0.0–1.0 | Share of governance that is cryptographically provable. Hero metric. Not a percentage. |
| `provable_surface_breakdown` | object | Per-level shares (all floats). Sub-fields: mathematical, verifiable_inference, execution, witnessed, attestation. Must sum to provable_surface ±0.0001 (PS-INV-1). |
| `provable_surface_pending` | float | Share where proof_pending: true at issuance (Verifiable Inference in-flight). |
| `provable_surface_ungoverned` | float | Share of manifest checks with no CheckExecutionRecord this run. |
| `provable_surface_basis` | enum | `executed_records` \| `manifest_checks` |
| `provable_surface_suppressed` | boolean | True if org suppressed distribution disclosure. |
| `gaps` | array | Gap records. Canonical name — `governance_gaps` is banned. |
| `environment` | enum | `sandbox` \| `production` — present on every VPEC. |

> ⚠ CRITICAL: `proof_level` (single field) is BANNED. Use `proof_level_floor`. `governance_gaps` is BANNED. Use `gaps`. `coverage_verified_pct` is BANNED. Use `provable_surface`. `proof_distribution` / `proof_level_breakdown` are BANNED. Use `provable_surface_breakdown`. `test_mode` is BANNED. Use `environment: "sandbox"`.

**PS-INV-1 through PS-INV-4 required. VPEC issuance rejected server-side on violation.**

---

## 7. SIGNING KEY ARCHITECTURE (CANONICAL)

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

## 8. FOUR VERIFICATION PATHS (UPDATED — v12)

Verification must not depend on Primust infrastructure. Four paths in priority order:

### Path 0 — primust-verify embedded (HIGHEST FREQUENCY — relying party)

The B2B integration pattern. A downstream system embeds primust-verify as a function call before processing upstream output. This is also what upstream_vpec_verify does internally.

```python
from primust_verify import verify

result = verify(vpec_json)
result = verify(vpec_json, trust_root_pem=KEY_PEM)  # zero network, pinned key
if not result.valid:
    raise GovernanceVerificationError(result.failure_reason)
```

```typescript
import { verify } from '@primust/sdk/verify'
const result = await verify(vpecJson)
if (!result.valid) throw new GovernanceVerificationError(result.failureReason)
```

**Java / C# gap:** No native verifier library. Workaround: shell out to `primust verify` CLI. Build primust-verify-java when first Java relying-party design partner requests embedded verification.

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

## 9. PACKAGE INVENTORY — CANONICAL (SHIPPED MARCH 15, 2026)

### Deployable Apps (3)
| App | Status |
|---|---|
| API (FastAPI/asyncpg) | Built. 16 files, 61 tests. Fly.io dual-region. |
| Dashboard (Next.js 15 / React 19) | Built. GREEN. 12 components, 6 tests. app.primust.com. |
| Verify Site (Next.js 15) | Built. GREEN. 3 components. verify.primust.com. |

### Customer SDKs — PUBLISHED
| Package | Lang | Registry | Status |
|---|---|---|---|
| primust (sdk-python) | Python | PyPI | Live 1.0.0 |
| primust-verify | Python | PyPI (Apache-2.0) | Live 1.0.0 |
| primust-checks | Python | PyPI (Apache-2.0) | Live 1.0.0 — 8 built-in checks, 7 bundles, 86 tests |
| @primust/sdk | TypeScript | npm | Live 1.0.0 |
| sdk-java | Java | Maven Central | Published 1.0.0 |
| sdk-csharp | C# | NuGet | Early — not yet published |

### AI Adapters — PUBLISHED (all 14 tests each)
primust-langgraph, primust-openai-agents, primust-google-adk, primust-otel (PyPI), @primust/otel (npm)

### Rule Engine Adapters — PUBLISHED (Mathematical ceiling)
primust-cedar (Mathematical via eval()), primust-drools (Mathematical via eval() + Map facts), primust-odm (Mathematical via eval() + IlrSessionFactory — 13 tests green including real ODM runtime), all Maven Central. primust-opa (pkg.go.dev — GREEN: go.mod fixed, recordCheck() gap-aware)

### Cross-Org Verification Checks (Built March 15, 2026)
Part of primust-checks package. 4 domain-neutral checks:

| Check | Proof Ceiling | Domain |
|---|---|---|
| upstream_vpec_verify | Mathematical | Any — verifies upstream VPEC before processing |
| schema_validation | Mathematical | Data pipelines, APIs, financial data |
| reconciliation_check | Mathematical | Financial data, reporting pipelines |
| dependency_hash_check | Mathematical | Software build, artifact acceptance |

2 new policy bundles: supply_chain_governance_v1, financial_data_governance_v1

### Audit Report (Built March 15, 2026)
- POST /api/v1/evidence-packs/{pack_id}/report — signed PDF generation
- primust verify-report — CLI verification of signed report PDF
- Migration 008 — audit_reports table

### Cryptographic Primitives (Built)
artifact-core (TS), artifact-core-py, zk-core (TS), zk-core-py (stub), runtime-core (TS), runtime-core-py, policy-engine (TS), policy-engine-py (early), registry (TS), evidence-pack (TS), evidence-pack-py (stub), verifier (TS)

### Infrastructure (Built)
zk-worker (Modal Python), db (11 migrations applied), rules-core (Java), rules-core-go

### Schemas (v4.0.0 — schema additions in §28 pending migration 009)

---

## 10. SHIPPED — AS OF MARCH 15, 2026

| Registry | Packages | Status |
|---|---|---|
| PyPI | primust, primust-verify, primust-checks, all 4 AI adapters | Live |
| npm | @primust/sdk, @primust/otel, @primust/artifact-core | Live |
| Maven Central | primust-cedar 1.0.1, primust-drools 1.0.1, primust-odm 1.1.0, sdk-java 1.0.0 | Live |
| Go | primust-opa v1.0.1, rules-core-go | GREEN — tag pushed, pkg.go.dev syncing |
| app.primust.com | Dashboard + Policy Center + onboarding | Live |
| GitHub | primust-dev/primust | Public |

**Infrastructure — LIVE as of March 16, 2026:**
- API: primust-api.fly.dev — status: ok, db: ok, kms: {us: ok, eu: ok}
- Migrations 001–011: Applied to Neon US + EU
- GCP KMS Ed25519: Deployed and verified. KMS health check double-suffix bug fixed.
- app.primust.com + verify.primust.com: Live

**Still pending:**
- Migration 009: AIUC-1 schema additions (not yet written — see §28)

---

## 11. WHAT NEEDS TO BE BUILT

| Item | Priority | Notes |
|---|---|---|
| Migration 009 — AIUC-1 schema fields | P0 | See §28. Add before any production data exists. |
| risk_treatment on waiver (required) | P0 | Required field, no default. Before waivers in prod. |
| primust discover (P15-A) | 1 | Standalone CLI, no dependencies. Gates archetype inference. |
| autoinstrument() runtime discovery (P15-B) | 1 | Depends on P15-A. |
| Archetype inference engine | 1 | Depends on P15-A. custom_check/process_only schema additive now. |
| primust verify-report CLI | 2 | Part of audit report build. |
| primust-verify-java | 2 | Demand-gate: first Java relying-party design partner. |
| primust-hook binary | 3 | AMDT-16 spec, open questions remain. |
| CrewAI (P11-E), Pydantic AI (P11-G), Semantic Kernel (P11-F) | 2 | Demand-gated. |
| Domain packs: primust-finance, primust-insurance, primust-cicd | 2 | Demand-gated. |

---

## 12. OPEN SOURCE HARNESS — primust.checks (CANONICAL)

Apache-2.0. Runs entirely in customer environment. No content transits Primust.

**Built-in checks (8 total, shipped March 15, 2026):**
- secrets_scanner (Mathematical), pii_regex (Mathematical), cost_bounds (Mathematical), command_patterns (Mathematical) — AI-focused
- upstream_vpec_verify (Mathematical), schema_validation (Mathematical), reconciliation_check (Mathematical), dependency_hash_check (Mathematical) — domain-neutral

**7 policy bundles:** ai_agent_general_v1, eu_ai_act_art12_v1, hipaa_safeguards_v1, soc2_cc_v1, coding_agent_v1, supply_chain_governance_v1, financial_data_governance_v1

**Motion:** Free harness = distribution. Proof layer activates with one line = revenue. Zero re-instrumentation on conversion.

**BYOC principle:** Customer wraps their Lakera, OPA, Guardrails, or homegrown check. Primust proves it ran.

---

## 13. POLICY/MANIFEST CENTER — app.primust.com (CANONICAL)

Three sections: Policy (bundles, required checks, thresholds, manifest registry, code generation) | Runs (VPEC history, gap inbox, waiver workflow) | Verify (Evidence Pack assembly, share link, audit report export)

---

## 14. MANIFEST LIVES ON CUSTOMER SIDE (ARCHITECTURAL INVARIANT)

Customer repo holds manifest. Customer environment runs checks. Primust receives commitment hash only at VPEC issuance.

**Required disclosure everywhere:**
> "Primust proves what the manifest says ran. Primust does not guarantee what should have been in the manifest."

---

## 15. ONBOARDING FLOW — CANONICAL

```
Sign up at primust.com
  → Sandbox API key (pk_sb_xxx), free, no credit card
  → Choose entry point: A) SDK B) CLI Discovery C) Policy Center
  → First VPEC in dashboard (environment: "sandbox")
  → Review provable surface breakdown
  → Promote to production key (no re-instrumentation)
  → Assemble Evidence Pack
  → verify.primust.com/{pack_id} — auditor front door
```

**Time targets:** First VPEC <5min | First governed production run <1 day | Mode 2 policy <7 days | First Evidence Pack <30 days

---

## 16. DOMAIN PACK PACKAGING (CANONICAL)

| Package | Ships When |
|---|---|
| primust | v1.0 — SHIPPED |
| primust-ai | v1.0 — SHIPPED |
| primust-checks | v1.0 — SHIPPED |
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
| Cedar/Drools/ODM/OPA | BUILT — Cedar: Mathematical (eval()). Drools: Mathematical (eval() + Map facts). ODM: Mathematical (eval() + IlrSessionFactory, real runtime verified). OPA: Mathematical local / Attestation remote, gap-aware. |
| Guidewire ClaimCenter | BUILT — Python REST connector, 38 tests, **Attestation ceiling**. Mathematical ceiling requires Java in-process SDK running inside ClaimCenter's JVM — spec only, requires Guidewire Studio license. |
| CrewAI | P11-E — demand-gated |
| Pydantic AI | P11-G — demand-gated |
| Semantic Kernel | P11-F — .NET-first, demand-gated |

MCP Proxy: PERMANENTLY DROPPED. AutoGen/MS Agent: DROPPED. LangChain chains: DROPPED.

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
- primust.checks harness: Apache-2.0, free forever. Distribution engine.
- **Locked principle:** Never create incentive to sample, suppress, or narrow scope.

---

## 22. GAP TAXONOMY — 47 TYPES (CANONICAL)

**Core (22):**
check_not_executed (High), enforcement_override (Critical), engine_error (High), check_degraded (Medium), external_boundary_traversal (High), lineage_token_missing (High), admission_gate_override (Critical), check_timing_suspect (Medium), reviewer_credential_invalid (Critical), witnessed_display_missing (High), witnessed_rationale_missing (High), witnessed_timestamp_invalid (High), deterministic_consistency_violation (Critical), skip_rationale_missing (High), policy_config_drift (Medium), proof_level_floor_breach (Critical), zkml_proof_pending_timeout (Medium), zkml_proof_failed (High), system_error (High), sla_breach (Medium), explanation_missing (Medium), bias_audit_missing (High)

**System availability (1):**
`system_unavailable` (High) — Primust API unreachable, SDK queued locally, queue lost or TTL expired. Distinct from `system_error` (Primust processing failure). Auto-records when queue expires.

**Unstructured check (1):**
`archetype_unmapped` (Medium) — custom_check VPEC exists for check_id but compliance officer has not mapped it. One gap per unique unmapped check_id. Auto-resolves when officer completes mapping.

**Cross-org verification (7):**
upstream_vpec_invalid_signature (Critical), upstream_vpec_sandbox (High), upstream_vpec_key_revoked (High), upstream_vpec_insufficient_proof_level (High), upstream_vpec_missing_claim (Medium), upstream_vpec_issuer_mismatch (Critical), upstream_vpec_missing (High)

**Connector-specific (16):**
Pattern: `{platform}_api_error` (High) = vendor API unreachable or 5xx. `{platform}_auth_failure` (Critical) = vendor API 401/403.

complyadvantage_api_error (High), complyadvantage_auth_failure (Critical), actimize_api_error (High), actimize_auth_failure (Critical), blaze_api_error (High), blaze_auth_failure (Critical), odm_api_error (High), odm_auth_failure (Critical), falcon_api_error (High), falcon_auth_failure (Critical), pega_api_error (High), pega_auth_failure (Critical), wolters_kluwer_api_error (High), wolters_kluwer_auth_failure (Critical), guidewire_api_error (High), guidewire_auth_failure (Critical)

> ⚠ check_candidate findings are NOT gap types. They are scan advisories. They do not appear in VPEC `gaps` array and do not affect `provable_surface`.
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
Cross-org verification chain composition (multi-hop VPEC provenance chains) is not claimed in any existing provisional — review for continuation on CMB or new standalone provisional before PCT filing.

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
| test: true | environment: "sandbox" |
| pk_test_xxx | pk_sb_xxx |
| proof_level (VPEC-level field) | proof_level_floor |
| proof_distribution | provable_surface_breakdown |
| proof_level_breakdown | provable_surface_breakdown |
| coverage_verified_pct | provable_surface |
| governance_gaps | gaps |

---

## 26. CROSS-ORG VERIFICATION (NEW — v12)

### What It Is

A cross-org verification check treats an upstream VPEC as the subject of a governance check. The check runs primust-verify against a received VPEC and records the outcome as a CheckExecutionRecord. The calling organization's own VPEC then contains a Mathematical-level claim: "We verified our upstream's governance before processing their output."

### Proof Ceiling: Mathematical

Ed25519 signature verification is deterministic. Same VPEC bytes + same public key = same outcome, always. No LLM judgment, no heuristic, no sampling. Proof ceiling is Mathematical.

### Domain-Neutral

upstream_vpec_verify is not an AI check. The upstream process can be: an AI pipeline, a software build system, a financial data delivery, a clinical data CRO delivery, a manufacturing QC check, any governed process that issues VPECs.

### Trust Root Modes

**Network mode (default):** trust_anchor_url in upstream VPEC signature field fetched once per key_id, cached. Subsequent verifications zero-network.

**Pinned mode (zero-network):** trust_root_pem configured per upstream org. Required for high-frequency pipelines, air-gapped environments. Trust root pins are versioned and hash-committed.

### Composition

```
Org A issues VPEC_A (governs their process)
→ Org B receives output + VPEC_A
→ Org B runs upstream_vpec_verify(VPEC_A) → Mathematical check
→ Org B's VPEC_B contains: "upstream_vpec_verified: vpec_A_id"
→ Org C can verify the full chain without involving Org A or Primust
```

No Primust infrastructure in the verification path after initial key fetch.

### Gap Taxonomy

See §22 — 7 cross-org gap types. All upstream_vpec_* prefixed.

### Patent Note

Cross-org verification chain composition is not claimed in any existing provisional. Review before PCT filing (July 2026).

---

## 27. AUDIT REPORT ARTIFACT (NEW — v12)

### What It Is

A signed, tamper-evident PDF derived from an Evidence Pack. Named artifact type alongside: VPEC, Evidence Pack, Waiver. The Audit Report is the human-presentable rendering of Evidence Pack verification outcomes.

### Generation

```
POST /api/v1/evidence-packs/{pack_id}/report
primust pack report evidence_pack.json --output report.pdf
Dashboard: Evidence Pack detail → "Export Audit Report"
```

### Signing

Ed25519 signature over SHA256(full PDF bytes), embedded in PDF metadata:
```
/PrimusReportSignature: <base64 Ed25519>
/PrimusReportKeyId: <kid>
/PrimusReportTrustAnchor: <JWKS URL or BYOK anchor>
/PrimusReportPackId: <evidence_pack_id>
/PrimusReportGeneratedAt: <RFC 3339>
```

Signing key: org's BYOK key if configured; Primust GCP KMS otherwise.

### Verification

```bash
primust verify-report report.pdf
```
Exit codes: 0=valid, 1=invalid, 2=sandbox, 3=key revoked.

### Coverage Basis Gating

P1 reports: full-page diagonal watermark "INTERNAL REVIEW ONLY — NOT AUDIT-ACCEPTABLE". No green checkmarks. Cannot export audit-acceptably without admin override.
P2/P3 reports: full export, audit-acceptable.

### Report Does NOT Contain

Raw inputs/outputs (System Invariant 1), reviewer rationale text (committed locally), matched PII/secret values, individual AgentActivityRecords. The report reproduces verification outcomes only.

---

## 28. AIUC-1 SCHEMA ADDITIONS (NEW — v12 — MIGRATION 009 PENDING)

All additions are additive, nullable unless stated. No architectural changes.

### 28.1 Pipeline Init — Two New Fields
```
retention_policy: string | null
  Values: FDA_PART11_7Y | EU_AI_ACT_10Y | HIPAA_6Y | SOC2_1Y | GDPR_3Y | null
  Flows into policy_snapshot. Closes AIUC-1 A001, FDA 21 CFR Part 11 §11.10(c).

risk_classification: string | null
  Values: EU_HIGH_RISK | EU_LIMITED_RISK | EU_MINIMAL_RISK | US_FEDERAL | null
  Flows into policy_snapshot. Closes EU AI Act Art 6, NIST AI RMF MAP 1.1.
```

### 28.2 check_execution_record — Three New Fields
```
actor_id: user_{uuid} | null
  Identity of user or service account that triggered this record.
  null = system-triggered. Required for ALCOA attribution.
  Closes AIUC-1 B007, FDA 21 CFR Part 11 §11.10(d).

explanation_commitment: poseidon2:hex | null
  Poseidon2 commitment over explanation text generated at decision time.
  Plaintext NEVER sent to Primust. Customer holds plaintext.
  null triggers explanation_missing gap when compliance_requirements.require_explanation_commitment set.
  Closes GDPR Art 22, ECOA, EU AI Act Art 13.

bias_audit: { ... } | null
  protected_categories: string[]
  disparity_metric: string
  disparity_threshold: float
  disparity_result_commitment: poseidon2:hex
  result: pass | fail | not_applicable
  All numeric values committed locally. null triggers bias_audit_missing gap.
  Closes NYC Local Law 144, ECOA/FHA, Colorado SB 24-205.
```

### 28.3 gap record — One New Field
```
incident_report_ref: string | null
  External regulator-assigned reference number. Populated by Approver role.
  Examples: "FDA_MDR_2026_00123", "EU_AIOFFICE_2026_00456", "DORA_INC_2026_789"
  Only meaningful on gap.severity = critical.
  Closes EU AI Act Art 73, FDA 21 CFR Part 803, DORA Art 19.
```

### 28.4 waiver — One New Field (REQUIRED)
```
risk_treatment: enum — REQUIRED, no default
  accept — accept risk with time limit (existing waiver behavior, now explicit)
  mitigate — active remediation in progress; resolution_vpec_id expected at expiry
  transfer — risk transferred to third party (insurer, vendor contract)
  avoid — process being modified to eliminate risk entirely
  Approver must declare at waiver creation. UI enforces.
  Closes NIST AI RMF MANAGE 4.1, ISO 42001 §6.1, SOC 2 CC9.1.
```

> ⚠ risk_treatment is already canonical in FLOWS_UI_SPEC and dashboard. This formalizes it in schema.

### 28.5 policy_pack — Two New Blocks
```
compliance_requirements: { ... } | null
  require_actor_id: boolean
  require_explanation_commitment: { on_check_result: enum[], on_check_types: string[] } | null
  require_bias_audit: { on_check_types: string[], protected_categories: string[] } | null
  require_retention_policy: boolean
  require_risk_classification: boolean
  null = no compliance requirements declared. When set: fires explanation_missing or bias_audit_missing gaps.
  Closes AIUC-1 B007, C003, E012, ECOA, NYC LL144.

sla_policy: { ... } | null
  proof_level_floor_minimum: enum
  provable_surface_minimum: float
  max_open_critical_gaps: integer
  max_open_high_gaps: integer | null
  retention_policy_required: string | null
  Replaces external --sla-policy file. Threshold inside signed artifact — self-evidencing.
  Closes EU AI Act Art 15, ISO 42001 §9.1, SOC 2 CC9.2.
```

### 28.6 policy_snapshot — Three New Fields
```
prompt_version_id: string | null
prompt_approved_by: user_{uuid} | null
prompt_approved_at: ISO8601 | null
  Documents formal approval of prompt/model version change.
  Closes AIUC-1 E004, change approval evidence requirement.

regulatory_context: string[] | null
  e.g. ["EU_AI_ACT_ART13", "AIUC1_E015", "HIPAA_164_312"]
  Machine-readable registry of applicable frameworks per workflow.
  Closes AIUC-1 E012. Also feeds Evidence Pack framework-specific views.
```

---

## 29. UNSTRUCTURED CHECK HANDLING (NEW — v12)

### 29.1 Archetype System — 15 Archetypes

14 named archetypes + custom_check (catch-all). Archetype assignment is automatic via confidence scoring (gated on P15-A CLI discovery build).

**Confidence tiers:**
- HIGH (≥80): auto-accept named archetype, VPEC issued immediately
- MEDIUM (50–79): shortlist presented to developer, selects from top 3
- LOW (<50): custom_check assigned, archetype_candidates[] populated for officer review

**VPEC fields added for archetype tracking:**
```
archetype: string                    # named archetype or "custom_check" or "process_only"
archetype_confidence: float | null   # 0.0–1.0, null if explicit_declaration
archetype_inference: string          # "auto" | "assisted" | "low_confidence" | "explicit_declaration"
archetype_candidates: array | null   # top 3 scored archetypes, for officer review
archetype_verified: boolean          # false until compliance officer confirms mapping
compliance_mapping_status: string    # "mapped" | "pending_review" | "opted_out"
```

> ⚠ custom_check is NOT a failure state. A VPEC with archetype: custom_check is a valid, billable credential. It proves the check ran.

**Status of archetype inference engine:** GATED ON P15-A (primust discover CLI). Schema fields are additive and can be added to SDK now. Inference logic builds after P15-A ships.

### 29.2 process_only Archetype

For organizations wanting cryptographic proof of process execution without framework compliance mapping.

```python
p.record(
    check='content_quality_gate',
    archetype='process_only',  # explicit — cannot be set globally on pipeline
    input=content, check_result='pass', output=result
)
```

**VPEC fields:**
```
archetype: "process_only"
archetype_inference: "explicit_declaration"
compliance_mapping_status: "opted_out"
framework_controls: []
provable_surface_contribution: false
```

**Critical:** archetype: process_only cannot be set globally via p.init(). Per-check only. Prevents accidental compliance opt-out at pipeline level.

**Retroactive mapping boundary:** custom_check VPECs can be retroactively mapped (mapping was just pending). process_only VPECs CANNOT be retroactively reclassified (credential was deliberately issued without a compliance claim). Do not conflate.

### 29.3 Check Candidate Detection (P15-A dependent)

primust scan runs static analysis over the codebase. check_candidates are advisory signals — NOT gap types, NOT control_not_covered findings. They do not appear in VPEC gap_records and do not affect provable_surface.

`primust scaffold <candidate_id>` generates ready-to-integrate instrumentation template from detected pattern.

**CRITICAL:** Do NOT conflate check_candidate (uninstrumented code advisory) with control_not_covered (framework control with no instrumented check).

---

## 30. DOMAIN-NEUTRAL MARKETS (NEW — v12)

The GEP primitive is not AI-specific. Expansion markets:

| Market | Trigger Check | Regulatory Driver |
|---|---|---|
| Software supply chain | dependency_hash_check, upstream_vpec_verify | SLSA, NIST SSDF, 2026 NDAA AI supply chain |
| Financial data pipelines | reconciliation_check, schema_validation, upstream_vpec_verify | OCC/FCA model risk, SEC audit trails |
| Clinical trial data (CRO → sponsor) | upstream_vpec_verify + data integrity checks | FDA 21 CFR Part 11 |
| Manufacturing QC | threshold_check, calibration_verified, upstream_vpec_verify | ISO 9001, GMP, aerospace AS9100 |
| Legal research / contract review | upstream_vpec_verify + source_citation_verified | Malpractice, bar association AI guidelines |
| Government / defense contracting | upstream_vpec_verify + provenance checks | 2026 NDAA AI supply chain mandates |

Entry point for non-AI buyers: primust-checks Apache-2.0 harness + supply_chain_governance_v1 bundle.
OPA wedge: primust-opa + primust-opa CLI shim — CI/CD buyers who don't self-identify as AI governance buyers.

---

## 31. AIUC-1 CONTROL COVERAGE SUMMARY

| Status | Count | Notes |
|---|---|---|
| COVERED / EXCEEDS | 16 | A005, A006, C001, C002, C005, C007, C008, D003, E005, E008, E011, E013, E015, F001, F002 + more |
| EVIDENCE SUBSTRATE | 12 | Customer instruments check; Primust proves it ran; VPEC is the auditor evidence artifact |
| SCHEMA ADDITION (§28) | 11 | actor_id, explanation_commitment, bias_audit, incident_report_ref, risk_treatment, compliance_requirements, sla_policy, prompt_version_id, regulatory_context, retention_policy, risk_classification |
| OUT OF SCOPE | 10 | Accredited assessor (Schellman) or policy documents. Primust Evidence Pack is what these consume. |

OUT OF SCOPE controls (B001, C010–C012, D002, D004) are the Big 4 GTM opportunity. Schellman reads Primust Evidence Packs to issue these attestations.

---

*DECISIONS_v13.0 · March 16, 2026 · Primust, Inc.*
*Supersedes DECISIONS_v12 + all prior versions and amendments.*
*This document wins all conflicts.*
