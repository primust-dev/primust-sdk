# PRIMUST CANONICAL AMENDMENT
## DECISIONS v13 · MASTER v9 · TECH_SPEC v8
## Surgical patch · March 16, 2026

> ⚠ THIS DOCUMENT WINS ALL CONFLICTS upon adoption.
> Apply each numbered patch to its target document.
> Do not regenerate base documents from this file.

---

## SCOPE

| Group | Subject | Target |
|---|---|---|
| A | VPEC field renames — `proof_level` → `proof_level_floor`, `governance_gaps` → `gaps`, `coverage_verified_pct` → `provable_surface`, `proof_distribution` → `provable_surface_breakdown` | DECISIONS v13 §6 · MASTER v9 §5 · TECH_SPEC v8 §1 |
| B | Gap taxonomy 30 → 49 types: `system_unavailable` + 16 connector-specific | DECISIONS v13 §22 · MASTER v9 §17 · TECH_SPEC v8 §15 |
| C | Connector build status: all 7 Python connectors built (321 tests). Guidewire: Python REST / Attestation, Java spec only. License: Apache-2.0. | DECISIONS v13 §19 · MASTER v9 §9 · TECH_SPEC v8 §2 |
| D | `visibility: "opaque"` — restore to SDK and connector spec | TECH_SPEC v8 §4 |
| E | API key prefix: `pk_sb_` canonical. `pk_test_` banned. | DECISIONS v13 §25 |
| F | `system_unavailable` gap type added | DECISIONS v13 §22 |

**Document version chain after adoption:**

| Document | Version After |
|---|---|
| DECISIONS | v13.0 · Supersedes DECISIONS v12 and all prior |
| MASTER | v9.0 · Supersedes MASTER v8 and all prior |
| TECH_SPEC | v8.0 · Supersedes TECH_SPEC v7 and all prior |

---

## GROUP A — VPEC FIELD RENAMES

### A.1 VPEC Schema — Canonical Field Names

Patch DECISIONS v13 §6, MASTER v9 §5, TECH_SPEC v8 §1.

**Replace the VPEC schema field table with:**

| Field | Type | Job |
|---|---|---|
| `proof_level_floor` | enum | Technical minimum. Weakest-link scalar. DERIVED — never set manually. |
| `provable_surface` | float 0.0–1.0 | Share of governance that is cryptographically provable. Hero metric. |
| `provable_surface_breakdown` | object | Per-level shares. All five sub-fields always present. Must sum to `provable_surface` ±0.0001 (PS-INV-1). Sub-fields: `mathematical`, `verifiable_inference`, `execution`, `witnessed`, `attestation` — all floats. |
| `provable_surface_pending` | float | Share where `proof_pending: true` at issuance (Verifiable Inference in-flight). |
| `provable_surface_ungoverned` | float | Share of manifest checks with no `CheckExecutionRecord` this run. |
| `provable_surface_basis` | enum | `executed_records` \| `manifest_checks` — denominator used to compute `provable_surface`. |
| `provable_surface_suppressed` | boolean | True if org suppressed distribution disclosure. |
| `gaps` | array | Gap records. Canonical name — `governance_gaps` is banned. |
| `environment` | enum | `sandbox` \| `production` — present on every VPEC. |

> ⚠ CRITICAL: `proof_level` (single field) is BANNED. Use `proof_level_floor`.
> `governance_gaps` is BANNED. Use `gaps`.
> `coverage_verified_pct` is BANNED. Use `provable_surface`.
> `proof_distribution` / `proof_level_breakdown` are BANNED. Use `provable_surface_breakdown`.

### A.2 `ProofLevelBreakdown` — int → float

The breakdown sub-fields are floats (share of total), not integer counts.

```
provable_surface_breakdown: {
  mathematical:        0.62,
  verifiable_inference: 0.00,
  execution:           0.11,
  witnessed:           0.00,
  attestation:         0.00
}
```

PS-INV-1: All five values sum to `provable_surface` ±0.0001. VPEC issuance rejected server-side on violation.

### A.3 Check Execution Record — wire format unchanged

`proof_level_achieved` on check execution records is already canonical. No change.

---

## GROUP B — GAP TAXONOMY 30 → 49 TYPES

### B.1 Replace Gap Taxonomy Section

**DECISIONS v13 §22 / MASTER v9 §17 / TECH_SPEC v8 §15 — full replacement:**

**Core (22):**
check_not_executed (High), enforcement_override (Critical), engine_error (High), check_degraded (Medium), external_boundary_traversal (High), lineage_token_missing (High), admission_gate_override (Critical), check_timing_suspect (Medium), reviewer_credential_invalid (Critical), witnessed_display_missing (High), witnessed_rationale_missing (High), witnessed_timestamp_invalid (High), deterministic_consistency_violation (Critical), skip_rationale_missing (High), policy_config_drift (Medium), proof_level_floor_breach (Critical), zkml_proof_pending_timeout (Medium), zkml_proof_failed (High), system_error (High), sla_breach (Medium), explanation_missing (Medium), bias_audit_missing (High)

**System availability (1):**
`system_unavailable` (High) — Primust API unreachable, SDK queued locally, queue lost or TTL expired before flush. Distinct from `system_error` (processing failure). Auto-records when queue expires.

**Unstructured check (1):**
`archetype_unmapped` (Medium) — custom_check VPEC exists for check_id but compliance officer has not mapped it. One gap per unique unmapped check_id. Auto-resolves when officer completes mapping.

**Cross-org verification (7):**
upstream_vpec_invalid_signature (Critical), upstream_vpec_sandbox (High), upstream_vpec_key_revoked (High), upstream_vpec_insufficient_proof_level (High), upstream_vpec_missing_claim (Medium), upstream_vpec_issuer_mismatch (Critical), upstream_vpec_missing (High)

**Connector-specific (14):**
These fire when the vendor platform API fails. Distinct from `system_error` (Primust-side) and `system_unavailable` (Primust unreachable). Pattern: `{platform}_api_error` (High) = vendor API unreachable or 5xx. `{platform}_auth_failure` (Critical) = vendor API 401/403.

| Gap Type | Severity | Connector |
|---|---|---|
| `complyadvantage_api_error` | High | ComplyAdvantage |
| `complyadvantage_auth_failure` | Critical | ComplyAdvantage |
| `actimize_api_error` | High | NICE Actimize |
| `actimize_auth_failure` | Critical | NICE Actimize |
| `blaze_api_error` | High | FICO Blaze |
| `blaze_auth_failure` | Critical | FICO Blaze |
| `odm_api_error` | High | IBM ODM |
| `odm_auth_failure` | Critical | IBM ODM |
| `falcon_api_error` | High | FICO Falcon |
| `falcon_auth_failure` | Critical | FICO Falcon |
| `pega_api_error` | High | Pega CDH |
| `pega_auth_failure` | Critical | Pega CDH |
| `wolters_kluwer_api_error` | High | Wolters Kluwer UpToDate |
| `wolters_kluwer_auth_failure` | Critical | Wolters Kluwer UpToDate |
| `guidewire_api_error` | High | Guidewire ClaimCenter |
| `guidewire_auth_failure` | Critical | Guidewire ClaimCenter |

**Total: 49 gap types.**

> ⚠ check_candidate findings are NOT gap types. They are scan advisories. They do not appear in VPEC `gaps` array and do not affect `provable_surface`.

---

## GROUP C — CONNECTOR BUILD STATUS + GUIDEWIRE + LICENSE

### C.1 Replace §19 Adapter/Connector Status

**DECISIONS v13 §19 — replace Guidewire row:**

| Adapter | Status |
|---|---|
| LangGraph | BUILT — primust-langgraph, 14 tests |
| Google ADK | BUILT — primust-google-adk, 14 tests |
| OTEL (three surfaces) | BUILT — primust-otel, 14 tests |
| OpenAI Agents SDK | BUILT — primust-openai-agents, 14 tests |
| Cedar/Drools/ODM/OPA | BUILT — Cedar: Mathematical (eval()). Drools: Mathematical (eval() + Map facts). ODM: Mathematical (eval() + IlrSessionFactory). OPA: Mathematical local / Attestation remote, gap-aware. |
| Guidewire ClaimCenter | BUILT — Python REST connector, 38 tests, **Attestation ceiling**. Mathematical ceiling requires Java in-process SDK running inside ClaimCenter's JVM — spec only, requires Guidewire Studio license. |
| CrewAI | P11-E — demand-gated |
| Pydantic AI | P11-G — demand-gated |
| Semantic Kernel | P11-F — demand-gated |

### C.2 Replace Connector Package Inventory

**TECH_SPEC v8 §2 — replace primust-connectors row:**

| Package | Contents | License | Status |
|---|---|---|---|
| primust-connectors | 7 Python REST connectors: ComplyAdvantage (48 tests), NICE Actimize (51 tests), FICO Blaze + IBM ODM (41 tests), FICO Falcon (45 tests), Pega CDH (46 tests), Wolters Kluwer UpToDate (46 tests), Guidewire ClaimCenter (38 tests). Total: 321 tests. All Attestation ceiling (REST wrappers). Java/C# in-process specs exist for Mathematical ceiling — require vendor SDK licenses. | **Apache-2.0** | Built. |

> ⚠ Previous entries showing "Guidewire: BUILT (38 tests). All others: deferred." are superseded. All 7 Python connectors are built. Java/C# are specs only.

---

## GROUP D — `visibility` FIELD RESTORATION

### D.1 Add to TECH_SPEC v8 §4 (SDK API Reference)

`visibility` is a confirmed SDK parameter, defaulting to `"opaque"` on all records.

```python
p.record(
    check="pii_scan",
    manifest_id="sha256:...",
    input=data,
    check_result="pass",
    visibility="opaque"    # default — always opaque for connector records
)
```

**Canonical values:**

| Value | Meaning |
|---|---|
| `"opaque"` | Commitment hashes only in VPEC. No metadata about content structure. Default. |
| `"selective"` | Stage categories visible, content replaced with Merkle stubs. |
| `"transparent"` | Full methodology visible to verifier. |

**Connector invariant:** All connector records enforce `visibility="opaque"`. Not configurable by caller. Regulated data (PHI, AML criteria, credit factors) must never be transparent or selective.

**SDK invariant:** Default is `"opaque"`. Developers must explicitly opt into non-opaque visibility on custom checks.

---

## GROUP E — API KEY PREFIX

### E.1 Add to DECISIONS v13 §25 Forbidden Terms

| Banned | Use Instead |
|---|---|
| `pk_test_xxx` | `pk_sb_xxx` |
| `proof_level` (VPEC-level field) | `proof_level_floor` |
| `proof_distribution` | `provable_surface_breakdown` |
| `proof_level_breakdown` | `provable_surface_breakdown` |
| `coverage_verified_pct` | `provable_surface` |
| `governance_gaps` | `gaps` |

### E.2 API Key Tiers — Canonical

| Key Prefix | Environment | Notes |
|---|---|---|
| `pk_sb_xxx` | Sandbox | Real GEP, same schema, `environment: "sandbox"`. Not audit-acceptable. Converts to production — same key, no re-instrumentation. |
| `pk_live_xxx` | Production | Audit-acceptable VPECs. |

Bootstrap API key deprecation: **2026-06-01. Hardcoded. No exceptions.**

---

## GROUP F — `system_unavailable` GAP TYPE

### F.1 Confirmed from code audit

`system_unavailable` is asserted in `sdk-python/tests/test_run_api.py:271`. It is a real gap type that was missing from the 30-type taxonomy. Now added as part of the 49-type taxonomy (Group B above).

**Definition:**
> `system_unavailable` (High) — Primust API was unreachable during a run. The SDK queued records locally. The queue was lost or exceeded TTL before successful flush. The run closed without full VPEC chain integrity. Agent pipeline continued (fail-open). Gap recorded honestly.

**Distinction from `system_error`:**
- `system_error` = Primust processed the request but encountered an unrecoverable error
- `system_unavailable` = Primust was not reachable — the request was never delivered

---

*PRIMUST CANONICAL AMENDMENT · DECISIONS v13 / MASTER v9 / TECH_SPEC v8*
*March 16, 2026 · Surgical patch — do not regenerate base documents*
*This document wins all conflicts upon adoption.*
