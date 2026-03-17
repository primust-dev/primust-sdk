# MIGRATION 009 — SCHEMA RECONCILIATION
## v1.0 · March 16, 2026
## Canonical sources: DECISIONS_v12, MASTER_v8, TECH_SPEC_v7, code audit March 16, 2026

> **CRITICAL: Write and apply this migration before any production data exists.**
> Migration 009 reconciles field names between the live codebase and the canonical spec.
> All renames are non-breaking in the sense that the API side already produces both names
> via the remapping layer in `_parse_vpec()`. This migration locks the canonical names
> and removes the aliases.

---

## 1. SCOPE

Migration 009 covers six categories of changes:

1. VPEC object field renames (code → spec alignment)
2. API key prefix sweep (`pk_test_` → `pk_sb_`)
3. Gap taxonomy addition (`system_unavailable` + 14 connector-specific types)
4. `visibility` field formalization
5. AIUC-1 schema additions (previously planned, now bundled)
6. Database schema changes required to support renames

---

## 2. VPEC FIELD RENAMES

These are live mismatches between what the code produces and what the canonical spec says. The `_parse_vpec()` remapping layer in `run.py:398–449` currently handles both names as aliases. Post-migration, only the canonical names are valid.

| Current Code Field | Canonical Spec Field | Location | Notes |
|---|---|---|---|
| `proof_level` | `proof_level_floor` | VPEC object (weakest-link scalar) | Same semantics — rename only |
| `proof_level_breakdown` / `proof_distribution` | `provable_surface_breakdown` | VPEC object + API wire format | Two aliases → one canonical name |
| `coverage_verified_pct` | `provable_surface` | VPEC object | Float 0.0–1.0, not percentage |
| `governance_gaps` | `gaps` | VPEC object | Rename only |

### 2.1 VPEC Python dataclass — before and after

**Before (models.py current):**
```python
@dataclass
class VPEC:
    vpec_id: str
    run_id: str
    workflow_id: str
    org_id: str
    issued_at: str
    proof_level: str                          # ← rename
    proof_level_breakdown: ProofLevelBreakdown  # ← rename
    coverage_verified_pct: float              # ← rename
    total_checks_run: int
    checks_passed: int
    checks_failed: int
    governance_gaps: list[GovernanceGap]      # ← rename
    chain_intact: bool
    merkle_root: str
    signature: str
    timestamp_rfc3161: str
    test_mode: bool = False
    raw: dict = field(default_factory=dict)
```

**After (canonical):**
```python
@dataclass
class VPEC:
    vpec_id: str
    run_id: str
    workflow_id: str
    org_id: str
    issued_at: str
    proof_level_floor: str                      # weakest-link scalar. DERIVED.
    provable_surface: float                     # float 0.0–1.0
    provable_surface_breakdown: ProofLevelBreakdown
    provable_surface_pending: float             # share where proof_pending: true
    provable_surface_ungoverned: float          # share of manifest checks with no record
    provable_surface_basis: str                 # "executed_records" | "manifest_checks"
    provable_surface_suppressed: bool           # True if org suppressed disclosure
    total_checks_run: int
    checks_passed: int
    checks_failed: int
    gaps: list[GovernanceGap]
    chain_intact: bool
    merkle_root: str
    signature: str
    timestamp_rfc3161: str
    environment: str                            # "sandbox" | "production"
    raw: dict = field(default_factory=dict)
```

### 2.2 ProofLevelBreakdown — rename and switch from count to float

**Before:**
```python
@dataclass
class ProofLevelBreakdown:
    mathematical: int = 0
    verifiable_inference: int = 0
    execution: int = 0
    witnessed: int = 0
    attestation: int = 0
```

**After (canonical — floats, not counts. Must sum to provable_surface ±0.0001):**
```python
@dataclass
class ProofLevelBreakdown:
    mathematical: float = 0.0
    verifiable_inference: float = 0.0
    execution: float = 0.0
    witnessed: float = 0.0
    attestation: float = 0.0
```

> ⚠ PS-INV-1: All five sub-fields must sum to `provable_surface` ±0.0001. VPEC issuance rejected server-side on violation.

### 2.3 API wire format renames

The `_parse_vpec()` remapping layer currently accepts both old and new names. Post-migration, remove aliases — canonical names only.

| API Response Field (current) | API Response Field (post-migration) |
|---|---|
| `proof_distribution` | `provable_surface_breakdown` |
| `proof_level` (VPEC-level) | `proof_level_floor` |
| `coverage.policy_coverage_pct` | `provable_surface` (top-level float) |
| `gaps` / `governance_gaps` | `gaps` |

### 2.4 Check execution record — wire format (already canonical, confirm)

The per-record field `proof_level_achieved` is already correct in `run.py:173`. No change needed.

```python
"proof_level_achieved": proof_level,  # per-record — already canonical
```

---

## 3. API KEY PREFIX — `pk_test_` → `pk_sb_`

**Decision locked: `pk_sb_` is canonical.** `pk_test_` is banned (added to §25 forbidden terms).

### Files requiring sweep:

**SDK:**
- `sdk-python/tests/` — all test fixtures using `pk_test_abc123`, `pk_test_456`, `pk_test_123`
- `sdk-python/src/primust/` — any docstrings referencing `pk_test_`
- `sdk-js/` — same sweep
- `sdk-java/` — same sweep
- `sdk-csharp/` — same sweep

**Connectors:**
- All 7 connector files — docstring examples use `pk_live_...` (correct) but some tests use `pk_test_`
- `tests/` — all test fixtures

**Docs:**
- `docs-ruddy-xi.vercel.app` — all four pages
- GitHub README files — both repos

**Pattern:**
```bash
# Find all occurrences
grep -r "pk_test_" .

# Replace
sed -i 's/pk_test_/pk_sb_/g' <file>
```

> ⚠ `pk_live_` stays as-is. Only `pk_test_` → `pk_sb_`.

---

## 4. GAP TAXONOMY EXPANSION — 30 → 45 TYPES

### 4.1 Add `system_unavailable` (gap #31)

Confirmed in `sdk-python/tests/test_run_api.py:271` — asserted as a real gap type. Not in the 30-type canonical taxonomy. Relationship to `system_error` (#19):

| Gap Type | Trigger | Severity |
|---|---|---|
| `system_error` | Unrecoverable error during governance processing (Primust-side) | High |
| `system_unavailable` | Primust API unreachable — SDK queued locally, queue lost or TTL expired | High |

These are distinct. `system_error` = something went wrong during processing. `system_unavailable` = Primust was unreachable and the local queue was lost. Both need to be in the taxonomy.

### 4.2 Add Connector-Specific Gap Types (gaps #32–#45)

Pattern: `{platform}_api_error` (High) and `{platform}_auth_failure` (Critical) per connector.

These fire when the vendor platform API (not Primust) is unreachable or rejects authentication. They are distinct from `system_error` and `system_unavailable` which are Primust-side.

| Gap Type | Severity | Connector | Trigger |
|---|---|---|---|
| `complyadvantage_api_error` | High | ComplyAdvantage | CA API unreachable or 5xx |
| `complyadvantage_auth_failure` | Critical | ComplyAdvantage | CA API 401/403 |
| `actimize_api_error` | High | NICE Actimize | Actimize API unreachable or 5xx |
| `actimize_auth_failure` | Critical | NICE Actimize | Actimize API 401/403 |
| `blaze_api_error` | High | FICO Blaze | Blaze API unreachable or 5xx |
| `blaze_auth_failure` | Critical | FICO Blaze | Blaze API 401/403 |
| `odm_api_error` | High | IBM ODM | ODM API unreachable or 5xx |
| `odm_auth_failure` | Critical | IBM ODM | ODM API 401/403 |
| `falcon_api_error` | High | FICO Falcon | Falcon API unreachable or 5xx |
| `falcon_auth_failure` | Critical | FICO Falcon | Falcon API 401/403 |
| `pega_api_error` | High | Pega CDH | Pega API unreachable or 5xx |
| `pega_auth_failure` | Critical | Pega CDH | Pega API 401/403 |
| `wolters_kluwer_api_error` | High | Wolters Kluwer UpToDate | WK API unreachable or 5xx |
| `wolters_kluwer_auth_failure` | Critical | Wolters Kluwer UpToDate | WK API 401/403 |

**Total gap taxonomy after migration: 45 types**
- Core: 22
- System availability: 1 (`system_unavailable`)
- Unstructured check: 1 (`archetype_unmapped`)
- Cross-org verification: 7
- Connector-specific: 14
- **Total: 45**

---

## 5. VISIBILITY FIELD FORMALIZATION

`visibility` is a real SDK parameter confirmed in `run.py:96–109`:

```python
def record(self, ..., visibility: str = "opaque", ...) -> RecordResult:
```

It was dropped from canonical docs during version churn. Restore to spec:

**Canonical definition:**
```
visibility: "opaque" | "selective" | "transparent"
Default: "opaque" — always set explicitly for connector records
```

**Connector invariant:** All connector records use `visibility: "opaque"`. This is not configurable by the caller — the connector enforces it. Raw regulated data (PHI, AML criteria, credit factors) must never be selectable or transparent.

**SDK invariant:** Default is `"opaque"`. Developers must explicitly pass `visibility="transparent"` or `visibility="selective"` if they want non-opaque visibility on custom checks.

---

## 6. AIUC-1 SCHEMA ADDITIONS (Previously planned, bundled here)

From DECISIONS_v12 §28 — these fields were planned for migration 009 and are bundled:

### 6.1 process_run — 2 new fields
```sql
ALTER TABLE process_runs ADD COLUMN retention_policy TEXT CHECK (
    retention_policy IN ('FDA_PART11_7Y', 'EU_AI_ACT_10Y', 'HIPAA_6Y', 'SOC2_1Y', 'GDPR_3Y')
) DEFAULT NULL;

ALTER TABLE process_runs ADD COLUMN risk_classification TEXT CHECK (
    risk_classification IN ('EU_HIGH_RISK', 'EU_LIMITED_RISK', 'EU_MINIMAL_RISK', 'US_FEDERAL')
) DEFAULT NULL;
```

### 6.2 check_execution_records — 3 new fields
```sql
ALTER TABLE check_execution_records ADD COLUMN actor_id TEXT DEFAULT NULL;
ALTER TABLE check_execution_records ADD COLUMN explanation_commitment TEXT DEFAULT NULL;
ALTER TABLE check_execution_records ADD COLUMN bias_audit JSONB DEFAULT NULL;
```

### 6.3 gaps — 1 new field
```sql
ALTER TABLE gaps ADD COLUMN incident_report_ref TEXT DEFAULT NULL;
```

### 6.4 waivers — 1 new field (REQUIRED, no default)
```sql
ALTER TABLE waivers ADD COLUMN risk_treatment TEXT NOT NULL
    CHECK (risk_treatment IN ('accept', 'mitigate', 'transfer', 'avoid'));
-- Migration default for existing rows:
UPDATE waivers SET risk_treatment = 'accept' WHERE risk_treatment IS NULL;
```

### 6.5 policy_snapshots — 3 new fields
```sql
ALTER TABLE policy_snapshots ADD COLUMN prompt_version_id TEXT DEFAULT NULL;
ALTER TABLE policy_snapshots ADD COLUMN prompt_approved_by TEXT DEFAULT NULL;
ALTER TABLE policy_snapshots ADD COLUMN prompt_approved_at TIMESTAMPTZ DEFAULT NULL;
ALTER TABLE policy_snapshots ADD COLUMN regulatory_context TEXT[] DEFAULT NULL;
```

---

## 7. DATABASE SCHEMA — VPEC TABLE FIELD RENAMES

```sql
-- Rename proof_level → proof_level_floor on vpecs table
ALTER TABLE vpecs RENAME COLUMN proof_level TO proof_level_floor;

-- Add new provable_surface fields
ALTER TABLE vpecs ADD COLUMN provable_surface FLOAT DEFAULT NULL;
ALTER TABLE vpecs ADD COLUMN provable_surface_breakdown JSONB DEFAULT NULL;
ALTER TABLE vpecs ADD COLUMN provable_surface_pending FLOAT DEFAULT 0.0;
ALTER TABLE vpecs ADD COLUMN provable_surface_ungoverned FLOAT DEFAULT 0.0;
ALTER TABLE vpecs ADD COLUMN provable_surface_basis TEXT DEFAULT 'executed_records';
ALTER TABLE vpecs ADD COLUMN provable_surface_suppressed BOOLEAN DEFAULT FALSE;

-- Rename governance_gaps → gaps (if stored as column, otherwise no-op)
-- Note: gaps are typically in a separate gaps table, not a VPEC column

-- Add environment field
ALTER TABLE vpecs ADD COLUMN environment TEXT DEFAULT 'production'
    CHECK (environment IN ('sandbox', 'production'));
```

---

## 8. MIGRATION CHECKLIST

- [ ] Write SQL migration file as `db/migrations/009_schema_reconciliation.sql`
- [ ] Apply to Neon US (DATABASE_URL_US) — test environment first
- [ ] Apply to Neon EU (DATABASE_URL_EU)
- [ ] Update `models.py` VPEC dataclass (§2.1)
- [ ] Update `ProofLevelBreakdown` (§2.2 — int → float)
- [ ] Update `_parse_vpec()` — remove aliases, canonical names only
- [ ] Run `pk_test_` → `pk_sb_` sweep across all packages
- [ ] Update gap taxonomy in API gap validation layer
- [ ] Update test fixtures — VPEC mocks to use canonical field names
- [ ] Update `test_run_api.py` gap assertion for `system_unavailable`
- [ ] Schema validation golden test vectors — regenerate for schema v5.0.0
- [ ] `PROVISIONAL_FREEZE.md` update

---

## 9. FORBIDDEN TERMS ADDITIONS (from this migration)

Add to DECISIONS_v12 §25:

| Banned | Use Instead |
|---|---|
| `pk_test_xxx` | `pk_sb_xxx` |
| `proof_level` (VPEC-level) | `proof_level_floor` |
| `proof_distribution` | `provable_surface_breakdown` |
| `proof_level_breakdown` | `provable_surface_breakdown` |
| `coverage_verified_pct` | `provable_surface` |
| `governance_gaps` | `gaps` |

---

*MIGRATION_009_SPEC_v1.0 · March 16, 2026 · Primust, Inc.*
*Apply before any production data exists. US environment first, EU second.*
