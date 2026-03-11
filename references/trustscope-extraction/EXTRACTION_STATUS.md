# TrustScope Extraction Status

> This file tracks the disposition of every TrustScope source file.
> Status: **Extract** | **Rewrite** | **Defer** | **Drop**
>
> - **Extract**: Cryptographic or runtime primitive — port to Primust with domain-neutral naming
> - **Rewrite**: Useful pattern but too AI/TrustScope-specific — rewrite from scratch
> - **Defer**: May be useful later — skip for now
> - **Drop**: TrustScope-specific, not applicable to Primust

## Root

| File | Status | Notes |
|------|--------|-------|
| `src/index.ts` | Drop | TrustScope entry point |
| `src/cache.ts` | Defer | Generic caching — may extract later |
| `src/mcp-entry.ts` | Drop | MCP-specific entry |
| `src/utils.ts` | Defer | Review for generic utilities |
| `src/validation.ts` | Rewrite | Validation patterns useful but AI-coupled |
| `src/version.ts` | Drop | TrustScope versioning |
| `tsup.config.ts` | Drop | Build config |

## src/analysis/

| File | Status | Notes |
|------|--------|-------|
| `behavior.ts` | Drop | AI behavior analysis |
| `index.ts` | Drop | AI analysis barrel |

## src/analyzers/

| File | Status | Notes |
|------|--------|-------|
| `governance.ts` | Drop | AI governance specific |
| `index.ts` | Drop | Barrel |
| `security.ts` | Drop | AI security analysis |

## src/auth/

| File | Status | Notes |
|------|--------|-------|
| `index.ts` | Rewrite | Auth patterns — rewrite for Primust registry auth |

## src/cli/

| File | Status | Notes |
|------|--------|-------|
| `cloud-connect.ts` | Drop | TrustScope cloud |
| `connect.ts` | Drop | TrustScope cloud |
| `doctor.ts` | Defer | Diagnostic pattern may be useful |
| `export.ts` | Rewrite | Export patterns — rewrite for evidence pack export |
| `init.ts` | Drop | TrustScope init |
| `mcp.ts` | Drop | MCP specific |
| `onboarding-scan.ts` | Drop | TrustScope onboarding |
| `scan.ts` | Drop | TrustScope scanning |
| `status.ts` | Defer | Status reporting pattern |
| `verify.ts` | Extract | Verification CLI — port to verifier package |

## src/cloud/

| File | Status | Notes |
|------|--------|-------|
| `diagnosis.ts` | Drop | TrustScope cloud |
| `import.ts` | Drop | TrustScope cloud |
| `queue.ts` | Defer | Queue pattern may be useful |
| `sync.ts` | Drop | TrustScope cloud sync |
| `upload.ts` | Defer | Upload pattern — review for evidence upload |

## src/config/

| File | Status | Notes |
|------|--------|-------|
| `defaults.ts` | Drop | TrustScope defaults |
| `index.ts` | Drop | Barrel |
| `types.ts` | Rewrite | Config type patterns — rewrite domain-neutral |

## src/crypto/

| File | Status | Notes |
|------|--------|-------|
| `signing.ts` | Rewrite | SECURITY AUDIT: top-level-only sort (Q1), key rotation destroys prior keys (Q2), no kid support, no-sort in sign(). See QUARANTINE.md Q1–Q6 |

## src/detection/

| File | Status | Notes |
|------|--------|-------|
| `index.ts` | Drop | AI detection barrel |
| `patterns.ts` | Drop | AI-specific patterns |
| `types.ts` | Drop | AI detection types |

## src/detection/pattern/

| File | Status | Notes |
|------|--------|-------|
| `action-label-mismatch.ts` | Drop | AI-specific |
| `blocked-phrases.ts` | Drop | AI-specific |
| `command-firewall.ts` | Drop | AI-specific |
| `data-exfiltration.ts` | Drop | AI-specific |
| `hate-speech-detector.ts` | Drop | AI-specific |
| `index.ts` | Drop | Barrel |
| `jailbreak.ts` | Drop | AI-specific |
| `pii-scanner.ts` | Drop | AI-specific |
| `prompt-injection.ts` | Drop | AI-specific |
| `secrets-scanner.ts` | Drop | AI-specific |
| `toxicity-filter.ts` | Drop | AI-specific |

## src/detection/statistical/

| File | Status | Notes |
|------|--------|-------|
| `budget-caps.ts` | Drop | AI-specific |
| `context-expansion.ts` | Drop | AI-specific |
| `cost-velocity.ts` | Drop | AI-specific |
| `error-rate.ts` | Defer | Generic error rate pattern |
| `index.ts` | Drop | Barrel |
| `loop-killer.ts` | Drop | AI-specific |
| `oscillation.ts` | Drop | AI-specific |
| `session-action-limit.ts` | Drop | AI-specific |
| `session-duration.ts` | Drop | AI-specific |
| `token-growth.ts` | Drop | AI-specific |
| `velocity-limit.ts` | Defer | Generic rate limiting pattern |

## src/detection/webhook/

| File | Status | Notes |
|------|--------|-------|
| `external-guardrail.ts` | Drop | AI-specific |
| `index.ts` | Drop | Barrel |

## src/detectors/

| File | Status | Notes |
|------|--------|-------|
| `code-patterns.ts` | Drop | AI code analysis |
| `env-vars.ts` | Drop | AI env detection |
| `github.ts` | Drop | AI GitHub analysis |
| `index.ts` | Drop | Barrel |
| `mcp-configs.ts` | Drop | MCP-specific |
| `package-deps.ts` | Drop | AI package analysis |

## src/enforcement/

| File | Status | Notes |
|------|--------|-------|
| `detector.ts` | Drop | AI enforcement |
| `index.ts` | Drop | Barrel |

## src/evidence/

| File | Status | Notes |
|------|--------|-------|
| `hash-chain.ts` | Rewrite | SECURITY AUDIT: plain 'genesis' literal (Q5), prohibited field names agent_id/action_type (Q7). See QUARANTINE.md |
| `index.ts` | Rewrite | Evidence barrel — rewrite for evidence-pack |
| `store.ts` | Extract | Evidence store — port to runtime-core |

## src/hybrid/

| File | Status | Notes |
|------|--------|-------|
| `index.ts` | Drop | TrustScope hybrid mode |

## src/mcp/

| File | Status | Notes |
|------|--------|-------|
| `http-transport.ts` | Drop | MCP transport |
| `server.ts` | Drop | MCP server |
| `types.ts` | Drop | MCP types |

## src/mcp/tools/

| File | Status | Notes |
|------|--------|-------|
| `agent-dna.ts` | Drop | AI-specific |
| `approvals.ts` | Drop | AI-specific |
| `compliance.ts` | Drop | AI-specific |
| `definitions.ts` | Drop | MCP-specific |
| `detection.ts` | Drop | AI-specific |
| `external-guardrail.ts` | Drop | AI-specific |
| `index.ts` | Drop | Barrel |
| `local.ts` | Drop | MCP-specific |
| `logging.ts` | Drop | MCP-specific |
| `policies.ts` | Drop | AI-specific |
| `policy.ts` | Drop | AI-specific |
| `redaction.ts` | Drop | AI-specific |
| `traces.ts` | Drop | AI-specific |

## src/policy/

| File | Status | Notes |
|------|--------|-------|
| `cache.ts` | Defer | Caching pattern — review later |
| `defaults.ts` | Drop | AI policy defaults |
| `engine.ts` | Rewrite | Policy engine pattern — rewrite domain-neutral for policy-engine |
| `index.ts` | Drop | Barrel |
| `types.ts` | Rewrite | Policy types — rewrite domain-neutral |

## src/report/

| File | Status | Notes |
|------|--------|-------|
| `github.ts` | Drop | GitHub reporting |
| `index.ts` | Drop | Barrel |
| `terminal.ts` | Drop | Terminal reporting |

## src/reporters/

| File | Status | Notes |
|------|--------|-------|
| `sarif.ts` | Defer | SARIF format — may be useful for evidence output |

## src/types/

| File | Status | Notes |
|------|--------|-------|
| `cli-original.ts` | Drop | TrustScope CLI types |
| `cli.ts` | Drop | TrustScope CLI types |
| `evidence.ts` | Extract | Evidence types — port to artifact-core |
| `index.ts` | Drop | Barrel |
| `mcp.ts` | Drop | MCP types |

## src/utils/

| File | Status | Notes |
|------|--------|-------|
| `api-client.ts` | Defer | HTTP client pattern |
| `index.ts` | Drop | Barrel |

## src/watch/

| File | Status | Notes |
|------|--------|-------|
| `index.ts` | Drop | AI watch mode |
| `proxy.ts` | Drop | AI proxy |
| `safety.ts` | Drop | AI safety |
| `ui.ts` | Drop | AI watch UI |

## src/__tests__/

| File | Status | Notes |
|------|--------|-------|
| `smoke.test.ts` | Drop | TrustScope smoke test |

---

## Summary

| Status | Count |
|--------|-------|
| Extract | 3 |
| Rewrite | 8 |
| Defer | 8 |
| Drop | 98 |
| **Total** | **117** |

> **Post-audit reclassifications (2026-03-10):**
> - `src/crypto/signing.ts`: Extract → **Rewrite** (Q1, Q2, Q4, Q6 — see SECURITY_AUDIT.md)
> - `src/evidence/hash-chain.ts`: Extract → **Rewrite** (Q5, Q7 — see SECURITY_AUDIT.md)
> - `canonical.py` (trustscope-api): Extract → **Rewrite** (Q8 — default=str coercion)

### Extract targets (port directly)
1. `src/evidence/store.ts` → `runtime-core`
2. `src/cli/verify.ts` → `verifier`
3. `src/types/evidence.ts` → `artifact-core`

### Rewrite targets (new implementation, inspired by pattern)
1. `src/crypto/signing.ts` → `artifact-core` **(reclassified — QUARANTINE Q1–Q6)**
2. `src/evidence/hash-chain.ts` → `runtime-core` **(reclassified — QUARANTINE Q5, Q7)**
3. `canonical.py` → `artifact-core` / `artifact-core-py` **(reclassified — QUARANTINE Q8)**
4. `src/auth/index.ts` → `registry` auth
5. `src/cli/export.ts` → `evidence-pack` export
6. `src/config/types.ts` → shared config types
7. `src/evidence/index.ts` → `evidence-pack`
8. `src/policy/engine.ts` → `policy-engine`
9. `src/policy/types.ts` → `policy-engine` types
