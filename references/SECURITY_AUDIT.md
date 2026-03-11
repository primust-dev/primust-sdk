# Primust Pre-Extraction Security Audit

> **This document must be read before running any extraction prompt P1–P8.**
>
> Audit date: 2026-03-10
> Auditor: Claude Code (automated)
> Scope: 6 TrustScope source files nominated for extraction

---

## File 1: signing.ts

**Source:** `trustscope/src/crypto/signing.ts` (238 lines)
**Purpose:** Ed25519 key management, signing, verification

### SAFE TO PORT

- `generateKeyPair()` (line 63–67): Clean Ed25519 keypair generation via `@noble/ed25519`. No issues.
- `bytesToHex()` / `hexToBytes()` (lines 43–58): Standard hex encoding. Safe.
- `verify()` (lines 173–189): Correct Ed25519 verification. Uses `@noble/ed25519` properly.
- `exportPublicKey()` (lines 228–237): Simple accessor. Safe.
- General pattern of using `@noble/ed25519` with `@noble/hashes/sha2` for SHA-512 configuration (line 15).

### REWRITE REQUIRED

1. **`signAttestation()` — TOP-LEVEL-ONLY key sorting (CRITICAL)**
   - Line 198: `JSON.stringify(claims, Object.keys(claims).sort(), 0)`
   - `Object.keys(claims).sort()` produces a replacer array of **top-level keys only**.
   - Nested objects retain their original insertion order.
   - **Primust requires recursive canonical sorting.** Two structurally identical objects
     with different nested key order will produce different signatures.
   - **Verdict: REWRITE.** Replace with a recursive canonical JSON function
     (RFC 8785 JCS or equivalent deep-sort-then-serialize).

2. **`verifyAttestation()` — same top-level-only sorting bug**
   - Line 210: Same `Object.keys(claims).sort()` pattern.
   - Verification will fail on any payload that was signed with a different key order
     at any nesting depth.
   - **Verdict: REWRITE.** Must use the same recursive canonical function as signing.

3. **`sign()` — no canonical form at all for objects**
   - Line 153: `JSON.stringify(data, null, 0)` — no key sorting whatsoever.
   - If the same object is serialized with keys in different order, it produces
     different signatures.
   - **Verdict: REWRITE.** All signing paths must use a single canonical serializer.

4. **Key storage paths hardcoded to `~/.trustscope/keys/`**
   - Lines 17–19: Paths reference TrustScope brand.
   - **Verdict: REWRITE.** Primust must use configurable key paths.

5. **No `kid` (key ID) support**
   - Keys are stored as bare files with no identifier.
   - Primust requires key IDs for multi-key registry and rotation.
   - **Verdict: REWRITE.** Add kid assignment on generation.

### DROP

1. **`rotateKeys()` — destroys prior key, invalidating all signatures (CRITICAL)**
   - Lines 218–223: Comment explicitly states "WARNING: This invalidates all previous
     signatures." Implementation overwrites the private and public key files.
   - **In Primust: rotating a key MUST NOT invalidate prior signatures.** Prior signatures
     remain valid against the `kid` that signed them. The old public key must be retained
     in the registry (marked as rotated, not deleted).
   - **Verdict: DROP.** This function and its entire rotation model must not appear
     in Primust. Build a new rotation system with kid-based key registry.

2. **`getOrCreateKeyPair()` — silent auto-generation**
   - Lines 110–117: Silently generates keys if none exist. In Primust, key generation
     must be an explicit, auditable action.
   - **Verdict: DROP.** Key provisioning should require explicit invocation.

---

## File 2: external-guardrail.ts

**Source:** `trustscope/src/detection/webhook/external-guardrail.ts` (497 lines)
**Purpose:** Webhook-based BYO detection engine for external guardrails

### SAFE TO PORT

- `generateSignature()` (lines 172–174): Clean HMAC-SHA256 webhook signing. Generic, reusable.
- `computeExternalGuardrailHash()` (lines 180–196): Pipe-delimited canonical hash.
  Pattern is sound (deterministic concatenation + SHA-256). Field names need renaming.
- Timeout budget management pattern (lines 88, 151–163): Well-designed per-org timeout
  budgeting. Extractable pattern.
- Fail-open / fail-closed error handling (lines 362–410): Good pattern for configurable
  failure modes.

### REWRITE REQUIRED

- Entire file is deeply coupled to TrustScope detection engine interfaces
  (`DetectionEngine`, `DetectionResult`, `DetectionContext`, `DetectionConfig`).
- Headers use `X-TrustScope-Signature` and `X-TrustScope-Timestamp` (line 288–289).
  Must be renamed for Primust.
- Payload fields include `agent_id`, `trace_id` (lines 53–63) — prohibited in Primust schemas.

### DROP

- **No hardcoded fallback encryption key found.** Issue #3 is NOT present in this file.
  The `secret` field is always supplied via `ExternalGuardrailConfig.secret`.
- **No scrypt usage found.** Issue #4 is NOT present. The file uses HMAC-SHA256 only.
- **However: the file is overwhelmingly TrustScope/AI-specific.** The core interfaces
  (`DetectionEngine`, `DetectionContext`) and payload structure (`agent_id`, `tool_calls`,
  `trace_id`) make this unsuitable for direct extraction.
- `testExternalGuardrail()` (lines 447–493): Contains hardcoded TrustScope test payload
  with `agentId`, `actionType`, "test payload from TrustScope" string literal.
- **Verdict: DROP the file as a whole.** Extract only the HMAC signing pattern and
  fail-mode pattern as standalone utilities. Do not reference this file.

---

## File 3: redactable.py

**Source:** `trustscope-api/app/services/evidence/redactable.py` (583 lines)
**Purpose:** Redactable evidence packs with Merkle proofs and Poseidon2 commitments

### SAFE TO PORT

- `RedactionResult` dataclass (lines 42–51): Clean result type. Rename `pack_id` fields.
- `VerificationResult` dataclass (lines 54–68): Clean verification result type.
- `prepare_for_redaction()` (lines 88–186): Well-structured Merkle tree + Poseidon2
  commitment flow. The cryptographic logic is sound. Must decouple from SQLAlchemy.
- `redact()` (lines 188–375): Solid redaction logic. ZIP assembly is clean.
  Path traversal isn't a risk here (we control paths). Must decouple from DB.
- `_write_redaction_verification_instructions()` (lines 490–524): Contains TrustScope
  branding ("signed by TrustScope") — must rewrite text, but the pattern of including
  verification instructions is good.

### REWRITE REQUIRED

- All DB access via `AsyncSession` + raw SQL `text()` queries must be abstracted
  to a storage interface.
- `_get_signing_key()` (lines 78–86): Generates ephemeral key per instance with
  comment "In production, load from HSM/KMS." Must implement proper key loading
  from Primust registry.
- Column name `pedersen_commitment` (line 164) — TrustScope names this incorrectly
  (it's actually Poseidon2, not Pedersen). Primust must use correct naming.

### DROP

1. **`verify_redacted()` — uses `bool(signature_hex)` for signature validation (CRITICAL)**
   - Line 411: `signature_valid = bool(signature_hex)  # Simplified`
   - This means **ANY non-empty string passes as a valid signature.** The comment
     says "Simplified" but this is a complete bypass of signature verification.
   - An attacker can submit a pack with `merkle_root_signature: "anything"` and
     it will report `signature_valid: True`.
   - **Verdict: DROP this entire verification path.** Rebuild signature verification
     from scratch using proper Ed25519 `verify()` with public key lookup.

2. **TrustScope branding in verification instructions** (lines 492–524):
   - References "TrustScope" and "TrustScope public key" throughout.
   - **Verdict: DROP these strings.** Rewrite instructions for Primust.

---

## File 4: canonical.py

**Source:** `trustscope-api/lib/pgc_verify/pgc_verify/canonical.py` (70 lines)
**Purpose:** Canonical JSON hashing for PGC documents

### SAFE TO PORT

- `compute_document_hash()` (lines 16–26): Uses `json.dumps(document, sort_keys=True,
  separators=(",", ":"), default=str)` which IS recursive key sorting (Python's
  `sort_keys=True` sorts at all nesting levels). The hashing pattern is correct.
  - **Note:** The `default=str` parameter silently converts non-serializable types
    (datetime, bytes, custom objects) to strings. This is acceptable for hashing
    but must be documented as a contract: all values must be JSON-native types
    or explicitly converted before hashing.

- `reconstruct_unsigned_document()` (lines 29–69): Clean document reconstruction
  for verification. The pattern of nulling signature fields, computing hash, then
  comparing is standard and correct. Uses `copy.deepcopy` to avoid mutations.

### REWRITE REQUIRED

- Remove all PGC terminology ("PGC document", "signed PGC", etc.).
- Remove references to `signature.dilithium3` (post-quantum field, line 37, 67) —
  Primust may add PQC later but should not inherit TrustScope's PQC structure.
- Rename `InvalidDocumentError` import from `.exceptions` — use Primust-native exceptions.
- The `default=str` in `json.dumps` should be replaced with explicit type checking
  that raises on non-JSON-native types, to prevent silent coercion.

### DROP

- Nothing to drop. The file is small and clean.

---

## File 5: verifier.py

**Source:** `trustscope-api/app/services/evidence/verifier.py` (728 lines)
**Purpose:** 4-level evidence pack verification

### SAFE TO PORT

- `VerificationLevel` enum (lines 36–40): Clean enum. Rename if needed.
- `VerificationStatus` enum (lines 43–48): Clean enum.
- `LevelResult` / `VerificationResult` dataclasses (lines 51–76): Well-structured
  result types.
- `_compute_hash()` (lines 91–94): Uses `sort_keys=True` — recursive canonical JSON. Correct.
- `_compute_file_hash()` (lines 96–102): Chunked SHA-256 file hashing. Correct.
- `_safe_extract_zip()` (lines 104–148): **Excellent security.** Blocks path traversal,
  zip bombs (entry count + total size limits), symlinks, and validates extraction targets.
  Port this directly.
- `_verify_manifest()` (lines 311–387): Proper Ed25519 signature verification using
  `cryptography` library. Catches `InvalidSignature` exception correctly.
- `_verify_artifacts()` (lines 389–479): Sound artifact hash verification with
  JSON content hashing and binary file hashing.
- `_verify_chain()` (lines 481–582): Chain integrity verification against database.
  Pattern is good; must decouple from SQLAlchemy.
- 4-level verification architecture (manifest → artifact → chain → completeness):
  The overall design pattern is solid and should be preserved in Primust.

### REWRITE REQUIRED

- All SQLAlchemy database access (`AsyncSession`, `text()` queries) must be abstracted
  behind a storage/registry interface.
- `_get_public_key()` (lines 150–165): Fetches from `signing_keys` table. Must use
  Primust signer registry instead.
- `_verify_completeness()` (lines 584–661): Contains TrustScope-specific compliance
  framework scoring (trust_model, period, etc.). Rewrite for Primust domain.
- Import of `app.services.hash_chain.verify_chain` (line 29): Must use Primust's
  own chain verification.

### DROP

- `app.config.get_settings` import (line 31): TrustScope config system. Use Primust config.
- All references to `trust_model`, `framework_code`, compliance-specific fields.

---

## File 6: hash-chain.ts

**Source:** `trustscope/src/evidence/hash-chain.ts` (153 lines)
**Purpose:** SHA-256 hash chain for tamper-evident evidence traces

### SAFE TO PORT

- `computeTraceHash()` (lines 36–49): Pipe-delimited canonical hashing with SHA-256.
  The concatenation pattern is deterministic and correct. Field names must change.
- `verifyTraceHash()` (lines 54–67): Correct hash recomputation and comparison.
- `verifyChain()` (lines 72–128): Sound chain verification — walks the chain from
  genesis, verifies each link's prev_hash and audit_hash. Returns detailed break info.
- `computeMerkleRoot()` (lines 133–152): Standard recursive Merkle root with
  last-element duplication for odd counts. Correct implementation.

### REWRITE REQUIRED

1. **Genesis constant is plain `'genesis'` literal (CONFIRMED)**
   - Line 20: `export const GENESIS_HASH = 'genesis';`
   - **Primust requires `PRIMUST_CHAIN_GENESIS`** as the genesis constant.
   - This is a namespace/identity issue — using a generic string means chains from
     different systems could appear compatible when they are not.
   - **Verdict: REWRITE.** Use `PRIMUST_CHAIN_GENESIS` (a defined constant, potentially
     the SHA-256 of a Primust-specific seed string for added uniqueness).

2. **`HashableTrace` interface uses prohibited field names**
   - Line 25: `agent_id: string | null` — prohibited in Primust.
   - Line 26: `action_type: string | null` — prohibited in Primust.
   - Lines 38–45: `computeTraceHash` references `trace.agent_id`, `trace.action_type`,
     `trace.request_summary`, `trace.response_summary` — all AI/TrustScope-specific.
   - **Verdict: REWRITE.** Define Primust-native `HashableRecord` interface with
     domain-neutral field names (e.g., `record_id`, `category`, `input_digest`,
     `output_digest`).

3. **Empty Merkle tree sentinel is `'empty'` string literal**
   - Line 135: `createHash('sha256').update('empty').digest('hex')`
   - Should use a named constant like `PRIMUST_EMPTY_TREE`.
   - **Verdict: REWRITE.** Minor but should be a named constant.

4. **Type imports reference TrustScope types**
   - Line 17: `import type { Trace, ChainVerificationResult } from '../types/evidence.js';`
   - Line 18: `import type { EvidenceStore } from './store.js';`
   - **Verdict: REWRITE.** Define Primust-native types.

### DROP

- The TrustScope-specific type imports and field names (`agent_id`, `action_type`,
  `trace`, `source` as used in TrustScope context).
- The `// TODO: Implement full functionality (TASK 3)` comment (line 14) and the
  comment "TODO: Implement full chain verification" (line 73) — these are stale
  TrustScope development artifacts.

---

## Summary of Known Issue Verification

| # | Issue | File | Status | Severity | Action |
|---|-------|------|--------|----------|--------|
| 1 | `signAttestation()` top-level-only sorting | signing.ts:198 | **CONFIRMED** | Critical | REWRITE |
| 2 | `rotateKeys()` invalidates prior signatures | signing.ts:218-223 | **CONFIRMED** | Critical | DROP |
| 3 | Hardcoded fallback encryption key | external-guardrail.ts | **NOT FOUND** | — | N/A |
| 4 | Static scrypt salt | external-guardrail.ts | **NOT FOUND** | — | N/A |
| 5 | `bool(signature_hex)` verification bypass | redactable.py:411 | **CONFIRMED** | Critical | DROP |
| 6 | Plain `'genesis'` literal | hash-chain.ts:20 | **CONFIRMED** | Medium | REWRITE |

## Additional Findings (Not in Original Checklist)

| # | Issue | File | Severity | Action |
|---|-------|------|----------|--------|
| A1 | `sign()` has no canonical form for objects | signing.ts:153 | High | REWRITE |
| A2 | No kid (key ID) support anywhere | signing.ts | High | REWRITE |
| A3 | `getOrCreateKeyPair()` silent key generation | signing.ts:110-117 | Medium | DROP |
| A4 | `default=str` silent type coercion in hashing | canonical.py:25 | Medium | REWRITE |
| A5 | Misnamed `pedersen_commitment` (is actually Poseidon2) | redactable.py:164 | Low | REWRITE |
| A6 | external-guardrail.ts is wholly TrustScope-specific | external-guardrail.ts | — | DROP file |
| A7 | `HashableTrace` uses prohibited fields (agent_id, etc.) | hash-chain.ts:23-31 | High | REWRITE |
