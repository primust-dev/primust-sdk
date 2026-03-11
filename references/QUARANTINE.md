# Primust Quarantine List

> **Patterns that must NEVER appear in Primust.**
> Read this before running any extraction prompt P1–P8.
>
> Each entry includes the exact function, line number, and reason for quarantine.

---

## Q1: Top-Level-Only Key Sorting for Signatures

**Source:** `trustscope/src/crypto/signing.ts`
**Function:** `signAttestation()` (line 198), `verifyAttestation()` (line 210)
**Pattern:**
```typescript
const canonical = JSON.stringify(claims, Object.keys(claims).sort(), 0);
```
**Why quarantined:** `Object.keys().sort()` only sorts top-level keys. Nested objects
retain arbitrary insertion order. Two structurally identical payloads with different
nested key order produce different signatures — a canonicalization failure.

**Primust requirement:** All canonical JSON must use recursive key sorting at every
nesting depth (RFC 8785 JCS or equivalent).

---

## Q2: Key Rotation That Destroys Prior Keys

**Source:** `trustscope/src/crypto/signing.ts`
**Function:** `rotateKeys()` (lines 218–223)
**Pattern:**
```typescript
export function rotateKeys(): KeyPair {
  const keyPair = generateKeyPair();
  saveKeyPair(keyPair);  // Overwrites existing key files
  return keyPair;
}
```
**Why quarantined:** Overwrites the existing private and public key files. All prior
signatures become unverifiable because the old public key no longer exists.

**Primust requirement:** Key rotation MUST retain old public keys in the signer registry,
indexed by `kid`. Prior signatures remain valid against the `kid` that produced them.
Old keys are marked `rotated`, never deleted.

---

## Q3: `bool(signature_hex)` as Signature Verification

**Source:** `trustscope-api/app/services/evidence/redactable.py`
**Function:** `verify_redacted()` (line 411)
**Pattern:**
```python
signature_valid = bool(signature_hex)  # Simplified
```
**Why quarantined:** This treats ANY non-empty string as a valid signature. An attacker
can submit `merkle_root_signature: "AAAA"` and verification reports `signature_valid: True`.
This is a **complete bypass** of cryptographic signature verification.

**Primust requirement:** Signature verification must always call `Ed25519PublicKey.verify()`
(or equivalent) with the actual public key and message bytes. There is no acceptable
shortcut.

---

## Q4: Silent Auto-Generation of Signing Keys

**Source:** `trustscope/src/crypto/signing.ts`
**Function:** `getOrCreateKeyPair()` (lines 110–117)
**Pattern:**
```typescript
export function getOrCreateKeyPair(): KeyPair {
  let keyPair = loadKeyPair();
  if (!keyPair) {
    keyPair = generateKeyPair();
    saveKeyPair(keyPair);
  }
  return keyPair;
}
```
**Why quarantined:** Silently generates cryptographic keys without explicit user/system
action. Key generation in Primust must be an auditable, intentional operation that
records the `kid`, creation timestamp, and creating principal.

---

## Q5: Plain `'genesis'` String as Chain Genesis

**Source:** `trustscope/src/evidence/hash-chain.ts`
**Constant:** `GENESIS_HASH` (line 20)
**Pattern:**
```typescript
export const GENESIS_HASH = 'genesis';
```
**Why quarantined:** A generic genesis string means hash chains from unrelated systems
could appear to share a common root. Primust chains must be identifiable as Primust chains.

**Primust requirement:** Use `PRIMUST_CHAIN_GENESIS` — a distinct, namespaced constant
(e.g., `SHA-256("primust:chain:genesis:v1")`).

---

## Q6: `JSON.stringify(data, null, 0)` for Signing (No Sorting)

**Source:** `trustscope/src/crypto/signing.ts`
**Function:** `sign()` (line 153)
**Pattern:**
```typescript
const dataStr = typeof data === 'string' ? data : JSON.stringify(data, null, 0);
```
**Why quarantined:** No key sorting at any level. The same logical object serialized
in different key order produces a different signature. This is a canonicalization
failure distinct from Q1 (which at least sorts top-level keys).

**Primust requirement:** A single canonical serializer for all signing paths.

---

## Q7: Prohibited Field Names in Hash Chain Records

**Source:** `trustscope/src/evidence/hash-chain.ts`
**Interface:** `HashableTrace` (lines 22–31)
**Fields:**
```typescript
agent_id: string | null;    // line 25
action_type: string | null; // line 26
```
**Also used in:** `computeTraceHash()` (lines 38–45)

**Why quarantined:** `agent_id` and `action_type` are prohibited in Primust schemas.
These are AI/TrustScope-specific domain terms. Primust's core object model is
domain-neutral.

**Primust requirement:** Use domain-neutral identifiers: `record_id`, `category`,
`input_digest`, `output_digest`, etc.

---

## Q8: `default=str` Silent Type Coercion in Canonical JSON

**Source:** `trustscope-api/lib/pgc_verify/pgc_verify/canonical.py`
**Function:** `compute_document_hash()` (line 25)
**Pattern:**
```python
canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), default=str)
```
**Why quarantined:** `default=str` silently converts `datetime`, `bytes`, `UUID`, and
any other non-JSON-native type to a string representation. This means the same logical
value can hash differently depending on Python's `str()` output (which can change
between Python versions or object states).

**Primust requirement:** Canonical JSON serialization must raise on non-JSON-native
types. All values must be explicitly converted to JSON primitives before hashing.
Define an allow-list of types: `str`, `int`, `float`, `bool`, `None`, `list`, `dict`.

---

## Q9: TrustScope Branding in Webhook Headers

**Source:** `trustscope/src/detection/webhook/external-guardrail.ts`
**Location:** Line 288–289
**Pattern:**
```typescript
'X-TrustScope-Signature': signature,
'X-TrustScope-Timestamp': timestamp,
```
**Why quarantined:** TrustScope branding in any header, export, or API contract.

**Primust requirement:** Use `X-Primust-Signature` / `X-Primust-Timestamp` or
standard webhook signature headers (`Webhook-Signature` per the emerging standard).

---

## Q10: Misnamed Cryptographic Primitive

**Source:** `trustscope-api/app/services/evidence/redactable.py`
**Location:** Line 164, SQL column name `pedersen_commitment`
**Pattern:** The column and variable are called `pedersen_commitment` but the code
actually uses `Poseidon2Commitment` (line 119–121).

**Why quarantined:** Naming a Poseidon2 commitment as "Pedersen" is a cryptographic
terminology error that will cause confusion in audits and documentation.

**Primust requirement:** Name the field `poseidon2_commitment` throughout.

---

## Quarantine Summary

| ID | Severity | File | Line(s) | Pattern |
|----|----------|------|---------|---------|
| Q1 | Critical | signing.ts | 198, 210 | Top-level-only key sorting |
| Q2 | Critical | signing.ts | 218–223 | Key rotation destroys prior keys |
| Q3 | Critical | redactable.py | 411 | `bool()` as signature verification |
| Q4 | High | signing.ts | 110–117 | Silent key auto-generation |
| Q5 | Medium | hash-chain.ts | 20 | Generic `'genesis'` constant |
| Q6 | High | signing.ts | 153 | No key sorting in `sign()` |
| Q7 | High | hash-chain.ts | 25–26 | Prohibited field names (agent_id, etc.) |
| Q8 | Medium | canonical.py | 25 | `default=str` silent coercion |
| Q9 | Medium | external-guardrail.ts | 288–289 | TrustScope branding in headers |
| Q10 | Low | redactable.py | 164 | Poseidon2 misnamed as Pedersen |

---

## Extraction Gate

Before any extraction prompt (P1–P8) proceeds, the implementer must confirm:

1. No quarantined pattern (Q1–Q10) appears in the extracted code
2. All signing uses recursive canonical JSON (not `Object.keys().sort()`)
3. Key rotation preserves prior public keys in registry
4. All signature verification calls the actual cryptographic verify function
5. Genesis constant is `PRIMUST_CHAIN_GENESIS`
6. No `agent_id`, `tool_name`, `trace`, `pipeline_id`, `PGC`, or `attestation` in schemas
7. No TrustScope branding in any export, header, or string literal
