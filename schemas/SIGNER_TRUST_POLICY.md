# Primust Signer Trust Policy

> **Authoritative reference for signer identity, key lifecycle, revocation
> semantics, and verifier trust modes.**
>
> Consumers: `verifier`, `registry`, `dashboard`
> Version: 1.0
> Date: 2026-03-10

---

## 1. Signer Identity vs Key Material

A **signer** is a logical entity. A **key** is a piece of cryptographic material
that a signer uses during a specific period.

### signer_id

- Stable logical identifier for the signing entity.
- Format: `signer_<random>` (e.g., `signer_7f3a9b2c`)
- Survives key rotation. A signer_id assigned on day one remains the same
  signer_id after 50 rotations.
- Uniquely identifies the principal (person, service, organization) that signs.
- **Immutable once assigned.** Cannot be renamed or reassigned.

### kid

- Identifies a specific Ed25519 key version.
- Format: `kid_<random>` (e.g., `kid_e4c1d8a0`)
- Generated at key creation time. Never reused.
- Embedded in every signed envelope so the verifier knows which public key
  to retrieve.

### Relationship

```
signer_id (1) ──── has ────► (N) kid records

  signer_7f3a9b2c
    ├── kid_e4c1d8a0  (active)
    ├── kid_a2b9f301  (rotated 2026-02-15)
    └── kid_00c4e7d2  (revoked 2026-01-10, key_compromise)
```

- One `signer_id` has one or more `kid` records over its lifetime.
- Exactly one `kid` per `signer_id` may be in `active` state at any time.
- Rotation creates a new `kid` under the same `signer_id`. The old `kid`
  transitions to `rotated`.

### Invariants

- Every signed envelope MUST contain both `signer_id` and `kid`.
- `signer_id` without `kid` is invalid. `kid` without `signer_id` is invalid.
- The verifier resolves the public key by `kid`, not by `signer_id`.
- The registry indexes keys by both `signer_id` (for listing) and `kid`
  (for lookup).

---

## 2. Key Lifecycle States

Every `kid` record has exactly one of three states:

| State | Meaning | Can sign? | In JWKS? |
|-------|---------|-----------|----------|
| `active` | Current signing key for this signer_id | Yes | Yes |
| `rotated` | Replaced by a newer key; still trusted for historical verification | No | Yes |
| `revoked` | Trust withdrawn; see revocation semantics | No | No |

### State transitions

```
             rotate()              revoke()
  active ──────────► rotated ──────────► revoked
    │                                      ▲
    └──────────────── revoke() ────────────┘
```

- `active → rotated`: Key rotation. A new `kid` is created with state `active`.
  The old `kid` moves to `rotated`. **Prior signatures remain valid.**
- `rotated → revoked`: Trust withdrawal. Requires `revocation_reason`.
- `active → revoked`: Emergency revocation (e.g., key compromise).
  Requires `revocation_reason`.
- No other transitions are permitted. States are terminal:
  `rotated` cannot return to `active`. `revoked` cannot return to any state.

### Key record fields

```
kid:                string        // unique key identifier
signer_id:          string        // parent signer
state:              "active" | "rotated" | "revoked"
algorithm:          "Ed25519"     // only supported algorithm at v1
public_key_hex:     string        // hex-encoded 32-byte Ed25519 public key
created_at:         string        // ISO 8601
rotated_at:         string | null // ISO 8601, set when state → rotated
revoked_at:         string | null // ISO 8601, set when state → revoked
revocation_reason:  "key_compromise" | "decommissioned" | null
```

---

## 3. Revocation Semantics

Revocation is not a single behavior. The meaning of a revoked key depends on
**why** it was revoked and **whether** the artifact has a trusted timestamp.

### 3a. Key Compromise

```
revocation_reason: "key_compromise"
```

The private key was exposed, stolen, or suspected compromised. All signatures
produced by this `kid` are untrustworthy — including those made before the
compromise was discovered, because the attacker may have used the key at any
time.

**Verifier behavior: FAIL always.** No timestamp evaluation. No grace period.
Every artifact signed by a compromised `kid` fails verification regardless
of when it was signed.

### 3b. Decommissioned + RFC 3161 Timestamp

```
revocation_reason: "decommissioned"
timestamp_anchor.type: "rfc3161"
```

The key was retired through normal operational lifecycle. There is no indication
the key material was ever exposed. Artifacts carry a trusted third-party
timestamp from a DigiCert (or equivalent) TSA.

**Verifier behavior: Evaluate `signed_at` vs `revoked_at`.**

```
if artifact.timestamp_anchor.signed_at < kid.revoked_at:
    → PASS (signed before decommission)
else:
    → FAIL (signed after decommission — key should not have been in use)
```

The RFC 3161 timestamp is the verifier's evidence that the signature was
produced at a specific time. Without it, the verifier cannot distinguish
"signed before decommission" from "signed after."

### 3c. Decommissioned + No Timestamp

```
revocation_reason: "decommissioned"
timestamp_anchor.type: "none"
```

The key was retired normally, but the artifact has no trusted timestamp anchor.
The verifier cannot determine when the signature was produced.

**Verifier behavior (default mode): WARN, not FAIL.**

Rationale: The key was not compromised. The signature may well have been produced
during the key's active or rotated period. However, without a timestamp anchor
the verifier cannot prove this, so it warns rather than asserting validity.

### Decision matrix

| revocation_reason | timestamp_anchor | signed_at < revoked_at? | Result |
|-------------------|------------------|-------------------------|--------|
| `key_compromise` | any | N/A | **FAIL** |
| `key_compromise` | none | N/A | **FAIL** |
| `decommissioned` | `rfc3161` | yes | **PASS** |
| `decommissioned` | `rfc3161` | no | **FAIL** |
| `decommissioned` | `none` | unknown | **WARN** |

---

## 4. Verifier Trust Policy Modes

The verifier accepts a `--trust-policy` flag (or equivalent config) that
controls how revoked keys are handled.

### `--strict`

Revoked `kid` → **FAIL always**, regardless of reason or timestamp.

No distinction between `key_compromise` and `decommissioned`. If a key is
revoked, every artifact it signed is rejected.

Use case: high-assurance environments where any revocation is disqualifying.

```
key_compromise   + any timestamp   → FAIL
decommissioned   + rfc3161         → FAIL
decommissioned   + none            → FAIL
```

### `--default`

Applies the full revocation semantics from Section 3.

```
key_compromise   + any timestamp   → FAIL
decommissioned   + rfc3161         → evaluate signed_at vs revoked_at
decommissioned   + none            → WARN
```

This is the mode used when no `--trust-policy` flag is specified.

### `--permissive`

All revocation conditions produce **WARN**, never FAIL.

The verifier reports findings but does not reject any artifact based on
key state alone.

Use case: forensic analysis, historical review, or environments where
signature state is advisory rather than enforced.

```
key_compromise   + any timestamp   → WARN
decommissioned   + rfc3161         → WARN (or PASS if signed_at < revoked_at)
decommissioned   + none            → WARN
```

### Summary table

| Condition | `--strict` | `--default` | `--permissive` |
|-----------|------------|-------------|----------------|
| `active` kid | PASS | PASS | PASS |
| `rotated` kid | PASS | PASS | PASS |
| `key_compromise` | FAIL | FAIL | WARN |
| `decommissioned` + rfc3161 + before | FAIL | PASS | PASS |
| `decommissioned` + rfc3161 + after | FAIL | FAIL | WARN |
| `decommissioned` + no timestamp | FAIL | WARN | WARN |

---

## 5. JWKS Inclusion Rules

The registry exposes a JWKS endpoint for public key discovery. Inclusion is
determined by key state:

| State | Included in JWKS? | Reason |
|-------|-------------------|--------|
| `active` | **YES** | Current signing key — consumers need it to verify new artifacts |
| `rotated` | **YES** | Historical artifacts still reference this `kid` — consumers need the public key to verify them |
| `revoked` | **NO** | Trust is withdrawn; the key must not be discoverable via the standard trust endpoint |

### Revoked key retrieval

Revoked keys are excluded from the JWKS set but are **not deleted** from the
registry database. The verifier retrieves revoked keys through a separate
authenticated endpoint:

```
GET /registry/keys/{kid}          → returns key record including revoked keys
GET /.well-known/jwks.json        → returns only active + rotated keys
```

This separation ensures:
- Public consumers (auditors, third parties) who trust the JWKS endpoint never
  receive a revoked key as if it were trustworthy.
- The verifier can still look up revoked keys to produce FAIL/WARN results
  with full context (revocation_reason, revoked_at).

### JWKS entry format

Each entry in the JWKS `keys` array follows RFC 8037 (OKP key type):

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "kid": "kid_e4c1d8a0",
  "x": "<base64url-encoded 32-byte public key>",
  "use": "sig",
  "key_ops": ["verify"],
  "x-primust-signer-id": "<signer_id>",
  "x-primust-state": "active"
}
```

- `x-primust-signer-id` and `x-primust-state` are custom claims. They are
  informational — the verifier does not trust them. It fetches the full key
  record from the registry for state evaluation.
- `rotated` keys have `"key_ops": ["verify"]` (never `"sign"`).

---

## 6. Timestamp Anchor Role

### Trusted timestamp authority

**RFC 3161 (DigiCert TSA)** is the only trusted timestamp anchor in Primust v1.

An RFC 3161 timestamp is a countersignature from a trusted third-party Time
Stamping Authority that binds a hash to a point in time. It proves the hash
existed at or before the stated time, independent of the signer's clock.

### Timestamp anchor in artifact envelope

Every signed artifact envelope contains a `timestamp_anchor` field:

```json
{
  "timestamp_anchor": {
    "type": "rfc3161",
    "signed_at": "2026-03-10T14:30:00Z",
    "tsa": "http://timestamp.digicert.com",
    "token_b64": "<base64-encoded RFC 3161 TimeStampToken>"
  }
}
```

Or, when no timestamp anchor is present:

```json
{
  "timestamp_anchor": {
    "type": "none"
  }
}
```

### Rules

1. `timestamp_anchor.type` MUST be either `"rfc3161"` or `"none"`.
   No other values are accepted at v1.
2. When `type` is `"rfc3161"`, the `signed_at`, `tsa`, and `token_b64` fields
   are REQUIRED. The verifier MUST validate the RFC 3161 token against the
   TSA's certificate chain before trusting `signed_at`.
3. When `type` is `"none"`, no other fields are present. The verifier treats
   the signing time as unknown.
4. The verifier MUST NOT use `envelope.created_at` or any signer-asserted
   timestamp as a substitute for an RFC 3161 anchor. Self-asserted timestamps
   are informational only and carry no trust weight in revocation evaluation.
5. Artifacts without timestamp anchors are not invalid — they are verifiable
   against `active` and `rotated` keys. They only produce degraded results
   (WARN instead of PASS/FAIL) when verified against `decommissioned` keys,
   because the verifier cannot evaluate timing.
