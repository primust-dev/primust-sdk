# primust-cedar

Your Cedar policies are deterministic. That means they're mathematically provable.

AWS built Cedar for AI agent authorization. We built the proof layer on top.
Wrap your existing Cedar policy in 3 lines — get a Mathematical-level VPEC
proving your policy evaluated this request at this time with this result.

## Why Mathematical level

Cedar is deterministic. Same principal + same action + same resource + same pinned
policy set = same authorization decision, every time. Primust's manifest system
maps deterministic rule engines to Mathematical proof level automatically.
No configuration. No upgrade. It's what the check actually is.

Mathematical-level proof means: no trust in any vendor, model, or person required.
The arithmetic proves it. Your auditor verifies it offline with:

```bash
pip install primust-verify
primust verify vpec.json
```

## Install

Maven:

```xml
<dependency>
    <groupId>com.primust</groupId>
    <artifactId>primust-cedar</artifactId>
    <version>0.1.0</version>
</dependency>
```

## 3-line integration

```java
import com.primust.cedar.PrimustCedar;

PrimustCedar adapter = new PrimustCedar(
    System.getenv("PRIMUST_API_KEY"),
    null,  // default: api.primust.com
    "your_manifest_id",
    "authz-v1",
    policySetHash,
    null   // default: opaque visibility
);

// After your Cedar isAuthorized() call:
String commitmentHash = adapter.recordEvaluation(
    principal, action, resource, context, decision, diagnostics
);
// commitmentHash — Poseidon2 commitment (input never leaves)
// decision — your Cedar result, unchanged
```

Your existing Cedar authorization call stays exactly as it is.
After `isAuthorized()` returns, call `adapter.recordEvaluation()` with the
Cedar inputs and result. Primust commits the input locally, records the
evaluation, and produces a VPEC.

## What you get

- VPEC with proof_level_floor: mathematical
- Offline-verifiable by anyone: `pip install primust-verify`
- Your Cedar policies stay exactly as they are — no policy changes
- No content transits Primust — only commitment hashes

## How it works

1. **Policy pinning:** Compute `SHA-256(cedar_policy_set)` and pass it as `policySetHash` to the adapter constructor. This hash is committed in the check manifest, binding this exact policy version to the governance record.

2. **Input commitment:** `recordEvaluation()` calls `CanonicalJson.canonical(input)` → `Commitment.commit(bytes)` to compute a Poseidon2 commitment locally. The raw authorization request (principal, action, resource, context) never leaves your environment.

3. **Deterministic evaluation:** Cedar evaluates your policy set. Same request + same pinned policy set = same decision, every time.

4. **Mathematical proof level:** The manifest declares `stage_type: deterministic_rule`. The proof level is derived automatically — not configured, not a premium. It falls out of the manifest system because the check is deterministic.

## Surface declaration

```java
SurfaceDeclaration.DECLARATION
// → {
//     "surface_type":     "policy_engine",
//     "stage_type":       "deterministic_rule",
//     "observation_mode": "instrumentation",
//     "scope_type":       "per_evaluation",
//     "proof_ceiling":    "mathematical",
//     "adapter":          "primust-cedar",
//     "engine":           "AWS Cedar"
// }
```

## Verify a VPEC

```bash
pip install primust-verify
primust verify vpec.json --trust-root primust-pubkey.pem
```

No Primust account required. Apache-2.0. Free forever. Works offline.

## Learn more

[docs.primust.com/adapters/cedar](https://docs.primust.com/adapters/cedar)
