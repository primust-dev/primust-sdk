# primust-drools

Your Drools rules are deterministic. That means they're mathematically provable.

Wrap your existing KIE session in 3 lines. Get a Mathematical-level VPEC —
a signed, offline-verifiable credential proving your rules evaluated these
facts at this time with this result.

## Why Mathematical level

Drools (KIE) is deterministic. Same facts + same pinned rule base = same
rules fired, every time. Primust's manifest system maps deterministic rule
engines to Mathematical proof level automatically. No configuration. No upgrade.
It's what the check actually is.

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
    <artifactId>primust-drools</artifactId>
    <version>0.1.0</version>
</dependency>
```

## 3-line integration

```java
import com.primust.drools.PrimustDrools;

PrimustDrools adapter = new PrimustDrools(
    System.getenv("PRIMUST_API_KEY"),
    null,  // default: api.primust.com
    "your_manifest_id",
    "underwriting-v1",
    null   // default: opaque visibility
);

// After your KieSession.fireAllRules() call:
String commitmentHash = adapter.recordEvaluation(
    List.of(fact1, fact2), rulesFired, "pass"
);
// commitmentHash — Poseidon2 commitment (facts never leave)
// rulesFired — your Drools result, unchanged
```

Your existing KIE session stays exactly as it is.
After `fireAllRules()` returns, call `adapter.recordEvaluation()` with the
facts, rule count, and result. Primust commits the facts locally, records the
evaluation, and produces a VPEC.

## With rule names

```java
// If you want per-rule tracking:
String commitmentHash = adapter.recordEvaluationWithRules(
    List.of(fact1, fact2),
    List.of("MinScoreCheck", "MaxDTICheck", "CollateralRequirement"),
    "pass"
);
```

Rule names are committed separately — the verifier sees the commitment, not the names.

## What you get

- VPEC with proof_level_floor: mathematical
- Offline-verifiable by anyone: `pip install primust-verify`
- Your DRL/Rete rules stay exactly as they are — no rule changes
- No content transits Primust — only commitment hashes

## How it works

1. **Fact commitment:** `recordEvaluation()` calls `CanonicalJson.canonical(facts)` → `Commitment.commit(bytes)` to compute a Poseidon2 commitment locally. The raw facts never leave your environment.

2. **Deterministic evaluation:** Drools evaluates your rule base. Same facts + same rules = same rules fired, every time.

3. **Mathematical proof level:** The manifest declares `stage_type: deterministic_rule`. The proof level is derived automatically — not configured, not a premium. It falls out of the manifest system because the check is deterministic.

## Surface declaration

```java
SurfaceDeclaration.DECLARATION
// → {
//     "surface_type":     "policy_engine",
//     "stage_type":       "deterministic_rule",
//     "observation_mode": "instrumentation",
//     "scope_type":       "per_evaluation",
//     "proof_ceiling":    "mathematical",
//     "adapter":          "primust-drools",
//     "engine":           "Drools (KIE)"
// }
```

## Verify a VPEC

```bash
pip install primust-verify
primust verify vpec.json --trust-root primust-pubkey.pem
```

No Primust account required. Apache-2.0. Free forever. Works offline.

## Learn more

[docs.primust.com/adapters/drools](https://docs.primust.com/adapters/drools)
