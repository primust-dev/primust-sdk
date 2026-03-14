# primust-odm

Your IBM ODM rules are deterministic. That means they're mathematically provable.

Wrap your existing ODM ruleset execution in 3 lines. Get a Mathematical-level VPEC —
a signed, offline-verifiable credential proving your rules evaluated these
parameters at this time with this result.

## Why Mathematical level

IBM Operational Decision Manager is deterministic. Same ruleset parameters +
same pinned rule app = same decision output, every time. Primust's manifest
system maps deterministic rule engines to Mathematical proof level automatically.
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
    <artifactId>primust-odm</artifactId>
    <version>0.1.0</version>
</dependency>
```

Note: `jrules-engine` JAR is distributed via IBM Passport Advantage, not Maven Central.
The adapter compiles against interfaces; you provide the runtime JAR.

## 3-line integration

```java
import com.primust.odm.PrimustODM;

PrimustODM adapter = new PrimustODM(
    System.getenv("PRIMUST_API_KEY"),
    null,  // default: api.primust.com
    "your_manifest_id",
    "underwriting-v1",
    "CreditApp",       // ruleApp
    "Underwriting",    // ruleSet
    null               // default: opaque visibility
);

// After your IlrStatelessSession.execute() call:
String commitmentHash = adapter.recordExecution(
    rulesetParams, rulesFired, decisionOutput, "pass"
);
// commitmentHash — Poseidon2 commitment (params never leave)
// decisionOutput — your ODM result, unchanged
```

Your existing ODM session stays exactly as it is.
After `execute()` returns, call `adapter.recordExecution()` with the
parameters, rules fired, decision output, and result. Primust commits
everything locally and produces a VPEC.

## Automatic manifest from getRulesFired()

ODM's `getRulesFired()` API enables automatic per-rule stage recording.
Each rule that fires becomes a separate stage in the manifest:

```java
List<Map<String, Object>> stages = adapter.generateStagesFromRules(rulesFired);
// Each stage: { stage: 1, name: "MinCreditScoreCheck", type: "policy_engine",
//               proof_level: "mathematical", method: "deterministic_rule" }
```

Fine-grained proof-level tracking per decision path without any manual stage mapping.

## What you get

- VPEC with proof_level_floor: mathematical
- Offline-verifiable by anyone: `pip install primust-verify`
- Your ODM rules stay exactly as they are — no rule changes
- No content transits Primust — only commitment hashes
- Per-rule stage tracking via `generateStagesFromRules()`

## How it works

1. **Input commitment:** `recordExecution()` calls `CanonicalJson.canonical(rulesetParams)` → `Commitment.commit(bytes)` to compute a Poseidon2 commitment locally. The raw ruleset parameters never leave your environment.

2. **Output commitment:** Decision output is committed the same way. Only commitment hashes transit to Primust.

3. **Rules commitment:** The list of rules fired is committed separately — the verifier sees the commitment, not the rule names.

4. **Deterministic evaluation:** ODM evaluates your rule app. Same parameters + same rules = same decision, every time.

5. **Mathematical proof level:** The manifest declares `stage_type: deterministic_rule`. The proof level is derived automatically — not configured, not a premium. It falls out of the manifest system because the check is deterministic.

## Surface declaration

```java
SurfaceDeclaration.DECLARATION
// → {
//     "surface_type":     "policy_engine",
//     "stage_type":       "deterministic_rule",
//     "observation_mode": "instrumentation",
//     "scope_type":       "per_evaluation",
//     "proof_ceiling":    "mathematical",
//     "adapter":          "primust-odm",
//     "engine":           "IBM Operational Decision Manager"
// }
```

## Verify a VPEC

```bash
pip install primust-verify
primust verify vpec.json --trust-root primust-pubkey.pem
```

No Primust account required. Apache-2.0. Free forever. Works offline.

## Learn more

[docs.primust.com/adapters/odm](https://docs.primust.com/adapters/odm)
