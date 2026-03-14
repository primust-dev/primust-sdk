# primust.com/odm

## HERO

**Headline:** Your IBM ODM rules are deterministic. Make them provable.

**Subhead:** 3 lines. Mathematical-level VPEC. Offline-verifiable by anyone.

**CTA:** Get started → primust.com/signup

---

## THE CLAIM

IBM Operational Decision Manager is deterministic. Same ruleset parameters,
same rule app, same decision output — every time. That determinism is exactly
what Mathematical-level proof requires. Primust wraps your existing ODM
execution and produces a VPEC: a signed, offline-verifiable credential proving
your rules evaluated these parameters at this time with this result. No rule
changes. No new governance layer. Your auditor verifies it with
`pip install primust-verify`.

---

## CODE BLOCK

```java
import com.primust.odm.PrimustODM;

PrimustODM adapter = new PrimustODM(
    System.getenv("PRIMUST_API_KEY"),
    null, "your_manifest_id", "underwriting-v1",
    "CreditApp", "Underwriting", null
);

// After your IlrStatelessSession.execute() call:
String commitmentHash = adapter.recordExecution(
    rulesetParams, rulesFired, decisionOutput, "pass"
);
```

---

## HOW IT WORKS

- Your ruleset parameters are committed locally via Poseidon2 before any network call
- ODM evaluates your rule app — same parameters, same rules, same decision
- Decision output and rules fired are committed separately
- After evaluation: VPEC issued with proof_level_floor: mathematical

---

## WHAT YOUR AUDITOR SEES

```
pip install primust-verify
primust verify vpec.json

  Signature valid
  Chain intact
  Proof level floor: mathematical
```

No Primust account needed. Apache-2.0. Free forever.

---

## AUTOMATIC PER-RULE MANIFEST

ODM's `getRulesFired()` API enables something no other rule engine adapter can do:
automatic manifest generation. Each rule that fires becomes a separate stage
with mathematical proof level — fine-grained proof tracking per decision path
without any manual stage mapping.

```java
List<Map<String, Object>> stages = adapter.generateStagesFromRules(rulesFired);
// → [{stage: 1, name: "MinCreditScoreCheck", proof_level: "mathematical"}, ...]
```

---

## FOR EXISTING ODM DEPLOYMENTS

You wrote the rules. We don't touch them. We sit next to your ODM instance
and produce proof each execution happened. No migration. No rule changes.
Your `IlrStatelessSession.execute()` call stays the same.
Call `adapter.recordExecution()` after — one line — and the proof layer activates.

---

## WHAT YOU GET

- VPEC with proof_level_floor: mathematical — the strongest proof level
- Offline-verifiable by anyone, anywhere, forever
- Your ODM rules stay exactly as they are
- No content transits Primust — only commitment hashes
- Per-rule stage tracking via `generateStagesFromRules()`
- Works with Decision Center, Decision Server, or embedded runtime

---

**CTA:** Get started → primust.com/signup

Sign up, get a sandbox key, first VPEC in under 5 minutes.
