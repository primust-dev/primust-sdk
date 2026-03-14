# primust.com/drools

## HERO

**Headline:** Your Drools rules are deterministic. Make them provable.

**Subhead:** 3 lines. Mathematical-level VPEC. Offline-verifiable by anyone.

**CTA:** Get started → primust.com/signup

---

## THE CLAIM

Drools is deterministic. Same facts, same rule base, same rules fired — every time.
That determinism is exactly what Mathematical-level proof requires.
Primust wraps your existing KIE session and produces a VPEC:
a signed, offline-verifiable credential proving your rules evaluated these
facts at this time with this result. No rule changes. No new governance layer.
Your auditor verifies it with `pip install primust-verify`.

---

## CODE BLOCK

```java
import com.primust.drools.PrimustDrools;

PrimustDrools adapter = new PrimustDrools(
    System.getenv("PRIMUST_API_KEY"),
    null, "your_manifest_id", "underwriting-v1", null
);

// After your KieSession.fireAllRules() call:
String commitmentHash = adapter.recordEvaluation(
    List.of(fact1, fact2), rulesFired, "pass"
);
```

---

## HOW IT WORKS

- Your facts are committed locally via Poseidon2 before any network call
- Drools evaluates your rule base — same facts, same rules, same result
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

## FOR EXISTING DROOLS DEPLOYMENTS

You wrote the DRL. We don't touch it. We sit next to your KIE session
and produce proof it evaluated. No migration. No rule changes.
Your `KieSession.fireAllRules()` call stays the same.
Call `adapter.recordEvaluation()` after — one line — and the proof layer activates.

---

## PER-RULE TRACKING

ODM and Drools both support per-rule stage recording. Each rule that fires
becomes a separate stage in the manifest with mathematical proof level.
Call `adapter.recordEvaluationWithRules()` with the rule names — fine-grained
proof tracking without any manual stage mapping.

---

## WHAT YOU GET

- VPEC with proof_level_floor: mathematical — the strongest proof level
- Offline-verifiable by anyone, anywhere, forever
- Your DRL/Rete rules stay exactly as they are
- No content transits Primust — only commitment hashes
- Works with any Drools deployment: embedded, KIE Server, Kogito

---

**CTA:** Get started → primust.com/signup

Sign up, get a sandbox key, first VPEC in under 5 minutes.
