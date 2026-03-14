# primust.com/cedar

## HERO

**Headline:** AWS built Cedar for AI agent authorization. We built the proof layer.

**Subhead:** Your Cedar policies are deterministic. Get Mathematical-level proof automatically.

**CTA:** Get started → primust.com/signup

---

## THE CLAIM

Cedar is deterministic. Same principal, same action, same resource, same policy set,
same decision — every time. That determinism is exactly what Mathematical-level
proof requires. Primust wraps your existing Cedar evaluation and produces a VPEC:
a signed, offline-verifiable credential proving your policy authorized this request
at this time with this result. No policy changes. No new authorization layer.
Your auditor verifies it with `pip install primust-verify`.

---

## CODE BLOCK

```java
import com.primust.cedar.PrimustCedar;

PrimustCedar adapter = new PrimustCedar(
    System.getenv("PRIMUST_API_KEY"),
    null, "your_manifest_id", "authz-v1", policySetHash, null
);

// After your Cedar isAuthorized() call:
String commitmentHash = adapter.recordEvaluation(
    principal, action, resource, context, decision, diagnostics
);
```

---

## HOW IT WORKS

- Your Cedar policy set is hashed and committed in the check manifest
- Authorization request (principal, action, resource, context) is committed locally via Poseidon2 before any network call
- After Cedar evaluates: VPEC issued with proof_level_floor: mathematical

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

## FOR AI AGENT AUTHORIZATION

Cedar was built for fine-grained authorization. AI agents making tool calls,
accessing resources, operating on behalf of users — all governed by Cedar policies.
Primust proves each authorization decision happened correctly:

- Agent called Action::"invoke_tool" on Resource::"customer_data" — proved
- Authorization checked Principal::"agent_123" against policy set v2.1 — proved
- Decision: Allow — committed, signed, verifiable offline

Every agent action gets a Mathematical-level VPEC. Your compliance team verifies
with `pip install primust-verify`.

---

## FOR EXISTING CEDAR DEPLOYMENTS

You wrote the policies. We don't touch them. We sit next to your Cedar
authorization engine and produce proof each evaluation happened.
No migration. No policy changes. Your `isAuthorized()` call stays the same.
Call `recordEvaluation()` after — one line — and the proof layer activates.

---

## WHAT YOU GET

- VPEC with proof_level_floor: mathematical — the strongest proof level
- Offline-verifiable by anyone, anywhere, forever
- Your Cedar policies stay exactly as they are
- No authorization data transits Primust — only commitment hashes
- Works with Cedar Java SDK, Kotlin, or any JVM language

---

**CTA:** Get started → primust.com/signup

Sign up, get a sandbox key, first VPEC in under 5 minutes.
