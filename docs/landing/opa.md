# primust.com/opa

## HERO

**Headline:** Your OPA policies are deterministic. Make them provable.

**Subhead:** 3 lines. Mathematical-level VPEC. Offline-verifiable by anyone.

**CTA:** Get started → primust.com/signup

---

## THE CLAIM

OPA is deterministic. Same input, same policy, same output — every time.
That determinism is exactly what Mathematical-level proof requires.
Primust wraps your existing OPA evaluation and produces a VPEC:
a signed, offline-verifiable credential proving your policy ran correctly
on this input at this time. No policy changes. No new governance layer.
Your auditor verifies it with `pip install primust-verify`.

---

## CODE BLOCK

```go
import primustopa "github.com/primust-dev/primust-opa"

adapter := primustopa.New(primustopa.Config{
    PrimustAPIKey: os.Getenv("PRIMUST_API_KEY"),
    ManifestID:    "your_manifest_id",
    WorkflowID:    "authz-v1",
    PolicyHash:    primustopa.HashPolicy(regoBytes),
})

result, err := adapter.Eval(ctx, preparedQuery, input)
```

---

## HOW IT WORKS

- Your Rego policy is hashed and committed in the check manifest
- Input is committed locally via Poseidon2 before any evaluation
- After OPA evaluates: VPEC issued with proof_level_floor: mathematical

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

## FOR EXISTING OPA DEPLOYMENTS

You wrote the Rego. We don't touch it. We sit next to your OPA instance
and produce proof it evaluated. No migration. No policy changes.
Your `rego.PreparedEvalQuery` goes in. Your OPA result comes out.
Primust adds a signed, offline-verifiable credential proving it happened.

---

## WHAT YOU GET

- VPEC with proof_level_floor: mathematical — the strongest proof level
- Offline-verifiable by anyone, anywhere, forever
- Your Rego stays exactly as it is
- No content transits Primust — only commitment hashes
- Works with any OPA deployment: library, daemon, sidecar

---

**CTA:** Get started → primust.com/signup

Sign up, get a sandbox key, first VPEC in under 5 minutes.
