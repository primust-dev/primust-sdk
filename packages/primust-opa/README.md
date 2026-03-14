# primust-opa

Your OPA policies are deterministic. That means they're mathematically provable.

Wrap your existing Rego policy in 3 lines. Get a Mathematical-level VPEC —
a signed, offline-verifiable credential proving your policy evaluated this
input at this time with this result.

## Why Mathematical level

OPA (Rego) is deterministic. Same input + same pinned policy = same output,
every time. Primust's manifest system maps deterministic rule engines to
Mathematical proof level automatically. No configuration. No upgrade.
It's what the check actually is.

Mathematical-level proof means: no trust in any vendor, model, or person required.
The arithmetic proves it. Your auditor verifies it offline with:

```bash
pip install primust-verify
primust verify vpec.json
```

## Install

```bash
go get github.com/primust-dev/primust-opa
```

## 3-line integration

```go
import primustopa "github.com/primust-dev/primust-opa"

adapter := primustopa.New(primustopa.Config{
    PrimustAPIKey: os.Getenv("PRIMUST_API_KEY"),
    ManifestID:    "your_manifest_id",
    WorkflowID:    "authz-v1",
    PolicyHash:    primustopa.HashPolicy(regoBytes),
})

result, err := adapter.Eval(ctx, preparedQuery, input)
// result.Allowed — your OPA result, unchanged
// result.CommitmentHash — Poseidon2 commitment (input never leaves)
// result.RecordID — governance record in Primust
```

Your existing `rego.PreparedEvalQuery` goes in. Your OPA result comes out.
Primust sits alongside — commits the input locally, records the evaluation,
and produces a VPEC.

## What you get

- VPEC with proof_level_floor: mathematical
- Offline-verifiable by anyone: `pip install primust-verify`
- Your Rego stays exactly as it is — no policy changes
- No content transits Primust — only commitment hashes

## How it works

1. **Policy pinning:** `primustopa.HashPolicy(regoBytes)` computes `SHA-256(rego_content)` and commits it in the check manifest. The manifest binds this exact policy version to the governance record.

2. **Input commitment:** Before OPA evaluates, `adapter.Eval()` calls `rulescore.Canonical(input)` → `rulescore.CommitDefault(bytes)` to compute a commitment hash locally. The raw input never leaves your environment.

3. **Deterministic evaluation:** OPA evaluates the prepared query. Same input + same pinned policy = same output, every time.

4. **Output commitment:** After evaluation, the output is committed the same way. Only commitment hashes and the pass/fail result are sent to Primust.

5. **Mathematical proof level:** The manifest declares `stage_type: deterministic_rule`. The proof level is derived automatically — not configured, not a premium. It falls out of the manifest system because the check is deterministic.

## Surface declaration

```go
primustopa.SurfaceDeclaration
// → map[string]interface{}{
//     "surface_type":     "policy_engine",
//     "stage_type":       "deterministic_rule",
//     "observation_mode": "instrumentation",
//     "scope_type":       "per_evaluation",
//     "proof_ceiling":    "mathematical",
//     "adapter":          "primust-opa",
//     "engine":           "Open Policy Agent",
// }
```

## Verify a VPEC

```bash
pip install primust-verify
primust verify vpec.json --trust-root primust-pubkey.pem
```

No Primust account required. Apache-2.0. Free forever. Works offline.

## Learn more

[docs.primust.com/adapters/opa](https://docs.primust.com/adapters/opa)
