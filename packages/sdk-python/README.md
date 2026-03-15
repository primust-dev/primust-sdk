# Primust Python SDK

Prove governance ran. Disclose nothing.

```bash
pip install primust
```

## What this is

Primust issues **Verifiable Process Execution Credentials (VPECs)** — portable, offline-verifiable proofs that a defined governance process executed correctly on specific data, without disclosing the data.

A VPEC answers: *"Did your AML screening actually run on this entity?"* — without your watchlist matching criteria, velocity thresholds, or customer data leaving your environment.

## Quickstart

```python
import primust

p = primust.Pipeline(
    api_key="pk_live_...",
    workflow_id="aml-screening-v2"
)

run = p.open()

result = run.record(
    check="aml_entity_screen",
    manifest_id="sha256:abc123...",   # from p.register_check()
    input=entity_data,                # committed locally — never sent to Primust
    check_result="pass",
    visibility="opaque",
)

# Write result.commitment_hash to your own logs
# This is your log linkage anchor — connects your logs to the VPEC
print(result.commitment_hash)  # sha256:...

vpec = run.close()
# vpec is the signed, portable credential
# Provide to your regulator. They verify at verify.primust.com
# without receiving your data.
```

## Privacy guarantee

Raw input values are committed locally via SHA-256 (Poseidon2 when the native extension is available) before any network call. Only the commitment hash and bounded normalized metadata transit to `api.primust.com`.

**Your data never leaves your environment.**

This is enforced in the SDK — not advisory. The transport layer never receives raw values. Tests verify this by intercepting every outbound HTTP request and asserting sensitive input strings are absent.

## Proof levels

| Level | When | Verifier confidence |
|---|---|---|
| `mathematical` | Deterministic rule, arithmetic verifiable | Cryptographic — can replay |
| `execution` | In-process instrumentation | Strong — execution binding |
| `witnessed` | Human review with RFC 3161 timing | Regulatory — signed review |
| `attestation` | API-level observation | Audit — process ran |

The VPEC applies weakest-link: the overall credential level is the lowest level across all checks in the run.

## API reference

### `Pipeline(api_key, workflow_id, ...)`

```python
p = primust.Pipeline(
    api_key="pk_live_...",        # or set PRIMUST_API_KEY env var
    workflow_id="my-workflow",    # identifies the governed process
    surface_id=None,              # optional: instrumentation surface
    environment="production",     # inferred from key prefix
)
```

### `p.open(policy_pack_id?) → Run`

Opens a governed process run. Returns a `Run`. All `.record()` calls belong to this run. Close with `.close()` to issue the VPEC.

### `run.record(check, manifest_id, check_result, input, ...) → RecordResult`

```python
result = run.record(
    check="pii_scan",
    manifest_id="sha256:...",
    check_result="pass",          # pass | fail | error | skipped | degraded | override
    input=content,                # committed locally — never sent
    details={"score": 0.04},      # bounded metadata — will transit, must not be sensitive
    output=None,                  # optional output commitment
    visibility="opaque",          # transparent | selective | opaque
)

result.commitment_hash   # sha256:... — write this to your logs
result.record_id         # rec_...
result.proof_level       # attestation | execution | witnessed | mathematical
result.queued            # True if API was unreachable — will flush on reconnect
```

### `run.open_check(check, manifest_id) → CheckSession`

Opens a timed check session. Returns an RFC 3161 timestamp at open time. Pass to `run.record(check_session=...)`. Sub-100ms ML inference emits `check_timing_suspect` gap.

### `run.open_review(check, manifest_id, reviewer_key_id, ...) → ReviewSession`

Opens a Witnessed level human review session. Pass to `run.record(check_session=..., reviewer_signature=..., rationale=...)`.

### `run.close() → VPEC`

Closes the run and issues the VPEC. After close, no further records can be added.

```python
vpec = run.close()

vpec.vpec_id                  # vpec_...
vpec.proof_level              # weakest-link across all checks
vpec.chain_intact             # True if commitment chain is unbroken
vpec.governance_gaps          # list of GovernanceGap — missing checks, timing anomalies
vpec.is_clean()               # True if chain intact and zero gaps
vpec.to_dict()                # full JSON for offline verification
```

### `p.register_check(manifest) → ManifestRegistration`

Register a check manifest. Call once per manifest version. Returns `manifest_id` — content-addressed SHA-256, idempotent.

## Offline durability

If `api.primust.com` is unreachable, records queue locally in SQLite. The SDK never throws to the caller due to API unavailability. When connectivity recovers, the queue flushes automatically on the next successful call.

If the queue is permanently lost, a `system_unavailable` gap is recorded in the VPEC — the SDK never silently drops governance evidence.

```python
p.pending_queue_count()   # items waiting in local queue
p.flush_queue()           # manually trigger flush attempt
```

## Governance gaps

The VPEC records gaps automatically:

| Gap type | Meaning |
|---|---|
| `check_missing` | Expected check in manifest not executed |
| `check_failed` | Check ran and returned fail |
| `check_timing_suspect` | Execution time implausibly fast (< 100ms for ML check) |
| `sequence_gap` | Record sequence broken — possible tampering |
| `system_unavailable` | Primust API unreachable during run |
| `policy_config_drift` | Policy changed between run open and close |

## Log linkage

Every `RecordResult` contains a `commitment_hash`. Write this to your operational logs alongside the transaction or decision ID it corresponds to. This creates a verifiable link between your logs and the VPEC — a verifier can confirm your log entry corresponds to a specific record in the credential.

```python
result = run.record(...)
logger.info("aml_screen completed",
    commitment_hash=result.commitment_hash,
    transaction_id=txn_id,
)
```

## Verify a VPEC

```bash
pip install primust-verify
primust-verify vpec.json
```

Or online at [verify.primust.com](https://verify.primust.com) — no account required.

## Requirements

- Python 3.11+
- `httpx>=0.27.0`

## License

Proprietary — see LICENSE file.

---

[Docs](https://docs.primust.com) · [Verify](https://verify.primust.com) · [Connectors](https://github.com/primust-dev/connectors)
