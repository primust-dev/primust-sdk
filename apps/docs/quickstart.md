# Quickstart

From zero to your first verifiable credential in under five minutes.

---

## Install

```bash
# Python SDK
pip install primust primust-ai

# Open source checks harness (Apache-2.0 — works without account)
pip install primust-checks

# Standalone verifier (Apache-2.0 — free forever)
pip install primust-verify

# JavaScript/TypeScript
npm install @primust/sdk
```

**Framework adapters:**
```bash
pip install primust-langgraph        # LangGraph
pip install primust-openai-agents    # OpenAI Agents SDK
pip install primust-google-adk       # Google ADK
pip install primust-otel             # OpenTelemetry
```

---

## Get an API Key

Sign up at **primust.com** and create a project. Your sandbox key will look like `pk_sb_xxx`.

```bash
export PRIMUST_API_KEY=pk_sb_xxx
```

**Sandbox keys** produce real cryptographic proofs with the same schema as production. VPECs carry `environment: "sandbox"` and are not accepted as audit evidence. When you're ready for production, the same key upgrades — no re-instrumentation.

---

## Path 1 — Two Lines (Recommended)

If you're using LangGraph, OpenAI Agents SDK, or Google ADK:

```python
import primust
import primust_ai

p = primust.Pipeline(api_key="pk_sb_xxx", policy="ai_agent_general_v1")
primust_ai.autoinstrument(pipeline=p)

# Your existing agent code — unchanged
result = your_agent.run(user_input)

vpec = p.close()
print(vpec.proof_level_floor)        # mathematical | execution | witnessed | attestation
print(vpec.provable_surface)         # 0.73 — float 0.0–1.0
print(vpec.provable_surface_breakdown)  # per-level shares
```

`autoinstrument()` attaches to your framework's hooks. No changes to your existing checks. VPECs start flowing immediately.

---

## Path 2 — Open Source Harness

Works with or without a Primust account:

```python
from primust_checks import Harness

# Without API key — observability only, no VPECs
harness = Harness(policy="ai_agent_general_v1")

# With API key — identical checks, VPECs issued
harness = Harness(policy="ai_agent_general_v1", api_key="pk_sb_xxx")

result = harness.run(input=user_message, output=agent_response)
# result.passed — did all checks pass?
# result.gaps   — list of gap records
# result.vpec   — VPEC object (None if no api_key)
```

Without API key: checks run, gaps identified, "Proof: Not issued" — the silent conversion prompt.

**Bring your own check:**
```python
@harness.check
def my_existing_check(input, output) -> CheckResult:
    return CheckResult(passed=your_logic(input), evidence="...")
```

---

## Path 3 — Framework Adapters

### LangGraph

```python
from primust import Pipeline
from primust_langgraph import PrimustLangGraph

p = Pipeline(api_key="pk_sb_xxx", workflow_id="wf_contract_review")
adapter = PrimustLangGraph(pipeline=p, manifest_map={"review_node": "manifest_review_v1"})

graph = adapter.wrap(graph.compile())
result = graph.invoke({"input": "Summarize this contract"})
vpec = p.close()
```

### OpenAI Agents SDK

```python
from primust import Pipeline
from primust_openai_agents import PrimustOpenAIAgents

p = Pipeline(api_key="pk_sb_xxx", workflow_id="wf_support")
adapter = PrimustOpenAIAgents(pipeline=p, manifest_map={"search": "manifest_search_v1"})

agent = adapter.wrap(agent)
result = agent.run("Review this contract")
vpec = p.close()
```

### OpenTelemetry

```python
from primust import Pipeline
from primust_otel import PrimustSpanProcessor
from opentelemetry import trace

p = Pipeline(api_key="pk_sb_xxx", workflow_id="wf_agent")
processor = PrimustSpanProcessor(pipeline=p, manifest_map={"llm_call": "manifest_llm_v1"})

provider = trace.get_tracer_provider()
provider.add_span_processor(processor)

# Your existing OTel-instrumented code runs unchanged.
vpec = p.close()
```

---

## Path 4 — Custom Checks (Advanced)

For governance logic that doesn't fit autoinstrument or the harness. Use this only after exhausting Paths 1–3.

```python
import primust

p = primust.Pipeline(api_key="pk_sb_xxx", policy="ai_agent_general_v1")

# Decorator pattern
@p.record_check("custom_bias_monitor")
def run_bias_check(text):
    score = my_model.score(text)
    return {"passed": score < 0.1, "score": score}

# Low-level API
session = p.open_check("pii_scan", "manifest_pii_v1")
result = your_pii_scanner(user_input)
p.record(session, input=user_input, check_result="pass", details={"score": result.score})

vpec = p.close()
```

> ⚠ `p.record()` without a `manifest_id` / `open_check()` session produces a floating record at Attestation proof level regardless of your check's actual quality. Always open a check session first.

---

## Pipeline API Reference

| Method | Signature |
|---|---|
| `Pipeline()` | `Pipeline(api_key, workflow_id=None, *, policy=None, base_url="https://api.primust.com")` |
| `open_check` | `p.open_check(check_name, manifest_id)` → `CheckSession` |
| `open_review` | `p.open_review(check_name, manifest_id, reviewer_key_id, min_duration_seconds=1800)` → `ReviewSession` |
| `record` | `p.record(session, input, check_result, *, output=None, visibility="opaque", reviewer_signature=None, display_content=None, rationale=None)` → `RecordResult` |
| `record_check` | `@p.record_check("check_name")` decorator — wraps existing function |
| `close` | `p.close(*, partial=False, request_zk=False)` → `VPEC` |

**JavaScript SDK:** Same API in camelCase — `openCheck`, `openReview`, `record`, `close`. All return Promises.

---

## Verify a VPEC

```bash
pip install primust-verify

primust verify vpec.json
primust verify vpec.json --trust-root key.pem    # zero network
primust verify vpec.json --production            # stricter validation
primust verify vpec.json --json                  # machine-readable
```

**Expected output:**
```
✓ VALID — vpec_01abc
  Floor:       execution
  Surface:     0.73  (mathematical: 0.62 · execution: 0.11 · attestation: 0.00)
  Gaps:        0 unresolved
  Signature:   Ed25519 ✓
  Timestamp:   RFC 3161 ✓  (DigiCert TSA)
  Chain:       14 records — intact
  Environment: production
```

**Exit codes:** `0` = valid · `1` = invalid · `2` = valid but SANDBOX · `3` = valid but key revoked/expired

---

## Cross-Org Verification

If you receive data from an upstream organization that uses Primust, verify their VPEC before processing:

```python
from primust_checks import Harness

harness = Harness(policy="supply_chain_governance_v1", api_key="pk_sb_xxx")

result = harness.run(
    input={
        "vpec_artifact": upstream_vpec_json,
        "expected_issuer_org_id": "acme-corp",
        "minimum_proof_level_floor": "execution",
        "reject_sandbox": True
    },
    output=upstream_data
)
# Proof ceiling: Mathematical — Ed25519 verify is deterministic
# Your VPEC contains: "I verified upstream governance before processing their output"
```

Chains compose across any number of org boundaries. No Primust infrastructure in the verification path.

---

## Production Checklist

- Swap sandbox key (`pk_sb_`) for live key (`pk_live_`)
- Use `open_review()` for human-in-the-loop checks — enforces minimum review duration
- Pass `request_zk=True` to `p.close()` for checks needing ZK proofs
- Define all checks in registered manifests — floating records degrade to Attestation
- Set `retention_policy` on pipeline if a compliance framework requires it
- Set `risk_classification` if EU AI Act enrolled
- Run `primust verify --production` in CI/CD to gate on VPEC validity
- Set `reject_sandbox: True` on `upstream_vpec_verify` in production

---

## Handling Failures — Never Suppress Gaps

```python
result = your_pii_scanner(user_input)

if result.found_pii:
    p.record(
        session,
        input=user_input,
        check_result="fail",
        details={"pii_types": result.pii_types}   # types only, never values
    )
    # Gap recorded honestly in the VPEC.
    # A VPEC with honest gaps > a VPEC claiming perfection.
    raise PIIViolationError("PII detected")
```

If Primust's API is unreachable: the SDK queues locally, your pipeline continues (fail-open), queue flushes on recovery. Queue loss records a `system_unavailable` gap — never silent.

---

## CI/CD Integration

```yaml
- name: Primust Scan
  run: |
    primust scan . --framework aiuc1 \
      --fail-on critical \
      --format sarif \
      --output primust.sarif
  env:
    PRIMUST_API_KEY: ${{ secrets.PRIMUST_API_KEY }}

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: primust.sarif
```

---

## Key Concepts

| Term | Definition |
|---|---|
| **VPEC** | Verifiable Process Execution Credential — signed JSON proving what checks ran and what they found |
| **Pipeline** | Core SDK object — open checks, record results, close to produce VPEC |
| **CheckSession** | Handle returned by `open_check()` — binds a result to a specific check and manifest |
| **ReviewSession** | Like CheckSession but for human reviews — enforces minimum review duration and reviewer signature |
| **proof_level_floor** | Weakest-link proof level across all records in a run — the compliance gate |
| **provable_surface** | Float 0.0–1.0 — share of governance that is cryptographically provable — the hero metric |
| **Manifest** | Versioned check definition — binds check to model hash, tool version, configuration |
| **Evidence Pack** | Signed collection of VPECs for an audit period — assembled locally, verified offline |

---

*Primust Quickstart · docs.primust.com/quickstart*
*Canonical sources: DECISIONS_v13, MASTER_v9, TECH_SPEC_v8*
