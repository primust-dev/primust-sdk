# primust-checks

Open-source governance check harness for AI agents. Run checks locally. Prove they ran with Primust.

## Install

```bash
pip install primust-checks
```

## Quickstart (observability only)

```python
from primust_checks import Harness

harness = Harness(policy="ai_agent_general_v1")
result = harness.run(input="Summarize this quarterly report.")
print(result.passed, result.gaps)
```

## With proof layer

```python
from primust_checks import Harness

harness = Harness(policy="ai_agent_general_v1", api_key="pk_live_...")
result = harness.run(input="Summarize this quarterly report.")
print(result.vpec)  # Verifiable Proof of Executed Compliance
```

## Bring Your Own Check (BYOC)

```python
from primust_checks import Harness, CheckResult

harness = Harness(policy="ai_agent_general_v1")

@harness.check(name="my_custom_check", proof_ceiling="execution")
def my_check(*, input, output=None, context=None, config=None):
    flagged = "forbidden" in str(input).lower()
    return CheckResult(
        passed=not flagged,
        check_id="my_custom_check",
        evidence="forbidden keyword detected" if flagged else "clean",
    )

result = harness.run(input="This is a test.")
```

## Available bundles

| Bundle ID | Framework |
|---|---|
| `ai_agent_general_v1` | General AI Agent |
| `eu_ai_act_art12_v1` | EU AI Act Article 12 |
| `hipaa_safeguards_v1` | HIPAA Technical Safeguards |
| `soc2_cc_v1` | SOC 2 Common Criteria |
| `coding_agent_v1` | Coding Agent Governance |

## Built-in checks

- **secrets_scanner** -- Detects AWS keys, GitHub tokens, GCP keys, generic API keys
- **pii_regex** -- Detects SSNs, credit cards (with Luhn), emails, US phone numbers
- **cost_bounds** -- Enforces token and cost limits
- **command_patterns** -- Blocks dangerous shell/SQL patterns

## License

Apache-2.0. See [LICENSE](LICENSE).
