# Primust SDK

Prove your governance checks ran. Portable, offline-verifiable cryptographic credentials.

**Input -> Checks -> Output -> Verify**

## Install

```bash
# Python SDK (proprietary)
pip install primust

# Python verifier (Apache-2.0, free forever)
pip install primust-verify

# Open source checks harness (Apache-2.0)
pip install primust-checks

# JavaScript/TypeScript SDK
npm install @primust/sdk
```

## Quick Start

```python
import primust

p = primust.Pipeline(api_key="pk_live_xxx")
session = p.open_check("pii_scan", "manifest_001")
p.record(session, input=data, check_result="pass")
vpec = p.close()  # VPEC issued
```

Three lines to instrument. Content never leaves your environment — only commitment hashes reach Primust.

## Verify (anyone, anywhere, offline)

```bash
pip install primust-verify
primust-verify vpec.json
primust-verify vpec.json --trust-root key.pem  # zero network
```

Works forever. Primust offline = irrelevant.

## Framework Adapters

| Package | Framework | Registry |
|---|---|---|
| `primust` | Core SDK | [PyPI](https://pypi.org/project/primust/) |
| `primust-verify` | Standalone verifier | [PyPI](https://pypi.org/project/primust-verify/) |
| `primust-checks` | Open source checks harness | [PyPI](https://pypi.org/project/primust-checks/) |
| `primust-langgraph` | LangGraph adapter | [PyPI](https://pypi.org/project/primust-langgraph/) |
| `primust-openai-agents` | OpenAI Agents SDK | [PyPI](https://pypi.org/project/primust-openai-agents/) |
| `primust-google-adk` | Google ADK adapter | [PyPI](https://pypi.org/project/primust-google-adk/) |
| `primust-otel` | OpenTelemetry bridge | [PyPI](https://pypi.org/project/primust-otel/) |
| `@primust/sdk` | JavaScript/TypeScript SDK | [npm](https://www.npmjs.com/package/@primust/sdk) |
| `@primust/otel` | JS OpenTelemetry bridge | [npm](https://www.npmjs.com/package/@primust/otel) |

## JSON Schemas

VPEC artifact schemas are published at [docs.primust.com/schemas](https://docs.primust.com/schemas).

## Documentation

- [docs.primust.com](https://docs.primust.com) — Full documentation
- [verify.primust.com](https://verify.primust.com) — Online verification (you don't need this website)
- [app.primust.com](https://app.primust.com) — Dashboard + Policy Center

## License

- `primust-verify` and `primust-checks`: Apache-2.0
- All other packages: Proprietary — see [LICENSE](LICENSE) in each package

## Security

Report vulnerabilities to security@primust.com.
