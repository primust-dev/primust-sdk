# Primust SDK

Prove your governance checks ran. Portable, offline-verifiable cryptographic credentials.

**Input → Checks → Output → Verify**

---

## Install

```bash
# Python SDK (proprietary)
pip install primust primust-ai

# Python verifier (Apache-2.0, free forever)
pip install primust-verify

# Open source checks harness (Apache-2.0)
pip install primust-checks

# JavaScript/TypeScript SDK
npm install @primust/sdk
```

---

## Quick Start — Two Lines

```python
import primust
import primust_ai

p = primust.Pipeline(api_key="pk_sb_xxx")
primust_ai.autoinstrument(pipeline=p)

# Your existing agent code — unchanged
result = your_agent.run(user_input)

vpec = p.close()   # VPEC issued
print(vpec.proof_level_floor)    # mathematical | execution | witnessed | attestation
print(vpec.provable_surface)     # float 0.0–1.0 — "73% of governance mathematically proven"
```

Three lines to instrument. Content never leaves your environment — only commitment hashes reach Primust.

**API keys:** `pk_sb_xxx` = sandbox (real proof, not audit-acceptable). `pk_live_xxx` = production.

---

## Verify (anyone, anywhere, offline)

```bash
pip install primust-verify

primust verify vpec.json
primust verify vpec.json --trust-root key.pem   # zero network — works forever
primust verify vpec.json --production            # reject sandbox VPECs
```

Works forever. Primust offline = irrelevant.

---

## Framework Adapters

| Package | Framework | Registry | Status |
|---|---|---|---|
| `primust` | Core SDK | PyPI | Live 1.0.0 |
| `primust-ai` | autoinstrument() meta-package | PyPI | Live 1.0.0 |
| `primust-verify` | Standalone verifier (Apache-2.0) | PyPI | Live 1.0.0 |
| `primust-checks` | Open source checks harness (Apache-2.0) | PyPI | Live 1.0.0 |
| `primust-langgraph` | LangGraph adapter | PyPI | Live 1.0.0 |
| `primust-openai-agents` | OpenAI Agents SDK | PyPI | Live 1.0.0 |
| `primust-google-adk` | Google ADK adapter | PyPI | Live 1.0.0 |
| `primust-otel` | OpenTelemetry bridge | PyPI | Live 1.0.0 |
| `@primust/sdk` | JavaScript/TypeScript SDK | npm | Live 1.0.0 |
| `@primust/otel` | JS OpenTelemetry bridge | npm | Live 1.0.0 |

## Rule Engine Adapters (Mathematical Ceiling)

| Package | Target | Registry |
|---|---|---|
| `primust-cedar` | AWS Cedar | Maven Central |
| `primust-drools` | Red Hat Drools | Maven Central |
| `primust-odm` | IBM ODM | Maven Central |
| `primust-opa` | Open Policy Agent | pkg.go.dev |

## Regulated Industry Connectors

```bash
pip install primust-connectors   # Apache-2.0
```

7 Python REST connectors (321 tests): ComplyAdvantage, NICE Actimize, FICO Blaze, IBM ODM, FICO Falcon, Pega CDH, Wolters Kluwer UpToDate, Guidewire ClaimCenter. All Attestation ceiling (REST wrappers). See [primust-connectors](https://github.com/primust-dev/primust-connectors) for details.

---

## What Never Leaves Your Environment

- Raw input data (documents, agent outputs, API payloads)
- Model weights or parameters
- PII or PHI
- Credentials or API keys
- Display content or rationale text (only commitment hashes transit)

Only commitment hashes (`poseidon2:hex` or `sha256:hex`) and bounded metadata reach `api.primust.com`.

---

## Documentation

- [docs.primust.com](https://docs.primust.com) — Full documentation
- [verify.primust.com](https://verify.primust.com) — Online verification (you don't need this website)
- [app.primust.com](https://app.primust.com) — Dashboard + Policy Center

---

## License

- `primust-verify` and `primust-checks`: Apache-2.0
- `primust-connectors`: Apache-2.0
- All other packages: Proprietary — see LICENSE in each package directory

## Security

Report vulnerabilities to security@primust.com.
