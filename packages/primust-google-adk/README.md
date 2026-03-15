# primust-google-adk

Primust governance adapter for [Google Agent Development Kit (ADK)](https://google.github.io/adk-docs/).

```bash
pip install primust-google-adk
```

## Quickstart

```python
import primust
from primust_google_adk import PrimustGoogleADK

p = primust.Pipeline(api_key="pk_live_...", workflow_id="my-agent")
adapter = PrimustGoogleADK(pipeline=p)

# Wrap your ADK agent
instrumented = adapter.instrument(agent)
result = instrumented.run("...")
```

## What it does

Automatically records governance checks at ADK tool and callback boundaries. Each execution produces a commitment hash — raw content never leaves your environment.

## Docs

[docs.primust.com/adapters/google-adk](https://docs.primust.com/adapters/google-adk)

## License

Proprietary — see LICENSE file.
