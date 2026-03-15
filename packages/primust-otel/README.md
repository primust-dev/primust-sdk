# primust-otel

Primust governance adapter for [OpenTelemetry](https://opentelemetry.io/).

```bash
pip install primust-otel
```

## Quickstart

```python
import primust
from primust_otel import PrimustSpanProcessor
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider

p = primust.Pipeline(api_key="pk_live_...", workflow_id="my-service")
provider = TracerProvider()
provider.add_span_processor(PrimustSpanProcessor(pipeline=p))
trace.set_tracer_provider(provider)
```

## What it does

Attaches as an OpenTelemetry SpanProcessor to automatically record governance checks from your existing trace spans. Each span produces a commitment hash — raw content never leaves your environment.

## Docs

[docs.primust.com/adapters/otel](https://docs.primust.com/adapters/otel)

## License

Proprietary — see LICENSE file.
