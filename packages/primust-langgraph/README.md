# primust-langgraph

Primust governance adapter for [LangGraph](https://github.com/langchain-ai/langgraph).

```bash
pip install primust-langgraph
```

## Quickstart

```python
import primust
from primust_langgraph import PrimustLangGraph

p = primust.Pipeline(api_key="pk_live_...", workflow_id="my-agent")
adapter = PrimustLangGraph(pipeline=p)

# Wrap your LangGraph compiled graph
instrumented = adapter.instrument(compiled_graph)
result = instrumented.invoke({"input": "..."})
```

## What it does

Automatically records governance checks at LangGraph node boundaries. Each node execution produces a commitment hash — raw content never leaves your environment.

## Docs

[docs.primust.com/adapters/langgraph](https://docs.primust.com/adapters/langgraph)

## License

Proprietary — see LICENSE file.
