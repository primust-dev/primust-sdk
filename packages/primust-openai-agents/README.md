# primust-openai-agents

Primust governance adapter for [OpenAI Agents SDK](https://github.com/openai/openai-agents-python).

```bash
pip install primust-openai-agents
```

## Quickstart

```python
import primust
from primust_openai_agents import PrimustOpenAIAgents

p = primust.Pipeline(api_key="pk_live_...", workflow_id="my-agent")
adapter = PrimustOpenAIAgents(pipeline=p)

# Wrap your agent
instrumented_agent = adapter.instrument(agent)
result = instrumented_agent.run("...")
```

## What it does

Automatically records governance checks at agent tool call and handoff boundaries. Each execution produces a commitment hash — raw content never leaves your environment.

## Docs

[docs.primust.com/adapters/openai-agents](https://docs.primust.com/adapters/openai-agents)

## License

Proprietary — see LICENSE file.
