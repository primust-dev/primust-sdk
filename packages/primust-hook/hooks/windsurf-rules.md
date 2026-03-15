# Primust Hook Integration for Windsurf

Windsurf uses the same shell-level hook surface as Claude Code. Add the following to your Windsurf rules configuration:

```json
{
  "hooks": {
    "pre_tool_use": [
      {
        "command": "primust-hook check"
      }
    ]
  }
}
```

## How it works

- Windsurf invokes tools via shell commands, same as Claude Code
- `primust-hook check` intercepts each action via stdin (JSON)
- Local checks run: secrets scan, PII scan, command patterns, cost bounds
- A commitment hash (SHA-256) of the action is computed
- Only the hash + check pass/fail booleans are sent to the Primust API (zero content transit)
- The hook NEVER blocks — exit code is always 0
- Results are logged to `~/.primust/hook.log`
