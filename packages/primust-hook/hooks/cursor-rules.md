# Primust Hook Integration for Cursor

Add the following to your `.cursorrules` file to enable Primust evidence recording:

```
# Primust Evidence Hook
# All tool invocations are recorded for compliance evidence.
# The hook NEVER blocks — it only observes and records.
Before executing any shell command, pipe the command details through primust-hook:
echo '{"tool":"shell","input":"<command>","output":""}' | primust-hook check 2>/dev/null
```

## How it works

- `primust-hook check` reads a JSON action from stdin
- It runs local checks (secrets, PII, dangerous commands, cost bounds)
- It computes a commitment hash (SHA-256) of the action
- It sends only the hash + check pass/fail to the Primust API (zero content transit)
- It NEVER blocks execution — exit code is always 0
- Results are logged to `~/.primust/hook.log`
