# DECISION: Coding Agent Hook Binary (AMDT-16 Resolution)
## Primust, Inc. · Amendment to DECISIONS
### March 15, 2026 · Resolves AMDT-16 open questions

---

## Summary

DECISIONS_v11 §18 defines the hook architecture: evidence layer only, never blocks, never allows. Three open questions blocked implementation of the `primust-hook` binary targeting Claude Code, Cursor, and Windsurf. This document resolves all three.

---

## Decision 1: Binary Distribution

**Decision:** GitHub Releases with cosign-signed checksums + install script + Homebrew tap.

**Install paths:**

| Method | Command / Mechanism |
|---|---|
| Scripted | `curl -sSL https://install.primust.com/hook \| sh` |
| Homebrew | `brew install primust-dev/tap/primust-hook` |
| MDM | Direct binary drop to `/usr/local/bin/primust-hook` |

**Versioning:** SemVer, tagged releases on GitHub.

**Signing:** Cosign keyless signing (Sigstore), SHA256 checksums published alongside binaries.

**Rationale:** GitHub Releases is the standard for Go binary distribution. Cosign provides supply chain integrity without managing GPG keys. Install script covers Linux/macOS. Homebrew covers developer-facing installs. MDM covers enterprise IT deployment.

---

## Decision 2: Policy Delivery

**Decision:** Pull from API on startup, cache locally, refresh every 5 minutes.

**Mechanism:**

1. On startup: `GET /api/v1/policy/active` → cache to `~/.primust/policy.json`
2. Background goroutine refreshes every 5 minutes
3. If API unreachable: use cached policy
4. If no cache and no API: observability-only mode (all checks run, no commitments sent)

```
startup
  ├─ fetch policy from API
  │   ├─ success → write cache, apply policy
  │   └─ fail → load cache
  │       ├─ cache exists → apply cached policy
  │       └─ no cache → observability-only mode
  └─ start background refresh (every 5 min)
```

**Rationale:** Pull model is simpler than MDM bundling, auto-updates without IT intervention, graceful degradation ensures the hook never fails. MDM bundling would require IT to push policy updates — pull model means policy changes propagate within 5 minutes automatically.

---

## Decision 3: Windsurf Hook Surface

**Decision:** Confirmed supported. Same shell-level hook mechanism as Claude Code.

**Mechanism:** All three IDEs (Claude Code, Cursor, Windsurf) invoke external tools via shell subprocess calls. `primust-hook` intercepts at the shell level — no IDE-specific API integration needed.

| IDE | Integration Point | Configuration |
|---|---|---|
| Claude Code | Native hooks support via `.claude/hooks.json` | `pre_tool_use` and `post_tool_use` events |
| Cursor | `.cursorrules` file instructs agent to pipe tool calls through `primust-hook` | Rules-based invocation |
| Windsurf | `.windsurfrules` mechanism (same as Cursor) | Rules-based invocation |

**Rationale:** Shell-level interception is IDE-agnostic. As new coding agents emerge (Copilot Workspace, Devin, etc.), the same binary works without modification. IDE-specific plugins would require separate maintenance per IDE.

---

## Invariants

- Hook NEVER blocks execution (exit code always 0)
- Hook NEVER allows or denies actions (evidence layer only)
- Zero content transit — only commitment hashes and check pass/fail booleans sent to API
- 2-second timeout on all API calls — IDE responsiveness is paramount
- Works fully offline in observability-only mode

---

## Patent Surface

Two novel claims flagged for review:

1. **Method for non-blocking evidence collection from IDE coding agent tool invocations via shell-level interception.** The mechanism by which a passive hook binary observes coding agent tool calls across multiple IDE platforms without blocking, denying, or altering execution — producing cryptographic evidence records from shell-level interception.

2. **Policy-pull caching mechanism with graceful degradation for development environment governance.** The mechanism by which governance policy is pulled from a remote API, cached locally, refreshed on a configurable interval, and degrades gracefully through three tiers (live policy → cached policy → observability-only mode) to ensure the hook never fails and never blocks developer workflow.

**Action required:** Flag for inclusion in next provisional filing. Both claims extend the hook architecture defined in DECISIONS_v11 §18.

---

## Implementation

- **Package:** `/packages/primust-hook` (Go)
- **Binary:** Single static binary, cross-compiled for `darwin/linux × amd64/arm64`
- **First release:** `v0.1.0`

---

*DECISION_hook_binary_amdt16.md · March 15, 2026 · Primust, Inc.*
*Resolves AMDT-16 open questions. Subject to review.*
