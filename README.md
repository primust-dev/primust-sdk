# Primust

Primust extracts cryptographic primitives and runtime patterns into a domain-neutral framework. The core object model is not AI-specific.

**Primust is not TrustScope. Do not import from `references/`.**

## Structure

- `packages/` — core libraries (TypeScript + Python mirrors)
- `apps/` — deployable services (API, dashboard, verifier)
- `schemas/` — frozen JSON Schema and SQL migrations (shared truth)
- `references/` — READ-ONLY extraction source material
- `tools/` — build, test, release scripts

## Getting Started

```bash
pnpm install
pnpm test
```

## Rules

- Shared truth lives in `schemas/` — TypeScript types and Python models are generated from JSON Schema
- `references/` is read-only source material — never import from it
- `apps/dashboard/` calls `apps/api/` via HTTP — no direct database access
- No cross-language imports
