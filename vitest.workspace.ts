import { defineWorkspace } from "vitest/config";

export default defineWorkspace([
  // Packages with Node environment (default)
  "packages/artifact-core/vitest.config.ts",
  "packages/runtime-core/vitest.config.ts",
  "packages/registry/vitest.config.ts",
  "packages/zk-core/vitest.config.ts",
  "packages/policy-engine/vitest.config.ts",
  "packages/sdk-js/vitest.config.ts",
  "packages/verifier/vitest.config.ts",
  "packages/evidence-pack/vitest.config.ts",
  "packages/primust-otel-js/vitest.config.ts",
  // Apps with jsdom environment
  "apps/dashboard/vitest.config.ts",
  "apps/verify-site/vitest.config.ts",
]);
