import path from 'node:path';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    passWithNoTests: true,
  },
  resolve: {
    alias: {
      '@primust/artifact-core': path.resolve(__dirname, '../artifact-core/src/index.ts'),
      '@primust/runtime-core': path.resolve(__dirname, '../runtime-core/src/index.ts'),
    },
  },
});
