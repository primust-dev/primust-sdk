import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';

export default defineConfig({
  resolve: {
    alias: {
      '@primust/artifact-core': resolve(__dirname, '../artifact-core/src/index.ts'),
    },
  },
  test: {
    include: ['src/**/*.test.ts'],
    passWithNoTests: true,
  },
});
