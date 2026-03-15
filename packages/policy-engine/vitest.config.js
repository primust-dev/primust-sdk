import { defineConfig } from 'vitest/config';
import path from 'path';
export default defineConfig({
    resolve: {
        alias: {
            '@primust/artifact-core': path.resolve(__dirname, '../artifact-core/src/index.ts'),
            '@primust/runtime-core': path.resolve(__dirname, '../runtime-core/src/index.ts'),
            '@primust/registry': path.resolve(__dirname, '../registry/src/index.ts'),
        },
    },
    test: {
        include: ['src/**/*.test.ts'],
        passWithNoTests: true,
    },
});
//# sourceMappingURL=vitest.config.js.map