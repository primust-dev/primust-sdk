import { defineConfig } from 'vitest/config';
import path from 'path';
export default defineConfig({
    resolve: {
        alias: {
            '@primust/artifact-core': path.resolve(__dirname, '../artifact-core/src/index.ts'),
        },
    },
    test: {
        include: ['src/**/*.test.ts'],
        passWithNoTests: true,
    },
});
//# sourceMappingURL=vitest.config.js.map