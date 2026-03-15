#!/usr/bin/env node
/**
 * primust-verify CLI
 *
 * Usage:
 *   primust-verify vpec_<id>.json
 *   primust-verify vpec_<id>.json --production
 *   primust-verify vpec_<id>.json --trust-root ./my-pubkey.pem
 *   primust-verify vpec_<id>.json --skip-network
 *   primust-verify vpec_<id>.json --json
 *
 * Exit codes:
 *   0 = valid
 *   1 = invalid
 *   2 = system error
 */
export declare function main(args?: string[]): Promise<number>;
//# sourceMappingURL=cli.d.ts.map