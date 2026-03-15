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
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { verify } from './verifier.js';
const PROOF_LEVEL_DISPLAY = {
    mathematical: 'mathematical',
    verifiable_inference: 'verifiable_inference',
    execution: 'execution',
    witnessed: 'witnessed',
    attestation: 'attestation',
};
function formatProofLevel(level) {
    return PROOF_LEVEL_DISPLAY[level] ?? level;
}
function formatDistribution(dist) {
    const levels = ['mathematical', 'verifiable_inference', 'execution', 'witnessed', 'attestation'];
    return levels
        .filter((l) => typeof dist[l] === 'number' && dist[l] > 0)
        .map((l) => `${formatProofLevel(l)}: ${dist[l]}`)
        .join('  ');
}
function formatGapsSummary(gaps) {
    if (gaps.length === 0)
        return '0';
    const counts = {};
    for (const g of gaps) {
        counts[g.severity] = (counts[g.severity] ?? 0) + 1;
    }
    const parts = Object.entries(counts).map(([sev, n]) => `${n} ${sev}`);
    return `${gaps.length} (${parts.join(', ')})`;
}
function formatTimestamp(result) {
    let ts = result.signed_at;
    if (result.timestamp_anchor_valid === true) {
        ts += ' (RFC 3161 \u2713)';
    }
    return ts;
}
function printHumanResult(result) {
    const dist = result.proof_distribution;
    const cov = result.coverage;
    if (result.valid) {
        console.log(`\n  \u2713 VPEC ${result.vpec_id} \u2014 VALID`);
    }
    else {
        console.log(`\n  \u2717 VPEC ${result.vpec_id} \u2014 INVALID`);
        for (const err of result.errors) {
            console.log(`    Error: ${err}`);
        }
    }
    console.log(`    Proof level:   ${formatProofLevel(result.proof_level)} (weakest-link)`);
    const distStr = formatDistribution(dist);
    if (distStr) {
        console.log(`    Distribution:  ${distStr}`);
    }
    console.log(`    Workflow:      ${result.workflow_id}`);
    console.log(`    Org:           ${result.org_id}`);
    console.log(`    Signed:        ${formatTimestamp(result)}`);
    console.log(`    Signer:        ${result.signer_id} / kid: ${result.kid}`);
    console.log(`    Rekor:         ${result.rekor_status}`);
    if (cov && typeof cov.policy_coverage_pct === 'number') {
        let covStr = `${cov.policy_coverage_pct}% policy`;
        if (typeof cov.instrumentation_surface_pct === 'number') {
            covStr += ` | ${cov.instrumentation_surface_pct}% instrumentation surface`;
        }
        console.log(`    Coverage:      ${covStr}`);
    }
    console.log(`    Gaps:          ${formatGapsSummary(result.gaps)}`);
    if (result.process_context_hash) {
        console.log(`    Process hash:  ${result.process_context_hash}`);
    }
    console.log(`    Test mode:     ${result.test_mode}`);
    if (result.test_mode && result.valid) {
        console.log(`    \u26A0 TEST CREDENTIAL \u2014 not for production use`);
    }
    if (result.warnings.length > 0) {
        for (const w of result.warnings) {
            console.log(`    Warning: ${w}`);
        }
    }
    console.log('');
}
export async function main(args) {
    let parsed;
    try {
        parsed = parseArgs({
            args: args ?? process.argv.slice(2),
            options: {
                production: { type: 'boolean', default: false },
                'skip-network': { type: 'boolean', default: false },
                'trust-root': { type: 'string' },
                json: { type: 'boolean', default: false },
                help: { type: 'boolean', short: 'h', default: false },
            },
            allowPositionals: true,
        });
    }
    catch (err) {
        console.error(`Error: ${err.message}`);
        return 2;
    }
    if (parsed.values.help || parsed.positionals.length === 0) {
        console.log('Usage: primust-verify <artifact.json> [--production] [--skip-network] [--trust-root <path>] [--json]');
        return parsed.values.help ? 0 : 2;
    }
    const filePath = parsed.positionals[0];
    const jsonOutput = parsed.values.json ?? false;
    // Read artifact file
    let rawJson;
    try {
        rawJson = readFileSync(filePath, 'utf-8');
    }
    catch {
        const msg = `Error: file not found: ${filePath}`;
        if (jsonOutput) {
            console.error(msg);
        }
        else {
            console.error(msg);
        }
        return 2;
    }
    let artifact;
    try {
        artifact = JSON.parse(rawJson);
    }
    catch {
        const msg = `Error: invalid JSON in ${filePath}`;
        if (jsonOutput) {
            console.error(msg);
        }
        else {
            console.error(msg);
        }
        return 2;
    }
    // Run verification
    let result;
    try {
        result = await verify(artifact, {
            production: parsed.values.production,
            skip_network: parsed.values['skip-network'],
            trust_root: parsed.values['trust-root'],
        });
    }
    catch (err) {
        const msg = `Error: verification failed: ${err.message}`;
        if (jsonOutput) {
            console.error(msg);
        }
        else {
            console.error(msg);
        }
        return 2;
    }
    // Output
    if (jsonOutput) {
        console.log(JSON.stringify(result, null, 2));
    }
    else {
        printHumanResult(result);
    }
    return result.valid ? 0 : 1;
}
// Run if invoked directly
const isDirectRun = process.argv[1] && (process.argv[1].endsWith('/cli.js') ||
    process.argv[1].endsWith('/cli.ts'));
if (isDirectRun) {
    main().then((code) => process.exit(code));
}
//# sourceMappingURL=cli.js.map