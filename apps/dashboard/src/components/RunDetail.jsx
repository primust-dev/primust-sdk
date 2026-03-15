import { ProofLevelBadge } from "./ProofLevelBadge";
import { CoverageDisplay } from "./CoverageDisplay";
import { GapTable } from "./GapTable";
import { ManifestHashesTable } from "./ManifestHashesTable";
import { ProofDistributionBar } from "./ProofDistributionBar";
export function RunDetail({ vpec, records }) {
    return (<div className="space-y-6" data-testid="run-detail">
      {/* Header */}
      <div className="flex items-center gap-3">
        <h2 className="text-xl font-bold">{vpec.vpec_id}</h2>
        <ProofLevelBadge level={vpec.proof_level}/>
        {vpec.partial && (<span className="rounded bg-amber-200 px-2 py-0.5 text-xs font-medium" data-testid="partial-badge">
            PARTIAL
          </span>)}
        {vpec.test_mode && (<span className="rounded bg-gray-200 px-2 py-0.5 text-xs">
            TEST MODE
          </span>)}
      </div>

      {/* Proof Distribution — all 5 levels */}
      <section>
        <h3 className="font-semibold mb-2">Proof Distribution</h3>
        <ProofDistributionBar distribution={vpec.proof_distribution}/>
      </section>

      {/* Two denominator display — mandatory, never collapse */}
      <section>
        <h3 className="font-semibold mb-2">Coverage</h3>
        <CoverageDisplay policyCoveragePct={vpec.policy_coverage_pct} recordsPass={vpec.records_pass} recordsTotal={vpec.records_total} instrumentationSurfacePct={vpec.instrumentation_surface_pct} instrumentationSurfaceBasis={vpec.instrumentation_surface_basis} coverageVerifiedPct={vpec.coverage_verified_pct} coveragePendingPct={vpec.coverage_pending_pct} coverageUngovernedPct={vpec.coverage_ungoverned_pct}/>
      </section>

      {/* Surface summary */}
      {vpec.surface_summary.length > 0 && (<section>
          <h3 className="font-semibold mb-2">Observation Surfaces</h3>
          <table className="w-full text-sm" data-testid="surface-summary-table">
            <thead>
              <tr className="border-b text-left">
                <th className="py-1 px-2">Surface</th>
                <th className="py-1 px-2">Type</th>
                <th className="py-1 px-2">Mode</th>
                <th className="py-1 px-2">Proof Ceiling</th>
                <th className="py-1 px-2">Scope</th>
                <th className="py-1 px-2">Coverage Statement</th>
              </tr>
            </thead>
            <tbody>
              {vpec.surface_summary.map((s) => (<tr key={s.surface_id}>
                  <td className="py-1 px-2 font-mono text-xs">{s.surface_id}</td>
                  <td className="py-1 px-2">{s.surface_type}</td>
                  <td className="py-1 px-2">{s.observation_mode}</td>
                  <td className="py-1 px-2">
                    <ProofLevelBadge level={s.proof_ceiling}/>
                  </td>
                  <td className="py-1 px-2">{s.scope_type}</td>
                  <td className="py-1 px-2">{s.surface_coverage_statement}</td>
                </tr>))}
            </tbody>
          </table>
        </section>)}

      {/* Manifest hashes — rendered as table from map (not array) */}
      <section>
        <h3 className="font-semibold mb-2">Manifest Hashes</h3>
        <ManifestHashesTable manifestHashes={vpec.manifest_hashes}/>
      </section>

      {/* Gaps — all 15 types must render */}
      <section>
        <h3 className="font-semibold mb-2">Gaps ({vpec.gaps.length})</h3>
        <GapTable gaps={vpec.gaps}/>
      </section>

      {/* Commitment root */}
      <section>
        <h3 className="font-semibold mb-2">Commitment Root</h3>
        <code className="text-xs font-mono bg-gray-100 px-2 py-1 rounded block">
          {vpec.commitment_root}
        </code>
      </section>

      {/* Process context hash — config epoch badge */}
      {vpec.process_context_hash && (<section>
          <h3 className="font-semibold mb-2">Config Epoch</h3>
          <span className="inline-block rounded bg-purple-100 px-2 py-0.5 text-xs font-mono" data-testid="config-epoch-badge">
            {vpec.process_context_hash}
          </span>
        </section>)}

      {/* Signature block */}
      <section>
        <h3 className="font-semibold mb-2">Signature</h3>
        <div className="text-sm space-y-1" data-testid="signature-block">
          <div>Signer: {vpec.signature.signer_id}</div>
          <div>Key ID: {vpec.signature.kid}</div>
          <div>Signed at: {vpec.signature.signed_at}</div>
        </div>
      </section>

      {/* Transparency log */}
      <section>
        <h3 className="font-semibold mb-2">Transparency Log</h3>
        {vpec.transparency_log?.rekor_log_id ? (<a href={`https://search.sigstore.dev/?logIndex=${vpec.transparency_log.rekor_log_id}`} className="text-blue-600 underline text-sm" data-testid="rekor-link">
            {vpec.transparency_log.rekor_log_id}
          </a>) : (<span className="inline-block rounded bg-yellow-200 px-2 py-0.5 text-xs" data-testid="rekor-pending-badge">
            Pending
          </span>)}
      </section>

      {/* ZK proof status */}
      {vpec.zk_proof && (<section>
          <h3 className="font-semibold mb-2">ZK Proof</h3>
          <ZkProofBadge status={vpec.zk_proof.status}/>
        </section>)}

      {/* Check execution records */}
      {records && records.length > 0 && (<section>
          <h3 className="font-semibold mb-2">
            Check Execution Records ({records.length})
          </h3>
          <table className="w-full text-sm" data-testid="records-table">
            <thead>
              <tr className="border-b text-left">
                <th className="py-1 px-2">Record</th>
                <th className="py-1 px-2">Manifest</th>
                <th className="py-1 px-2">Result</th>
                <th className="py-1 px-2">Proof Level</th>
                <th className="py-1 px-2">Recorded</th>
                <th className="py-1 px-2">Output</th>
                <th className="py-1 px-2">Timestamps</th>
                <th className="py-1 px-2">Reviewer</th>
              </tr>
            </thead>
            <tbody>
              {records.map((rec) => (<tr key={rec.record_id}>
                  <td className="py-1 px-2 font-mono text-xs">
                    {rec.record_id}
                  </td>
                  <td className="py-1 px-2 font-mono text-xs">
                    {rec.manifest_id}
                  </td>
                  <td className="py-1 px-2">{rec.check_result}</td>
                  <td className="py-1 px-2">
                    <ProofLevelBadge level={rec.proof_level_achieved}/>
                  </td>
                  <td className="py-1 px-2">{rec.recorded_at}</td>
                  <td className="py-1 px-2">
                    {rec.output_commitment ? (<span className="text-green-600 text-xs">present</span>) : (<span className="text-gray-400 text-xs">absent</span>)}
                  </td>
                  <td className="py-1 px-2 text-xs">
                    {rec.check_open_tst && (<span className="bg-blue-100 rounded px-1 mr-1">
                        open
                      </span>)}
                    {rec.check_close_tst && (<span className="bg-blue-100 rounded px-1">close</span>)}
                  </td>
                  <td className="py-1 px-2">
                    {rec.reviewer_credential ? (<span className="inline-block rounded bg-indigo-100 px-1 text-xs" data-testid="reviewer-credential-badge">
                        reviewed
                      </span>) : null}
                  </td>
                </tr>))}
            </tbody>
          </table>
        </section>)}
    </div>);
}
function ZkProofBadge({ status }) {
    const colors = {
        verified: "bg-green-200 text-green-800",
        pending: "bg-yellow-200 text-yellow-800",
        failed: "bg-red-200 text-red-800",
        none: "bg-gray-200 text-gray-600",
    };
    return (<span className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${colors[status] ?? colors.none}`} data-testid="zk-proof-badge">
      {status}
    </span>);
}
//# sourceMappingURL=RunDetail.js.map