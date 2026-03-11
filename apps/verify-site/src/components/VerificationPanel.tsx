import type { VerificationResult } from "../types/vpec";

interface VerificationPanelProps {
  result: VerificationResult;
  artifact: Record<string, unknown> | null;
}

export function VerificationPanel({ result, artifact }: VerificationPanelProps) {
  const witnessedCount = (artifact?.gaps as Array<Record<string, string>> | undefined)
    ?.filter(
      (g) =>
        g.gap_type === "witnessed_display_missing" ||
        g.gap_type === "witnessed_rationale_missing" ||
        g.gap_type === "reviewer_credential_invalid",
    ).length ?? 0;

  const configDriftCount = (artifact?.gaps as Array<Record<string, string>> | undefined)
    ?.filter((g) => g.gap_type === "policy_config_drift").length ?? 0;

  // Count witnessed records from proof distribution
  const witnessedRecords =
    typeof result.proof_distribution.witnessed === "number"
      ? result.proof_distribution.witnessed
      : 0;

  return (
    <div className="space-y-4" data-testid="verification-panel">
      {/* Valid / Invalid banner */}
      {result.valid ? (
        <div
          className="bg-green-50 border border-green-300 rounded p-4"
          data-testid="valid-banner"
        >
          <div className="text-green-800 font-bold text-lg">
            &#10003; Signature valid (signer: {result.signer_id}, kid: {result.kid})
          </div>
          <div className="text-green-700 text-sm mt-1">
            &#10003; Signer status: active
          </div>
        </div>
      ) : (
        <div
          className="bg-red-50 border border-red-300 rounded p-4"
          data-testid="invalid-banner"
        >
          <div className="text-red-800 font-bold text-lg">
            &#10007; Verification failed
          </div>
          <ul className="text-red-700 text-sm mt-1 list-disc ml-4">
            {result.errors.map((err, i) => (
              <li key={i} data-testid={`error-${err}`}>
                {err}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Offline verification */}
      <div className="bg-gray-50 rounded p-4" data-testid="offline-verify">
        <div className="font-semibold mb-2">Verify offline:</div>
        <pre className="text-xs font-mono bg-white p-2 rounded border">
          pip install primust-verify{"\n"}
          primust verify &lt;vpec.json&gt; --trust-root &lt;key.pem&gt;
        </pre>
      </div>

      {/* What this proves / does not prove */}
      <div data-testid="provenance-explanation">
        <div className="mb-2">
          <span className="font-semibold">What this proves: </span>
          The listed governance checks were executed by the declared observation
          surface during process execution. Results are commitment-bound and
          cryptographically signed.
        </div>
        <div>
          <span className="font-semibold">What this does not prove: </span>
          The correctness of the process itself, the completeness of the
          observation surface, or the absence of unobserved actions outside the
          declared scope.
        </div>
      </div>

      {/* Witnessed records section */}
      {witnessedRecords > 0 && (
        <div
          className="bg-indigo-50 border border-indigo-200 rounded p-4"
          data-testid="witnessed-section"
        >
          {witnessedRecords} checks had Witnessed-level review (display_hash +
          rationale_hash committed by reviewer). Reviewer credentials verifiable
          against org JWKS URL.
        </div>
      )}

      {/* Policy config drift notice */}
      {configDriftCount > 0 && (
        <div
          className="bg-amber-50 border border-amber-200 rounded p-4"
          data-testid="config-drift-notice"
        >
          Configuration drift detected during this run. {configDriftCount}{" "}
          check(s) had changed manifest hashes.
        </div>
      )}

      {/* Warnings */}
      {result.warnings.length > 0 && (
        <div className="text-sm text-amber-600" data-testid="warnings">
          {result.warnings.map((w, i) => (
            <div key={i}>{w}</div>
          ))}
        </div>
      )}
    </div>
  );
}
