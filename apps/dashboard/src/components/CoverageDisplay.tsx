interface CoverageDisplayProps {
  policyCoveragePct: number;
  recordsPass: number;
  recordsTotal: number;
  instrumentationSurfacePct: number | null;
  instrumentationSurfaceBasis: string | null;
  scopeType?: string;
  coverageVerifiedPct: number;
  coveragePendingPct: number;
  coverageUngovernedPct: number;
}

/**
 * TWO DENOMINATOR DISPLAY — mandatory, never collapse.
 * 1. Policy denominator: "Policy coverage: X% (Y of Z required checks ran)"
 * 2. Surface denominator: "Instrumentation surface: X% (scope — basis)"
 *    null → "Scope partially unknown — coverage is a lower bound"
 */
export function CoverageDisplay({
  policyCoveragePct,
  recordsPass,
  recordsTotal,
  instrumentationSurfacePct,
  instrumentationSurfaceBasis,
  scopeType,
  coverageVerifiedPct,
  coveragePendingPct,
  coverageUngovernedPct,
}: CoverageDisplayProps) {
  return (
    <div className="space-y-3" data-testid="coverage-display">
      {/* Denominator 1: Policy coverage */}
      <div data-testid="policy-denominator">
        <span className="font-semibold">Policy coverage: </span>
        <span>{policyCoveragePct}%</span>
        <span className="text-gray-500 ml-1">
          ({recordsPass}/{recordsTotal} required checks ran)
        </span>
      </div>

      {/* Denominator 2: Instrumentation surface */}
      <div data-testid="surface-denominator">
        <span className="font-semibold">Instrumentation surface: </span>
        {instrumentationSurfacePct !== null ? (
          <>
            <span>{instrumentationSurfacePct}%</span>
            {instrumentationSurfaceBasis && (
              <span className="text-gray-500 ml-1">
                ({scopeType ?? "full_workflow"} — {instrumentationSurfaceBasis})
              </span>
            )}
          </>
        ) : (
          <span className="text-amber-600" data-testid="lower-bound-warning">
            Scope partially unknown — coverage is a lower bound
          </span>
        )}
      </div>

      {/* Coverage buckets — must sum to 100 */}
      <div data-testid="coverage-buckets">
        <div className="flex h-4 rounded overflow-hidden">
          {coverageVerifiedPct > 0 && (
            <div
              className="bg-green-600"
              style={{ width: `${coverageVerifiedPct}%` }}
              data-testid="bucket-verified"
            />
          )}
          {coveragePendingPct > 0 && (
            <div
              className="bg-yellow-400"
              style={{ width: `${coveragePendingPct}%` }}
              data-testid="bucket-pending"
            />
          )}
          {coverageUngovernedPct > 0 && (
            <div
              className="bg-gray-300"
              style={{ width: `${coverageUngovernedPct}%` }}
              data-testid="bucket-ungoverned"
            />
          )}
        </div>
        <div className="flex text-xs mt-1 gap-4">
          <span>Verified: {coverageVerifiedPct}%</span>
          <span>Pending: {coveragePendingPct}%</span>
          <span>Ungoverned: {coverageUngovernedPct}%</span>
        </div>
      </div>
    </div>
  );
}
