interface SurfaceBreakdownProps {
  mathematical: number;
  execution: number;
  attestation: number;
}

const SEGMENT_COLORS = {
  mathematical: "bg-green-600",
  execution: "bg-yellow-500",
  attestation: "bg-gray-500",
};

const SEGMENT_TEXT_COLORS = {
  mathematical: "text-green-700",
  execution: "text-yellow-700",
  attestation: "text-gray-600",
};

export function SurfaceBreakdown({
  mathematical,
  execution,
  attestation,
}: SurfaceBreakdownProps) {
  const total = mathematical + execution + attestation;

  return (
    <div data-testid="surface-breakdown">
      {total > 0 && (
        <div className="flex h-6 rounded overflow-hidden mb-2">
          {mathematical > 0 && (
            <div
              className={`${SEGMENT_COLORS.mathematical} flex items-center justify-center text-xs font-medium text-white`}
              style={{ width: `${mathematical}%` }}
              data-testid="surface-bar-mathematical"
            >
              {mathematical >= 10 ? `${mathematical}%` : ""}
            </div>
          )}
          {execution > 0 && (
            <div
              className={`${SEGMENT_COLORS.execution} flex items-center justify-center text-xs font-medium text-black`}
              style={{ width: `${execution}%` }}
              data-testid="surface-bar-execution"
            >
              {execution >= 10 ? `${execution}%` : ""}
            </div>
          )}
          {attestation > 0 && (
            <div
              className={`${SEGMENT_COLORS.attestation} flex items-center justify-center text-xs font-medium text-white`}
              style={{ width: `${attestation}%` }}
              data-testid="surface-bar-attestation"
            >
              {attestation >= 10 ? `${attestation}%` : ""}
            </div>
          )}
        </div>
      )}

      <div className="flex flex-wrap gap-4 text-sm">
        <div className="flex items-center gap-1.5">
          <span className={`inline-block h-3 w-3 rounded ${SEGMENT_COLORS.mathematical}`} />
          <span className={SEGMENT_TEXT_COLORS.mathematical}>
            Mathematical {mathematical}%
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className={`inline-block h-3 w-3 rounded ${SEGMENT_COLORS.execution}`} />
          <span className={SEGMENT_TEXT_COLORS.execution}>
            Execution {execution}%
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className={`inline-block h-3 w-3 rounded ${SEGMENT_COLORS.attestation}`} />
          <span className={SEGMENT_TEXT_COLORS.attestation}>
            Attestation {attestation}%
          </span>
        </div>
      </div>

      <p className="text-xs text-gray-400 mt-2 italic">
        Actual provable_surface depends on manifest completeness at runtime.
      </p>
    </div>
  );
}
