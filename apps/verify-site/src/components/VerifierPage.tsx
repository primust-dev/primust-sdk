import { useState, useCallback } from "react";
import type { VerificationResult } from "../types/vpec";
import { verifyArtifact } from "../lib/verify";
import { VerificationPanel } from "./VerificationPanel";

const PROOF_LEVEL_COLORS: Record<string, string> = {
  mathematical: "text-green-600",
  verifiable_inference: "text-blue-600",
  execution: "text-yellow-600",
  witnessed: "text-orange-600",
  attestation: "text-gray-600",
};

const PROOF_LEVEL_LABELS: Record<string, string> = {
  mathematical: "mathematical",
  verifiable_inference: "verifiable_inference",
  execution: "execution",
  witnessed: "witnessed",
  attestation: "attestation",
};

/**
 * verify.primust.com — No login required.
 * File drop or paste JSON → verification result.
 */
export function VerifierPage() {
  const [result, setResult] = useState<VerificationResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [artifact, setArtifact] = useState<Record<string, unknown> | null>(null);

  const handleVerify = useCallback((json: string) => {
    setError(null);
    setResult(null);
    try {
      const parsed = JSON.parse(json);
      setArtifact(parsed);
      const res = verifyArtifact(parsed);
      setResult(res);
    } catch {
      setError("Invalid JSON");
    }
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      const file = e.dataTransfer.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => handleVerify(reader.result as string);
      reader.readAsText(file);
    },
    [handleVerify],
  );

  const handlePaste = useCallback(
    (e: React.ChangeEvent<HTMLTextAreaElement>) => {
      const val = e.target.value;
      if (val.trim()) handleVerify(val);
    },
    [handleVerify],
  );

  return (
    <div className="max-w-3xl mx-auto p-6" data-testid="verifier-page">
      <h1 className="text-2xl font-bold mb-4">verify.primust.com</h1>
      <p className="text-gray-600 mb-6">
        Drop a VPEC JSON file or paste the contents. No login required.
      </p>

      {/* File drop zone */}
      <div
        className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center mb-4"
        onDrop={handleDrop}
        onDragOver={(e) => e.preventDefault()}
        data-testid="drop-zone"
      >
        <p className="text-gray-500">Drop VPEC JSON here</p>
      </div>

      {/* Paste area */}
      <textarea
        className="w-full border rounded p-3 font-mono text-xs h-32 mb-4"
        placeholder="Or paste VPEC JSON here..."
        onChange={handlePaste}
        data-testid="paste-area"
      />

      {error && (
        <div className="text-red-600 mb-4" data-testid="parse-error">
          {error}
        </div>
      )}

      {/* Landing summary */}
      {result && (
        <div className="mb-6" data-testid="landing-summary">
          <div className="text-lg font-bold mb-2">
            VPEC ID: <span className="font-mono">{result.vpec_id}</span>
          </div>
          <div className="space-y-1 text-sm">
            <div>
              Coverage:{" "}
              {String((result.coverage as Record<string, unknown>).policy_coverage_pct ?? "—")}%
            </div>
            <div>
              Proof Level:{" "}
              <span className={PROOF_LEVEL_COLORS[result.proof_level] ?? ""}>
                {PROOF_LEVEL_LABELS[result.proof_level] ?? result.proof_level}
              </span>
              {" ("}
              {Object.entries(result.proof_distribution)
                .filter(
                  ([k, v]) =>
                    typeof v === "number" &&
                    v > 0 &&
                    k !== "weakest_link" &&
                    k !== "weakest_link_explanation",
                )
                .map(([k, v]) => `${v} ${PROOF_LEVEL_LABELS[k] ?? k}`)
                .join(" · ")}
              {")"}
            </div>
            <div>
              Weakest link:{" "}
              {PROOF_LEVEL_LABELS[result.proof_distribution.weakest_link] ??
                result.proof_distribution.weakest_link}
            </div>
            <div>Issued: {result.signed_at}</div>
          </div>
        </div>
      )}

      {/* Verification panel */}
      {result && <VerificationPanel result={result} artifact={artifact} />}

      {/* P1 disclaimer — always visible, never hideable */}
      <div
        className="mt-8 border-t pt-4 text-xs text-gray-500"
        data-testid="p1-disclaimer"
      >
        This verification checks the cryptographic integrity of the VPEC
        artifact. It does not constitute an independent audit or certification.
        The VPEC documents what governance checks were observed during process
        execution. Primust does not warrant the correctness of the underlying
        process.
      </div>
    </div>
  );
}
