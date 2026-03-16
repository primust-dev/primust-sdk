"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "../../lib/api";
import type {
  VPECArtifact,
  GapSeverity,
  ProofDistribution,
} from "../../types/vpec";
import { EvidencePackAssembler } from "../../components/EvidencePackAssembler";
import { CoverageReport } from "../../components/CoverageReport";

interface ArtifactsResponse {
  artifacts: VPECArtifact[];
}

export default function EvidencePage() {
  const [artifacts, setArtifacts] = useState<VPECArtifact[]>([]);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [assembleStatus, setAssembleStatus] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function fetchArtifacts() {
      try {
        const res = await apiFetch<ArtifactsResponse>("/artifacts");
        if (!cancelled) {
          setArtifacts(res.artifacts);
          setLoading(false);
        }
      } catch (err) {
        if (!cancelled) {
          setError(
            err instanceof Error ? err.message : "Failed to load artifacts",
          );
          setLoading(false);
        }
      }
    }

    fetchArtifacts();
    return () => {
      cancelled = true;
    };
  }, []);

  function toggleSelection(vpecId: string) {
    setSelectedIds((prev) =>
      prev.includes(vpecId)
        ? prev.filter((id) => id !== vpecId)
        : [...prev, vpecId],
    );
  }

  function selectAll() {
    setSelectedIds(artifacts.map((a) => a.vpec_id));
  }

  function clearSelection() {
    setSelectedIds([]);
  }

  async function handleAssembleLocal(ids: string[]) {
    try {
      setAssembleStatus("Assembling locally...");
      await apiFetch("/evidence-packs/assemble", {
        method: "POST",
        body: { artifact_ids: ids, mode: "local" },
      });
      setAssembleStatus("Local evidence pack assembled successfully.");
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to assemble evidence pack",
      );
      setAssembleStatus(null);
    }
  }

  async function handleAssembleHosted(ids: string[]) {
    try {
      setAssembleStatus("Assembling via hosted service...");
      await apiFetch("/evidence-packs/assemble", {
        method: "POST",
        body: { artifact_ids: ids, mode: "hosted" },
      });
      setAssembleStatus("Hosted evidence pack assembled successfully.");
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to assemble evidence pack",
      );
      setAssembleStatus(null);
    }
  }

  // Compute aggregate coverage report from selected artifacts
  const selectedArtifacts = artifacts.filter((a) =>
    selectedIds.includes(a.vpec_id),
  );

  const aggregateCoverage = computeAggregateCoverage(selectedArtifacts);

  return (
    <div className="space-y-6" data-testid="evidence-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Evidence</h1>
          <p className="mt-1 text-sm text-gray-600">
            Select VPECs and assemble evidence packs for audit and compliance
            reporting.
          </p>
        </div>
      </div>

      {error && (
        <div
          className="rounded-lg border border-red-300 bg-red-50 p-4 text-sm text-red-800"
          data-testid="evidence-error"
        >
          {error}
        </div>
      )}

      {assembleStatus && (
        <div
          className="rounded-lg border border-green-300 bg-green-50 p-4 text-sm text-green-800"
          data-testid="evidence-status"
        >
          {assembleStatus}
        </div>
      )}

      {loading ? (
        <div className="text-sm text-gray-500 py-8 text-center">
          Loading artifacts...
        </div>
      ) : (
        <>
          {/* VPEC selection table */}
          <div className="rounded-lg border border-gray-200 bg-white">
            <div className="px-4 py-3 border-b flex items-center justify-between">
              <span className="text-sm font-semibold">
                {selectedIds.length} of {artifacts.length} VPECs selected
              </span>
              <div className="flex gap-2">
                <button
                  onClick={selectAll}
                  className="text-sm text-blue-600 hover:underline"
                >
                  Select all
                </button>
                <button
                  onClick={clearSelection}
                  className="text-sm text-gray-500 hover:underline"
                >
                  Clear
                </button>
              </div>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm" data-testid="vpec-select-table">
                <thead>
                  <tr className="border-b text-left">
                    <th className="py-2 px-2 w-8"></th>
                    <th className="py-2 px-2">VPEC ID</th>
                    <th className="py-2 px-2">Workflow</th>
                    <th className="py-2 px-2">Proof Level</th>
                    <th className="py-2 px-2">Coverage</th>
                    <th className="py-2 px-2">Gaps</th>
                    <th className="py-2 px-2">Closed</th>
                  </tr>
                </thead>
                <tbody>
                  {artifacts.map((artifact) => (
                    <tr
                      key={artifact.vpec_id}
                      className={`border-b cursor-pointer hover:bg-gray-50 ${
                        selectedIds.includes(artifact.vpec_id)
                          ? "bg-blue-50"
                          : ""
                      }`}
                      onClick={() => toggleSelection(artifact.vpec_id)}
                    >
                      <td className="py-2 px-2">
                        <input
                          type="checkbox"
                          checked={selectedIds.includes(artifact.vpec_id)}
                          onChange={() => toggleSelection(artifact.vpec_id)}
                          className="rounded"
                        />
                      </td>
                      <td className="py-2 px-2 font-mono text-xs">
                        {artifact.vpec_id}
                      </td>
                      <td className="py-2 px-2">{artifact.workflow_id}</td>
                      <td className="py-2 px-2">{artifact.proof_level}</td>
                      <td className="py-2 px-2">
                        {artifact.policy_coverage_pct}%
                      </td>
                      <td className="py-2 px-2">{artifact.gaps.length}</td>
                      <td className="py-2 px-2">{artifact.closed_at}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {artifacts.length === 0 && (
              <div className="py-12 text-center text-sm text-gray-400">
                No artifacts found. Complete a governance run to generate VPECs.
              </div>
            )}
          </div>

          {/* Assembler and coverage report for selection */}
          {selectedIds.length > 0 && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="rounded-lg border border-gray-200 bg-white p-6">
                <EvidencePackAssembler
                  artifactIds={selectedIds}
                  onAssembleLocal={handleAssembleLocal}
                  onAssembleHosted={handleAssembleHosted}
                />
              </div>

              <div className="rounded-lg border border-gray-200 bg-white p-6">
                <h2 className="text-lg font-bold mb-4">Coverage Summary</h2>
                <CoverageReport
                  policyCoveragePct={aggregateCoverage.policyCoveragePct}
                  recordsPass={aggregateCoverage.recordsPass}
                  recordsTotal={aggregateCoverage.recordsTotal}
                  instrumentationSurfacePct={
                    aggregateCoverage.instrumentationSurfacePct
                  }
                  instrumentationSurfaceBasis={
                    aggregateCoverage.instrumentationSurfaceBasis
                  }
                  coverageVerifiedPct={aggregateCoverage.coverageVerifiedPct}
                  coveragePendingPct={aggregateCoverage.coveragePendingPct}
                  coverageUngovernedPct={aggregateCoverage.coverageUngovernedPct}
                  proofDistribution={aggregateCoverage.proofDistribution}
                  gapSummary={aggregateCoverage.gapSummary}
                />
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

/** Aggregate coverage metrics across selected artifacts. */
function computeAggregateCoverage(artifacts: VPECArtifact[]) {
  if (artifacts.length === 0) {
    return {
      policyCoveragePct: 0,
      recordsPass: 0,
      recordsTotal: 0,
      instrumentationSurfacePct: null as number | null,
      instrumentationSurfaceBasis: null as string | null,
      coverageVerifiedPct: 0,
      coveragePendingPct: 0,
      coverageUngovernedPct: 0,
      proofDistribution: {
        mathematical: 0,
        verifiable_inference: 0,
        execution: 0,
        witnessed: 0,
        attestation: 0,
        weakest_link: "attestation" as const,
        weakest_link_explanation: "",
      } satisfies ProofDistribution,
      gapSummary: {
        Critical: 0,
        High: 0,
        Medium: 0,
        Low: 0,
        Informational: 0,
      } as Record<GapSeverity, number>,
    };
  }

  const totalRecords = artifacts.reduce((sum, a) => sum + a.records_total, 0);
  const totalPass = artifacts.reduce((sum, a) => sum + a.records_pass, 0);

  const avgCoverage =
    artifacts.reduce((sum, a) => sum + a.policy_coverage_pct, 0) /
    artifacts.length;
  const avgVerified =
    artifacts.reduce((sum, a) => sum + a.coverage_verified_pct, 0) /
    artifacts.length;
  const avgPending =
    artifacts.reduce((sum, a) => sum + a.coverage_pending_pct, 0) /
    artifacts.length;
  const avgUngoverned =
    artifacts.reduce((sum, a) => sum + a.coverage_ungoverned_pct, 0) /
    artifacts.length;

  // Use the first artifact's instrumentation basis as representative
  const firstWithSurface = artifacts.find(
    (a) => a.instrumentation_surface_pct !== null,
  );

  // Aggregate proof distribution (average)
  const proofDistribution: ProofDistribution = {
    mathematical:
      artifacts.reduce((s, a) => s + a.proof_distribution.mathematical, 0) /
      artifacts.length,
    verifiable_inference:
      artifacts.reduce(
        (s, a) => s + a.proof_distribution.verifiable_inference,
        0,
      ) / artifacts.length,
    execution:
      artifacts.reduce((s, a) => s + a.proof_distribution.execution, 0) /
      artifacts.length,
    witnessed:
      artifacts.reduce((s, a) => s + a.proof_distribution.witnessed, 0) /
      artifacts.length,
    attestation:
      artifacts.reduce((s, a) => s + a.proof_distribution.attestation, 0) /
      artifacts.length,
    weakest_link: artifacts[0].proof_distribution.weakest_link,
    weakest_link_explanation:
      artifacts[0].proof_distribution.weakest_link_explanation,
  };

  // Aggregate gap summary
  const gapSummary: Record<GapSeverity, number> = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Informational: 0,
  };
  for (const artifact of artifacts) {
    for (const gap of artifact.gaps) {
      gapSummary[gap.severity]++;
    }
  }

  return {
    policyCoveragePct: Math.round(avgCoverage * 100) / 100,
    recordsPass: totalPass,
    recordsTotal: totalRecords,
    instrumentationSurfacePct:
      firstWithSurface?.instrumentation_surface_pct ?? null,
    instrumentationSurfaceBasis:
      firstWithSurface?.instrumentation_surface_basis ?? null,
    coverageVerifiedPct: Math.round(avgVerified * 100) / 100,
    coveragePendingPct: Math.round(avgPending * 100) / 100,
    coverageUngovernedPct: Math.round(avgUngoverned * 100) / 100,
    proofDistribution,
    gapSummary,
  };
}
