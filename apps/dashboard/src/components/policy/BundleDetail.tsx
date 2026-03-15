"use client";

import { useState } from "react";
import type { PolicyBundle, BundleCheck } from "../../types/policy";
import type { ProofLevel } from "../../types/vpec";
import { PROOF_LEVEL_COLORS, PROOF_LEVEL_LABELS } from "../../lib/constants";
import { SurfaceBreakdown } from "./SurfaceBreakdown";

interface BundleDetailProps {
  bundle: PolicyBundle;
  onSelectBundle: (bundleId: string) => void;
}

function ProofCeilingBadge({ level }: { level: ProofLevel }) {
  return (
    <span
      className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${PROOF_LEVEL_COLORS[level]}`}
    >
      {PROOF_LEVEL_LABELS[level]}
    </span>
  );
}

function CheckRow({
  check,
  onThresholdChange,
}: {
  check: BundleCheck;
  onThresholdChange: (checkId: string, value: number) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [localThreshold, setLocalThreshold] = useState(
    check.threshold?.toString() ?? "",
  );

  function handleBlur() {
    setEditing(false);
    const parsed = parseFloat(localThreshold);
    if (!isNaN(parsed)) {
      onThresholdChange(check.check_id, parsed);
    }
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Enter") {
      (e.target as HTMLInputElement).blur();
    }
    if (e.key === "Escape") {
      setLocalThreshold(check.threshold?.toString() ?? "");
      setEditing(false);
    }
  }

  return (
    <tr className="border-b" data-testid={`check-row-${check.check_id}`}>
      <td className="py-2 px-2 text-sm">
        <div className="font-medium">{check.check_name}</div>
        {check.required && (
          <span className="text-xs text-red-600">Required</span>
        )}
      </td>
      <td className="py-2 px-2">
        <ProofCeilingBadge level={check.proof_ceiling} />
      </td>
      <td className="py-2 px-2 text-sm text-gray-600">{check.what_it_proves}</td>
      <td className="py-2 px-2">
        {check.threshold !== undefined ? (
          editing ? (
            <input
              type="number"
              value={localThreshold}
              onChange={(e) => setLocalThreshold(e.target.value)}
              onBlur={handleBlur}
              onKeyDown={handleKeyDown}
              className="w-20 rounded border border-blue-400 px-2 py-1 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400"
              autoFocus
              data-testid={`threshold-input-${check.check_id}`}
            />
          ) : (
            <button
              type="button"
              onClick={() => setEditing(true)}
              className="rounded px-2 py-1 text-sm font-mono hover:bg-gray-100 transition-colors"
              data-testid={`threshold-value-${check.check_id}`}
            >
              {check.threshold}
            </button>
          )
        ) : (
          <span className="text-xs text-gray-400">n/a</span>
        )}
      </td>
      <td className="py-2 px-2 text-center">
        {check.zk_circuit ? (
          <span
            className="inline-block rounded bg-green-100 px-2 py-0.5 text-xs text-green-700 font-medium"
            title={check.zk_circuit}
          >
            ZK
          </span>
        ) : (
          <span className="text-xs text-gray-400">—</span>
        )}
      </td>
    </tr>
  );
}

export function BundleDetail({ bundle, onSelectBundle }: BundleDetailProps) {
  const [checks, setChecks] = useState<BundleCheck[]>(bundle.checks);

  function handleThresholdChange(checkId: string, value: number) {
    setChecks((prev) =>
      prev.map((c) => (c.check_id === checkId ? { ...c, threshold: value } : c)),
    );
  }

  const surfaceSplit = computeSurfaceSplit(checks);

  return (
    <div data-testid="bundle-detail">
      <div className="mb-4">
        <h2 className="text-xl font-semibold">{bundle.name}</h2>
        <div className="flex items-center gap-2 mt-1">
          <span className="text-sm text-gray-500">v{bundle.version}</span>
          {bundle.framework_mappings.map((fw) => (
            <span
              key={fw}
              className="inline-block rounded bg-purple-100 px-1.5 py-0.5 text-xs text-purple-700"
            >
              {fw}
            </span>
          ))}
        </div>
        {bundle.description && (
          <p className="text-sm text-gray-600 mt-2">{bundle.description}</p>
        )}
      </div>

      <div className="mb-4">
        <h3 className="text-sm font-semibold mb-2">Required Checks</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm" data-testid="checks-table">
            <thead>
              <tr className="border-b text-left">
                <th className="py-2 px-2">Check Name</th>
                <th className="py-2 px-2">Proof Ceiling</th>
                <th className="py-2 px-2">What It Proves</th>
                <th className="py-2 px-2">Threshold</th>
                <th className="py-2 px-2 text-center">ZK?</th>
              </tr>
            </thead>
            <tbody>
              {checks.map((check) => (
                <CheckRow
                  key={check.check_id}
                  check={check}
                  onThresholdChange={handleThresholdChange}
                />
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="mb-4">
        <h3 className="text-sm font-semibold mb-2">Estimated Provable Surface</h3>
        <SurfaceBreakdown
          mathematical={surfaceSplit.mathematical}
          execution={surfaceSplit.execution}
          attestation={surfaceSplit.attestation}
        />
      </div>

      <button
        type="button"
        onClick={() => onSelectBundle(bundle.bundle_id)}
        className="rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 transition-colors"
        data-testid="select-bundle-btn"
      >
        Select this bundle
      </button>
    </div>
  );
}

function computeSurfaceSplit(checks: BundleCheck[]): {
  mathematical: number;
  execution: number;
  attestation: number;
} {
  if (checks.length === 0) return { mathematical: 0, execution: 0, attestation: 0 };

  const mathLevels: ProofLevel[] = ["mathematical", "verifiable_inference"];
  const execLevels: ProofLevel[] = ["execution", "witnessed"];

  let math = 0;
  let exec = 0;
  let attest = 0;

  for (const check of checks) {
    if (mathLevels.includes(check.proof_ceiling)) math++;
    else if (execLevels.includes(check.proof_ceiling)) exec++;
    else attest++;
  }

  const total = checks.length;
  return {
    mathematical: Math.round((math / total) * 100),
    execution: Math.round((exec / total) * 100),
    attestation: Math.round((attest / total) * 100),
  };
}
