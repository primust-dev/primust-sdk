"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "../../lib/api";
import type { GapEntry } from "../../types/vpec";
import { GapInbox } from "../../components/GapInbox";
import { GapTable } from "../../components/GapTable";
import { GapDetail } from "../../components/GapDetail";
import { WaiverForm } from "../../components/WaiverForm";

interface GapsResponse {
  gaps: GapEntry[];
}

export default function GapsPage() {
  const [gaps, setGaps] = useState<GapEntry[]>([]);
  const [selectedGap, setSelectedGap] = useState<GapEntry | null>(null);
  const [showWaiverForm, setShowWaiverForm] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<"inbox" | "table">("inbox");

  useEffect(() => {
    let cancelled = false;

    async function fetchGaps() {
      try {
        const res = await apiFetch<GapsResponse>("/gaps");
        if (!cancelled) {
          setGaps(res.gaps);
          setLoading(false);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load gaps");
          setLoading(false);
        }
      }
    }

    fetchGaps();
    return () => {
      cancelled = true;
    };
  }, []);

  async function handleWaiverSubmit(data: {
    reason: string;
    compensating_control: string | null;
    expires_at: string;
  }) {
    if (!selectedGap) return;

    try {
      await apiFetch(`/gaps/${selectedGap.gap_id}/waiver`, {
        method: "POST",
        body: data,
      });
      // Update local state to reflect waiver
      setGaps((prev) =>
        prev.map((g) =>
          g.gap_id === selectedGap.gap_id ? { ...g, state: "waived" as const } : g,
        ),
      );
      setShowWaiverForm(false);
      setSelectedGap(null);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to submit waiver",
      );
    }
  }

  return (
    <div className="space-y-6" data-testid="gaps-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Gaps</h1>
          <p className="mt-1 text-sm text-gray-600">
            Governance gaps sorted by severity. Review, investigate, or waive
            gaps as needed.
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setView("inbox")}
            className={`px-3 py-1.5 rounded text-sm ${
              view === "inbox"
                ? "bg-blue-600 text-white"
                : "border hover:bg-gray-50"
            }`}
          >
            Inbox
          </button>
          <button
            onClick={() => setView("table")}
            className={`px-3 py-1.5 rounded text-sm ${
              view === "table"
                ? "bg-blue-600 text-white"
                : "border hover:bg-gray-50"
            }`}
          >
            Table
          </button>
        </div>
      </div>

      {error && (
        <div
          className="rounded-lg border border-red-300 bg-red-50 p-4 text-sm text-red-800"
          data-testid="gaps-error"
        >
          {error}
        </div>
      )}

      {loading ? (
        <div className="text-sm text-gray-500 py-8 text-center">
          Loading gaps...
        </div>
      ) : selectedGap ? (
        <div className="flex gap-6">
          <div className="flex-1 min-w-0">
            <button
              onClick={() => {
                setSelectedGap(null);
                setShowWaiverForm(false);
              }}
              className="text-sm text-blue-600 hover:underline mb-4"
            >
              &larr; Back to all gaps
            </button>
            <div className="rounded-lg border border-gray-200 bg-white p-6">
              <GapDetail gap={selectedGap} />
              {selectedGap.state === "open" && !showWaiverForm && (
                <button
                  onClick={() => setShowWaiverForm(true)}
                  className="mt-4 px-4 py-2 border rounded text-sm hover:bg-gray-50"
                  data-testid="open-waiver-btn"
                >
                  Request Waiver
                </button>
              )}
            </div>
          </div>

          {showWaiverForm && selectedGap.state === "open" && (
            <aside className="w-1/3 min-w-[300px]">
              <div className="rounded-lg border border-gray-200 bg-white p-6">
                <WaiverForm
                  gapId={selectedGap.gap_id}
                  onSubmit={handleWaiverSubmit}
                />
              </div>
            </aside>
          )}
        </div>
      ) : (
        <div className="rounded-lg border border-gray-200 bg-white">
          {view === "inbox" ? (
            <div className="overflow-x-auto">
              <div
                onClick={(e) => {
                  const row = (e.target as HTMLElement).closest("tr[data-testid]");
                  if (!row) return;
                  const gapId = row.getAttribute("data-testid")?.replace("gap-inbox-row-", "");
                  const gap = gaps.find((g) => g.gap_id === gapId);
                  if (gap) setSelectedGap(gap);
                }}
                className="cursor-pointer"
              >
                <GapInbox gaps={gaps} />
              </div>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <GapTable gaps={gaps} />
            </div>
          )}

          {gaps.length === 0 && (
            <div className="py-12 text-center text-sm text-gray-400">
              No gaps found. All governance checks are passing.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
