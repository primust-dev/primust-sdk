/**
 * P12-B: Gap Inbox + Waiver Flow — 5 MUST PASS.
 */
import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import React from "react";

import { GapInbox } from "../src/components/GapInbox";
import { GapDetail } from "../src/components/GapDetail";
import { WaiverForm } from "../src/components/WaiverForm";
import type { GapEntry, GapType } from "../src/types/vpec";
import { GAP_TYPE_LABELS } from "../src/lib/constants";

const ALL_15_GAP_TYPES: GapType[] = [
  "check_not_executed",
  "enforcement_override",
  "engine_error",
  "check_degraded",
  "external_boundary_traversal",
  "lineage_token_missing",
  "admission_gate_override",
  "check_timing_suspect",
  "reviewer_credential_invalid",
  "witnessed_display_missing",
  "witnessed_rationale_missing",
  "deterministic_consistency_violation",
  "skip_rationale_missing",
  "policy_config_drift",
  "zkml_proof_pending_timeout",
  "zkml_proof_failed",
];

function makeGap(
  type: GapType,
  severity: GapEntry["severity"] = "High",
  details: Record<string, unknown> = {},
): GapEntry {
  return {
    gap_id: `gap_${type}`,
    gap_type: type,
    severity,
    state: "open",
    details,
    detected_at: "2026-03-10T12:00:00Z",
    resolved_at: null,
  };
}

describe("P12-B: Gap Inbox + Waiver Flow", () => {
  it("MUST PASS: all 15 gap types display with correct label", () => {
    const gaps = ALL_15_GAP_TYPES.map((t) => makeGap(t));
    render(<GapInbox gaps={gaps} />);

    for (const type of ALL_15_GAP_TYPES) {
      const label = screen.getByTestId(`gap-type-label-${type}`);
      expect(label).toBeInTheDocument();
      expect(label.textContent).toBe(GAP_TYPE_LABELS[type]);
    }
  });

  it("MUST PASS: waiver form blocked without expires_at", () => {
    const onSubmit = vi.fn();
    render(<WaiverForm gapId="gap_001" onSubmit={onSubmit} />);

    const submitBtn = screen.getByTestId("waiver-submit");
    expect(submitBtn).toBeDisabled();

    // Try submitting without expires_at
    fireEvent.click(submitBtn);
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("MUST PASS: expires_at > 90 days → form error", () => {
    const onSubmit = vi.fn();
    render(<WaiverForm gapId="gap_001" onSubmit={onSubmit} />);

    // Fill in reason (> 50 chars)
    const reasonInput = screen.getByTestId("waiver-reason");
    fireEvent.change(reasonInput, {
      target: { value: "A".repeat(60) },
    });

    // Set expires_at to 100 days from now
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 100);
    const expiresInput = screen.getByTestId("waiver-expires-at");
    fireEvent.change(expiresInput, {
      target: { value: futureDate.toISOString().split("T")[0] },
    });

    // Submit the form
    const form = screen.getByTestId("waiver-form");
    fireEvent.submit(form);

    expect(screen.getByTestId("waiver-error")).toBeInTheDocument();
    expect(screen.getByTestId("waiver-error").textContent).toContain("90 days");
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("MUST PASS: policy_config_drift gap shows prior_hash / current_hash diff", () => {
    const gap = makeGap("policy_config_drift", "Medium", {
      prior_hash: "sha256:oldconfig111",
      current_hash: "sha256:newconfig222",
    });
    render(<GapDetail gap={gap} />);

    const diff = screen.getByTestId("config-drift-diff");
    expect(diff).toBeInTheDocument();
    expect(diff.textContent).toContain("sha256:oldconfig111");
    expect(diff.textContent).toContain("sha256:newconfig222");
  });

  it("MUST PASS: Critical gaps display in red at top of inbox", () => {
    const gaps: GapEntry[] = [
      makeGap("engine_error", "Medium"),
      makeGap("enforcement_override", "Critical"),
      makeGap("check_not_executed", "High"),
    ];
    render(<GapInbox gaps={gaps} />);

    // Critical gap row should have red background
    const criticalRow = screen.getByTestId("gap-inbox-row-gap_enforcement_override");
    expect(criticalRow.className).toContain("bg-red-50");

    // Critical should be first in rendered order
    const rows = screen.getAllByRole("row").slice(1); // skip header
    expect(rows[0]).toHaveAttribute(
      "data-testid",
      "gap-inbox-row-gap_enforcement_override",
    );
  });
});
