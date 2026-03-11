/**
 * P12-D: Evidence Pack Assembler UI — 2 MUST PASS.
 */
import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import React from "react";

import { EvidencePackAssembler } from "../src/components/EvidencePackAssembler";

describe("P12-D: Evidence Pack Assembler UI", () => {
  it("MUST PASS: local download works (default mode)", () => {
    const onLocal = vi.fn();
    const onHosted = vi.fn();
    render(
      <EvidencePackAssembler
        artifactIds={["vpec_001", "vpec_002"]}
        onAssembleLocal={onLocal}
        onAssembleHosted={onHosted}
      />,
    );

    // Local mode button visible with correct badge
    const localBtn = screen.getByTestId("mode-local");
    expect(localBtn).toBeInTheDocument();
    expect(screen.getByTestId("local-badge").textContent).toContain(
      "raw content does not leave your environment",
    );

    // Click local → calls onAssembleLocal
    fireEvent.click(localBtn);
    expect(onLocal).toHaveBeenCalledWith(["vpec_001", "vpec_002"]);
    expect(onHosted).not.toHaveBeenCalled();
  });

  it("MUST PASS: hosted requires acknowledgment", () => {
    const onLocal = vi.fn();
    const onHosted = vi.fn();
    render(
      <EvidencePackAssembler
        artifactIds={["vpec_001"]}
        onAssembleLocal={onLocal}
        onAssembleHosted={onHosted}
      />,
    );

    // Click hosted → should show acknowledgment dialog, NOT call onHosted yet
    const hostedBtn = screen.getByTestId("mode-hosted");
    fireEvent.click(hostedBtn);

    expect(onHosted).not.toHaveBeenCalled();
    const dialog = screen.getByTestId("hosted-ack-dialog");
    expect(dialog).toBeInTheDocument();
    expect(dialog.textContent).toContain("ephemerally under your DPA");

    // Confirm acknowledgment → now calls onHosted
    const confirmBtn = screen.getByTestId("hosted-ack-confirm");
    fireEvent.click(confirmBtn);
    expect(onHosted).toHaveBeenCalledWith(["vpec_001"]);
  });
});
