/**
 * P13-B: Reviewer Guide — 4 MUST PASS.
 */
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";

import { ReviewerGuide } from "../src/components/ReviewerGuide";

describe("P13-B: Reviewer Guide", () => {
  it("MUST PASS: guide explains all 5 proof levels with clear distinction", () => {
    render(<ReviewerGuide />);

    const levels = [
      "mathematical",
      "execution_zkml",
      "execution",
      "witnessed",
      "attestation",
    ];

    for (const level of levels) {
      expect(
        screen.getByTestId(`proof-level-guide-${level}`),
      ).toBeInTheDocument();
    }

    // Witnessed level should mention "human reviewer required"
    const witnessed = screen.getByTestId("proof-level-guide-witnessed");
    expect(witnessed.textContent).toContain("Human reviewer required");

    // Mathematical should mention "no human reviewer"
    const mathematical = screen.getByTestId("proof-level-guide-mathematical");
    expect(mathematical.textContent).toContain("no human reviewer needed");
  });

  it("MUST PASS: reviewer key never appears in any example that sends to Primust API", () => {
    render(<ReviewerGuide />);

    // Key privacy section must exist
    const privacySection = screen.getByTestId("key-privacy-section");
    expect(privacySection).toBeInTheDocument();

    // Must state key never leaves reviewer environment
    expect(screen.getByTestId("key-never-sent")).toBeInTheDocument();
    expect(screen.getByTestId("key-never-sent").textContent).toContain(
      "never sent to the Primust API",
    );

    // Transit list should only include: reviewer_signature, display_hash, rationale_hash, key_id
    expect(privacySection.textContent).toContain("reviewer_signature");
    expect(privacySection.textContent).toContain("display_hash");
    expect(privacySection.textContent).toContain("rationale_hash");
    expect(privacySection.textContent).toContain("key_id");
    expect(privacySection.textContent).not.toContain("private_key");
  });

  it("MUST PASS: timing requirement documented (min_duration_seconds)", () => {
    render(<ReviewerGuide />);

    const timingStep = screen.getByTestId("timing-requirement");
    expect(timingStep).toBeInTheDocument();
    expect(timingStep.textContent).toContain("min_duration_seconds");
    expect(timingStep.textContent).toContain("30 minutes");
    expect(timingStep.textContent).toContain("check_open_tst");
    expect(timingStep.textContent).toContain("check_close_tst");
  });

  it("MUST PASS: all 3 witnessed-related gap types documented", () => {
    render(<ReviewerGuide />);

    const gapTypes = [
      "reviewer_credential_invalid",
      "witnessed_display_missing",
      "witnessed_rationale_missing",
    ];

    for (const gapType of gapTypes) {
      const el = screen.getByTestId(`gap-doc-${gapType}`);
      expect(el).toBeInTheDocument();
      expect(el.textContent).toContain(gapType);
    }

    // Verify severities
    const criticalGap = screen.getByTestId("gap-doc-reviewer_credential_invalid");
    expect(criticalGap.textContent).toContain("Critical");

    const highGap1 = screen.getByTestId("gap-doc-witnessed_display_missing");
    expect(highGap1.textContent).toContain("High");

    const highGap2 = screen.getByTestId("gap-doc-witnessed_rationale_missing");
    expect(highGap2.textContent).toContain("High");
  });
});
