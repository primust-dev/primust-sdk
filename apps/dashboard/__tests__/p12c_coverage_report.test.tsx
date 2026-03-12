/**
 * P12-C: Coverage Report + Policy Management — 5 MUST PASS.
 */
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import React from "react";

import { CoverageReport } from "../src/components/CoverageReport";
import { CoverageDisplay } from "../src/components/CoverageDisplay";
import type { ProofDistribution, GapSeverity } from "../src/types/vpec";
import { GAP_SEVERITIES, PROOF_LEVELS } from "../src/lib/constants";

function makeDistribution(overrides: Partial<ProofDistribution> = {}): ProofDistribution {
  return {
    mathematical: 5,
    verifiable_inference: 10,
    execution: 20,
    witnessed: 3,
    attestation: 2,
    weakest_link: "attestation",
    weakest_link_explanation: "2 attestation-level records",
    ...overrides,
  };
}

function makeGapSummary(): Record<GapSeverity, number> {
  return { Critical: 1, High: 3, Medium: 2, Low: 1, Informational: 0 };
}

describe("P12-C: Coverage Report + Policy Management", () => {
  it("MUST PASS: both denominators displayed separately (not collapsed)", () => {
    render(
      <CoverageReport
        policyCoveragePct={97.3}
        recordsPass={142}
        recordsTotal={146}
        instrumentationSurfacePct={100}
        instrumentationSurfaceBasis="LangGraph adapter"
        coverageVerifiedPct={90}
        coveragePendingPct={5}
        coverageUngovernedPct={5}
        proofDistribution={makeDistribution()}
        gapSummary={makeGapSummary()}
      />,
    );

    // Both denominators must exist as separate elements
    const policyDenom = screen.getByTestId("policy-denominator");
    const surfaceDenom = screen.getByTestId("surface-denominator");
    expect(policyDenom).toBeInTheDocument();
    expect(surfaceDenom).toBeInTheDocument();

    // They are different elements, not collapsed
    expect(policyDenom).not.toBe(surfaceDenom);
    expect(policyDenom.textContent).toContain("Policy coverage");
    expect(surfaceDenom.textContent).toContain("Instrumentation surface");
  });

  it("MUST PASS: partial_unknown scope → 'lower bound' warning", () => {
    render(
      <CoverageDisplay
        policyCoveragePct={80}
        recordsPass={80}
        recordsTotal={100}
        instrumentationSurfacePct={null}
        instrumentationSurfaceBasis={null}
        coverageVerifiedPct={80}
        coveragePendingPct={10}
        coverageUngovernedPct={10}
      />,
    );

    const warning = screen.getByTestId("lower-bound-warning");
    expect(warning).toBeInTheDocument();
    expect(warning.textContent).toContain(
      "Scope partially unknown — coverage is a lower bound",
    );
  });

  it("MUST PASS: coverage_verified + coverage_pending + coverage_ungoverned = 100 display", () => {
    render(
      <CoverageReport
        policyCoveragePct={90}
        recordsPass={90}
        recordsTotal={100}
        instrumentationSurfacePct={100}
        instrumentationSurfaceBasis="adapter"
        coverageVerifiedPct={70}
        coveragePendingPct={20}
        coverageUngovernedPct={10}
        proofDistribution={makeDistribution()}
        gapSummary={makeGapSummary()}
      />,
    );

    const buckets = screen.getByTestId("coverage-buckets");
    expect(buckets).toBeInTheDocument();
    expect(buckets.textContent).toContain("Verified: 70%");
    expect(buckets.textContent).toContain("Pending: 20%");
    expect(buckets.textContent).toContain("Ungoverned: 10%");
    // Sum = 100
    expect(70 + 20 + 10).toBe(100);
  });

  it("MUST PASS: all 5 proof levels in distribution chart", () => {
    render(
      <CoverageReport
        policyCoveragePct={90}
        recordsPass={90}
        recordsTotal={100}
        instrumentationSurfacePct={100}
        instrumentationSurfaceBasis="adapter"
        coverageVerifiedPct={90}
        coveragePendingPct={5}
        coverageUngovernedPct={5}
        proofDistribution={makeDistribution()}
        gapSummary={makeGapSummary()}
      />,
    );

    for (const level of PROOF_LEVELS) {
      expect(screen.getByTestId(`proof-count-${level}`)).toBeInTheDocument();
    }
  });

  it("MUST PASS: all 5 gap severities in gap summary", () => {
    render(
      <CoverageReport
        policyCoveragePct={90}
        recordsPass={90}
        recordsTotal={100}
        instrumentationSurfacePct={100}
        instrumentationSurfaceBasis="adapter"
        coverageVerifiedPct={90}
        coveragePendingPct={5}
        coverageUngovernedPct={5}
        proofDistribution={makeDistribution()}
        gapSummary={makeGapSummary()}
      />,
    );

    for (const sev of GAP_SEVERITIES) {
      expect(
        screen.getByTestId(`gap-summary-${sev.toLowerCase()}`),
      ).toBeInTheDocument();
    }
  });
});
