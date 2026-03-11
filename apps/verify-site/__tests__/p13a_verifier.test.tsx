/**
 * P13-A: verify.primust.com — 3 MUST PASS.
 */
import { describe, it, expect } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";

import { VerifierPage } from "../src/components/VerifierPage";
import { verifyArtifact } from "../src/lib/verify";

function makeValidArtifact(): Record<string, unknown> {
  return {
    vpec_id: "vpec_abc123",
    schema_version: "3.0.0",
    run_id: "run_001",
    workflow_id: "wf_001",
    org_id: "org_acme",
    state: "signed",
    partial: false,
    test_mode: false,
    proof_level: "attestation",
    proof_distribution: {
      mathematical: 0,
      execution_zkml: 0,
      execution: 124,
      witnessed: 0,
      attestation: 3,
      weakest_link: "attestation",
      weakest_link_explanation: "3 audit log records",
    },
    policy_coverage_pct: 98.7,
    instrumentation_surface_pct: 100,
    instrumentation_surface_basis: "LangGraph adapter",
    coverage: {
      policy_coverage_pct: 98.7,
      instrumentation_surface_pct: 100,
    },
    records_total: 127,
    records_pass: 127,
    records_fail: 0,
    records_degraded: 0,
    records_not_applicable: 0,
    commitment_root: "poseidon2:abc123",
    manifest_hashes: {
      manifest_001: "sha256:aaa",
      manifest_002: "sha256:bbb",
    },
    gaps: [],
    surface_summary: [],
    process_context_hash: null,
    issuer: {
      signer_id: "org_acme",
      kid: "v3",
      public_key_url: "https://keys.primust.com/org_acme/v3.pem",
    },
    signature: {
      signer_id: "org_acme",
      kid: "v3",
      algorithm: "Ed25519",
      signature: "valid_sig_base64",
      signed_at: "2026-03-09T15:30:00Z",
    },
    timestamp_anchor: {
      type: "rfc3161",
      tsa: "digicert_us",
      value: "dGVzdA==",
    },
    started_at: "2026-03-09T15:00:00Z",
    closed_at: "2026-03-09T15:30:00Z",
  };
}

describe("P13-A: verify.primust.com", () => {
  it("MUST PASS: valid VPEC shows valid", () => {
    const artifact = makeValidArtifact();
    render(<VerifierPage />);

    // Paste valid JSON
    const textarea = screen.getByTestId("paste-area");
    fireEvent.change(textarea, {
      target: { value: JSON.stringify(artifact) },
    });

    // Should show valid banner
    expect(screen.getByTestId("valid-banner")).toBeInTheDocument();
    expect(screen.getByTestId("valid-banner").textContent).toContain(
      "Signature valid",
    );

    // Landing summary should show
    expect(screen.getByTestId("landing-summary")).toBeInTheDocument();
    expect(screen.getByTestId("landing-summary").textContent).toContain(
      "vpec_abc123",
    );

    // P1 disclaimer always visible
    expect(screen.getByTestId("p1-disclaimer")).toBeInTheDocument();
  });

  it("MUST PASS: tampered artifact shows invalid", () => {
    const artifact = makeValidArtifact();
    (artifact as Record<string, unknown>)._tampered = true;

    render(<VerifierPage />);

    const textarea = screen.getByTestId("paste-area");
    fireEvent.change(textarea, {
      target: { value: JSON.stringify(artifact) },
    });

    // Should show invalid banner
    expect(screen.getByTestId("invalid-banner")).toBeInTheDocument();
    expect(screen.getByTestId("invalid-banner").textContent).toContain(
      "Verification failed",
    );

    // Should show integrity error
    expect(screen.getByTestId("error-integrity_check_failed")).toBeInTheDocument();
  });

  it("MUST PASS: no auth required (page renders without login)", () => {
    // Verify the page renders without any auth context
    render(<VerifierPage />);

    expect(screen.getByTestId("verifier-page")).toBeInTheDocument();
    expect(screen.getByTestId("drop-zone")).toBeInTheDocument();
    expect(screen.getByTestId("paste-area")).toBeInTheDocument();

    // P1 disclaimer always visible even before verification
    expect(screen.getByTestId("p1-disclaimer")).toBeInTheDocument();
  });
});
