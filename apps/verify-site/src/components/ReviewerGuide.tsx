/**
 * P13-B: Reviewer Guide for witnessed-level approvals.
 *
 * Purpose: Step-by-step guide for humans executing witnessed-level governance checks.
 * Reviewer never interacts with Primust infrastructure directly — they use their own
 * Ed25519 signing key and the customer's review tooling.
 */

const PROOF_LEVELS = [
  {
    name: "Mathematical",
    level: "mathematical",
    description:
      "Deterministic rules with ZK proof; no human reviewer needed. " +
      "Examples: regex validation, threshold checks, allowlist membership.",
  },
  {
    name: "Verifiable Inference",
    level: "verifiable_inference",
    description:
      "ML model with ZK proof; no human reviewer needed. " +
      "The model output is bound to a zero-knowledge proof of correct execution.",
  },
  {
    name: "Execution",
    level: "execution",
    description:
      "ML model or code execution; no human reviewer needed. " +
      "Output is commitment-bound but no ZK proof is generated.",
  },
  {
    name: "Witnessed",
    level: "witnessed",
    description:
      "Human reviewer required (this guide applies). " +
      "A qualified reviewer examines display_content and signs their approval.",
  },
  {
    name: "Attestation",
    level: "attestation",
    description:
      "Assertion only; weakest level. " +
      "The check result is recorded but no execution or review evidence is available.",
  },
];

const WITNESSED_GAP_TYPES = [
  {
    type: "reviewer_credential_invalid",
    severity: "Critical",
    description:
      "The reviewer's Ed25519 signature could not be verified against the registered public key. " +
      "This may indicate a compromised key or incorrect signing process.",
  },
  {
    type: "witnessed_display_missing",
    severity: "High",
    description:
      "The witnessed record is missing display_hash. Without it, there is no proof of " +
      "what the reviewer actually saw during their review.",
  },
  {
    type: "witnessed_rationale_missing",
    severity: "High",
    description:
      "The witnessed record is missing rationale_hash. Without it, there is no proof of " +
      "the reviewer's reasoning for their approval decision.",
  },
];

export function ReviewerGuide() {
  return (
    <div className="max-w-3xl mx-auto p-6 space-y-8" data-testid="reviewer-guide">
      <h1 className="text-2xl font-bold">Reviewer Guide</h1>
      <p className="text-gray-600">
        Step-by-step guide for humans executing witnessed-level governance
        checks. Reviewers never interact with Primust infrastructure directly.
      </p>

      {/* All 5 proof levels explained */}
      <section data-testid="proof-levels-section">
        <h2 className="text-xl font-bold mb-3">Proof Levels</h2>
        <p className="text-sm text-gray-600 mb-4">
          Primust recognizes 5 proof levels, from strongest to weakest:
        </p>
        <div className="space-y-3">
          {PROOF_LEVELS.map((pl) => (
            <div
              key={pl.level}
              className="border rounded p-3"
              data-testid={`proof-level-guide-${pl.level}`}
            >
              <div className="font-semibold">{pl.name}</div>
              <div className="text-sm text-gray-600">{pl.description}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Witnessed level flow */}
      <section data-testid="witnessed-flow-section">
        <h2 className="text-xl font-bold mb-3">Witnessed Level Flow</h2>
        <ol className="list-decimal ml-6 space-y-3 text-sm">
          <li>
            <strong>Receive review request</strong> with{" "}
            <code className="bg-gray-100 px-1 rounded">display_content</code>{" "}
            (rendered, not raw input).
          </li>
          <li data-testid="timing-requirement">
            <strong>Review display_content</strong> for minimum{" "}
            <code className="bg-gray-100 px-1 rounded">
              min_duration_seconds
            </code>{" "}
            (default 30 minutes). Timing enforced:{" "}
            <code className="bg-gray-100 px-1 rounded">check_open_tst</code> to{" "}
            <code className="bg-gray-100 px-1 rounded">check_close_tst</code>.
          </li>
          <li>
            <strong>Sign:</strong>{" "}
            <code className="bg-gray-100 px-1 rounded text-xs">
              SHA-256(key_id || role || signed_content_hash || display_hash ||
              rationale_hash || open_tst)
            </code>{" "}
            using reviewer&apos;s Ed25519 private key.
          </li>
          <li>
            <strong>Submit signature + rationale</strong> (rationale committed
            locally via poseidon2).
          </li>
        </ol>
      </section>

      {/* Key requirement: private key never sent */}
      <section data-testid="key-privacy-section">
        <h2 className="text-xl font-bold mb-3">Key Privacy</h2>
        <div className="bg-amber-50 border border-amber-200 rounded p-4">
          <p className="font-semibold text-amber-800">
            The reviewer&apos;s Ed25519 private key NEVER leaves the
            reviewer&apos;s environment.
          </p>
          <p className="text-sm text-amber-700 mt-2">
            Only the following transit to Primust:{" "}
            <code>reviewer_signature</code>, <code>display_hash</code>,{" "}
            <code>rationale_hash</code>, <code>key_id</code>.
          </p>
          <p
            className="text-sm text-amber-700 mt-1"
            data-testid="key-never-sent"
          >
            The private key, raw display content, and raw rationale text are
            never sent to the Primust API.
          </p>
        </div>
      </section>

      {/* Witnessed gap types */}
      <section data-testid="witnessed-gaps-section">
        <h2 className="text-xl font-bold mb-3">
          Witnessed-Related Gap Types
        </h2>
        <p className="text-sm text-gray-600 mb-3">
          Three gap types can be raised during witnessed-level reviews:
        </p>
        <div className="space-y-3">
          {WITNESSED_GAP_TYPES.map((gap) => (
            <div
              key={gap.type}
              className="border rounded p-3"
              data-testid={`gap-doc-${gap.type}`}
            >
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm">{gap.type}</span>
                <span
                  className={`text-xs px-2 py-0.5 rounded ${
                    gap.severity === "Critical"
                      ? "bg-red-600 text-white"
                      : "bg-orange-600 text-white"
                  }`}
                >
                  {gap.severity}
                </span>
              </div>
              <div className="text-sm text-gray-600 mt-1">
                {gap.description}
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
