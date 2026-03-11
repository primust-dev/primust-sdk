import { useState } from "react";

interface EvidencePackAssemblerProps {
  artifactIds: string[];
  onAssembleLocal: (ids: string[]) => void;
  onAssembleHosted: (ids: string[]) => void;
}

/**
 * Evidence Pack Assembler — LOCAL default, HOSTED opt-in.
 * LOCAL: "Local Assembly — raw content does not leave your environment"
 * HOSTED: requires acknowledgment dialog before proceeding.
 */
export function EvidencePackAssembler({
  artifactIds,
  onAssembleLocal,
  onAssembleHosted,
}: EvidencePackAssemblerProps) {
  const [mode, setMode] = useState<"local" | "hosted">("local");
  const [hostedAcknowledged, setHostedAcknowledged] = useState(false);
  const [showAckDialog, setShowAckDialog] = useState(false);

  const handleLocalAssemble = () => {
    onAssembleLocal(artifactIds);
  };

  const handleHostedClick = () => {
    if (!hostedAcknowledged) {
      setShowAckDialog(true);
      return;
    }
    onAssembleHosted(artifactIds);
  };

  const handleAcknowledge = () => {
    setHostedAcknowledged(true);
    setShowAckDialog(false);
    setMode("hosted");
    onAssembleHosted(artifactIds);
  };

  return (
    <div className="space-y-4" data-testid="evidence-pack-assembler">
      <h2 className="text-lg font-bold">Assemble Evidence Pack</h2>

      <div className="text-sm text-gray-600">
        {artifactIds.length} artifact(s) selected
      </div>

      {/* Mode selection */}
      <div className="flex gap-4">
        <button
          onClick={() => {
            setMode("local");
            handleLocalAssemble();
          }}
          className={`flex-1 p-4 rounded border-2 text-left ${
            mode === "local" ? "border-blue-600 bg-blue-50" : "border-gray-200"
          }`}
          data-testid="mode-local"
        >
          <div className="font-semibold">Local Assembly</div>
          <div
            className="text-xs text-green-700 mt-1"
            data-testid="local-badge"
          >
            Local Assembly — raw content does not leave your environment
          </div>
        </button>

        <button
          onClick={handleHostedClick}
          className={`flex-1 p-4 rounded border-2 text-left ${
            mode === "hosted" ? "border-blue-600 bg-blue-50" : "border-gray-200"
          }`}
          data-testid="mode-hosted"
        >
          <div className="font-semibold">Hosted Assembly</div>
          <div className="text-xs text-gray-500 mt-1" data-testid="hosted-badge">
            Hosted Assembly — processed by Primust under DPA
          </div>
        </button>
      </div>

      {/* Acknowledgment dialog */}
      {showAckDialog && (
        <div
          className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
          data-testid="hosted-ack-dialog"
        >
          <div className="bg-white rounded-lg p-6 max-w-md">
            <h3 className="font-bold mb-3">Hosted Assembly</h3>
            <p className="text-sm mb-4">
              Primust will process your artifact data ephemerally under your DPA.
            </p>
            <div className="flex gap-3">
              <button
                onClick={handleAcknowledge}
                className="px-4 py-2 bg-blue-600 text-white rounded text-sm"
                data-testid="hosted-ack-confirm"
              >
                I Acknowledge
              </button>
              <button
                onClick={() => setShowAckDialog(false)}
                className="px-4 py-2 bg-gray-200 rounded text-sm"
                data-testid="hosted-ack-cancel"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
