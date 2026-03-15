import { useState } from "react";
/**
 * Waiver form with mandatory expires_at.
 * - reason: min 50 chars enforced
 * - expires_at: REQUIRED, max 90 days from today
 * - No permanent waivers ever
 */
export function WaiverForm({ gapId, onSubmit }) {
    const [reason, setReason] = useState("");
    const [compensatingControl, setCompensatingControl] = useState("");
    const [expiresAt, setExpiresAt] = useState("");
    const [error, setError] = useState(null);
    const maxDate = new Date();
    maxDate.setDate(maxDate.getDate() + 90);
    const maxDateStr = maxDate.toISOString().split("T")[0];
    const handleSubmit = (e) => {
        e.preventDefault();
        setError(null);
        if (!expiresAt) {
            setError("expires_at required — no permanent waivers allowed");
            return;
        }
        const expiry = new Date(expiresAt);
        if (expiry > maxDate) {
            setError("expires_at cannot be more than 90 days from today");
            return;
        }
        if (reason.length < 50) {
            setError("Reason must be at least 50 characters");
            return;
        }
        onSubmit({
            reason,
            compensating_control: compensatingControl || null,
            expires_at: new Date(expiresAt).toISOString(),
        });
    };
    const isSubmitDisabled = !expiresAt || reason.length < 50;
    return (<form onSubmit={handleSubmit} className="space-y-4" data-testid="waiver-form">
      <div>
        <label className="block text-sm font-semibold mb-1">
          Gap: <span className="font-mono">{gapId}</span>
        </label>
      </div>

      <div>
        <label className="block text-sm font-semibold mb-1">
          Reason (min 50 characters) *
        </label>
        <textarea value={reason} onChange={(e) => setReason(e.target.value)} className="w-full border rounded p-2 text-sm" rows={3} data-testid="waiver-reason"/>
        <div className="text-xs text-gray-500">{reason.length}/50 min</div>
      </div>

      <div>
        <label className="block text-sm font-semibold mb-1">
          Compensating Control (optional)
        </label>
        <input type="text" value={compensatingControl} onChange={(e) => setCompensatingControl(e.target.value)} className="w-full border rounded p-2 text-sm" data-testid="waiver-compensating-control"/>
      </div>

      <div>
        <label className="block text-sm font-semibold mb-1">
          Expires At (max 90 days) *
        </label>
        <input type="date" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} max={maxDateStr} className="w-full border rounded p-2 text-sm" data-testid="waiver-expires-at"/>
      </div>

      {error && (<div className="text-red-600 text-sm" data-testid="waiver-error">
          {error}
        </div>)}

      <button type="submit" disabled={isSubmitDisabled} className={`px-4 py-2 rounded text-sm font-medium ${isSubmitDisabled
            ? "bg-gray-300 cursor-not-allowed"
            : "bg-blue-600 text-white hover:bg-blue-700"}`} data-testid="waiver-submit">
        Submit Waiver
      </button>
    </form>);
}
//# sourceMappingURL=WaiverForm.js.map