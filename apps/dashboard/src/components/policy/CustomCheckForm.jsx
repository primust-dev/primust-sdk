"use client";
import { useState } from "react";
import { PROOF_LEVELS, PROOF_LEVEL_LABELS } from "../../lib/constants";
import { apiFetch } from "../../lib/api";
const INITIAL_STATE = {
    check_name: "",
    description: "",
    proof_level_ceiling: "execution",
};
function generateManifestStub(form) {
    return JSON.stringify({
        name: form.check_name,
        check_name: form.check_name,
        version: "1.0.0",
        proof_level_ceiling: form.proof_level_ceiling,
        description: form.description,
        schema_version: "1.0",
        inputs: [],
        outputs: [],
        config: {},
    }, null, 2);
}
export function CustomCheckForm({ open, onClose, onCreated }) {
    const [form, setForm] = useState(INITIAL_STATE);
    const [submitting, setSubmitting] = useState(false);
    const [submitError, setSubmitError] = useState(null);
    const [errors, setErrors] = useState({});
    function validate() {
        const newErrors = {};
        if (!form.check_name.trim())
            newErrors.check_name = "Check name is required";
        if (!form.description.trim())
            newErrors.description = "Description is required";
        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    }
    async function handleSubmit(e) {
        e.preventDefault();
        if (!validate())
            return;
        setSubmitting(true);
        setSubmitError(null);
        try {
            await apiFetch("/policy/checks", {
                method: "POST",
                body: {
                    check_name: form.check_name,
                    description: form.description,
                    proof_level_ceiling: form.proof_level_ceiling,
                    type: "custom",
                },
            });
            onCreated();
            handleClose();
        }
        catch (err) {
            setSubmitError(err instanceof Error ? err.message : "Failed to create check");
        }
        finally {
            setSubmitting(false);
        }
    }
    function handleDownloadStub() {
        const stub = generateManifestStub(form);
        const blob = new Blob([stub], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `${form.check_name || "custom_check"}_manifest.json`;
        a.click();
        URL.revokeObjectURL(url);
    }
    function handleClose() {
        onClose();
        setForm(INITIAL_STATE);
        setErrors({});
        setSubmitError(null);
    }
    function updateField(key, value) {
        setForm((prev) => ({ ...prev, [key]: value }));
        if (errors[key])
            setErrors((prev) => ({ ...prev, [key]: undefined }));
    }
    if (!open)
        return null;
    return (<div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40" data-testid="custom-check-modal">
      <div className="w-full max-w-md rounded-lg bg-white shadow-xl">
        <div className="flex items-center justify-between border-b px-6 py-4">
          <h2 className="text-lg font-semibold">Add Custom Check (BYOC)</h2>
          <button type="button" onClick={handleClose} className="text-gray-400 hover:text-gray-600 text-xl leading-none" data-testid="custom-check-close-btn">
            &times;
          </button>
        </div>

        <form onSubmit={handleSubmit} className="px-6 py-4 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Check Name
            </label>
            <input type="text" value={form.check_name} onChange={(e) => updateField("check_name", e.target.value)} placeholder="e.g., custom_pii_scan" className={`w-full rounded border px-3 py-2 text-sm focus:outline-none focus:ring-1 ${errors.check_name
            ? "border-red-400 focus:ring-red-400"
            : "border-gray-300 focus:ring-blue-400 focus:border-blue-400"}`} data-testid="check-name-input"/>
            {errors.check_name && (<p className="text-xs text-red-600 mt-1">{errors.check_name}</p>)}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Description
            </label>
            <textarea value={form.description} onChange={(e) => updateField("description", e.target.value)} placeholder="Describe what this check verifies..." rows={3} className={`w-full rounded border px-3 py-2 text-sm focus:outline-none focus:ring-1 ${errors.description
            ? "border-red-400 focus:ring-red-400"
            : "border-gray-300 focus:ring-blue-400 focus:border-blue-400"}`} data-testid="check-description-input"/>
            {errors.description && (<p className="text-xs text-red-600 mt-1">{errors.description}</p>)}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Expected Proof Level
            </label>
            <select value={form.proof_level_ceiling} onChange={(e) => updateField("proof_level_ceiling", e.target.value)} className="w-full rounded border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400 focus:border-blue-400" data-testid="proof-level-select">
              {PROOF_LEVELS.map((level) => (<option key={level} value={level}>
                  {PROOF_LEVEL_LABELS[level]}
                </option>))}
            </select>
          </div>

          {submitError && (<div className="rounded bg-red-50 p-3">
              <p className="text-sm text-red-600">{submitError}</p>
            </div>)}

          <div className="flex items-center justify-between pt-2">
            <button type="button" onClick={handleDownloadStub} disabled={!form.check_name.trim()} className={`rounded border px-3 py-2 text-sm font-medium transition-colors ${form.check_name.trim()
            ? "border-gray-300 text-gray-700 hover:bg-gray-50"
            : "border-gray-200 text-gray-300 cursor-not-allowed"}`} data-testid="generate-stub-btn">
              Generate Manifest Stub
            </button>

            <div className="flex gap-2">
              <button type="button" onClick={handleClose} className="rounded border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 transition-colors">
                Cancel
              </button>
              <button type="submit" disabled={submitting} className={`rounded px-4 py-2 text-sm font-medium transition-colors ${submitting
            ? "bg-gray-200 text-gray-400 cursor-not-allowed"
            : "bg-blue-600 text-white hover:bg-blue-700"}`} data-testid="create-check-btn">
                {submitting ? "Creating..." : "Create Check"}
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>);
}
//# sourceMappingURL=CustomCheckForm.js.map