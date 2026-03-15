"use client";
import { useState, useCallback, useRef } from "react";
import { apiFetch } from "../../lib/api";
function validateManifest(data) {
    const errors = [];
    if (typeof data !== "object" || data === null) {
        return { valid: false, errors: ["Manifest must be a JSON object"] };
    }
    const obj = data;
    if (typeof obj.name !== "string" || !obj.name)
        errors.push("Missing required field: name");
    if (typeof obj.check_name !== "string" || !obj.check_name)
        errors.push("Missing required field: check_name");
    if (typeof obj.version !== "string" || !obj.version)
        errors.push("Missing required field: version");
    if (typeof obj.proof_level_ceiling !== "string" || !obj.proof_level_ceiling) {
        errors.push("Missing required field: proof_level_ceiling");
    }
    else {
        const validLevels = ["mathematical", "verifiable_inference", "execution", "witnessed", "attestation"];
        if (!validLevels.includes(obj.proof_level_ceiling)) {
            errors.push(`Invalid proof_level_ceiling: ${obj.proof_level_ceiling}. Must be one of: ${validLevels.join(", ")}`);
        }
    }
    return { valid: errors.length === 0, errors };
}
async function computeHash(text) {
    const encoded = new TextEncoder().encode(text);
    const buffer = await crypto.subtle.digest("SHA-256", encoded);
    const hashArray = Array.from(new Uint8Array(buffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}
export function RegisterManifestModal({ open, onClose, onRegistered, }) {
    const [activeTab, setActiveTab] = useState("upload");
    const [jsonText, setJsonText] = useState("");
    const [parsedManifest, setParsedManifest] = useState(null);
    const [computedHash, setComputedHash] = useState(null);
    const [validationErrors, setValidationErrors] = useState([]);
    const [submitting, setSubmitting] = useState(false);
    const [submitError, setSubmitError] = useState(null);
    const [dragActive, setDragActive] = useState(false);
    const fileInputRef = useRef(null);
    const processJson = useCallback(async (text) => {
        setJsonText(text);
        setSubmitError(null);
        try {
            const data = JSON.parse(text);
            const result = validateManifest(data);
            setValidationErrors(result.errors);
            if (result.valid) {
                setParsedManifest(data);
                const hash = await computeHash(text);
                setComputedHash(hash);
            }
            else {
                setParsedManifest(null);
                setComputedHash(null);
            }
        }
        catch {
            setValidationErrors(["Invalid JSON"]);
            setParsedManifest(null);
            setComputedHash(null);
        }
    }, []);
    function handleFileRead(file) {
        const reader = new FileReader();
        reader.onload = (e) => {
            const text = e.target?.result;
            processJson(text);
            setActiveTab("paste"); // show the parsed content
        };
        reader.readAsText(file);
    }
    function handleDrop(e) {
        e.preventDefault();
        setDragActive(false);
        const file = e.dataTransfer.files[0];
        if (file && file.name.endsWith(".json")) {
            handleFileRead(file);
        }
        else {
            setValidationErrors(["Only .json files are accepted"]);
        }
    }
    async function handleConfirm() {
        if (!parsedManifest)
            return;
        setSubmitting(true);
        setSubmitError(null);
        try {
            await apiFetch("/manifests", {
                method: "POST",
                body: parsedManifest,
            });
            onRegistered();
            onClose();
            resetState();
        }
        catch (err) {
            setSubmitError(err instanceof Error ? err.message : "Registration failed");
        }
        finally {
            setSubmitting(false);
        }
    }
    function resetState() {
        setJsonText("");
        setParsedManifest(null);
        setComputedHash(null);
        setValidationErrors([]);
        setSubmitError(null);
        setActiveTab("upload");
    }
    function handleClose() {
        onClose();
        resetState();
    }
    if (!open)
        return null;
    return (<div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40" data-testid="register-manifest-modal">
      <div className="w-full max-w-xl rounded-lg bg-white shadow-xl">
        <div className="flex items-center justify-between border-b px-6 py-4">
          <h2 className="text-lg font-semibold">Register Manifest</h2>
          <button type="button" onClick={handleClose} className="text-gray-400 hover:text-gray-600 text-xl leading-none" data-testid="modal-close-btn">
            &times;
          </button>
        </div>

        <div className="px-6 py-4">
          <div className="flex border-b mb-4">
            <button type="button" onClick={() => setActiveTab("upload")} className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${activeTab === "upload"
            ? "border-blue-600 text-blue-600"
            : "border-transparent text-gray-500 hover:text-gray-700"}`} data-testid="tab-upload">
              Upload File
            </button>
            <button type="button" onClick={() => setActiveTab("paste")} className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${activeTab === "paste"
            ? "border-blue-600 text-blue-600"
            : "border-transparent text-gray-500 hover:text-gray-700"}`} data-testid="tab-paste">
              Paste JSON
            </button>
          </div>

          {activeTab === "upload" && (<div onDragOver={(e) => { e.preventDefault(); setDragActive(true); }} onDragLeave={() => setDragActive(false)} onDrop={handleDrop} onClick={() => fileInputRef.current?.click()} className={`flex flex-col items-center justify-center rounded-lg border-2 border-dashed p-8 cursor-pointer transition-colors ${dragActive
                ? "border-blue-400 bg-blue-50"
                : "border-gray-300 hover:border-gray-400"}`} data-testid="drop-zone">
              <p className="text-sm text-gray-600 mb-1">
                Drag and drop a .json manifest file here
              </p>
              <p className="text-xs text-gray-400">or click to browse</p>
              <input ref={fileInputRef} type="file" accept=".json" className="hidden" onChange={(e) => {
                const file = e.target.files?.[0];
                if (file)
                    handleFileRead(file);
            }} data-testid="file-input"/>
            </div>)}

          {activeTab === "paste" && (<textarea value={jsonText} onChange={(e) => processJson(e.target.value)} placeholder='{"name": "...", "check_name": "...", "version": "1.0.0", "proof_level_ceiling": "execution"}' className="w-full h-48 rounded border border-gray-300 px-3 py-2 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-blue-400 focus:border-blue-400" data-testid="json-textarea"/>)}

          {validationErrors.length > 0 && (<div className="mt-3 rounded bg-red-50 p-3" data-testid="validation-errors">
              {validationErrors.map((err, i) => (<p key={i} className="text-sm text-red-600">{err}</p>))}
            </div>)}

          {computedHash && parsedManifest && (<div className="mt-3 rounded bg-green-50 p-3" data-testid="manifest-preview">
              <p className="text-sm text-green-800 font-medium mb-1">Manifest valid</p>
              <p className="text-xs text-green-700">
                <span className="font-medium">Hash:</span>{" "}
                <code className="font-mono">{computedHash.slice(0, 16)}...</code>
              </p>
              <p className="text-xs text-green-700">
                <span className="font-medium">Name:</span> {parsedManifest.name}
              </p>
              <p className="text-xs text-green-700">
                <span className="font-medium">Check:</span> {parsedManifest.check_name}
              </p>
              <p className="text-xs text-green-700">
                <span className="font-medium">Proof ceiling:</span> {parsedManifest.proof_level_ceiling}
              </p>
            </div>)}

          {submitError && (<div className="mt-3 rounded bg-red-50 p-3" data-testid="submit-error">
              <p className="text-sm text-red-600">{submitError}</p>
            </div>)}
        </div>

        <div className="flex justify-end gap-3 border-t px-6 py-4">
          <button type="button" onClick={handleClose} className="rounded border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 transition-colors" data-testid="cancel-btn">
            Cancel
          </button>
          <button type="button" onClick={handleConfirm} disabled={!parsedManifest || submitting} className={`rounded px-4 py-2 text-sm font-medium transition-colors ${parsedManifest && !submitting
            ? "bg-blue-600 text-white hover:bg-blue-700"
            : "bg-gray-200 text-gray-400 cursor-not-allowed"}`} data-testid="confirm-register-btn">
            {submitting ? "Registering..." : "Register Manifest"}
          </button>
        </div>
      </div>
    </div>);
}
//# sourceMappingURL=RegisterManifestModal.js.map