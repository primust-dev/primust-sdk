"use client";

import { useState, useEffect } from "react";
import type {
  CheckManifest,
  CodeGenFramework,
  CodeGenLanguage,
  CodeGenResponse,
} from "../../types/policy";
import { apiFetch } from "../../lib/api";

interface GenerateCodeDrawerProps {
  open: boolean;
  onClose: () => void;
}

const FRAMEWORKS: { id: CodeGenFramework; label: string }[] = [
  { id: "langgraph", label: "LangGraph" },
  { id: "openai_agents", label: "OpenAI Agents" },
  { id: "google_adk", label: "Google ADK" },
  { id: "otel", label: "OTEL" },
  { id: "custom", label: "Custom" },
];

const LANGUAGES: { id: CodeGenLanguage; label: string }[] = [
  { id: "python", label: "Python" },
  { id: "typescript", label: "TypeScript" },
  { id: "java", label: "Java" },
];

export function GenerateCodeDrawer({ open, onClose }: GenerateCodeDrawerProps) {
  const [step, setStep] = useState(1);
  const [framework, setFramework] = useState<CodeGenFramework | null>(null);
  const [manifests, setManifests] = useState<CheckManifest[]>([]);
  const [selectedManifestIds, setSelectedManifestIds] = useState<Set<string>>(new Set());
  const [language, setLanguage] = useState<CodeGenLanguage>("python");
  const [generatedCode, setGeneratedCode] = useState<CodeGenResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    async function loadManifests() {
      try {
        const data = await apiFetch<CheckManifest[]>("/manifests");
        if (!cancelled) setManifests(data);
      } catch {
        /* handle silently */
      }
    }
    loadManifests();
    return () => { cancelled = true; };
  }, [open]);

  function toggleManifest(id: string) {
    setSelectedManifestIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  async function handleGenerate() {
    if (!framework || selectedManifestIds.size === 0) return;
    setLoading(true);
    try {
      const result = await apiFetch<CodeGenResponse>("/policy/generate-code", {
        method: "POST",
        body: {
          framework,
          manifest_ids: Array.from(selectedManifestIds),
          language,
        },
      });
      setGeneratedCode(result);
      setStep(3);
    } catch {
      /* handle silently */
    } finally {
      setLoading(false);
    }
  }

  async function handleCopy() {
    if (!generatedCode) return;
    await navigator.clipboard.writeText(generatedCode.code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function handleClose() {
    onClose();
    setStep(1);
    setFramework(null);
    setSelectedManifestIds(new Set());
    setGeneratedCode(null);
    setCopied(false);
  }

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end" data-testid="generate-code-drawer">
      <div className="absolute inset-0 bg-black/30" onClick={handleClose} />
      <div className="relative w-full max-w-lg bg-white shadow-xl flex flex-col h-full">
        <div className="flex items-center justify-between border-b px-6 py-4">
          <h2 className="text-lg font-semibold">Generate Integration Code</h2>
          <button
            type="button"
            onClick={handleClose}
            className="text-gray-400 hover:text-gray-600 text-xl leading-none"
            data-testid="drawer-close-btn"
          >
            &times;
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-6 py-4">
          {/* Step indicators */}
          <div className="flex items-center gap-2 mb-6">
            {[1, 2, 3].map((s) => (
              <div key={s} className="flex items-center gap-2">
                <div
                  className={`flex h-7 w-7 items-center justify-center rounded-full text-xs font-medium ${
                    step >= s
                      ? "bg-blue-600 text-white"
                      : "bg-gray-200 text-gray-500"
                  }`}
                >
                  {s}
                </div>
                {s < 3 && <div className="h-px w-8 bg-gray-300" />}
              </div>
            ))}
          </div>

          {/* Step 1: Select Framework */}
          {step === 1 && (
            <div data-testid="step-1">
              <h3 className="text-sm font-semibold mb-3">Select Framework</h3>
              <div className="space-y-2">
                {FRAMEWORKS.map((fw) => (
                  <button
                    key={fw.id}
                    type="button"
                    onClick={() => {
                      setFramework(fw.id);
                      setStep(2);
                    }}
                    className={`w-full text-left rounded border px-4 py-3 text-sm transition-colors ${
                      framework === fw.id
                        ? "border-blue-400 bg-blue-50"
                        : "border-gray-200 hover:border-gray-300 hover:bg-gray-50"
                    }`}
                    data-testid={`framework-${fw.id}`}
                  >
                    {fw.label}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Step 2: Select Manifests */}
          {step === 2 && (
            <div data-testid="step-2">
              <h3 className="text-sm font-semibold mb-3">Select Manifests</h3>
              {manifests.length === 0 ? (
                <p className="text-sm text-gray-500">No manifests available.</p>
              ) : (
                <div className="space-y-1">
                  {manifests.map((m) => (
                    <label
                      key={m.manifest_id}
                      className="flex items-center gap-3 rounded border px-3 py-2 cursor-pointer hover:bg-gray-50 transition-colors"
                      data-testid={`manifest-checkbox-${m.manifest_id}`}
                    >
                      <input
                        type="checkbox"
                        checked={selectedManifestIds.has(m.manifest_id)}
                        onChange={() => toggleManifest(m.manifest_id)}
                        className="h-4 w-4 rounded border-gray-300"
                      />
                      <div className="flex-1">
                        <div className="text-sm font-medium">{m.check_name}</div>
                        <div className="text-xs text-gray-500">
                          {m.manifest_hash.slice(0, 12)} &middot; v{m.version}
                        </div>
                      </div>
                    </label>
                  ))}
                </div>
              )}

              <div className="flex items-center justify-between mt-4">
                <button
                  type="button"
                  onClick={() => setStep(1)}
                  className="rounded border border-gray-300 px-3 py-1.5 text-sm text-gray-600 hover:bg-gray-50 transition-colors"
                >
                  Back
                </button>

                <div className="flex items-center gap-3">
                  <div className="flex rounded border overflow-hidden">
                    {LANGUAGES.map((lang) => (
                      <button
                        key={lang.id}
                        type="button"
                        onClick={() => setLanguage(lang.id)}
                        className={`px-3 py-1 text-xs font-medium transition-colors ${
                          language === lang.id
                            ? "bg-blue-600 text-white"
                            : "bg-white text-gray-600 hover:bg-gray-50"
                        }`}
                        data-testid={`lang-${lang.id}`}
                      >
                        {lang.label}
                      </button>
                    ))}
                  </div>

                  <button
                    type="button"
                    onClick={handleGenerate}
                    disabled={selectedManifestIds.size === 0 || loading}
                    className={`rounded px-4 py-1.5 text-sm font-medium transition-colors ${
                      selectedManifestIds.size > 0 && !loading
                        ? "bg-blue-600 text-white hover:bg-blue-700"
                        : "bg-gray-200 text-gray-400 cursor-not-allowed"
                    }`}
                    data-testid="generate-btn"
                  >
                    {loading ? "Generating..." : "Generate"}
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Step 3: Preview */}
          {step === 3 && generatedCode && (
            <div data-testid="step-3">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold">Generated Code</h3>
                <div className="flex items-center gap-2">
                  <div className="flex rounded border overflow-hidden">
                    {LANGUAGES.map((lang) => (
                      <button
                        key={lang.id}
                        type="button"
                        onClick={() => {
                          setLanguage(lang.id);
                          /* re-generate with new language */
                          handleGenerate();
                        }}
                        className={`px-3 py-1 text-xs font-medium transition-colors ${
                          language === lang.id
                            ? "bg-blue-600 text-white"
                            : "bg-white text-gray-600 hover:bg-gray-50"
                        }`}
                        data-testid={`preview-lang-${lang.id}`}
                      >
                        {lang.label}
                      </button>
                    ))}
                  </div>
                  <button
                    type="button"
                    onClick={handleCopy}
                    className="rounded border border-gray-300 px-3 py-1 text-xs font-medium text-gray-600 hover:bg-gray-50 transition-colors"
                    data-testid="copy-code-btn"
                  >
                    {copied ? "Copied!" : "Copy"}
                  </button>
                </div>
              </div>

              <pre className="rounded bg-gray-900 p-4 text-sm text-green-400 font-mono overflow-x-auto max-h-96 overflow-y-auto">
                <code data-testid="generated-code">{generatedCode.code}</code>
              </pre>

              <p className="text-xs text-gray-400 mt-2">
                {generatedCode.manifest_count} manifest(s) &middot;{" "}
                {generatedCode.framework} &middot; {generatedCode.language}
              </p>

              <div className="mt-4">
                <button
                  type="button"
                  onClick={() => setStep(2)}
                  className="rounded border border-gray-300 px-3 py-1.5 text-sm text-gray-600 hover:bg-gray-50 transition-colors"
                >
                  Back
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
