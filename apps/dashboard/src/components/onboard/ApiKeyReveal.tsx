"use client";

import { useCallback, useState } from "react";

interface ApiKeyRevealProps {
  apiKey: string;
}

export function ApiKeyReveal({ apiKey }: ApiKeyRevealProps) {
  const [revealed, setRevealed] = useState(false);
  const [copied, setCopied] = useState(false);

  const masked = apiKey.slice(0, 6) + "\u2022".repeat(32) + apiKey.slice(-4);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(apiKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback for non-HTTPS contexts
      const textarea = document.createElement("textarea");
      textarea.value = apiKey;
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }, [apiKey]);

  return (
    <div data-testid="api-key-reveal" className="rounded-lg border border-amber-300 bg-amber-50 p-4">
      <div className="mb-2 flex items-center gap-2">
        <span className="text-sm font-semibold text-amber-800">
          Your Sandbox API Key
        </span>
        <span className="rounded bg-amber-200 px-1.5 py-0.5 text-xs font-medium text-amber-900">
          ONE-TIME REVEAL
        </span>
      </div>

      <p className="mb-3 text-xs text-amber-700">
        This key is shown once. Store it securely. You will not be able to
        retrieve it again.
      </p>

      <div className="flex items-center gap-2">
        <code
          data-testid="api-key-value"
          className="flex-1 rounded bg-white px-3 py-2 font-mono text-sm text-gray-900 border border-gray-200 select-all"
        >
          {revealed ? apiKey : masked}
        </code>

        <button
          type="button"
          onClick={() => setRevealed((r) => !r)}
          className="rounded bg-gray-100 px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-200 transition-colors"
          data-testid="reveal-toggle"
        >
          {revealed ? "Hide" : "Reveal"}
        </button>

        <button
          type="button"
          onClick={handleCopy}
          className="rounded bg-indigo-600 px-3 py-2 text-sm font-medium text-white hover:bg-indigo-700 transition-colors"
          data-testid="copy-button"
        >
          {copied ? "Copied!" : "Copy"}
        </button>
      </div>
    </div>
  );
}
