"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "../../lib/api";
import { ApiKeyReveal } from "../../components/onboard/ApiKeyReveal";

interface OnboardResponse {
  api_key: string | null;
  org_id: string;
  org_region: string;
  already_existed: boolean;
}

type PageState =
  | { kind: "loading" }
  | { kind: "new_key"; apiKey: string; orgId: string; orgRegion: string }
  | { kind: "already_existed"; orgId: string }
  | { kind: "error"; message: string };

export default function OnboardPage() {
  const [state, setState] = useState<PageState>({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;

    async function onboard() {
      try {
        const res = await apiFetch<OnboardResponse>("/onboard", {
          method: "POST",
        });

        if (cancelled) return;

        if (res.already_existed || !res.api_key) {
          setState({ kind: "already_existed", orgId: res.org_id });
        } else {
          setState({
            kind: "new_key",
            apiKey: res.api_key,
            orgId: res.org_id,
            orgRegion: res.org_region,
          });
        }
      } catch (err) {
        if (cancelled) return;
        const message =
          err instanceof Error ? err.message : "Onboarding failed";
        setState({ kind: "error", message });
      }
    }

    onboard();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="mx-auto max-w-2xl py-12 px-4">
      <h1 className="mb-2 text-2xl font-bold text-gray-900">
        Welcome to Primust
      </h1>
      <p className="mb-8 text-gray-600">
        Set up your sandbox environment to start issuing VPECs.
      </p>

      {state.kind === "loading" && (
        <div className="py-8 text-center text-sm text-gray-500" data-testid="onboard-loading">
          Setting up your sandbox...
        </div>
      )}

      {state.kind === "error" && (
        <div
          className="rounded-lg border border-red-300 bg-red-50 p-4 text-sm text-red-800"
          data-testid="onboard-error"
        >
          <p className="font-semibold">Onboarding failed</p>
          <p>{state.message}</p>
        </div>
      )}

      {state.kind === "already_existed" && (
        <div
          className="rounded-lg border border-blue-300 bg-blue-50 p-4 text-sm text-blue-800"
          data-testid="onboard-existing"
        >
          <p className="font-semibold">Sandbox key already issued</p>
          <p className="mt-1">
            Your sandbox key was issued previously. You can view your keys in{" "}
            <a
              href="/settings/api-keys"
              className="font-medium underline hover:text-blue-900"
            >
              Settings &gt; API Keys
            </a>
            .
          </p>
        </div>
      )}

      {state.kind === "new_key" && (
        <div className="space-y-6">
          <ApiKeyReveal apiKey={state.apiKey} />

          <div className="rounded-lg border border-gray-200 bg-white p-6">
            <h2 className="mb-4 text-lg font-semibold text-gray-900">
              Getting Started
            </h2>

            <ol className="space-y-4 text-sm text-gray-700">
              <li>
                <span className="mr-2 inline-flex h-6 w-6 items-center justify-center rounded-full bg-indigo-100 text-xs font-bold text-indigo-700">
                  1
                </span>
                <span className="font-medium">Install the SDK</span>
                <pre className="mt-2 rounded bg-gray-900 p-3 text-xs text-green-400 overflow-x-auto">
                  pip install primust
                </pre>
              </li>

              <li>
                <span className="mr-2 inline-flex h-6 w-6 items-center justify-center rounded-full bg-indigo-100 text-xs font-bold text-indigo-700">
                  2
                </span>
                <span className="font-medium">Issue your first VPEC</span>
                <pre className="mt-2 rounded bg-gray-900 p-3 text-xs text-green-400 overflow-x-auto">
{`import primust

client = primust.Client(api_key="${state.apiKey.slice(0, 12)}...")
vpec = client.vpecs.create(workflow_id="my-first-workflow")`}
                </pre>
              </li>

              <li>
                <span className="mr-2 inline-flex h-6 w-6 items-center justify-center rounded-full bg-indigo-100 text-xs font-bold text-indigo-700">
                  3
                </span>
                <span className="font-medium">Read the docs</span>
                <p className="mt-1">
                  See the{" "}
                  <a
                    href="https://docs.primust.com/quickstart"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-medium text-indigo-600 underline hover:text-indigo-800"
                  >
                    Quickstart Guide
                  </a>{" "}
                  for complete setup instructions, policy configuration, and
                  evidence pack assembly.
                </p>
              </li>
            </ol>
          </div>

          <div className="text-center">
            <a
              href="/settings/api-keys"
              className="text-sm text-gray-500 hover:text-gray-700 underline"
            >
              View all API keys
            </a>
          </div>
        </div>
      )}
    </div>
  );
}
