"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "../../../lib/api";
import {
  WebhookSettings,
  type WebhookConfig,
  type DeliveryFailure,
  type TestResult,
} from "../../../components/WebhookSettings";

interface WebhookResponse {
  config: WebhookConfig;
  failures: DeliveryFailure[];
}

export default function WebhooksPage() {
  const [config, setConfig] = useState<WebhookConfig | null>(null);
  const [failures, setFailures] = useState<DeliveryFailure[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function fetchWebhook() {
      try {
        const res = await apiFetch<WebhookResponse>("/settings/webhook");
        if (!cancelled) {
          setConfig(res.config);
          setFailures(res.failures);
          setLoading(false);
        }
      } catch (err) {
        if (!cancelled) {
          // 404 means no webhook configured yet — that's fine
          setConfig({ configured: false });
          setFailures([]);
          setLoading(false);
          if (
            !(err instanceof Error && err.message.includes("404"))
          ) {
            setError(
              err instanceof Error
                ? err.message
                : "Failed to load webhook settings",
            );
          }
        }
      }
    }

    fetchWebhook();
    return () => {
      cancelled = true;
    };
  }, []);

  async function handleSave(data: {
    endpoint_url: string;
    auth_header: string;
    coverage_threshold_floor: number;
  }) {
    const res = await apiFetch<{ config: WebhookConfig }>(
      "/settings/webhook",
      {
        method: "PUT",
        body: data,
      },
    );
    setConfig(res.config);
  }

  async function handleDelete() {
    await apiFetch("/settings/webhook", { method: "DELETE" });
    setConfig({ configured: false });
    setFailures([]);
  }

  async function handleTest(): Promise<TestResult> {
    return apiFetch<TestResult>("/settings/webhook/test", {
      method: "POST",
    });
  }

  async function handleRetry(deliveryId: string): Promise<TestResult> {
    return apiFetch<TestResult>(
      `/settings/webhook/deliveries/${deliveryId}/retry`,
      { method: "POST" },
    );
  }

  return (
    <div className="mx-auto max-w-3xl py-12 px-4" data-testid="webhooks-page">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Webhooks</h1>
        <p className="mt-1 text-sm text-gray-600">
          Configure SIEM webhook integration to receive governance events in
          real time.
        </p>
      </div>

      {error && (
        <div
          className="mb-4 rounded-lg border border-red-300 bg-red-50 p-4 text-sm text-red-800"
          data-testid="webhooks-error"
        >
          {error}
        </div>
      )}

      {loading ? (
        <div className="text-sm text-gray-500 py-8 text-center">
          Loading webhook settings...
        </div>
      ) : config ? (
        <WebhookSettings
          config={config}
          failures={failures}
          onSave={handleSave}
          onDelete={handleDelete}
          onTest={handleTest}
          onRetry={handleRetry}
        />
      ) : null}
    </div>
  );
}
