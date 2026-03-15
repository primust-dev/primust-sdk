/**
 * Persistent warning banner shown across all dashboard pages when
 * the webhook is configured but failing (last_status outside 2xx).
 *
 * Renders nothing when:
 * - No webhook configured
 * - Webhook is healthy (last_status 2xx)
 */
export function WebhookStatusBanner({ config, failureCount = 0, settingsHref = "/settings/webhook", }) {
    if (!config?.configured)
        return null;
    const isHealthy = config.last_status != null &&
        config.last_status >= 200 &&
        config.last_status < 300;
    if (isHealthy)
        return null;
    return (<div data-testid="webhook-status-banner" className="bg-red-50 border-b border-red-200 px-4 py-2 flex items-center justify-between text-sm" role="alert">
      <span className="text-red-800">
        SIEM webhook delivery is failing
        {config.last_status != null && (<> — last response HTTP {config.last_status}</>)}
        {failureCount > 0 && (<> · {failureCount} unresolved failure{failureCount > 1 ? "s" : ""}</>)}
      </span>
      <a href={settingsHref} className="text-red-700 font-medium hover:underline" data-testid="webhook-banner-link">
        View settings →
      </a>
    </div>);
}
//# sourceMappingURL=WebhookStatusBanner.js.map