import type { WebhookConfig } from "./WebhookSettings";
export interface WebhookStatusBannerProps {
    config: WebhookConfig | null;
    failureCount?: number;
    settingsHref?: string;
}
/**
 * Persistent warning banner shown across all dashboard pages when
 * the webhook is configured but failing (last_status outside 2xx).
 *
 * Renders nothing when:
 * - No webhook configured
 * - Webhook is healthy (last_status 2xx)
 */
export declare function WebhookStatusBanner({ config, failureCount, settingsHref, }: WebhookStatusBannerProps): import("react").JSX.Element | null;
//# sourceMappingURL=WebhookStatusBanner.d.ts.map