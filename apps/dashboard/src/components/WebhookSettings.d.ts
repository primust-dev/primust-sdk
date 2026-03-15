export interface WebhookConfig {
    configured: boolean;
    id?: string;
    endpoint_url?: string;
    auth_header?: string;
    enabled?: boolean;
    coverage_threshold_floor?: number;
    last_delivery?: string | null;
    last_status?: number | null;
    siem_examples?: SiemExample[];
}
export interface SiemExample {
    siem: string;
    format: string;
}
export interface DeliveryFailure {
    id: string;
    delivery_id: string;
    vpec_id: string;
    event_type: string;
    attempted_at: string;
    http_status: number | null;
    error_msg: string | null;
}
export interface TestResult {
    delivery_id: string;
    status: number;
    latency_ms: number;
    error?: string | null;
}
export interface WebhookSettingsProps {
    config: WebhookConfig;
    failures?: DeliveryFailure[];
    onSave: (data: {
        endpoint_url: string;
        auth_header: string;
        coverage_threshold_floor: number;
    }) => Promise<void>;
    onDelete: () => Promise<void>;
    onTest: () => Promise<TestResult>;
    onRetry: (deliveryId: string) => Promise<TestResult>;
}
export declare function WebhookSettings({ config, failures, onSave, onDelete, onTest, onRetry, }: WebhookSettingsProps): import("react").JSX.Element;
//# sourceMappingURL=WebhookSettings.d.ts.map