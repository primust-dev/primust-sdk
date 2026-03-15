interface RedactedKey {
    key_id: string;
    key_type: string;
    prefix: string;
    created_at: string;
    status: string;
}
interface ApiKeyTableProps {
    keys: RedactedKey[];
    loading?: boolean;
}
export declare function ApiKeyTable({ keys, loading }: ApiKeyTableProps): import("react").JSX.Element;
export {};
//# sourceMappingURL=ApiKeyTable.d.ts.map