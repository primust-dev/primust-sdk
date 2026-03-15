/**
 * Centralized fetch wrapper for the Primust API.
 * Adds auth headers and base URL, handles common error patterns.
 */
interface ApiOptions extends Omit<RequestInit, "body"> {
    body?: unknown;
}
declare class ApiError extends Error {
    status: number;
    statusText: string;
    detail?: string | undefined;
    constructor(status: number, statusText: string, detail?: string | undefined);
}
export declare function apiFetch<T>(path: string, options?: ApiOptions): Promise<T>;
export { ApiError };
//# sourceMappingURL=api.d.ts.map