/**
 * Centralized fetch wrapper for the Primust API.
 * Adds auth headers and base URL, handles common error patterns.
 */
const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "/api/v1";
class ApiError extends Error {
    status;
    statusText;
    detail;
    constructor(status, statusText, detail) {
        super(`API ${status}: ${statusText}${detail ? ` — ${detail}` : ""}`);
        this.status = status;
        this.statusText = statusText;
        this.detail = detail;
        this.name = "ApiError";
    }
}
function getAuthHeaders() {
    if (typeof window === "undefined")
        return {};
    const token = localStorage.getItem("primust_token");
    if (!token)
        return {};
    return { Authorization: `Bearer ${token}` };
}
export async function apiFetch(path, options = {}) {
    const { body, headers: extraHeaders, ...rest } = options;
    const headers = {
        "Content-Type": "application/json",
        ...getAuthHeaders(),
        ...extraHeaders,
    };
    const response = await fetch(`${API_BASE}${path}`, {
        ...rest,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (!response.ok) {
        let detail;
        try {
            const errBody = await response.json();
            detail = errBody.detail ?? errBody.message;
        }
        catch {
            /* ignore parse errors */
        }
        throw new ApiError(response.status, response.statusText, detail);
    }
    if (response.status === 204)
        return undefined;
    return response.json();
}
export { ApiError };
//# sourceMappingURL=api.js.map