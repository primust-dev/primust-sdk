"use client";

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

const TYPE_BADGES: Record<string, string> = {
  sandbox: "bg-amber-100 text-amber-800",
  test: "bg-blue-100 text-blue-800",
  live: "bg-green-100 text-green-800",
};

const STATUS_BADGES: Record<string, string> = {
  active: "bg-green-100 text-green-800",
  revoked: "bg-red-100 text-red-800",
  expired: "bg-gray-100 text-gray-600",
};

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

export function ApiKeyTable({ keys, loading }: ApiKeyTableProps) {
  if (loading) {
    return (
      <div className="py-8 text-center text-sm text-gray-500" data-testid="loading">
        Loading API keys...
      </div>
    );
  }

  if (keys.length === 0) {
    return (
      <div className="py-8 text-center text-sm text-gray-500" data-testid="empty-state">
        No API keys found. Complete onboarding to get your first sandbox key.
      </div>
    );
  }

  return (
    <table className="w-full text-sm" data-testid="api-key-table">
      <thead>
        <tr className="border-b text-left">
          <th className="py-2 px-2">Key Prefix</th>
          <th className="py-2 px-2">Type</th>
          <th className="py-2 px-2">Status</th>
          <th className="py-2 px-2">Created</th>
        </tr>
      </thead>
      <tbody>
        {keys.map((key) => (
          <tr key={key.key_id} className="border-b" data-testid={`key-row-${key.key_id}`}>
            <td className="py-2 px-2 font-mono text-xs">{key.prefix}</td>
            <td className="py-2 px-2">
              <span
                className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${TYPE_BADGES[key.key_type] ?? "bg-gray-100 text-gray-800"}`}
              >
                {key.key_type}
              </span>
            </td>
            <td className="py-2 px-2">
              <span
                className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${STATUS_BADGES[key.status] ?? "bg-gray-100 text-gray-600"}`}
              >
                {key.status}
              </span>
            </td>
            <td className="py-2 px-2 text-gray-600">{formatDate(key.created_at)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
