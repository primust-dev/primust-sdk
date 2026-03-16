export default function Home() {
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Dashboard</h1>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <a
          href="/onboard"
          className="border rounded-lg p-6 hover:border-blue-500 transition-colors"
        >
          <h2 className="font-semibold mb-2">Get Started</h2>
          <p className="text-sm text-gray-500">
            Set up your first workflow and generate API keys.
          </p>
        </a>
        <a
          href="/policy"
          className="border rounded-lg p-6 hover:border-blue-500 transition-colors"
        >
          <h2 className="font-semibold mb-2">Policy Bundles</h2>
          <p className="text-sm text-gray-500">
            Manage policy configurations and manifest hashes.
          </p>
        </a>
        <a
          href="/settings/api-keys"
          className="border rounded-lg p-6 hover:border-blue-500 transition-colors"
        >
          <h2 className="font-semibold mb-2">API Keys</h2>
          <p className="text-sm text-gray-500">
            Create and manage live, test, and sandbox keys.
          </p>
        </a>
        <a
          href="/runs"
          className="border rounded-lg p-6 hover:border-blue-500 transition-colors"
        >
          <h2 className="font-semibold mb-2">Runs</h2>
          <p className="text-sm text-gray-500">
            View all governance runs with status, proof level, and coverage.
          </p>
        </a>
        <a
          href="/gaps"
          className="border rounded-lg p-6 hover:border-blue-500 transition-colors"
        >
          <h2 className="font-semibold mb-2">Gaps</h2>
          <p className="text-sm text-gray-500">
            Review governance gaps by severity and submit waivers.
          </p>
        </a>
        <a
          href="/evidence"
          className="border rounded-lg p-6 hover:border-blue-500 transition-colors"
        >
          <h2 className="font-semibold mb-2">Evidence</h2>
          <p className="text-sm text-gray-500">
            Assemble evidence packs from VPECs for audit and compliance.
          </p>
        </a>
        <a
          href="/settings/webhooks"
          className="border rounded-lg p-6 hover:border-blue-500 transition-colors"
        >
          <h2 className="font-semibold mb-2">Webhooks</h2>
          <p className="text-sm text-gray-500">
            Configure SIEM integration for real-time governance events.
          </p>
        </a>
      </div>
    </div>
  );
}
