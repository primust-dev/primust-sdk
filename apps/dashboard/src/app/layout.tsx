import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Primust Dashboard",
  description: "Manage your Primust workflows, API keys, and VPECs.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <head>
        <script src="https://cdn.tailwindcss.com" async />
      </head>
      <body className="bg-gray-50 text-gray-900 min-h-screen">
        <nav className="bg-white border-b px-6 py-3 flex items-center justify-between text-sm">
          <a href="/" className="font-bold text-lg">
            Primust
          </a>
          <div className="flex gap-4 text-gray-500">
            <a href="/onboard" className="hover:text-gray-900">
              Onboard
            </a>
            <a href="/policy" className="hover:text-gray-900">
              Policy
            </a>
            <a href="/settings/api-keys" className="hover:text-gray-900">
              API Keys
            </a>
            <a
              href="https://docs.primust.com"
              className="hover:text-gray-900"
              target="_blank"
              rel="noopener noreferrer"
            >
              Docs
            </a>
          </div>
        </nav>
        <main className="max-w-5xl mx-auto p-6">{children}</main>
      </body>
    </html>
  );
}
