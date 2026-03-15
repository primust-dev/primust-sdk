import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Primust Verify — Offline VPEC Verification",
  description:
    "Verify VPEC credentials. No login required. No data sent to any server.",
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
      <body className="bg-white text-gray-900 min-h-screen">
        <nav className="border-b px-6 py-3 flex items-center justify-between text-sm">
          <a href="/" className="font-bold text-lg">
            verify.primust.com
          </a>
          <div className="flex gap-4 text-gray-500">
            <a href="/guide" className="hover:text-gray-900">
              Reviewer Guide
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
        <div className="bg-amber-50 border-b border-amber-200 px-6 py-2 text-xs text-amber-800 text-center">
          You don&apos;t need this website.{" "}
          <code className="bg-amber-100 px-1 rounded">
            pip install primust-verify
          </code>{" "}
          — works offline, forever.
        </div>
        {children}
      </body>
    </html>
  );
}
