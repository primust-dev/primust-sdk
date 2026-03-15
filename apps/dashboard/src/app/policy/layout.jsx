export const metadata = {
    title: "Policy Center — Primust",
};
export default function PolicyLayout({ children }) {
    return (<section className="min-h-screen bg-gray-50">
      <header className="border-b bg-white px-6 py-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold">Policy Center</h1>
            <p className="text-sm text-gray-500">
              Configure bundles, manifests, and checks
            </p>
          </div>
          <nav className="flex gap-1">
            <a href="/policy" className="rounded px-3 py-1.5 text-sm font-medium text-gray-600 hover:bg-gray-100 transition-colors">
              Bundles
            </a>
            <a href="/policy/manifests" className="rounded px-3 py-1.5 text-sm font-medium text-gray-600 hover:bg-gray-100 transition-colors">
              Manifests
            </a>
            <a href="/policy/checks" className="rounded px-3 py-1.5 text-sm font-medium text-gray-600 hover:bg-gray-100 transition-colors">
              Checks
            </a>
          </nav>
        </div>
      </header>
      <main className="p-6">{children}</main>
    </section>);
}
//# sourceMappingURL=layout.js.map