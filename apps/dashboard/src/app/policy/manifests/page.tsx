"use client";

import { useState, useCallback } from "react";
import { ManifestRegistry } from "../../../components/policy/ManifestRegistry";
import { RegisterManifestModal } from "../../../components/policy/RegisterManifestModal";
import { GenerateCodeDrawer } from "../../../components/policy/GenerateCodeDrawer";

export default function ManifestsPage() {
  const [registerModalOpen, setRegisterModalOpen] = useState(false);
  const [codeDrawerOpen, setCodeDrawerOpen] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);

  const handleRegistered = useCallback(() => {
    setRefreshKey((k) => k + 1);
  }, []);

  return (
    <div data-testid="manifests-page">
      <div className="rounded border bg-white p-6">
        <ManifestRegistry
          onRegisterClick={() => setRegisterModalOpen(true)}
          onGenerateCodeClick={() => setCodeDrawerOpen(true)}
          refreshKey={refreshKey}
        />
      </div>

      <RegisterManifestModal
        open={registerModalOpen}
        onClose={() => setRegisterModalOpen(false)}
        onRegistered={handleRegistered}
      />

      <GenerateCodeDrawer
        open={codeDrawerOpen}
        onClose={() => setCodeDrawerOpen(false)}
      />
    </div>
  );
}
