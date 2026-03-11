interface ManifestHashesTableProps {
  /** manifest_hashes is a map (object), NOT an array. */
  manifestHashes: Record<string, string>;
}

export function ManifestHashesTable({ manifestHashes }: ManifestHashesTableProps) {
  const entries = Object.entries(manifestHashes);

  return (
    <table className="w-full text-sm" data-testid="manifest-hashes-table">
      <thead>
        <tr className="border-b text-left">
          <th className="py-1 px-2">Manifest ID</th>
          <th className="py-1 px-2">Hash</th>
        </tr>
      </thead>
      <tbody>
        {entries.map(([manifestId, hash]) => (
          <tr key={manifestId}>
            <td className="py-1 px-2 font-mono text-xs">{manifestId}</td>
            <td className="py-1 px-2 font-mono text-xs truncate max-w-xs">
              {hash}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
