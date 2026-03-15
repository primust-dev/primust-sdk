interface EvidencePackAssemblerProps {
    artifactIds: string[];
    onAssembleLocal: (ids: string[]) => void;
    onAssembleHosted: (ids: string[]) => void;
}
/**
 * Evidence Pack Assembler — LOCAL default, HOSTED opt-in.
 * LOCAL: "Local Assembly — raw content does not leave your environment"
 * HOSTED: requires acknowledgment dialog before proceeding.
 */
export declare function EvidencePackAssembler({ artifactIds, onAssembleLocal, onAssembleHosted, }: EvidencePackAssemblerProps): import("react").JSX.Element;
export {};
//# sourceMappingURL=EvidencePackAssembler.d.ts.map