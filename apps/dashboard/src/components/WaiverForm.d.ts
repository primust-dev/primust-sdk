interface WaiverFormProps {
    gapId: string;
    onSubmit: (data: {
        reason: string;
        compensating_control: string | null;
        expires_at: string;
    }) => void;
}
/**
 * Waiver form with mandatory expires_at.
 * - reason: min 50 chars enforced
 * - expires_at: REQUIRED, max 90 days from today
 * - No permanent waivers ever
 */
export declare function WaiverForm({ gapId, onSubmit }: WaiverFormProps): import("react").JSX.Element;
export {};
//# sourceMappingURL=WaiverForm.d.ts.map