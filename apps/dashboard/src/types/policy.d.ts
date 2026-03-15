/**
 * Policy Center types for the dashboard.
 * Covers bundles, checks, manifests, and code generation.
 */
import type { ProofLevel } from "./vpec";
export type PolicyStatus = "draft" | "simulation" | "active";
export interface PolicyBundle {
    bundle_id: string;
    name: string;
    description?: string;
    version: string;
    checks: BundleCheck[];
    framework_mappings: string[];
    estimated_provable_surface: number;
    is_builtin: boolean;
    created_at: string;
}
export interface BundleCheck {
    check_id: string;
    check_name: string;
    required: boolean;
    threshold?: number;
    proof_ceiling: ProofLevel;
    what_it_proves: string;
    zk_circuit?: string;
    config?: Record<string, unknown>;
}
export interface CheckManifest {
    manifest_id: string;
    manifest_hash: string;
    name: string;
    check_name: string;
    version: string;
    proof_level_ceiling: ProofLevel;
    registered_at: string;
    status: "active" | "deprecated" | "pending";
}
export interface ActivePolicy {
    policy_id: string;
    bundle_id: string;
    bundle_name: string;
    status: PolicyStatus;
    activated_at: string | null;
    simulation_started_at: string | null;
    simulation_completed_at: string | null;
}
export interface CheckDefinition {
    check_id: string;
    check_name: string;
    type: "builtin" | "custom";
    proof_ceiling: ProofLevel;
    description: string;
    default_threshold?: number;
    zk_available: boolean;
}
export type CodeGenFramework = "langgraph" | "openai_agents" | "google_adk" | "otel" | "custom";
export type CodeGenLanguage = "python" | "typescript" | "java";
export interface CodeGenRequest {
    framework: CodeGenFramework;
    manifest_ids: string[];
    language: CodeGenLanguage;
}
export interface CodeGenResponse {
    code: string;
    language: CodeGenLanguage;
    framework: CodeGenFramework;
    manifest_count: number;
}
//# sourceMappingURL=policy.d.ts.map