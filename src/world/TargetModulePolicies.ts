import { SharedStorage } from "@hotbunny/hackhub-content-sdk";

export const TARGET_MODULE_POLICY_SHARED_KEY = "reconng.target.modulePolicies";

export interface TargetModulePolicy {
    id: string;
    targets: string[];
    requirement: "crafted";
    service: string;
    version: string;
    vulnerability: string;
}

function normalizeTarget(value: unknown): string {
    return String(value ?? "")
        .replace(/^https?:\/\//i, "")
        .replace(/\/.*$/, "")
        .trim()
        .toLowerCase();
}

function isPolicy(value: unknown): value is TargetModulePolicy {
    if (!value || typeof value !== "object") return false;
    const policy = value as Record<string, unknown>;
    return typeof policy.id === "string"
        && Array.isArray(policy.targets)
        && policy.targets.every((target) => typeof target === "string")
        && policy.requirement === "crafted"
        && typeof policy.service === "string"
        && typeof policy.version === "string"
        && typeof policy.vulnerability === "string";
}

export function getTargetModulePolicy(...targets: string[]): TargetModulePolicy | undefined {
    const keys = new Set(targets.map(normalizeTarget).filter(Boolean));
    if (!keys.size) return undefined;

    const raw = SharedStorage.get<unknown>(TARGET_MODULE_POLICY_SHARED_KEY);
    if (!Array.isArray(raw)) return undefined;

    return raw.filter(isPolicy).find((policy) =>
        policy.targets.some((target) => keys.has(normalizeTarget(target)))
    );
}
