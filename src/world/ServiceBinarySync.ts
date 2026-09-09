import { SharedStorage } from "@hotbunny/hackhub-content-sdk";
import { registerServiceBinary, type ServiceBinaryOverride } from "./ServiceBinary";

export const SERVICE_BINARY_SHARED_KEY = "reconng.binary.overrides";

function isOverride(value: unknown): value is ServiceBinaryOverride {
    if (!value || typeof value !== "object") return false;
    const o = value as Record<string, unknown>;
    return typeof o.service === "string" && typeof o.version === "string";
}

function entryKey(override: ServiceBinaryOverride): string {
    return `${override.service.toLowerCase()}@${override.version.toLowerCase()}`;
}

export function syncExternalServiceBinaries(): void {
    const raw = SharedStorage.get<unknown>(SERVICE_BINARY_SHARED_KEY);
    if (!Array.isArray(raw)) return;
    for (const entry of raw) {
        if (isOverride(entry)) registerServiceBinary(entry);
    }
}

export function publishServiceBinary(override: ServiceBinaryOverride): void {
    const raw = SharedStorage.get<unknown>(SERVICE_BINARY_SHARED_KEY);
    const list = Array.isArray(raw) ? (raw.filter(isOverride) as ServiceBinaryOverride[]) : [];
    const key = entryKey(override);
    const next = list.filter((existing) => entryKey(existing) !== key);
    next.push(override);
    SharedStorage.set(SERVICE_BINARY_SHARED_KEY, next);
}
