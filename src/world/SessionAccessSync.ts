import { SharedStorage } from "@hotbunny/hackhub-content-sdk";
import { registerAccessProfile, type AccessProfile, type AccessCommand } from "./SessionAccess";

export const ACCESS_PROFILE_SHARED_KEY = "reconng.access.profiles";

function isCommand(value: unknown): value is AccessCommand {
    if (!value || typeof value !== "object") return false;
    const command = value as Record<string, unknown>;
    return typeof command.name === "string"
        && (command.kind === "list" || command.kind === "read")
        && typeof command.path === "string";
}

function isProfile(value: unknown): value is AccessProfile {
    if (!value || typeof value !== "object") return false;
    const profile = value as Record<string, unknown>;
    return typeof profile.id === "string"
        && typeof profile.role === "string"
        && Array.isArray(profile.commands)
        && profile.commands.every(isCommand);
}

export function syncExternalAccessProfiles(): void {
    const raw = SharedStorage.get<unknown>(ACCESS_PROFILE_SHARED_KEY);
    if (!Array.isArray(raw)) return;
    for (const entry of raw) {
        if (isProfile(entry)) registerAccessProfile(entry);
    }
}

export function publishAccessProfile(profile: AccessProfile): void {
    const raw = SharedStorage.get<unknown>(ACCESS_PROFILE_SHARED_KEY);
    const list = Array.isArray(raw) ? (raw.filter(isProfile) as AccessProfile[]) : [];
    const next = list.filter((existing) => existing.id.toLowerCase() !== profile.id.toLowerCase());
    next.push(profile);
    SharedStorage.set(ACCESS_PROFILE_SHARED_KEY, next);
}
