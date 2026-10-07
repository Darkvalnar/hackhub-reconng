import { SharedStorage } from "@hotbunny/hackhub-content-sdk";
import { buildLocalPrivilegeProfile, type LocalPrivilegeProfile, type LocalPrivilegeTarget } from "./LocalPrivilege";

export const LOCAL_PRIVILEGE_TARGETS_KEY = "reconng.localPrivilege.targets";

function isTarget(value: unknown): value is LocalPrivilegeTarget {
    if (!value || typeof value !== "object") return false;
    const target = value as Record<string, unknown>;
    return typeof target.target === "string"
        && (target.seed === undefined || typeof target.seed === "string")
        && (target.os === undefined || target.os === "linux" || target.os === "windows")
        && (target.families === undefined || (Array.isArray(target.families)
            && target.families.every((family) => family === "search-path" || family === "fixed-buffer")));
}

export function localPrivilegeProfile(ip: string, host: string): LocalPrivilegeProfile | undefined {
    const raw = SharedStorage.get<unknown>(LOCAL_PRIVILEGE_TARGETS_KEY);
    if (!Array.isArray(raw)) return undefined;
    const keys = new Set([ip.trim().toLowerCase(), host.trim().toLowerCase()]);
    const target = raw.filter(isTarget).find((entry) => keys.has(entry.target.trim().toLowerCase()));
    return target ? buildLocalPrivilegeProfile(target, ip, host) : undefined;
}
