import { Network, SharedStorage } from "@hotbunny/hackhub-content-sdk";
import { GameStorage as Storage } from "./ReconNgStorage";

export const REVERSE_PAYLOAD_SHARED_KEY = "reconng.reverse.payloads";
export const REVERSE_PAYLOAD_PACKAGES_SHARED_KEY = "reconng.reverse.payload.packages";
const REVERSE_PAYLOAD_STATE_KEY = "recon-ng.reversePayloads.owned";
const ARMED_LISTENER_KEY = "recon-ng.reversePayloads.armed";

export interface ArmedReverseListener {
    payloadId: string;
    lhost: string;
    lport: number;
    target: string;
}

export interface ReverseListenerNetworkCheck {
    ok: boolean;
    reason?: string;
    expectedLhost?: string;
}

function callbackToken(listener: ArmedReverseListener): string {
    const value = `${listener.payloadId}|${listener.lhost}|${listener.lport}|${listener.target}`;
    let result = 2166136261;
    for (let index = 0; index < value.length; index += 1) {
        result ^= value.charCodeAt(index);
        result = Math.imul(result, 16777619);
    }
    return (result >>> 0).toString(36).padStart(7, "0");
}

export function reverseCallbackUrl(listener: ArmedReverseListener): string {
    const route = listener.payloadId.includes("doc_macro")
        ? "document"
        : listener.payloadId.includes("fake_update")
            ? "update"
            : listener.payloadId.includes("script_drop")
                ? "diagnostic"
                : "confirm";
    return `https://${listener.lhost}:${listener.lport}/${route}/${callbackToken(listener)}`;
}

export function checkReverseListenerNetwork(listener: ArmedReverseListener): ReverseListenerNetworkCheck {
    const playerIp = Network.getPlayerIp();
    if (!playerIp || playerIp === "0.0.0.0") {
        return { ok: false, reason: "connect to a network before starting a reverse listener." };
    }

    const player = Network.getSubnet(playerIp);
    if (!player?.lanIp) {
        return { ok: false, reason: "the current player network has no reachable LAN address." };
    }
    if (listener.lhost.trim() !== player.lanIp) {
        return {
            ok: false,
            reason: `LHOST must be your current LAN address (${player.lanIp}).`,
            expectedLhost: player.lanIp,
        };
    }

    const forwarded = player.ports.some((port) => port.port === listener.lport && port.active === true);
    if (!forwarded) {
        return {
            ok: false,
            reason: `LPORT ${listener.lport} is not active on your router for ${player.lanIp}.`,
            expectedLhost: player.lanIp,
        };
    }
    return { ok: true, expectedLhost: player.lanIp };
}

export function armReverseListener(listener: ArmedReverseListener): void {
    Storage.set(ARMED_LISTENER_KEY, listener);
}

export function getArmedReverseListener(): ArmedReverseListener | undefined {
    const raw = Storage.get<ArmedReverseListener>(ARMED_LISTENER_KEY);
    if (!raw || typeof raw !== "object") return undefined;
    if (typeof raw.payloadId !== "string" || typeof raw.lhost !== "string" || typeof raw.lport !== "number" || typeof raw.target !== "string") return undefined;
    return raw;
}

export function clearArmedReverseListener(): void {
    Storage.remove(ARMED_LISTENER_KEY);
}

export type ReversePayloadFamily = "portal_link" | "doc_macro" | "fake_update" | "script_drop";

export interface ReversePayloadDefinition {
    id: string;
    family: ReversePayloadFamily;
    label: string;
    delivery: "link" | "attachment" | "archive";
    affinities: string[];
    summary: string;
}

export interface ReversePayloadPackageEntitlement {
    providerId: string;
    packageName: string;
    payload: ReversePayloadDefinition;
}

function isPayload(value: unknown): value is ReversePayloadDefinition {
    if (!value || typeof value !== "object") return false;
    const payload = value as Record<string, unknown>;
    return typeof payload.id === "string"
        && (payload.family === "portal_link" || payload.family === "doc_macro" || payload.family === "fake_update" || payload.family === "script_drop")
        && typeof payload.label === "string"
        && (payload.delivery === "link" || payload.delivery === "attachment" || payload.delivery === "archive")
        && Array.isArray(payload.affinities)
        && payload.affinities.every((item) => typeof item === "string")
        && typeof payload.summary === "string";
}

function ownedPayloads(): ReversePayloadDefinition[] {
    const raw = Storage.get<unknown>(REVERSE_PAYLOAD_STATE_KEY);
    return Array.isArray(raw) ? raw.filter(isPayload) : [];
}

export function registerReversePayload(payload: ReversePayloadDefinition): void {
    const list = ownedPayloads();
    const key = payload.id.toLowerCase();
    Storage.set(REVERSE_PAYLOAD_STATE_KEY, [...list.filter((item) => item.id.toLowerCase() !== key), payload]);
}

export function listReversePayloads(): ReversePayloadDefinition[] {
    syncExternalReversePayloads();
    return ownedPayloads().sort((a, b) => a.id.localeCompare(b.id));
}

export function findReversePayload(idOrIndex: string): ReversePayloadDefinition | undefined {
    const list = listReversePayloads();
    const index = Number(idOrIndex);
    if (Number.isInteger(index) && index >= 0) return list[index];
    const needle = idOrIndex.toLowerCase();
    return list.find((payload) =>
        payload.id.toLowerCase() === needle ||
        payload.id.toLowerCase().endsWith(needle) ||
        payload.label.toLowerCase() === needle,
    );
}

export function syncExternalReversePayloads(): void {
    const raw = SharedStorage.get<unknown>(REVERSE_PAYLOAD_SHARED_KEY);
    if (!Array.isArray(raw)) return;
    const incoming = raw.filter(isPayload);
    if (incoming.length === 0) return;
    const byId = new Map(ownedPayloads().map((item) => [item.id.toLowerCase(), item]));
    let changed = false;
    for (const payload of incoming) {
        const key = payload.id.toLowerCase();
        if (JSON.stringify(byId.get(key)) !== JSON.stringify(payload)) {
            byId.set(key, payload);
            changed = true;
        }
    }
    if (changed) Storage.set(REVERSE_PAYLOAD_STATE_KEY, [...byId.values()]);
}

function isPackageEntitlement(value: unknown): value is ReversePayloadPackageEntitlement {
    if (!value || typeof value !== "object") return false;
    const entitlement = value as Record<string, unknown>;
    return typeof entitlement.providerId === "string"
        && entitlement.providerId.trim().length > 0
        && typeof entitlement.packageName === "string"
        && entitlement.packageName.toLowerCase().endsWith(".rpkg")
        && isPayload(entitlement.payload);
}

export function findReversePayloadPackageEntitlement(packageName: string):
    | { ok: true; entitlement: ReversePayloadPackageEntitlement }
    | { ok: false; reason: string } {
    const wanted = packageName.trim().toLowerCase();
    const raw = SharedStorage.get<unknown>(REVERSE_PAYLOAD_PACKAGES_SHARED_KEY);
    const matches = Array.isArray(raw)
        ? raw.filter(isPackageEntitlement).filter((entry) => entry.packageName.trim().toLowerCase() === wanted)
        : [];

    if (matches.length === 0) {
        return { ok: false, reason: "no trusted provider entitlement exists for this package." };
    }

    const identities = new Set(matches.map((entry) => `${entry.providerId.toLowerCase()}|${entry.payload.id.toLowerCase()}`));
    if (identities.size > 1) {
        return { ok: false, reason: "multiple providers published conflicting entitlements for this package name." };
    }

    return { ok: true, entitlement: matches[0] };
}

const REVERSE_TARGETS_SHARED_KEY = "reconng.reverse.targets";

export interface ReverseTargetRecord {
    providerId?: string;
    ip: string;
    username: string;
    tier: string;
    desktop?: { os: "linux" | "windows"; profile: string; label?: string };
}

export function getReverseTarget(email: string): ReverseTargetRecord | undefined {
    const key = email.trim().toLowerCase();
    if (!key) return undefined;
    const map = SharedStorage.get<Record<string, unknown>>(REVERSE_TARGETS_SHARED_KEY);
    if (!map || typeof map !== "object") return undefined;
    const record = (map as Record<string, any>)[key];
    if (!record || typeof record.ip !== "string" || typeof record.username !== "string") return undefined;
    const d = record.desktop;
    const desktop = d && (d.os === "linux" || d.os === "windows") && typeof d.profile === "string"
        ? { os: d.os as "linux" | "windows", profile: d.profile as string, label: typeof d.label === "string" ? d.label : undefined }
        : undefined;
    return { ip: record.ip, username: record.username, tier: typeof record.tier === "string" ? record.tier : "user", desktop };
}
