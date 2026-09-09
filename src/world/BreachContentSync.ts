import { SharedStorage } from "@hotbunny/hackhub-content-sdk";
import { BreachBackend, type BreachFile, type BreachModule, type UserEnumTarget, type WordlistSpec } from "./BreachBackend";

export const BREACH_MODULE_SHARED_KEY = "reconng.modules";
export const BREACH_LOOT_SHARED_KEY = "reconng.loot";
export const BREACH_WORDLIST_SHARED_KEY = "reconng.wordlists";
export const BREACH_WORDLIST_GRANT_SHARED_KEY = "reconng.wordlist.grants";
export const BREACH_WORDLIST_GATE_SHARED_KEY = "reconng.wordlist.gates";
export const USER_ENUM_TARGET_SHARED_KEY = "reconng.user.enum.targets";

export interface BreachWordlistGate {
    target: string;
    tier: number;
}

export interface BreachLootOverlay {
    target: string;
    files: BreachFile[];
}

function isDesktop(value: unknown): boolean {
    if (value === undefined) return true;
    if (!value || typeof value !== "object") return false;
    const desktop = value as Record<string, unknown>;
    return (desktop.os === "linux" || desktop.os === "windows")
        && typeof desktop.profile === "string"
        && (desktop.label === undefined || typeof desktop.label === "string");
}

function isModule(value: unknown): value is BreachModule {
    if (!value || typeof value !== "object") return false;
    const module = value as Record<string, unknown>;
    return typeof module.id === "string"
        && typeof module.name === "string"
        && (module.family === "exploit" || module.family === "auxiliary" || module.family === "post")
        && typeof module.service === "string"
        && (module.port === undefined || typeof module.port === "number")
        && (module.requiresRport === undefined || typeof module.requiresRport === "boolean")
        && (module.versions === undefined || Array.isArray(module.versions))
        && (module.vulnerabilities === undefined || Array.isArray(module.vulnerabilities))
        && (module.privilege === "guest" || module.privilege === "user" || module.privilege === "www-data" || module.privilege === "root")
        && typeof module.description === "string"
        && (module.locked === undefined || typeof module.locked === "boolean")
        && (module.price === undefined || typeof module.price === "number")
        && (module.access === undefined || typeof module.access === "string")
        && isDesktop(module.desktop);
}

function isFile(value: unknown): value is BreachFile {
    if (!value || typeof value !== "object") return false;
    const file = value as Record<string, unknown>;
    return typeof file.path === "string"
        && typeof file.data === "string"
        && (file.readable === undefined || typeof file.readable === "boolean")
        && (file.downloadable === undefined || typeof file.downloadable === "boolean")
        && (file.deletable === undefined || typeof file.deletable === "boolean");
}

function isLootOverlay(value: unknown): value is BreachLootOverlay {
    if (!value || typeof value !== "object") return false;
    const overlay = value as Record<string, unknown>;
    return typeof overlay.target === "string"
        && Array.isArray(overlay.files)
        && overlay.files.every(isFile);
}

function isWordlist(value: unknown): value is WordlistSpec {
    if (!value || typeof value !== "object") return false;
    const spec = value as Record<string, unknown>;
    return typeof spec.name === "string"
        && typeof spec.tier === "number"
        && typeof spec.entries === "number";
}

function isWordlistGate(value: unknown): value is BreachWordlistGate {
    if (!value || typeof value !== "object") return false;
    const gate = value as Record<string, unknown>;
    return typeof gate.target === "string" && typeof gate.tier === "number";
}

function isUserEnumTarget(value: unknown): value is UserEnumTarget {
    if (!value || typeof value !== "object") return false;
    const record = value as Record<string, unknown>;
    return typeof record.target === "string"
        && Array.isArray(record.users)
        && record.users.every((user) => typeof user === "string")
        && (record.service === undefined || typeof record.service === "string")
        && (record.port === undefined || typeof record.port === "number")
        && (record.observationProfile === undefined || ["preauth", "timing", "auth-methods", "keyboard-interactive", "key-parse"].includes(String(record.observationProfile)))
        && (record.observation === undefined || typeof record.observation === "string")
        && (record.note === undefined || typeof record.note === "string");
}

export function syncExternalBreachContent(): void {
    const lootRaw = SharedStorage.get<unknown>(BREACH_LOOT_SHARED_KEY);
    const wordlistsRaw = SharedStorage.get<unknown>(BREACH_WORDLIST_SHARED_KEY);
    const grantsRaw = SharedStorage.get<unknown>(BREACH_WORDLIST_GRANT_SHARED_KEY);
    const gatesRaw = SharedStorage.get<unknown>(BREACH_WORDLIST_GATE_SHARED_KEY);
    const userEnumRaw = SharedStorage.get<unknown>(USER_ENUM_TARGET_SHARED_KEY);

    BreachBackend.applyExternalContent({
        loot: Array.isArray(lootRaw) ? lootRaw.filter(isLootOverlay) : [],
        wordlists: Array.isArray(wordlistsRaw) ? wordlistsRaw.filter(isWordlist) : [],
        wordlistGrants: Array.isArray(grantsRaw)
            ? grantsRaw.filter((name): name is string => typeof name === "string")
            : [],
        gates: Array.isArray(gatesRaw) ? gatesRaw.filter(isWordlistGate) : [],
        userEnumTargets: Array.isArray(userEnumRaw) ? userEnumRaw.filter(isUserEnumTarget) : [],
    });
}

export function publishBreachWordlist(spec: WordlistSpec): void {
    const raw = SharedStorage.get<unknown>(BREACH_WORDLIST_SHARED_KEY);
    const list = Array.isArray(raw) ? (raw.filter(isWordlist) as WordlistSpec[]) : [];
    const next = list.filter((existing) => existing.name.toLowerCase() !== spec.name.toLowerCase());
    next.push(spec);
    SharedStorage.set(BREACH_WORDLIST_SHARED_KEY, next);
}

export function publishBreachWordlistGrant(name: string): void {
    const key = String(name ?? "").trim().toLowerCase();
    if (!key) return;
    const raw = SharedStorage.get<unknown>(BREACH_WORDLIST_GRANT_SHARED_KEY);
    const list = Array.isArray(raw) ? raw.filter((entry): entry is string => typeof entry === "string") : [];
    if (list.some((entry) => entry.trim().toLowerCase() === key)) return;
    SharedStorage.set(BREACH_WORDLIST_GRANT_SHARED_KEY, [...list, key]);
}

export function publishBreachWordlistGate(gate: BreachWordlistGate): void {
    const raw = SharedStorage.get<unknown>(BREACH_WORDLIST_GATE_SHARED_KEY);
    const list = Array.isArray(raw) ? (raw.filter(isWordlistGate) as BreachWordlistGate[]) : [];
    const key = gate.target.toLowerCase();
    const next = list.filter((existing) => existing.target.toLowerCase() !== key);
    next.push(gate);
    SharedStorage.set(BREACH_WORDLIST_GATE_SHARED_KEY, next);
}

export function publishBreachModule(module: BreachModule): void {
    const raw = SharedStorage.get<unknown>(BREACH_MODULE_SHARED_KEY);
    const list = Array.isArray(raw) ? (raw.filter(isModule) as BreachModule[]) : [];
    const next = list.filter((existing) => existing.id.toLowerCase() !== module.id.toLowerCase());
    next.push(module);
    SharedStorage.set(BREACH_MODULE_SHARED_KEY, next);
}

export function publishBreachLoot(overlay: BreachLootOverlay): void {
    const raw = SharedStorage.get<unknown>(BREACH_LOOT_SHARED_KEY);
    const list = Array.isArray(raw) ? (raw.filter(isLootOverlay) as BreachLootOverlay[]) : [];
    const key = overlay.target.toLowerCase();
    const next = list.filter((existing) => existing.target.toLowerCase() !== key);
    next.push(overlay);
    SharedStorage.set(BREACH_LOOT_SHARED_KEY, next);
}

export function publishUserEnumTarget(record: UserEnumTarget): void {
    const raw = SharedStorage.get<unknown>(USER_ENUM_TARGET_SHARED_KEY);
    const list = Array.isArray(raw) ? (raw.filter(isUserEnumTarget) as UserEnumTarget[]) : [];
    const key = record.target.toLowerCase();
    const next = list.filter((existing) => existing.target.toLowerCase() !== key);
    next.push(record);
    SharedStorage.set(USER_ENUM_TARGET_SHARED_KEY, next);
}
