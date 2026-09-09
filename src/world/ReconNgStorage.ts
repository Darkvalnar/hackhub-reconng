import { Events, SaveStorage } from "@hotbunny/hackhub-content-sdk";

/**
 * SaveStorage picks its namespace from whichever mod context is current when it is called, and that
 * context is one global shared across async work. While this console waits at a prompt another
 * mod's callback can leave its id in place, and reads then land somewhere this mod never wrote.
 *
 * Events.on captures the mod id at registration and restores it before invoking the listener, so a
 * gateway registered during load stays pinned to this mod. Every storage call is routed through a
 * synchronous emit to it and therefore runs under the right namespace.
 */
const GATEWAY_EVENT = "ReconNg.Internal.Storage";

type StorageOp = "get" | "set" | "remove" | "clear";

interface StorageRequest {
    op: StorageOp;
    key?: string;
    value?: unknown;
    result?: unknown;
    handled?: boolean;
}

let gatewayReady = false;

function clone<T>(value: T): T {
    if (value === undefined || value === null) return value;
    if (typeof value !== "object") return value;
    return JSON.parse(JSON.stringify(value)) as T;
}

function perform(request: StorageRequest): void {
    switch (request.op) {
        case "get":
            request.result = SaveStorage.get(request.key as string);
            break;
        case "set":
            SaveStorage.set(request.key as string, request.value);
            break;
        case "remove":
            SaveStorage.remove(request.key as string);
            break;
        case "clear":
            SaveStorage.clear();
            break;
    }
    request.handled = true;
}

/** Call once from OnModPackageLoaded, before anything reads or writes storage. */
export function installReconNgStorageGateway(): void {
    if (gatewayReady) return;
    try {
        Events.register(GATEWAY_EVENT);
    } catch {
        // Already registered by a previous load.
    }
    Events.on(GATEWAY_EVENT as any, (request: StorageRequest) => perform(request));
    gatewayReady = true;
}

/**
 * The listener runs synchronously inside the emit, so the result is readable straight after.
 *
 * Events.emit is permission gated and throws when no mod context is current, which app exports
 * and some unload paths hit. Falling back to a direct call there keeps the old unpinned
 * behaviour instead of failing the caller and rolling back the whole mod.
 */
function route(request: StorageRequest): StorageRequest {
    if (gatewayReady) {
        try {
            Events.emit(GATEWAY_EVENT as any, request);
        } catch { }
    }
    if (!request.handled) perform(request);
    return request;
}

export const GameStorage = {
    get<T = any>(key: string): T | undefined {
        return clone(route({ op: "get", key }).result as T | undefined);
    },

    set(key: string, value: any): void {
        route({ op: "set", key, value });
    },

    remove(key: string): void {
        route({ op: "remove", key });
    },

    clear(): void {
        route({ op: "clear" });
    },
};
