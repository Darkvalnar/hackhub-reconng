import { Events, Network, Random, SharedStorage } from "@hotbunny/hackhub-content-sdk";
import { GameStorage as Storage } from "./ReconNgStorage";
import {
    armReverseListener,
    checkReverseListenerNetwork,
    clearArmedReverseListener,
    findReversePayload,
    getArmedReverseListener,
    listReversePayloads,
    reverseCallbackUrl,
    type ArmedReverseListener,
    type ReversePayloadDefinition,
} from "./ReversePayloads";

export const REVERSE_LISTENER_REQUEST_EVENT = "ReconNg.ReverseListener.Request.v1";
export const REVERSE_DELIVERY_AVAILABLE_EVENT = "ReconNg.ReverseDelivery.Available.v1";
export const REVERSE_LISTENER_RESPONSES_KEY = "reconng.reverse.listener.responses.v1";

const LISTENER_RESULTS_KEY = "recon-ng.reversePayloads.listenerResults.v1";
const LISTENER_TIMEOUT_MS = 10 * 60 * 1000;
const MAX_RESPONSES = 50;
const MAX_RESULTS = 25;
let registered = false;

export type ReverseListenerState = "listening" | "opened" | "failed" | "cancelled" | "timed_out";

export interface ReverseListenerSnapshot {
    listenerId: string;
    payloadId: string;
    lhost: string;
    lport: number;
    target: string;
    callbackUrl: string;
    state: ReverseListenerState;
    startedAt: number;
    expiresAt: number;
    reason?: string;
    sessionId?: string;
    sessionHost?: string;
}

export interface ReverseListenerApiSnapshot {
    protocol: 1;
    providerId: "recon-ng";
    payloads: ReversePayloadDefinition[];
    suggestedLhost?: string;
    busy: boolean;
    listener?: ReverseListenerSnapshot;
}

export interface ReverseListenerApiResponse {
    requestId: string;
    ok: boolean;
    reason?: string;
    snapshot: ReverseListenerApiSnapshot;
}

interface ReverseListenerRequest {
    requestId?: unknown;
    operation?: unknown;
    listenerId?: unknown;
    payloadId?: unknown;
    lhost?: unknown;
    lport?: unknown;
    target?: unknown;
}

function results(): ReverseListenerSnapshot[] {
    const raw = Storage.get<unknown>(LISTENER_RESULTS_KEY);
    return Array.isArray(raw) ? raw as ReverseListenerSnapshot[] : [];
}

function saveResult(result: ReverseListenerSnapshot): void {
    Storage.set(LISTENER_RESULTS_KEY, [
        ...results().filter((entry) => entry.listenerId !== result.listenerId),
        result,
    ].slice(-MAX_RESULTS));
}

function listeningSnapshot(listener: ArmedReverseListener): ReverseListenerSnapshot | undefined {
    if (!listener.listenerId || listener.startedAt === undefined || listener.expiresAt === undefined) return undefined;
    return {
        listenerId: listener.listenerId,
        payloadId: listener.payloadId,
        lhost: listener.lhost,
        lport: listener.lport,
        target: listener.target,
        callbackUrl: reverseCallbackUrl(listener),
        state: "listening",
        startedAt: listener.startedAt,
        expiresAt: listener.expiresAt,
    };
}

function expireListener(): void {
    const listener = getArmedReverseListener();
    const snapshot = listener && listeningSnapshot(listener);
    if (!snapshot || snapshot.expiresAt > Date.now()) return;
    clearArmedReverseListener();
    saveResult({ ...snapshot, state: "timed_out", reason: "listener timed out before a callback arrived." });
}

function currentListener(listenerId?: string): ReverseListenerSnapshot | undefined {
    expireListener();
    const active = getArmedReverseListener();
    const listening = active && listeningSnapshot(active);
    if (listening && (!listenerId || listening.listenerId === listenerId)) return listening;
    if (!listenerId) return undefined;
    return results().find((entry) => entry.listenerId === listenerId);
}

function suggestedLhost(): string | undefined {
    const playerIp = Network.getPlayerIp();
    if (!playerIp || playerIp === "0.0.0.0") return undefined;
    return Network.getSubnet(playerIp)?.lanIp;
}

function snapshot(listenerId?: string): ReverseListenerApiSnapshot {
    expireListener();
    const active = getArmedReverseListener();
    return {
        protocol: 1,
        providerId: "recon-ng",
        payloads: listReversePayloads(),
        suggestedLhost: suggestedLhost(),
        busy: !!active,
        listener: currentListener(listenerId),
    };
}

function publishResponse(response: ReverseListenerApiResponse): void {
    const raw = SharedStorage.get<unknown>(REVERSE_LISTENER_RESPONSES_KEY);
    const responses = Array.isArray(raw) ? raw as ReverseListenerApiResponse[] : [];
    SharedStorage.set(REVERSE_LISTENER_RESPONSES_KEY, [...responses, response].slice(-MAX_RESPONSES));
}

function respond(requestId: string, ok: boolean, reason?: string, listenerId?: string): void {
    publishResponse({ requestId, ok, reason, snapshot: snapshot(listenerId) });
}

function arm(requestId: string, request: ReverseListenerRequest): void {
    const payloadId = String(request.payloadId ?? "").trim();
    const lhost = String(request.lhost ?? "").trim();
    const lport = Number(request.lport);
    const target = String(request.target ?? "").trim();
    const payload = findReversePayload(payloadId);
    if (!payload) return respond(requestId, false, "payload is not installed.");
    if (!target) return respond(requestId, false, "TARGET is required.");
    if (!Number.isInteger(lport) || lport < 1 || lport > 65535) return respond(requestId, false, "LPORT must be between 1 and 65535.");

    expireListener();
    if (getArmedReverseListener()) return respond(requestId, false, "another reverse listener is already active.");

    const listenerId = `listener-${Random.id(12).toLowerCase()}`;
    const startedAt = Date.now();
    const listener: ArmedReverseListener = {
        listenerId,
        payloadId: payload.id,
        lhost,
        lport,
        target,
        startedAt,
        expiresAt: startedAt + LISTENER_TIMEOUT_MS,
    };
    const network = checkReverseListenerNetwork(listener);
    if (!network.ok) return respond(requestId, false, network.reason);

    SharedStorage.set("reconng.reverse.deliveries", []);
    armReverseListener(listener);
    respond(requestId, true, undefined, listenerId);
}

function cancel(requestId: string, listenerId: string): void {
    const listener = getArmedReverseListener();
    const active = listener && listeningSnapshot(listener);
    if (!active || active.listenerId !== listenerId) {
        const previous = currentListener(listenerId);
        return respond(requestId, !!previous, previous ? undefined : "listener was not found.", listenerId);
    }
    clearArmedReverseListener();
    saveResult({ ...active, state: "cancelled", reason: "listener cancelled by its controlling client." });
    respond(requestId, true, undefined, listenerId);
}

export function completeReverseListener(
    listener: ArmedReverseListener,
    outcome: { state: "opened"; sessionId: string; sessionHost: string } | { state: "failed"; reason: string },
): void {
    const active = listeningSnapshot(listener);
    if (!active) return;
    saveResult({ ...active, ...outcome });
}

export function registerReverseListenerApi(): void {
    if (registered) return;
    registered = true;
    Events.on(REVERSE_LISTENER_REQUEST_EVENT as any, (raw: unknown) => {
        const request = raw && typeof raw === "object" ? raw as ReverseListenerRequest : {};
        const requestId = String(request.requestId ?? "").trim();
        if (!requestId) return;
        const operation = String(request.operation ?? "").trim().toLowerCase();
        if (operation === "inspect") return respond(requestId, true);
        if (operation === "arm") return arm(requestId, request);
        const listenerId = String(request.listenerId ?? "").trim();
        if (!listenerId) return respond(requestId, false, "listenerId is required.");
        if (operation === "status") {
            const listener = currentListener(listenerId);
            return respond(requestId, !!listener, listener ? undefined : "listener was not found.", listenerId);
        }
        if (operation === "cancel") return cancel(requestId, listenerId);
        respond(requestId, false, "unsupported listener operation.");
    });
}
