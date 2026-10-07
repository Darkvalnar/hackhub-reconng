import { Events, SharedStorage } from "@hotbunny/hackhub-content-sdk";
import { BreachBackend } from "./BreachBackend";
import { completeReverseListener, REVERSE_DELIVERY_AVAILABLE_EVENT } from "./ReverseListenerApi";
import {
    checkReverseListenerNetwork,
    clearArmedReverseListener,
    findReversePayload,
    getArmedReverseListener,
    getReverseTarget,
    reverseCallbackUrl,
    type ArmedReverseListener,
} from "./ReversePayloads";

const REVERSE_DELIVERIES_KEY = "reconng.reverse.deliveries";
const REVERSE_BURNED_LURES_KEY = "reconng.reverse.burnedlures";
let deliverySignalRegistered = false;

function burnLure(email: string, lureId?: string): void {
    const id = String(lureId ?? "").trim().toLowerCase();
    const target = String(email ?? "").trim().toLowerCase();
    if (!id || !target) return;
    try {
        const raw = SharedStorage.get<any[]>(REVERSE_BURNED_LURES_KEY);
        const list = Array.isArray(raw) ? raw : [];
        const exists = list.some(
            (entry) =>
                String(entry?.email ?? "").trim().toLowerCase() === target &&
                String(entry?.lureId ?? "").trim().toLowerCase() === id,
        );
        if (exists) return;
        list.push({ email: target, lureId: id, t: Date.now() });
        SharedStorage.set(REVERSE_BURNED_LURES_KEY, list);
    } catch {
        // Burn tracking is best-effort; never block the callback path.
    }
}

export function clearReverseDeliveries(): void {
    SharedStorage.set(REVERSE_DELIVERIES_KEY, []);
}

// Provider mods write completed deliveries to SharedStorage. Recon-NG drains them
// on console launch, from an interactive listener, or after the documented signal.
export type ReverseCallbackResult =
    | { status: "ignored" }
    | { status: "opened"; sessionId: string; sessionHost: string }
    | { status: "failed"; reason: string };

export function consumeReverseDeliveries(): ReverseCallbackResult[] {
    const raw = SharedStorage.get<any[]>(REVERSE_DELIVERIES_KEY);
    if (!Array.isArray(raw) || raw.length === 0) return [];
    const results: ReverseCallbackResult[] = [];
    for (const delivery of raw) {
        results.push(attemptReverseCallback({
            email: String(delivery?.email ?? ""),
            role: String(delivery?.role ?? ""),
            id: delivery?.id != null ? String(delivery.id) : undefined,
            name: delivery?.name != null ? String(delivery.name) : undefined,
            lureId: delivery?.lureId != null ? String(delivery.lureId) : undefined,
            lureLabel: delivery?.lureLabel != null ? String(delivery.lureLabel) : undefined,
            lureDescription: delivery?.lureDescription != null ? String(delivery.lureDescription) : undefined,
            lureTags: Array.isArray(delivery?.lureTags) ? delivery.lureTags.map((tag: unknown) => String(tag)) : undefined,
            lureOutcome: delivery?.lureOutcome != null ? String(delivery.lureOutcome) as ReverseLureOutcome : undefined,
            messageBody: delivery?.messageBody != null ? String(delivery.messageBody) : undefined,
        }));
    }
    SharedStorage.set(REVERSE_DELIVERIES_KEY, []);
    return results;
}

export function registerReverseDeliverySignal(): void {
    if (deliverySignalRegistered) return;
    deliverySignalRegistered = true;
    Events.on(REVERSE_DELIVERY_AVAILABLE_EVENT as any, () => {
        if (!getArmedReverseListener()?.listenerId) return;
        consumeReverseDeliveries();
    });
}

/**
 * A provider delivery that could satisfy an armed reverse listener.
 */
export type ReverseLureOutcome = "success" | "not_interested" | "bounce";

export interface ReverseDelivery {
    email: string;
    role: string;
    id?: string;
    name?: string;
    lureId?: string;
    lureLabel?: string;
    lureDescription?: string;
    lureTags?: string[];
    lureOutcome?: ReverseLureOutcome;
    messageBody?: string;
}

export function attemptReverseCallback(delivery: ReverseDelivery): ReverseCallbackResult {
    const armed = getArmedReverseListener();
    if (!armed) return { status: "ignored" };

    const email = delivery.email.trim().toLowerCase();
    const targetKey = armed.target.trim().toLowerCase();

    const matchesTarget =
        !!targetKey &&
        (targetKey === email ||
            targetKey === String(delivery.id ?? "").toLowerCase() ||
            targetKey === String(delivery.name ?? "").toLowerCase());
    if (!matchesTarget) return { status: "ignored" };

    const payload = findReversePayload(armed.payloadId);
    if (!payload) return fail(armed, "the selected payload is no longer installed.");

    const target = getReverseTarget(email);
    if (!target) {
        return fail(armed, "no reachable host is tied to that target.");
    }

    if (!affinityMatches(payload.affinities, delivery)) {
        return fail(armed, "that payload does not fit the delivered pretext.");
    }

    const outcome = delivery.lureOutcome ?? "success";
    if (outcome === "not_interested") {
        return fail(armed, "the target read the message and did not interact with the payload.");
    }
    if (outcome === "bounce") {
        burnLure(email, delivery.lureId);
        return fail(armed, "the pretext was rejected and is now burned for this target.");
    }

    const callbackUrl = reverseCallbackUrl(armed);
    if (!String(delivery.messageBody ?? "").includes(callbackUrl)) {
        return fail(armed, "the delivered message did not resolve to this listener's callback URL.");
    }

    const network = checkReverseListenerNetwork(armed);
    if (!network.ok) {
        return fail(armed, network.reason ?? "the listener is no longer reachable.");
    }

    const opened = BreachBackend.openReverseSession(target.ip, {
        user: target.username,
        tier: target.tier,
        payloadId: payload.id,
        desktop: target.desktop,
    });
    if (!opened.ok) {
        return fail(armed, opened.reason);
    }

    completeReverseListener(armed, { state: "opened", sessionId: opened.session.id, sessionHost: opened.session.host });
    clearArmedReverseListener();
    return { status: "opened", sessionId: opened.session.id, sessionHost: opened.session.host };
}

function fail(listener: ArmedReverseListener, reason: string): ReverseCallbackResult {
    completeReverseListener(listener, { state: "failed", reason });
    clearArmedReverseListener();
    return { status: "failed", reason };
}

function affinityMatches(affinities: string[], delivery: ReverseDelivery): boolean {
    const lureContext = [
        delivery.lureId,
        delivery.lureLabel,
        ...(delivery.lureTags ?? []),
    ].map(normalize).filter(Boolean);

    if (lureContext.length > 0) {
        return affinities.some((affinity) => contextMatchesAffinity(lureContext, affinity, false));
    }

    const roleContext = [delivery.role].map(normalize).filter(Boolean);
    return affinities.some((affinity) => contextMatchesAffinity(roleContext, affinity, true));
}

function normalize(value: unknown): string {
    return String(value ?? "").trim().toLowerCase();
}

function contextMatchesAffinity(context: string[], affinity: string, allowSingleWordFallback: boolean): boolean {
    const aff = normalize(affinity);
    if (!aff) return false;
    if (context.some((item) => item === aff || item.includes(aff))) return true;

    const words = aff.split(/\s+/).filter((word) => word.length > 3);
    if (words.length === 0) return false;
    if (context.some((item) => words.every((word) => item.includes(word)))) return true;
    return allowSingleWordFallback && context.some((item) => words.some((word) => item.includes(word)));
}
