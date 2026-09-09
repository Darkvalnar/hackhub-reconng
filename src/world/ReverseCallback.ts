import { SharedStorage, UI } from "@hotbunny/hackhub-content-sdk";
import { BreachBackend } from "./BreachBackend";
import {
    checkReverseListenerNetwork,
    clearArmedReverseListener,
    findReversePayload,
    getArmedReverseListener,
    getReverseTarget,
    reverseCallbackUrl,
} from "./ReversePayloads";

const SET_DELIVERIES_KEY = "reconng.reverse.deliveries";
const SET_BURNED_LURES_KEY = "reconng.reverse.burnedlures";

function burnLure(email: string, lureId?: string): void {
    const id = String(lureId ?? "").trim().toLowerCase();
    const target = String(email ?? "").trim().toLowerCase();
    if (!id || !target) return;
    try {
        const raw = SharedStorage.get<any[]>(SET_BURNED_LURES_KEY);
        const list = Array.isArray(raw) ? raw : [];
        const exists = list.some(
            (entry) =>
                String(entry?.email ?? "").trim().toLowerCase() === target &&
                String(entry?.lureId ?? "").trim().toLowerCase() === id,
        );
        if (exists) return;
        list.push({ email: target, lureId: id, t: Date.now() });
        SharedStorage.set(SET_BURNED_LURES_KEY, list);
    } catch {
        // Burn tracking is best-effort; never block the callback path.
    }
}

export function clearReverseDeliveries(): void {
    SharedStorage.set(SET_DELIVERIES_KEY, []);
}

// Provider mods write completed deliveries to SharedStorage. Recon-NG drains them
// on console launch and while a listener is armed.
export function consumeReverseDeliveries(): void {
    const raw = SharedStorage.get<any[]>(SET_DELIVERIES_KEY);
    if (!Array.isArray(raw) || raw.length === 0) return;
    for (const delivery of raw) {
        attemptReverseCallback({
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
        });
    }
    SharedStorage.set(SET_DELIVERIES_KEY, []);
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

export function attemptReverseCallback(delivery: ReverseDelivery): void {
    const armed = getArmedReverseListener();
    if (!armed) return;

    const email = delivery.email.trim().toLowerCase();
    const targetKey = armed.target.trim().toLowerCase();

    const matchesTarget =
        !!targetKey &&
        (targetKey === email ||
            targetKey === String(delivery.id ?? "").toLowerCase() ||
            targetKey === String(delivery.name ?? "").toLowerCase());
    if (!matchesTarget) return;

    const payload = findReversePayload(armed.payloadId);
    if (!payload) return;

    const target = getReverseTarget(email);
    if (!target) {
        UI.notify("Callback failed: no reachable host is tied to that target.");
        clearArmedReverseListener();
        return;
    }

    if (!affinityMatches(payload.affinities, delivery)) {
        UI.notify(`Callback failed: that payload doesn't fit this target. No session.`);
        clearArmedReverseListener();
        return;
    }

    const outcome = delivery.lureOutcome ?? "success";
    if (outcome === "not_interested") {
        UI.notify("No callback. The target read it and moved on.");
        clearArmedReverseListener();
        return;
    }
    if (outcome === "bounce") {
        burnLure(email, delivery.lureId);
        UI.notify("No callback. That pretext put them on guard - it will not work on them again.");
        clearArmedReverseListener();
        return;
    }

    const callbackUrl = reverseCallbackUrl(armed);
    if (!String(delivery.messageBody ?? "").includes(callbackUrl)) {
        UI.notify("Callback failed: the delivered message did not contain this listener's callback URL.");
        clearArmedReverseListener();
        return;
    }

    const network = checkReverseListenerNetwork(armed);
    if (!network.ok) {
        UI.notify(`Callback failed: ${network.reason ?? "the listener is no longer reachable."}`);
        clearArmedReverseListener();
        return;
    }

    const opened = BreachBackend.openReverseSession(target.ip, {
        user: target.username,
        tier: target.tier,
        payloadId: payload.id,
        desktop: target.desktop,
    });
    if (!opened.ok) {
        UI.notify(`Callback failed: ${opened.reason}`);
        return;
    }

    clearArmedReverseListener();
    UI.notify(`Callback received - session ${opened.session.id} opened on ${opened.session.host}.`);
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
