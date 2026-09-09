import { SharedStorage } from "@hotbunny/hackhub-content-sdk";

// Generic session-control primitives, driven entirely by external content mods
// via SharedStorage. recon-ng knows nothing about *why* a session is being
// terminated or a target locked - it just honours the requests.
//
//   reconng.session.terminations : Array<{ target; message? }>
//       close the active session on a matching target.
//   reconng.session.locks        : Array<{ target; until; message? }>
//       refuse to open new sessions on a matching target until `until` (epoch ms).
//   reconng.target.gates         : Array<{ target; open; message? }>
//       refuse recon/check/session access while `open` is false.
//
// `target` matches the session's ip OR host (case-insensitive).

const TERMINATIONS_KEY = "reconng.session.terminations";
const LOCKS_KEY = "reconng.session.locks";
const TARGET_GATES_KEY = "reconng.target.gates";

interface TerminationRequest {
    target: string;
    message?: string;
}

interface SessionLock {
    target: string;
    until: number;
    message?: string;
}

interface TargetGate {
    target: string;
    open: boolean;
    message?: string;
}

function norm(value: unknown): string {
    return String(value ?? "").trim().toLowerCase();
}

function matches(target: unknown, ip: string, host: string): boolean {
    const t = norm(target);
    return t !== "" && (t === norm(ip) || t === norm(host));
}

export function consumeSessionTermination(ip: string, host: string): { message?: string } | undefined {
    const raw = SharedStorage.get<TerminationRequest[]>(TERMINATIONS_KEY);
    const list = Array.isArray(raw) ? raw : [];
    const index = list.findIndex((request) => matches(request?.target, ip, host));
    if (index < 0) return undefined;

    const [hit] = list.splice(index, 1);
    SharedStorage.set(TERMINATIONS_KEY, list);
    return { message: hit?.message };
}

export function getActiveSessionLock(ip: string, host: string): { until: number; message?: string } | undefined {
    const raw = SharedStorage.get<SessionLock[]>(LOCKS_KEY);
    const list = Array.isArray(raw) ? raw : [];
    const now = Date.now();

    const active = list.filter((lock) => Number(lock?.until) > now);
    if (active.length !== list.length) SharedStorage.set(LOCKS_KEY, active);

    const hit = active.find((lock) => matches(lock?.target, ip, host));
    return hit ? { until: Number(hit.until), message: hit.message } : undefined;
}

export function getClosedTargetGate(ip: string, host: string): { message?: string } | undefined {
    const raw = SharedStorage.get<TargetGate[]>(TARGET_GATES_KEY);
    const list = Array.isArray(raw) ? raw : [];
    const hit = list.find((gate) => gate?.open === false && matches(gate?.target, ip, host));
    return hit ? { message: hit.message } : undefined;
}
