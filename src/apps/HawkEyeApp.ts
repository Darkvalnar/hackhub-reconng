import { App, Events, RegisterApp } from "@hotbunny/hackhub-content-sdk";
import hawkEyeHTML from "./hawkeye.html";
import { BreachBackend, type BreachSession } from "../world/BreachBackend";

interface HawkEyeTargetSummary {
    id: string;
    host: string;
    ip: string;
    os: "linux" | "windows";
    profile: string;
    label: string;
    opened: boolean;
    user: string;
    moduleId: string;
}

interface HawkEyeFileEntry {
    id: string;
    path: string;
    name: string;
    kind: "file" | "folder";
}

interface HawkEyeAppRequest {
    requestId: string;
    action: string;
    args?: unknown[];
}

const HAWKEYE_APP_REQUEST = "ReconNg.HawkEye.AppRequest";
const HAWKEYE_APP_RESULT = "ReconNg.HawkEye.AppResult";

function isHawkEyeSession(session: BreachSession): boolean {
    return !!session.desktop;
}

function summarize(session: BreachSession): HawkEyeTargetSummary {
    const desktop = session.desktop!;
    return {
        id: session.id,
        host: session.host,
        ip: session.ip,
        os: desktop.os,
        profile: desktop.profile,
        label: desktop.label ?? session.host,
        opened: desktop.opened === true,
        user: session.user,
        moduleId: session.moduleId,
    };
}

function displayName(path: string, os: "linux" | "windows"): string {
    if (os === "windows") {
        const drivePath = path.match(/^\/drives\/([a-z])(?:\/(.*))?$/i);
        if (drivePath) {
            const drive = drivePath[1].toUpperCase();
            const rest = String(drivePath[2] ?? "").replace(/\//g, "\\");
            return rest ? `${drive}:\\${rest}` : `${drive}:\\`;
        }
        return path.replace(/^\//, "C:\\").replace(/\//g, "\\");
    }
    return path;
}

function readableFiles(session: BreachSession): string[] {
    const filesystem = session.filesystem ?? {};
    return Object.keys(filesystem).filter((path) => {
        const node = filesystem[path];
        return !!node && node.type === "file" && node.readable !== false;
    });
}

function listHawkEyeTargets(): HawkEyeTargetSummary[] {
    return BreachBackend.listSessions().filter(isHawkEyeSession).map(summarize);
}

function deployHawkEye(sessionId: string) {
    const session = BreachBackend.getSession(sessionId);
    if (!session || !session.desktop) return { ok: false, reason: "No validated ReconNG deployment path." };
    if (session.desktop.opened) return { ok: true, reason: "HAWK EYE already initialized." };
    session.desktop.opened = true;
    session.desktop.openedAt = Date.now();
    BreachBackend.updateSession(session);
    return { ok: true, reason: "HAWK EYE monitor initialized." };
}

function getHawkEyeFiles(sessionId: string): HawkEyeFileEntry[] {
    const session = BreachBackend.getSession(sessionId);
    if (!session || !session.desktop) return [];
    return readableFiles(session).map((path) => ({
        id: path,
        path,
        name: displayName(path, session.desktop!.os),
        kind: "file",
    }));
}

function readHawkEyeFile(sessionId: string, path: string) {
    const session = BreachBackend.getSession(sessionId);
    if (!session || !session.desktop) return { ok: false, reason: "session not found", path, data: "" };
    const file = BreachBackend.read(session, path);
    if (!file) return { ok: false, reason: "file not found", path, data: "" };
    return { ok: true, path: displayName(file.path, session.desktop.os), data: file.data };
}

function hawkEyeAction(action: string, args: unknown[]): unknown {
    switch (action) {
        case "listHawkEyeTargets": return listHawkEyeTargets();
        case "deployHawkEye": return deployHawkEye(String(args[0] ?? ""));
        case "getHawkEyeFiles": return getHawkEyeFiles(String(args[0] ?? ""));
        case "readHawkEyeFile": return readHawkEyeFile(String(args[0] ?? ""), String(args[1] ?? ""));
        default: throw new Error(`Unknown HawkEye app action: ${action}`);
    }
}

/** Keep storage-backed HawkEye work inside Recon-NG's event listener context. */
export function registerHawkEyeAppBridge(): void {
    Events.register(HAWKEYE_APP_REQUEST as any);
    Events.register(HAWKEYE_APP_RESULT as any);
    Events.on(HAWKEYE_APP_REQUEST as any, (request: HawkEyeAppRequest) => {
        try {
            Events.emit(HAWKEYE_APP_RESULT as any, {
                requestId: request.requestId,
                ok: true,
                data: hawkEyeAction(request.action, Array.isArray(request.args) ? request.args : []),
            });
        } catch (error) {
            Events.emit(HAWKEYE_APP_RESULT as any, {
                requestId: request.requestId,
                ok: false,
                error: error instanceof Error ? error.message : String(error),
            });
        }
    });
}

@RegisterApp
export class HawkEyeApp extends App {
    AppName = "hawkeye";
    Title = "HAWK EYE";
    Icon = "./assets/hawkeye-icon.png";
    HTML = hawkEyeHTML;
    DefaultSize = { width: 1180, height: 720 };
    MinSize = { width: 920, height: 560 };
    Unlocked = true;
    Store = {
        title: "HAWK EYE",
        ratings: 4.6,
        description: "Visual remote monitor for validated ReconNG desktop sessions.",
    };

    Exports = {
        listHawkEyeTargets,
        deployHawkEye,
        getHawkEyeFiles,
        readHawkEyeFile,
    };
}
