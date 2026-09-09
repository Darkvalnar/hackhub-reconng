import { Events } from "@hotbunny/hackhub-content-sdk";
import { BreachBackend } from "./BreachBackend";

const HOST_FILE_REQUEST = "ReconNg.HostFiles.Request";
const HOST_FILE_RESULT = "ReconNg.HostFiles.Result";

interface HostFileRequest {
    requestId: string;
    action: string;
    target: string;
}

function hostFileAction(action: string, target: string): unknown {
    switch (action) {
        case "listHostFiles": return BreachBackend.listHostFiles(target);
        case "wipeHostFiles": return BreachBackend.wipeHostFiles(target);
        case "encryptHostFiles": return BreachBackend.encryptHostFiles(target);
        case "decryptHostFiles": return BreachBackend.decryptHostFiles(target);
        case "clearDeletedPaths": return BreachBackend.clearDeletedPaths(target);
        default: throw new Error(`Unknown host file action: ${action}`);
    }
}

/** Lets other mods read and wipe a breached host's files without holding a session. */
export function registerHostFileBridge(): void {
    Events.register(HOST_FILE_REQUEST as any);
    Events.register(HOST_FILE_RESULT as any);
    Events.on(HOST_FILE_REQUEST as any, (request: HostFileRequest) => {
        try {
            Events.emit(HOST_FILE_RESULT as any, {
                requestId: request.requestId,
                ok: true,
                data: hostFileAction(request.action, String(request.target ?? "")),
            });
        } catch (error) {
            Events.emit(HOST_FILE_RESULT as any, {
                requestId: request.requestId,
                ok: false,
                error: error instanceof Error ? error.message : String(error),
            });
        }
    });
}
