import { Events, type QuestEvents } from "@hotbunny/hackhub-content-sdk";

export interface ReconNgEventMap {
    "ReconNg.Breach.SessionOpened": {
        sessionId: string;
        ip: string;
        host: string;
        moduleId: string;
        privilege: string;
        access: string;
        via?: "forward" | "reverse";
        desktop?: { os: "linux" | "windows"; profile: string; label?: string; hwid: string; opened: boolean };
    };
    "ReconNg.Breach.DesktopOpened": {
        sessionId: string;
        ip: string;
        host: string;
        moduleId: string;
        os: "linux" | "windows";
        profile: string;
        label?: string;
        hwid: string;
    };
    "ReconNg.Breach.DirListed":     { sessionId: string; ip: string; host: string; path: string };
    "ReconNg.Breach.FileRead":      { sessionId: string; ip: string; host: string; path: string; name: string };
    "ReconNg.Breach.FileDownloaded":{ sessionId: string; ip: string; host: string; path: string; name: string; localPath: string };
    "ReconNg.Breach.FileDeleted":   { sessionId: string; ip: string; host: string; path: string; name: string };
    "ReconNg.Breach.Shutdown":      { sessionId: string; ip: string; host: string };
    "ReconNg.Breach.SessionClosed": { sessionId: string; ip: string; host: string; reason: string };
    "ReconNg.UserEnum.Complete":    { ip: string; host: string; moduleId: string; users: string[] };
}

export const ReconNgEvents = {
    emit<K extends keyof ReconNgEventMap>(name: K, payload: ReconNgEventMap[K]): void {
        Events.emit(name as any, payload as any);
    },

    on<K extends keyof ReconNgEventMap>(name: K, handler: (payload: ReconNgEventMap[K]) => void): void {
        Events.on(name as any, handler as any);
    },

    questOn<K extends keyof ReconNgEventMap>(
        events: QuestEvents,
        name: K,
        handler: (payload: ReconNgEventMap[K]) => void,
    ): () => void {
        return events.on(name as any, handler as any);
    },
};
