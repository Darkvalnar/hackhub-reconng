import { ModSettings } from "@hotbunny/hackhub-content-sdk";

export const DEMO_CONTENT_SETTING_KEY = "demoContent";

let enabled = false;

const MOD_ID = "recon-ng";

/**
 * The runtime points ModSettings at a mod only after that mod's quests, websites and commands
 * have been registered, and registration copies Name off a single instance and never reads it
 * again. A setting read from a registered class therefore resolves against another mod's
 * namespace. Pointing ModSettings at this mod first makes the value readable at any time.
 */
export function readDemoContentSetting(): boolean {
    try {
        (ModSettings as { __setCurrentModId__?: (modId: string) => void })
            .__setCurrentModId__?.(MOD_ID);
        return ModSettings.get<boolean>(DEMO_CONTENT_SETTING_KEY) === true;
    } catch {
        return false;
    }
}

/**
 * ModSettings resolves against a mod id that later loads overwrite, so reading it from a quest
 * callback or other deferred context silently falls back to the default. Read once during load.
 */
export function initDemoContent(): void {
    try {
        enabled = readDemoContentSetting();
    } catch (error) {
        console.warn("[recon-ng] Practice targets setting could not be read", error);
        enabled = false;
    }
}

/** Checked inside each register function, so no caller can stand up practice content around it. */
export function isDemoContentEnabled(): boolean {
    return enabled;
}
