export interface AccessCommand {
    name: string;
    kind: "list" | "read";
    path: string;
    description?: string;
}

export interface AccessProfile {
    id: string;
    role: string;
    commands: AccessCommand[];
}

const profiles = new Map<string, AccessProfile>();

export function registerAccessProfile(profile: AccessProfile): void {
    profiles.set(profile.id.toLowerCase(), profile);
}

export function getAccessProfile(id: string): AccessProfile | undefined {
    return profiles.get(id.toLowerCase());
}

export function clearAccessProfiles(): void {
    profiles.clear();
}

const BUILT_IN_PROFILES: AccessProfile[] = [
    {
        id: "memory-leak",
        role: "memory-gill",
        commands: [
            { name: "memlist", kind: "list", path: "/mem/fragments", description: "list leaked memory fragments" },
            { name: "readmem", kind: "read", path: "/mem/fragments/memory_leak_{arg}.bin", description: "read a fragment by id" },
        ],
    },
    {
        id: "packet-tap",
        role: "packet-tap",
        commands: [
            { name: "captures", kind: "list", path: "/captures", description: "list captured traffic" },
            { name: "capread", kind: "read", path: "/captures/{arg}.pcap.txt", description: "read a captured stream" },
        ],
    },
    {
        id: "firmware-extract",
        role: "firmware-extract",
        commands: [
            { name: "fwlist", kind: "list", path: "/firmware/extracted", description: "list extracted firmware files" },
            { name: "fwread", kind: "read", path: "/firmware/extracted/{arg}.txt", description: "read an extracted file" },
        ],
    },
    {
        id: "process-view",
        role: "process-lantern",
        commands: [
            { name: "ps", kind: "list", path: "/proc", description: "list processes" },
            { name: "penv", kind: "read", path: "/proc/{arg}/env", description: "read a process environment" },
        ],
    },
    {
        id: "route-map",
        role: "route-reef",
        commands: [
            { name: "routes", kind: "list", path: "/var/cache/routes", description: "list cached route maps" },
            { name: "routeread", kind: "read", path: "/var/cache/routes/{arg}.map", description: "read a route map" },
        ],
    },
];

export function registerBuiltInAccessProfiles(): void {
    for (const profile of BUILT_IN_PROFILES) registerAccessProfile(profile);
}
