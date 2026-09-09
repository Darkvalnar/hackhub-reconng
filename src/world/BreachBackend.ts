import { Network, Random, SharedStorage, Shell, type SubnetInfo } from "@hotbunny/hackhub-content-sdk";
import { GameStorage as Storage } from "./ReconNgStorage";
import { ReconNgEvents } from "./ReconNgEvents";
import { getActiveSessionLock, getClosedTargetGate } from "./SessionControl";

export type BreachPrivilege = "guest" | "user" | "www-data" | "root";
export type DesktopOs = "linux" | "windows";

export interface DesktopProfile {
    os: DesktopOs;
    profile: string;
    label?: string;
}

export interface DesktopSession extends DesktopProfile {
    hwid: string;
    opened: boolean;
    openedAt?: number;
    sourceModuleId?: string;
}

export interface BreachModule {
    id: string;
    name: string;
    family: "exploit" | "auxiliary" | "post";
    service: string;
    port?: number;
    requiresRport?: boolean;
    requiresUser?: boolean;
    requiresWordlist?: boolean;
    versions?: string[];
    vulnerabilities?: string[];
    privilege: BreachPrivilege;
    description: string;
    locked?: boolean;
    price?: number;
    access?: string;
    desktop?: DesktopProfile;
}

export interface BreachFile {
    path: string;
    data: string;
    readable?: boolean;
    downloadable?: boolean;
    deletable?: boolean;
}

export interface WordlistSpec {
    name: string;
    tier: number;
    entries: number;
}

export const BASE_WORDLIST: WordlistSpec = { name: "wordlist.lst", tier: 1, entries: 14344 };

export type UserEnumObservationProfile =
    | "preauth"
    | "timing"
    | "auth-methods"
    | "keyboard-interactive"
    | "key-parse";

export interface UserEnumObservation {
    profile: UserEnumObservationProfile | "custom";
    summary: string;
    detail?: string;
}

export interface UserEnumTarget {
    target: string;
    users: string[];
    service?: string;
    port?: number;
    observationProfile?: UserEnumObservationProfile;
    observation?: string;
    /** Legacy custom observation text. Prefer observation. */
    note?: string;
}

export interface BreachNode {
    type: "dir" | "file";
    data?: string;
    readable?: boolean;
    downloadable?: boolean;
    deletable?: boolean;
}

export interface BreachSession {
    id: string;
    target: string;
    ip: string;
    host: string;
    moduleId: string;
    privilege: BreachPrivilege;
    user: string;
    cwd: string;
    openedAt: number;
    access: string;
    desktop?: DesktopSession;
    filesystem: Record<string, BreachNode>;
}

interface BreachState {
    sessions: BreachSession[];
    overlays: Record<string, BreachFile[]>;
    deletedPaths?: Record<string, string[]>;
    encryptedPaths?: Record<string, string[]>;
    customModules?: BreachModule[];
    ownedModuleIds?: string[];
    wordlists?: WordlistSpec[];
    wordlistGrants?: string[];
    wordlistGates?: Record<string, number>;
    userEnumTargets?: UserEnumTarget[];
    nextSessionId: number;
    schemaVersion?: number;
}

export interface BreachResolvedTarget {
    subnet: SubnetInfo;
    ip: string;
    host: string;
    ports: Array<{
        external?: number;
        port?: number;
        internal?: number;
        active?: boolean;
        service?: string;
        version?: string;
        status?: string;
    }>;
    vulnerabilities: string[];
    users: string[];
}

const STATE_KEY = "recon-ng.breachBackend.state";
const EXTERNAL_MODULES_KEY = "reconng.modules";
const SHARED_LOOT_KEY = "reconng.loot";
const STATE_SCHEMA_VERSION = 2;

export const BREACH_MODULES: BreachModule[] = [
    {
        id: "exploit/unix/ftp/vsftpd_234_backdoor",
        name: "VSFTPD 2.3.x backdoor command channel",
        family: "exploit",
        service: "ftp",
        port: 21,
        versions: ["vsftpd 2.3.5", "vsftpd 2.3.4"],
        vulnerabilities: ["RCE"],
        privilege: "root",
        description: "Abuses a backdoor handler in old vsftpd builds to open a root shell.",
    },
    {
        id: "exploit/ftp/ftp_brute",
        name: "FTP Brute",
        family: "exploit",
        service: "ftp",
        port: 21,
        requiresUser: true,
        requiresWordlist: true,
        privilege: "user",
        description: "Brute-forces an FTP account against a supplied wordlist, opening a shell as that user once a password is recovered.",
    },
    {
        id: "exploit/printer/raw_spool_9100",
        name: "RAW print spool driver fault",
        family: "exploit",
        service: "printer",
        port: 9100,
        privilege: "root",
        description: "Leverages a binary fault in RAW print spool drivers exposed on port 9100.",
    },
    {
        id: "exploit/unix/ftp/proftpd_modcopy",
        name: "ProFTPD mod_copy file write",
        family: "exploit",
        service: "ftp",
        port: 21,
        versions: ["ProFTPD 1.3.5", "proftpd 1.3.5"],
        vulnerabilities: ["RCE", "LFI"],
        privilege: "user",
        description: "Uses mod_copy path handling to stage files outside the FTP root.",
    },
    {
        id: "exploit/http/nginx_chunked_size",
        name: "Nginx chunked size overflow",
        family: "exploit",
        service: "http",
        port: 80,
        versions: ["nginx 1.18.0", "nginx 1.18"],
        vulnerabilities: ["RCE"],
        privilege: "www-data",
        description: "Targets vulnerable chunked transfer parsing in exposed nginx workers.",
    },
    {
        id: "exploit/http/nginx_alias_traversal",
        name: "Nginx alias traversal disclosure",
        family: "exploit",
        service: "http",
        port: 80,
        versions: ["nginx 1.16", "nginx 1.17", "nginx 1.18", "nginx 1.20"],
        vulnerabilities: ["LFI"],
        privilege: "www-data",
        description: "Reads files exposed by unsafe alias path normalization.",
    },
    {
        id: "exploit/http/apache_path_traversal",
        name: "Apache path traversal file disclosure",
        family: "exploit",
        service: "http",
        port: 80,
        versions: ["Apache 2.4.49", "Apache/2.4.49"],
        vulnerabilities: ["LFI", "RCE"],
        privilege: "www-data",
        description: "Uses a traversal bug to read application files and, on weak hosts, execute helpers.",
    },
    {
        id: "exploit/http/apache_cgi_shellshock",
        name: "Apache CGI shellshock environment injection",
        family: "exploit",
        service: "http",
        port: 80,
        versions: ["Apache", "Apache/2", "Apache 2"],
        vulnerabilities: ["RCE"],
        privilege: "www-data",
        description: "Targets exposed CGI handlers that pass attacker-controlled headers into bash.",
    },
    {
        id: "exploit/webapp/php_include",
        name: "PHP remote include loader",
        family: "exploit",
        service: "http",
        port: 80,
        vulnerabilities: ["RFI", "RCE"],
        privilege: "www-data",
        description: "Loads a remote PHP helper through an unsafe include parameter.",
    },
    {
        id: "exploit/webapp/php_lfi_log_poison",
        name: "PHP local include log poison",
        family: "exploit",
        service: "http",
        port: 80,
        vulnerabilities: ["LFI"],
        privilege: "www-data",
        description: "Combines local file inclusion with poisoned access logs to obtain a shell.",
    },
    {
        id: "exploit/webapp/ssrf_metadata_leak",
        name: "SSRF metadata credential leak",
        family: "exploit",
        service: "http",
        port: 80,
        vulnerabilities: ["SSRF"],
        privilege: "user",
        description: "Abuses server-side fetch behavior to read local metadata and service credentials.",
    },
    {
        id: "exploit/webapp/cors_token_grab",
        name: "CORS credential reflection token grab",
        family: "exploit",
        service: "http",
        port: 80,
        vulnerabilities: ["CORS", "XSS"],
        privilege: "user",
        description: "Uses permissive CORS and a reflected page to pull browser-scoped session material.",
    },
    {
        id: "exploit/webapp/tomcat_manager_upload",
        name: "Tomcat manager WAR upload",
        family: "exploit",
        service: "http",
        port: 8080,
        versions: ["Tomcat", "Apache Tomcat"],
        vulnerabilities: ["RCE"],
        privilege: "www-data",
        description: "Uploads a small WAR helper through an exposed manager interface.",
    },
    {
        id: "exploit/ssh/weak_maintenance_key",
        name: "OpenSSH weak maintenance key",
        family: "exploit",
        service: "ssh",
        port: 22,
        versions: ["OpenSSH", "openssh"],
        vulnerabilities: ["RCE"],
        privilege: "user",
        description: "Checks for old maintenance key material and opens a restricted shell.",
    },
    {
        id: "auxiliary/scanner/ssh/user_enum",
        name: "SSH username enumeration probe",
        family: "auxiliary",
        service: "ssh",
        port: 22,
        versions: ["OpenSSH", "Dropbear", "libssh"],
        privilege: "guest",
        access: "user-enum",
        description: "Probes an SSH service for account-name response differences. Effective against certain OpenSSH, Dropbear, and libssh builds, and only against targets explicitly exposed to enumeration.",
    },
    {
        id: "exploit/database/mysql_udf_loader",
        name: "MySQL UDF loader",
        family: "exploit",
        service: "database",
        port: 3306,
        versions: ["MySQL", "MariaDB"],
        vulnerabilities: ["RCE", "SQL_INJECTION"],
        privilege: "user",
        description: "Uses writable plugin paths to load a command helper through the database service.",
    },
    {
        id: "exploit/cache/redis_unauth_write",
        name: "Redis unauthenticated config write",
        family: "exploit",
        service: "redis",
        port: 6379,
        versions: ["Redis"],
        vulnerabilities: ["RCE"],
        privilege: "user",
        description: "Writes controlled content through an unauthenticated Redis service.",
    },
    {
        id: "exploit/smb/samba_usermap_script",
        name: "Samba username map script execution",
        family: "exploit",
        service: "smb",
        port: 445,
        versions: ["Samba 3.0", "samba 3.0"],
        vulnerabilities: ["RCE"],
        privilege: "root",
        description: "Triggers command execution through unsafe username mapping.",
    },
    {
        id: "exploit/mail/postfix_pipe_escape",
        name: "Postfix pipe command escape",
        family: "exploit",
        service: "smtp",
        port: 25,
        versions: ["Postfix"],
        vulnerabilities: ["RCE"],
        privilege: "user",
        description: "Abuses a misconfigured pipe transport to write and execute a helper.",
    },
];

export const POST_MODULES: BreachModule[] = [
    {
        id: "post/multi/gui/desktop_implant",
        name: "Remote desktop implant",
        family: "post",
        service: "post",
        privilege: "guest",
        access: "desktop",
        description: "Drops a desktop implant, upgrading the session to a full desktop.",
    },
    {
        id: "post/loot/passwd_dump",
        name: "passwd hash dump",
        family: "post",
        service: "post",
        privilege: "guest",
        access: "passwd-dump",
        description: "Reads /etc/passwd from the current session and prints hash material for cracking.",
    },
];

function getState(): BreachState {
    const stored = Storage.get<BreachState>(STATE_KEY);
    if (!stored) return { sessions: [], overlays: {}, nextSessionId: 1 };
    if ((stored.schemaVersion ?? 1) < STATE_SCHEMA_VERSION) {
        // v1 copied every shared loot overlay into SaveStorage. Generated worlds
        // can publish thousands of entries, which bloats cloud-save payloads.
        stored.overlays = {};
        stored.schemaVersion = STATE_SCHEMA_VERSION;
        Storage.set(STATE_KEY, stored);
    }
    if (!stored.overlays) stored.overlays = {};
    if (!stored.sessions) stored.sessions = [];
    if (!stored.nextSessionId) stored.nextSessionId = 1;
    return stored;
}

function setState(state: BreachState): void {
    Storage.set(STATE_KEY, state);
}

function getExistingState(): BreachState | null {
    if (!Storage.get<BreachState>(STATE_KEY)) return null;
    return getState();
}

function normalizeTarget(input: string): string {
    return input.replace(/^https?:\/\//i, "").replace(/\/.*$/, "").trim().toLowerCase();
}

function normalizePath(path: string, cwd = "/"): string {
    const raw = path.startsWith("/") ? path : `${cwd.replace(/\/$/, "")}/${path}`;
    const parts: string[] = [];
    for (const part of raw.split("/")) {
        if (!part || part === ".") continue;
        if (part === "..") parts.pop();
        else parts.push(part);
    }
    return `/${parts.join("/")}`;
}

function parentPath(path: string): string {
    const normalized = normalizePath(path);
    if (normalized === "/") return "/";
    const idx = normalized.lastIndexOf("/");
    return idx <= 0 ? "/" : normalized.slice(0, idx);
}

function baseName(path: string): string {
    const normalized = normalizePath(path);
    if (normalized === "/") return "/";
    return normalized.slice(normalized.lastIndexOf("/") + 1);
}

function portNumber(port: { external?: number; port?: number }): number | undefined {
    return port.external ?? port.port;
}

function portActive(port: { active?: boolean; status?: string }): boolean {
    if (typeof port.active === "boolean") return port.active;
    return String(port.status ?? "").toUpperCase() === "OPEN";
}

function matchesVersion(actual: string | undefined, accepted: string[] | undefined): boolean {
    if (!accepted || accepted.length === 0) return true;
    const normalized = String(actual ?? "").toLowerCase();
    return accepted.some((candidate) => normalized.includes(candidate.toLowerCase()));
}

/**
 * Port the exploit will attempt:
 * - player RPORT if set
 * - else the module's classic port (e.g. 22 for SSH)
 * Never invent a non-classic external from the target when RPORT is unset.
 */
function effectiveAttemptPort(module: BreachModule, rport?: number): number | undefined {
    return rport ?? module.port;
}

/**
 * Active port rows the module may run against for this attempt port.
 * - Default (RPORT unset / equals module.port): external must equal the classic module.port.
 * - Remapped (RPORT set to a different external): that external must be active. When a
 *   richer port record includes `internal`, it must equal module.port. The shipped SDK's
 *   SubnetInfo deliberately exposes only `{ port, service, version, active }`, so a module
 *   cannot require an internal mapping that the bridge never publishes.
 */
function portMatchesAttempt(
    port: { external?: number; port?: number; internal?: number; active?: boolean; status?: string; service?: string; version?: string },
    module: BreachModule,
    attemptPort: number,
): boolean {
    if (!portActive(port)) return false;
    if (!servicesCompatible(port.service, module.service)) return false;
    if (!matchesVersion(port.version, module.versions)) return false;

    const exposed = portNumber(port);
    if (exposed !== attemptPort) return false;

    if (module.port !== undefined && attemptPort !== module.port) {
        return typeof port.internal !== "number" || port.internal === module.port;
    }

    return true;
}

function servicesCompatible(actual: string | undefined, expected: string): boolean {
    const service = String(actual ?? "").toLowerCase();
    const moduleService = expected.toLowerCase();
    if (service === moduleService) return true;
    if (moduleService === "http") return service === "https" || service === "web";
    if (moduleService === "database") return service === "mysql" || service === "mariadb" || service === "postgres";
    if (moduleService === "printer") return service === "jetdirect" || service === "raw" || service === "raw-print" || service === "pjl";
    return false;
}

function targetKeys(target: { ip?: string; host?: string }): string[] {
    return [target.ip, target.host].map((value) => normalizeTarget(String(value ?? ""))).filter(Boolean);
}

function findUserEnumTarget(target: BreachResolvedTarget, state = getState()): UserEnumTarget | undefined {
    const keys = targetKeys(target);
    return (state.userEnumTargets ?? []).find((record) => keys.includes(normalizeTarget(record.target)));
}

function stableHash(value: string): number {
    let hash = 2166136261;
    for (let index = 0; index < value.length; index += 1) {
        hash ^= value.charCodeAt(index);
        hash = Math.imul(hash, 16777619);
    }
    return hash >>> 0;
}

function userEnumProfiles(version: string): UserEnumObservationProfile[] {
    const normalized = version.toLowerCase();
    if (normalized.includes("dropbear")) return ["key-parse", "timing", "preauth"];
    if (normalized.includes("libssh")) return ["auth-methods", "preauth", "timing"];
    return ["preauth", "timing", "keyboard-interactive", "auth-methods"];
}

function userEnumServiceVersion(target: BreachResolvedTarget, record: UserEnumTarget): string {
    const port = record.port ?? 22;
    const service = record.service ?? "ssh";
    const match = target.ports.find((candidate) =>
        portActive(candidate)
        && portNumber(candidate) === port
        && servicesCompatible(candidate.service, service)
    );
    return String(match?.version ?? service);
}

function buildUserEnumObservation(target: BreachResolvedTarget, record: UserEnumTarget, users: string[]): UserEnumObservation {
    const custom = String(record.observation ?? record.note ?? "").trim();
    if (custom) return { profile: "custom", summary: custom };

    const version = userEnumServiceVersion(target, record);
    const seed = stableHash(`${normalizeTarget(target.host)}|${normalizeTarget(target.ip)}|${version.toLowerCase()}|${users.join("|").toLowerCase()}`);
    const profiles = userEnumProfiles(version);
    const profile = record.observationProfile ?? profiles[seed % profiles.length];
    const probes = 5 + (seed % 3);

    switch (profile) {
        case "timing":
            return {
                profile,
                summary: `candidate responses remained outside the control latency band across ${probes} probes.`,
                detail: `median response delta: +${72 + ((seed >>> 5) % 71)} ms.`,
            };
        case "auth-methods":
            return {
                profile,
                summary: "candidate probes advertised publickey,password.",
                detail: "control names advertised password only.",
            };
        case "keyboard-interactive":
            return {
                profile,
                summary: "candidate probes returned a keyboard-interactive prompt.",
                detail: "control names returned no authentication prompt.",
            };
        case "key-parse":
            return {
                profile,
                summary: "candidate probes completed key parsing before rejection.",
                detail: "control names were rejected before key processing.",
            };
        case "preauth":
        default:
            return {
                profile: "preauth",
                summary: `alternate pre-auth failure reproduced across ${probes}/${probes} candidate probes.`,
                detail: "control names were rejected before account lookup.",
            };
    }
}

function moduleMatches(target: BreachResolvedTarget, module: BreachModule, rport?: number): boolean {
    if (module.access === "user-enum" && !findUserEnumTarget(target)) return false;

    const vulnOk = !module.vulnerabilities?.length ||
        module.vulnerabilities.some((vuln) => target.vulnerabilities.includes(vuln));
    if (!vulnOk) return false;

    const attemptPort = effectiveAttemptPort(module, rport);

    // Modules with no classic port and no RPORT: any active service/version match.
    if (attemptPort === undefined) {
        return target.ports.some((port) => {
            if (!portActive(port)) return false;
            if (!servicesCompatible(port.service, module.service)) return false;
            return matchesVersion(port.version, module.versions);
        });
    }

    return target.ports.some((port) => portMatchesAttempt(port, module, attemptPort));
}

function allModules(state = getState()): BreachModule[] {
    const byId = new Map<string, BreachModule>();

    for (const module of [...BREACH_MODULES, ...POST_MODULES, ...(state.customModules ?? []), ...externalModules()]) {
        byId.set(module.id.toLowerCase(), module);
    }

    return [...byId.values()];
}

function isOwned(module: BreachModule, state: BreachState): boolean {
    return !module.locked || (state.ownedModuleIds ?? []).includes(module.id);
}

function ownedModules(state = getState()): BreachModule[] {
    return allModules(state).filter((module) => isOwned(module, state));
}

function exploitModules(state = getState()): BreachModule[] {
    return ownedModules(state).filter((module) => module.family !== "post");
}

function postModulesOwned(state = getState()): BreachModule[] {
    return ownedModules(state).filter((module) => module.family === "post");
}

function readSessionFile(session: BreachSession, path: string): BreachFile | null {
    const node = session.filesystem[normalizePath(path, session.cwd)];
    if (!node || node.type !== "file" || node.readable === false) return null;
    return {
        path: normalizePath(path, session.cwd),
        data: node.data ?? "",
        readable: node.readable,
        downloadable: node.downloadable,
        deletable: node.deletable,
    };
}

function passwdDumpEffects(session: BreachSession): string[] {
    const file = readSessionFile(session, "/etc/passwd");
    if (!file) return [];
    const lines = file.data
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean);
    const hashes = lines
        .map((line) => {
            const [user, hash] = line.split(":");
            if (!user || !hash || hash === "x" || hash === "*" || hash === "!" || hash.length < 8) return "";
            return `${user}:${hash}`;
        })
        .filter(Boolean);
    if (hashes.length === 0) return [];
    return [
        `/etc/passwd hash entries on ${session.host}:`,
        ...hashes,
    ];
}

function passwdHashEntries(session: BreachSession): Array<{ user: string; hash: string }> {
    const file = readSessionFile(session, "/etc/passwd");
    if (!file) return [];
    return file.data
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean)
        .map((line) => {
            const [user, hash] = line.split(":");
            return { user: user ?? "", hash: hash ?? "" };
        })
        .filter((entry) => !!entry.user && !!entry.hash && entry.hash !== "x" && entry.hash !== "*" && entry.hash !== "!" && entry.hash.length >= 8);
}

function passwordMatchesHash(hash: string, password: string): boolean {
    const cracked = Shell.getCommandData("john", hash);
    return String(cracked ?? "") === password;
}

function validateModule(module: BreachModule): string | null {
    if (!module || typeof module !== "object") return "module spec must be an object";
    if (!module.id || typeof module.id !== "string") return "module.id is required";
    if (!module.name || typeof module.name !== "string") return "module.name is required";
    if (!["exploit", "auxiliary", "post"].includes(module.family)) return "module.family must be exploit, auxiliary, or post";
    if (!module.service || typeof module.service !== "string") return "module.service is required";
    if (!["guest", "user", "www-data", "root"].includes(module.privilege)) return "module.privilege is invalid";
    if (!module.description || typeof module.description !== "string") return "module.description is required";
    if (module.port !== undefined && typeof module.port !== "number") return "module.port must be a number";
    if (module.requiresRport !== undefined && typeof module.requiresRport !== "boolean") return "module.requiresRport must be a boolean";
    if (module.requiresUser !== undefined && typeof module.requiresUser !== "boolean") return "module.requiresUser must be a boolean";
    if (module.versions !== undefined && !Array.isArray(module.versions)) return "module.versions must be an array";
    if (module.vulnerabilities !== undefined && !Array.isArray(module.vulnerabilities)) return "module.vulnerabilities must be an array";
    if (module.locked !== undefined && typeof module.locked !== "boolean") return "module.locked must be a boolean";
    if (module.price !== undefined && typeof module.price !== "number") return "module.price must be a number";
    if (module.access !== undefined && typeof module.access !== "string") return "module.access must be a string";
    if (module.desktop !== undefined && typeof module.desktop !== "object") return "module.desktop must be an object";
    if (module.family !== "post" && module.access === "desktop" && !module.desktop) return "module.desktop is required when an exploit grants desktop access";
    if (module.desktop) {
        if (!["linux", "windows"].includes(module.desktop.os)) return "module.desktop.os must be linux or windows";
        if (!module.desktop.profile || typeof module.desktop.profile !== "string") return "module.desktop.profile is required";
        if (module.desktop.label !== undefined && typeof module.desktop.label !== "string") return "module.desktop.label must be a string";
    }
    return null;
}

function isExternalModule(value: unknown): value is BreachModule {
    return validateModule(value as BreachModule) === null;
}

function externalModules(): BreachModule[] {
    const raw = SharedStorage.get<unknown>(EXTERNAL_MODULES_KEY);
    return Array.isArray(raw) ? raw.filter(isExternalModule) : [];
}

function isBreachFile(value: unknown): value is BreachFile {
    if (!value || typeof value !== "object") return false;
    const file = value as Record<string, unknown>;
    return typeof file.path === "string"
        && typeof file.data === "string"
        && (file.readable === undefined || typeof file.readable === "boolean")
        && (file.downloadable === undefined || typeof file.downloadable === "boolean")
        && (file.deletable === undefined || typeof file.deletable === "boolean");
}

function sharedLootForTarget(target: { ip?: string; host?: string }): BreachFile[] {
    const raw = SharedStorage.get<unknown>(SHARED_LOOT_KEY);
    if (!Array.isArray(raw)) return [];
    const keys = new Set(targetKeys(target));
    const files: BreachFile[] = [];

    for (const overlay of raw) {
        if (!overlay || typeof overlay !== "object") continue;
        const record = overlay as Record<string, unknown>;
        if (!keys.has(normalizeTarget(String(record.target ?? "")))) continue;
        if (!Array.isArray(record.files)) continue;
        files.push(...record.files.filter(isBreachFile));
    }

    return files;
}

function createDesktopSession(profile: DesktopProfile, opened: boolean, sourceModuleId?: string): DesktopSession {
    return {
        os: profile.os,
        profile: profile.profile,
        label: profile.label,
        hwid: Random.uuid(),
        opened,
        openedAt: opened ? Date.now() : undefined,
        sourceModuleId,
    };
}

function addDir(fs: Record<string, BreachNode>, path: string): void {
    const normalized = normalizePath(path);
    if (!fs["/"]) fs["/"] = { type: "dir" };
    if (normalized === "/") return;
    let built = "";
    for (const part of normalized.split("/").filter(Boolean)) {
        built += `/${part}`;
        if (!fs[built]) fs[built] = { type: "dir" };
    }
}

function addFile(fs: Record<string, BreachNode>, file: BreachFile): void {
    const path = normalizePath(file.path);
    let parent = parentPath(path);
    const stack: string[] = [];
    while (parent && parent !== "/" && !fs[parent]) {
        stack.unshift(parent);
        parent = parentPath(parent);
    }
    addDir(fs, "/");
    for (const dir of stack) addDir(fs, dir);
    fs[path] = {
        type: "file",
        data: file.data,
        readable: file.readable ?? true,
        downloadable: file.downloadable ?? true,
        deletable: file.deletable ?? false,
    };
}

const ACCESS_LOG_PATH = "/var/log/access.log";
const ACCESS_LOG_MAX_LINES = 200;
const ACCESS_LOG_TRIM_NOTICE = "... (older entries rotated out) ...";

export type AccessLogAction = "opendir" | "open" | "get" | "remove";

function accessLogStamp(): string {
    return new Date().toISOString();
}

function accessLogPid(session: BreachSession): number {
    let hash = 0;
    for (const char of session.id) hash = (hash * 31 + char.charCodeAt(0)) % 8000;
    return 1024 + hash;
}

function accessLogLine(session: BreachSession, action: AccessLogAction, path: string): string {
    const pid = accessLogPid(session);
    const user = session.user || "operator";
    if (action === "open") {
        return `${accessLogStamp()} sshd[${pid}]: subsystem sftp: open "${path}" flags READ (user ${user})`;
    }
    return `${accessLogStamp()} sshd[${pid}]: subsystem sftp: ${action} "${path}" (user ${user})`;
}

function appendAccessLog(session: BreachSession, action: AccessLogAction, path: string): boolean {
    const node = session.filesystem[ACCESS_LOG_PATH];
    if (!node || node.type !== "file") return false;

    const lines = String(node.data ?? "").split("\n").filter((entry) => entry.length > 0);
    lines.push(accessLogLine(session, action, path));
    if (lines.length > ACCESS_LOG_MAX_LINES) {
        const kept = lines.slice(lines.length - ACCESS_LOG_MAX_LINES);
        if (kept[0] !== ACCESS_LOG_TRIM_NOTICE) kept.unshift(ACCESS_LOG_TRIM_NOTICE);
        node.data = `${kept.join("\n")}\n`;
    } else {
        node.data = `${lines.join("\n")}\n`;
    }
    return true;
}

function defaultUserForPrivilege(privilege: BreachPrivilege): string {
    if (privilege === "root") return "root";
    if (privilege === "www-data") return "www-data";
    return "operator";
}

function breachSourceIp(): string {
    try {
        const ip = Network.getPlayerIp();
        return ip && ip !== "0.0.0.0" ? ip : "10.0.0.12";
    } catch {
        return "10.0.0.12";
    }
}

function genericFilesystem(target: BreachResolvedTarget, privilege: BreachPrivilege, user?: string): Record<string, BreachNode> {
    const account = user || defaultUserForPrivilege(privilege);
    const fs: Record<string, BreachNode> = {};
    for (const dir of ["/", "/etc", "/home", "/tmp", "/var", "/var/log"]) addDir(fs, dir);
    addFile(fs, { path: "/etc/hostname", data: `${target.host}\n`, downloadable: false });
    addFile(fs, { path: "/etc/issue", data: "Ubuntu 22.04 LTS \\n \\l\n", downloadable: false });
    const passwdRows = [
        "root:x:0:0:root:/root:/bin/bash",
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        `${privilege === "www-data" ? "www-data" : "operator"}:x:1001:1001:service user:/home/operator:/bin/sh`,
    ];
    // The account the player holds is listed alongside the host own service user rather
    // than replacing it: /home/operator is seeded on ssh targets, so renaming that row
    // would orphan the directory it points at.
    if (account !== "root" && account !== "daemon" && !passwdRows.some((row) => row.startsWith(`${account}:`))) {
        passwdRows.push(`${account}:x:1002:1002:service user:/home/${account}:/bin/sh`);
    }
    addFile(fs, {
        path: "/etc/passwd",
        data: [...passwdRows, ""].join("\n"),
    });
    addFile(fs, {
        path: "/var/log/auth.log",
        data: [
            `${new Date().toISOString()} sshd[811]: Accepted publickey for operator from 10.0.0.12`,
            `${new Date().toISOString()} sudo[1220]: operator : TTY=pts/0 ; COMMAND=/usr/bin/systemctl status app`,
            "",
        ].join("\n"),
        deletable: true,
    });
    addFile(fs, {
        path: "/var/log/access.log",
        data: [
            `${new Date().toISOString()} sshd[1182]: accepted publickey for ${account} from ${breachSourceIp()}`,
            `${new Date().toISOString()} cron[204]: session opened for user root`,
            `${new Date().toISOString()} systemd[1]: Started network target.`,
            "",
        ].join("\n"),
        deletable: true,
    });

    for (const port of target.ports) {
        const service = String(port.service ?? "").toLowerCase();
        const version = port.version ?? "unknown";
        if (service === "http" || service === "https") {
            addDir(fs, "/var/www");
            addFile(fs, {
                path: "/var/www/index.html",
                data: `<html><body><h1>${target.host}</h1><p>${version}</p></body></html>\n`,
            });
            addFile(fs, {
                path: "/var/www/config.env",
                data: `APP_HOST=${target.host}\nAPP_ENV=production\nSESSION_STORE=file\n`,
            });
            addFile(fs, {
                path: service === "https" ? "/etc/nginx/site.conf" : "/etc/httpd/site.conf",
                data: `server_name ${target.host};\nlisten ${portNumber(port) ?? 80};\nroot /var/www;\n`,
            });
        }
        if (service === "ftp") {
            addDir(fs, "/srv/ftp");
            addDir(fs, "/srv/ftp/incoming");
            addFile(fs, { path: "/srv/ftp/readme.txt", data: "Drop directory. Automated cleanup runs nightly.\n" });
            addFile(fs, { path: "/etc/vsftpd.conf", data: `listen=YES\nbanner_file=/etc/issue\n# ${version}\n` });
            addFile(fs, { path: "/var/log/vsftpd.log", data: "CONNECT anonymous\nUPLOAD incoming/tmp.dat\n", deletable: true });
        }
        if (service === "database" || service === "mysql") {
            addDir(fs, "/etc/mysql");
            addDir(fs, "/var/lib/mysql");
            addFile(fs, { path: "/etc/mysql/my.cnf", data: `[mysqld]\nbind-address=${target.ip}\nlog_error=/var/log/mysql.log\n` });
            addFile(fs, { path: "/var/log/mysql.log", data: "ready for connections\naborted connection from app worker\n", deletable: true });
        }
        if (service === "redis") {
            addDir(fs, "/etc/redis");
            addDir(fs, "/var/lib/redis");
            addFile(fs, { path: "/etc/redis/redis.conf", data: `bind ${target.ip}\nprotected-mode no\nappendonly yes\n` });
            addFile(fs, { path: "/var/lib/redis/dump.rdb", data: "redis serialized cache dump\nsession:* present\n" });
            addFile(fs, { path: "/var/log/redis.log", data: "Ready to accept connections\nCONFIG SET dir /var/spool\n", deletable: true });
        }
        if (service === "smb") {
            addDir(fs, "/srv/shares");
            addDir(fs, "/srv/shares/public");
            addFile(fs, { path: "/etc/samba/smb.conf", data: `[global]\nworkgroup = WORKGROUP\nmap to guest = Bad User\n` });
            addFile(fs, { path: "/srv/shares/public/README.txt", data: "Shared operational documents. Do not store secrets here.\n" });
            addFile(fs, { path: "/var/log/samba.log", data: "tree connect public\nsession setup failed for guest\n", deletable: true });
        }
        if (service === "smtp") {
            addDir(fs, "/etc/postfix");
            addDir(fs, "/var/spool/mail");
            addFile(fs, { path: "/etc/postfix/main.cf", data: `myhostname = ${target.host}\nrelayhost =\nmailbox_command =\n` });
            addFile(fs, { path: "/var/log/mail.log", data: "connect from unknown\nstatus=sent queued as 9F13A\n", deletable: true });
        }
        if (service === "ssh") {
            addDir(fs, "/home/operator");
            addDir(fs, "/home/operator/.ssh");
            addFile(fs, { path: "/home/operator/.ssh/authorized_keys", data: "ssh-rsa AAAA... operator-maint\n" });
        }
    }

    return fs;
}

function mergeOverlays(fs: Record<string, BreachNode>, overlays: BreachFile[]): Record<string, BreachNode> {
    const merged = { ...fs };
    for (const overlay of overlays) addFile(merged, overlay);
    return merged;
}

function refreshExistingOverlayFiles(session: BreachSession, overlays: BreachFile[]): boolean {
    let changed = false;
    for (const overlay of overlays) {
        const node = session.filesystem[normalizePath(overlay.path)];
        if (!node || node.type !== "file") continue;
        const readable = overlay.readable ?? true;
        const downloadable = overlay.downloadable ?? true;
        const deletable = overlay.deletable ?? false;
        if (
            node.data === overlay.data
            && node.readable === readable
            && node.downloadable === downloadable
            && node.deletable === deletable
        ) continue;
        node.data = overlay.data;
        node.readable = readable;
        node.downloadable = downloadable;
        node.deletable = deletable;
        changed = true;
    }
    return changed;
}

function deletedPathsForTarget(state: BreachState, target: { ip?: string; host?: string }): Set<string> {
    const deleted = new Set<string>();
    for (const key of targetKeys(target)) {
        for (const path of state.deletedPaths?.[key] ?? []) deleted.add(normalizePath(path));
    }
    return deleted;
}

function markPathDeleted(state: BreachState, target: { ip?: string; host?: string }, path: string): void {
    const full = normalizePath(path);
    state.deletedPaths ??= {};
    for (const key of targetKeys(target)) {
        if (!key) continue;
        const existing = state.deletedPaths[key] ?? [];
        if (!existing.includes(full)) state.deletedPaths[key] = [...existing, full];
    }
}

const ENCRYPTED_EXTENSION = "locked";

function encryptedPathsForTarget(state: BreachState, target: { ip?: string; host?: string }): Set<string> {
    const encrypted = new Set<string>();
    for (const key of targetKeys(target)) {
        for (const path of state.encryptedPaths?.[key] ?? []) encrypted.add(normalizePath(path));
    }
    return encrypted;
}

// An encrypted file is still on the box: the path gains the ransom extension and the
// contents stop being readable. Undoing the pass restores both.
function applyEncryption(file: BreachFile): BreachFile {
    return { ...file, path: `${file.path}.${ENCRYPTED_EXTENSION}`, readable: false, downloadable: false };
}

function getOverlaysForTarget(state: BreachState, target: BreachResolvedTarget): BreachFile[] {
    const deleted = deletedPathsForTarget(state, target);
    const encrypted = encryptedPathsForTarget(state, target);
    return [
        ...(state.overlays[target.ip] ?? []),
        ...(state.overlays[target.host] ?? []),
        ...sharedLootForTarget(target),
    ]
        .filter((file) => !deleted.has(normalizePath(file.path)))
        .map((file) => (encrypted.has(normalizePath(file.path)) ? applyEncryption(file) : file));
}

function wordlistBasename(input: string): string {
    const parts = String(input ?? "").replace(/\\/g, "/").split("/");
    return (parts[parts.length - 1] ?? "").trim().toLowerCase();
}

// Publishing a spec describes a list; it does not hand it over. Without this split the name is
// the only thing standing between a player and any list a content mod has ever registered.
function ownedWordlists(state = getState()): WordlistSpec[] {
    const granted = new Set((state.wordlistGrants ?? []).map((name) => name.trim().toLowerCase()));
    return [BASE_WORDLIST, ...(state.wordlists ?? []).filter((spec) => granted.has(spec.name.trim().toLowerCase()))];
}

function resolveWordlist(input: string, state = getState()): WordlistSpec | null {
    const name = wordlistBasename(input);
    if (!name) return null;
    return ownedWordlists(state).find((list) => list.name.toLowerCase() === name) ?? null;
}

function requiredWordlistTier(target: BreachResolvedTarget, state = getState()): number {
    const gates = state.wordlistGates ?? {};
    return gates[normalizeTarget(target.ip)] ?? gates[normalizeTarget(target.host)] ?? 1;
}

// Maps an open-ended access tier to a session privilege. Known tiers pass through;
// unknown/future tiers stay inert (default "user") until the backend gives them meaning.
function tierToPrivilege(tier?: string): BreachPrivilege {
    switch ((tier ?? "").trim().toLowerCase()) {
        case "root": return "root";
        case "www-data": return "www-data";
        default: return "user";
    }
}

export const BreachBackend = {
    getModules(): BreachModule[] {
        return exploitModules();
    },

    getWordlists(): WordlistSpec[] {
        return ownedWordlists();
    },

    resolveWordlist(input: string): WordlistSpec | null {
        return resolveWordlist(input);
    },

    requiredWordlistTier(input: string): number {
        const target = this.resolveTarget(input);
        return target ? requiredWordlistTier(target) : 1;
    },

    registerWordlist(spec: WordlistSpec): void {
        const state = getState();
        const list = (state.wordlists ?? []).filter((existing) => existing.name.toLowerCase() !== spec.name.toLowerCase());
        state.wordlists = [...list, spec];
        setState(state);
    },

    grantWordlist(name: string): void {
        const key = String(name ?? "").trim().toLowerCase();
        if (!key) return;
        const state = getState();
        const granted = state.wordlistGrants ?? [];
        if (granted.includes(key)) return;
        state.wordlistGrants = [...granted, key];
        setState(state);
    },

    revokeWordlist(name: string): void {
        const key = String(name ?? "").trim().toLowerCase();
        if (!key) return;
        const state = getState();
        state.wordlistGrants = (state.wordlistGrants ?? []).filter((granted) => granted !== key);
        setState(state);
    },

    removeWordlist(name: string): void {
        const key = String(name ?? "").trim().toLowerCase();
        if (!key || key === BASE_WORDLIST.name.toLowerCase()) return;
        const state = getExistingState();
        if (!state) return;
        state.wordlists = (state.wordlists ?? []).filter((wordlist) => wordlist.name.toLowerCase() !== key);
        state.wordlistGrants = (state.wordlistGrants ?? []).filter((granted) => granted !== key);
        setState(state);
    },

    isWordlistGranted(name: string): boolean {
        const key = String(name ?? "").trim().toLowerCase();
        if (!key) return false;
        if (key === BASE_WORDLIST.name.toLowerCase()) return true;
        return (getState().wordlistGrants ?? []).includes(key);
    },

    setWordlistGate(target: string, tier: number): void {
        const state = getState();
        const gates = state.wordlistGates ?? {};
        gates[normalizeTarget(target)] = tier;
        state.wordlistGates = gates;
        setState(state);
    },

    registerUserEnumTarget(record: UserEnumTarget): void {
        const users = (record.users ?? []).map((user) => String(user ?? "").trim()).filter(Boolean);
        const key = normalizeTarget(record.target);
        if (!key || users.length === 0) return;
        const state = getState();
        const next: UserEnumTarget = {
            target: record.target,
            users,
            service: record.service ?? "ssh",
            port: record.port ?? 22,
            observationProfile: record.observationProfile,
            observation: record.observation,
            note: record.note,
        };
        state.userEnumTargets = [
            ...(state.userEnumTargets ?? []).filter((existing) => normalizeTarget(existing.target) !== key),
            next,
        ];
        setState(state);
    },

    clearUserEnumTarget(target: string): void {
        const key = normalizeTarget(target);
        if (!key) return;
        const state = getState();
        state.userEnumTargets = (state.userEnumTargets ?? []).filter((existing) => normalizeTarget(existing.target) !== key);
        setState(state);
    },

    clearWordlistGate(target: string): void {
        const state = getExistingState();
        if (!state) return;
        const gates = state.wordlistGates ?? {};
        delete gates[normalizeTarget(target)];
        state.wordlistGates = gates;
        setState(state);
    },

    getCatalog(): BreachModule[] {
        return allModules();
    },

    getPostModules(): BreachModule[] {
        return postModulesOwned();
    },

    getPostModule(idOrIndex: string): BreachModule | undefined {
        const modules = postModulesOwned();
        const asIndex = Number(idOrIndex);
        if (Number.isInteger(asIndex) && asIndex >= 0) return modules[asIndex];
        const needle = idOrIndex.toLowerCase();
        return modules.find((module) =>
            module.id.toLowerCase() === needle ||
            module.id.toLowerCase().endsWith(needle) ||
            module.name.toLowerCase() === needle,
        );
    },

    runPost(sessionId: string, moduleId: string): { ok: true; session: BreachSession; module: BreachModule; effects: string[] } | { ok: false; reason: string } {
        const state = getState();
        const session = state.sessions.find((item) => item.id === sessionId);
        if (!session) return { ok: false, reason: "session not found" };
        const modules = postModulesOwned(state);
        const asIndex = Number(moduleId);
        const module = Number.isInteger(asIndex) && asIndex >= 0
            ? modules[asIndex]
            : modules.find((item) =>
            item.id.toLowerCase() === moduleId.toLowerCase() || item.id.toLowerCase().endsWith(moduleId.toLowerCase()),
        );
        if (!module) return { ok: false, reason: "post module not found" };

        const effects: string[] = [];
        if (module.access === "desktop" && session.access !== "desktop") {
            if (!session.desktop) return { ok: false, reason: "desktop implant is not compatible with this session" };
            session.access = "desktop";
            session.desktop.opened = true;
            session.desktop.openedAt = Date.now();
            session.desktop.sourceModuleId = module.id;
            effects.push("desktop access granted");
            ReconNgEvents.emit("ReconNg.Breach.DesktopOpened", {
                sessionId: session.id,
                ip: session.ip,
                host: session.host,
                moduleId: module.id,
                os: session.desktop.os,
                profile: session.desktop.profile,
                label: session.desktop.label,
                hwid: session.desktop.hwid,
            });
        }
        if (module.access === "passwd-dump") {
            const hashLines = passwdDumpEffects(session);
            if (hashLines.length === 0) return { ok: false, reason: "/etc/passwd has no readable hash material in this session" };
            effects.push(...hashLines);
        }
        if (effects.length === 0) return { ok: false, reason: "no effect on this session" };

        setState(state);
        return { ok: true, session, module, effects };
    },

    getLockedExploits(): BreachModule[] {
        const state = getState();
        return allModules(state).filter((module) => module.locked && !isOwned(module, state));
    },

    ownsExploit(id: string): boolean {
        const state = getState();
        const module = allModules(state).find((item) => item.id === id);
        return !!module && isOwned(module, state);
    },

    grantExploit(id: string): { ok: true; module: BreachModule } | { ok: false; reason: string } {
        const state = getState();
        const module = allModules(state).find((item) => item.id === id);
        if (!module) return { ok: false, reason: "unknown exploit" };
        const owned = state.ownedModuleIds ?? [];
        if (!owned.includes(id)) {
            state.ownedModuleIds = [...owned, id];
            setState(state);
        }
        return { ok: true, module };
    },

    revokeExploit(id: string): void {
        const state = getState();
        state.ownedModuleIds = (state.ownedModuleIds ?? []).filter((owned) => owned !== id);
        setState(state);
    },

    registerModule(module: BreachModule): { ok: true; module: BreachModule } | { ok: false; reason: string } {
        const reason = validateModule(module);
        if (reason) return { ok: false, reason };
        const state = getState();
        const modules = state.customModules ?? [];
        state.customModules = [...modules.filter((item) => item.id !== module.id), module];
        setState(state);
        return { ok: true, module };
    },

    removeModule(id: string): void {
        const state = getExistingState();
        if (!state) return;
        state.customModules = (state.customModules ?? []).filter((module) => module.id !== id);
        state.ownedModuleIds = (state.ownedModuleIds ?? []).filter((owned) => owned !== id);
        setState(state);
    },

    clearCustomModules(): void {
        const state = getState();
        state.customModules = [];
        setState(state);
    },

    attachLoot(target: string, files: BreachFile[]): void {
        const key = normalizeTarget(target);
        const state = getState();
        const paths = new Set(files.map((file) => normalizePath(file.path)));
        state.overlays[key] = [
            ...(state.overlays[key] ?? []).filter((file) => !paths.has(normalizePath(file.path))),
            ...files,
        ];
        setState(state);
    },

    applyExternalContent(content: {
        modules?: BreachModule[];
        loot?: Array<{ target: string; files: BreachFile[] }>;
        wordlists?: WordlistSpec[];
        wordlistGrants?: string[];
        gates?: Array<{ target: string; tier: number }>;
        userEnumTargets?: UserEnumTarget[];
    }): void {
        const state = getState();
        let changed = false;

        // External mods may update a file while a session remains open. Refresh only paths
        // already present in that session so a deleted file is never recreated.
        for (const session of state.sessions) {
            const targets = new Set([
                normalizeTarget(session.target),
                normalizeTarget(session.ip),
                normalizeTarget(session.host),
            ]);
            const overlays = (content.loot ?? [])
                .filter((entry) => targets.has(normalizeTarget(entry.target)))
                .flatMap((entry) => entry.files);
            if (refreshExistingOverlayFiles(session, overlays)) changed = true;
        }

        for (const module of content.modules ?? []) {
            if (validateModule(module)) continue;
            state.customModules = [...(state.customModules ?? []).filter((item) => item.id !== module.id), module];
            changed = true;
        }
        // External loot stays in SharedStorage and is merged on session open.
        // Copying it into recon-ng SaveStorage duplicates generated worlds and
        // can make Steam Cloud payloads huge.
        for (const spec of content.wordlists ?? []) {
            state.wordlists = [...(state.wordlists ?? []).filter((item) => item.name.toLowerCase() !== spec.name.toLowerCase()), spec];
            changed = true;
        }
        if (content.wordlistGrants) {
            const granted = content.wordlistGrants
                .map((name) => String(name ?? "").trim())
                .filter(Boolean);
            const current = state.wordlistGrants ?? [];
            const merged = Array.from(new Set([...current, ...granted].map((name) => name.toLowerCase())));
            if (merged.length !== current.length) {
                state.wordlistGrants = merged;
                changed = true;
            }
        }
        for (const gate of content.gates ?? []) {
            const gates = state.wordlistGates ?? {};
            gates[normalizeTarget(gate.target)] = gate.tier;
            state.wordlistGates = gates;
            changed = true;
        }
        for (const record of content.userEnumTargets ?? []) {
            const users = (record.users ?? []).map((user) => String(user ?? "").trim()).filter(Boolean);
            const key = normalizeTarget(record.target);
            if (!key || users.length === 0) continue;
            state.userEnumTargets = [
                ...(state.userEnumTargets ?? []).filter((existing) => normalizeTarget(existing.target) !== key),
                {
                    target: record.target,
                    users,
                    service: record.service ?? "ssh",
                    port: record.port ?? 22,
                    observationProfile: record.observationProfile,
                    observation: record.observation,
                    note: record.note,
                },
            ];
            changed = true;
        }

        if (changed) setState(state);
    },

    attachSharedLootForTarget(target: { ip?: string; host?: string }): void {
        // Compatibility no-op. getOverlaysForTarget() reads shared loot directly.
        void target;
    },

    clearLoot(target: string): void {
        const state = getState();
        const key = normalizeTarget(target);
        delete state.overlays[key];
        if (state.deletedPaths) delete state.deletedPaths[key];
        if (state.encryptedPaths) delete state.encryptedPaths[key];
        setState(state);
    },

    purgeTargets(targets: string[]): void {
        const keys = new Set(targets.map(normalizeTarget).filter(Boolean));
        if (keys.size === 0) return;
        const state = getExistingState();
        if (!state) return;
        const removedSessions = state.sessions.filter((session) =>
            [session.target, session.ip, session.host].some((value) => keys.has(normalizeTarget(value))),
        );
        state.sessions = state.sessions.filter((session) => !removedSessions.includes(session));
        for (const key of keys) {
            delete state.overlays[key];
            if (state.deletedPaths) delete state.deletedPaths[key];
            if (state.encryptedPaths) delete state.encryptedPaths[key];
            if (state.wordlistGates) delete state.wordlistGates[key];
        }
        state.userEnumTargets = (state.userEnumTargets ?? []).filter(
            (record) => !keys.has(normalizeTarget(record.target)),
        );
        setState(state);
        for (const session of removedSessions) {
            ReconNgEvents.emit("ReconNg.Breach.SessionClosed", {
                sessionId: session.id,
                ip: session.ip,
                host: session.host,
                reason: "target removed",
            });
        }
    },

    clearDeletedPaths(target: string): void {
        const state = getState();
        if (!state.deletedPaths) return;
        delete state.deletedPaths[normalizeTarget(target)];
        setState(state);
    },

    listHostFiles(target: string): BreachFile[] {
        const resolved = this.resolveTarget(target);
        const key = normalizeTarget(target);
        const state = getState();
        const scope = resolved ? { ip: resolved.ip, host: resolved.host } : { ip: key, host: key };
        const deleted = deletedPathsForTarget(state, scope);
        const encrypted = encryptedPathsForTarget(state, scope);
        return [
            ...(state.overlays[normalizeTarget(scope.ip ?? "")] ?? []),
            ...(state.overlays[normalizeTarget(scope.host ?? "")] ?? []),
            ...sharedLootForTarget(scope),
        ]
            .filter((file) => !deleted.has(normalizePath(file.path)))
            .map((file) => (encrypted.has(normalizePath(file.path)) ? applyEncryption(file) : file));
    },

    encryptHostFiles(target: string): { ok: boolean; encrypted: string[]; destroyed: string[] } {
        const resolved = this.resolveTarget(target);
        const key = normalizeTarget(target);
        const scope = resolved ? { ip: resolved.ip, host: resolved.host } : { ip: key, host: key };
        const files = this.listHostFiles(target);
        if (!files.length) return { ok: true, encrypted: [], destroyed: [] };

        const state = getState();
        state.encryptedPaths ??= {};
        const encrypted: string[] = [];
        const destroyed: string[] = [];
        const alreadyEncrypted = encryptedPathsForTarget(state, scope);

        for (const file of files) {
            const fullPath = normalizePath(file.path);
            // Recovery artifacts are authored deletable. Ransomware destroys the backup
            // and encrypts everything else.
            if (file.deletable) {
                markPathDeleted(state, scope, fullPath);
                destroyed.push(fullPath);
                continue;
            }
            // listHostFiles already reports encrypted files with the suffix applied.
            if (alreadyEncrypted.has(fullPath) || fullPath.endsWith(`.${ENCRYPTED_EXTENSION}`)) continue;
            for (const scopeKey of targetKeys(scope)) {
                if (!scopeKey) continue;
                const existing = state.encryptedPaths[scopeKey] ?? [];
                if (!existing.includes(fullPath)) state.encryptedPaths[scopeKey] = [...existing, fullPath];
            }
            encrypted.push(fullPath);
        }

        for (const session of state.sessions) {
            if (!targetKeys(scope).includes(normalizeTarget(session.ip))
                && !targetKeys(scope).includes(normalizeTarget(session.host))) continue;
            for (const fullPath of destroyed) delete session.filesystem[fullPath];
        }
        setState(state);

        const session = state.sessions.find((item) =>
            targetKeys(scope).includes(normalizeTarget(item.ip))
            || targetKeys(scope).includes(normalizeTarget(item.host)));
        for (const fullPath of destroyed) {
            ReconNgEvents.emit("ReconNg.Breach.FileDeleted", {
                sessionId: session?.id ?? "",
                ip: scope.ip ?? key,
                host: scope.host ?? key,
                path: fullPath,
                name: baseName(fullPath),
            });
        }
        return { ok: true, encrypted, destroyed };
    },

    decryptHostFiles(target: string): { ok: boolean; restored: string[] } {
        const state = getState();
        if (!state.encryptedPaths) return { ok: true, restored: [] };
        const resolved = this.resolveTarget(target);
        const key = normalizeTarget(target);
        const scope = resolved ? { ip: resolved.ip, host: resolved.host } : { ip: key, host: key };
        const restored = [...encryptedPathsForTarget(state, scope)];
        for (const scopeKey of targetKeys(scope)) delete state.encryptedPaths[scopeKey];
        setState(state);
        return { ok: true, restored };
    },

    wipeHostFiles(target: string): { ok: boolean; removed: string[] } {
        const resolved = this.resolveTarget(target);
        const key = normalizeTarget(target);
        const scope = resolved ? { ip: resolved.ip, host: resolved.host } : { ip: key, host: key };
        const files = this.listHostFiles(target);
        if (!files.length) return { ok: true, removed: [] };

        const state = getState();
        const removed: string[] = [];
        for (const file of files) {
            const fullPath = normalizePath(file.path);
            markPathDeleted(state, scope, fullPath);
            removed.push(fullPath);
        }
        for (const session of state.sessions) {
            if (!targetKeys(scope).includes(normalizeTarget(session.ip))
                && !targetKeys(scope).includes(normalizeTarget(session.host))) continue;
            for (const fullPath of removed) delete session.filesystem[fullPath];
        }
        setState(state);

        const session = state.sessions.find((item) =>
            targetKeys(scope).includes(normalizeTarget(item.ip))
            || targetKeys(scope).includes(normalizeTarget(item.host)));
        for (const fullPath of removed) {
            ReconNgEvents.emit("ReconNg.Breach.FileDeleted", {
                sessionId: session?.id ?? "",
                ip: scope.ip ?? key,
                host: scope.host ?? key,
                path: fullPath,
                name: baseName(fullPath),
            });
        }
        return { ok: true, removed };
    },

    resolveTarget(input: string): BreachResolvedTarget | null {
        const target = normalizeTarget(input);
        const subnet = Network.getSubnetByDomain(target) ?? Network.getSubnet(target);
        if (!subnet) return null;
        const domain = subnet.domain?.name ?? target;
        return {
            subnet,
            ip: subnet.ip,
            host: domain,
            ports: [...(subnet.ports ?? [])],
            vulnerabilities: (subnet.domain?.vulnerabilities ?? []).map((vuln) => vuln.type),
            users: (subnet.users ?? []).map((user) => String(user.username ?? "").toLowerCase()),
        };
    },

    findModules(input: string, options?: { rport?: number }): BreachModule[] {
        const target = this.resolveTarget(input);
        if (!target) return [];
        if (getClosedTargetGate(target.ip, target.host)) return [];
        return exploitModules().filter((module) => moduleMatches(target, module, options?.rport));
    },

    searchModules(query: string): BreachModule[] {
        const q = query.trim().toLowerCase();
        if (!q) return exploitModules();
        return exploitModules().filter((module) =>
            module.id.toLowerCase().includes(q) ||
            module.name.toLowerCase().includes(q) ||
            module.service.toLowerCase().includes(q),
        );
    },

    getModule(idOrIndex: string): BreachModule | undefined {
        const asIndex = Number(idOrIndex);
        const modules = exploitModules();
        if (Number.isInteger(asIndex) && asIndex >= 0) return modules[asIndex];
        const needle = idOrIndex.toLowerCase();
        return modules.find((module) =>
            module.id.toLowerCase() === needle ||
            module.id.toLowerCase().endsWith(needle) ||
            module.name.toLowerCase() === needle,
        );
    },

    check(input: string, moduleId: string, options?: { rport?: number; user?: string; wordlist?: string }): { ok: boolean; reason: string; target?: BreachResolvedTarget; module?: BreachModule } {
        const target = this.resolveTarget(input);
        if (!target) {
            console.warn("[reconng-check] resolveTarget NULL", JSON.stringify({ input }));
            return { ok: false, reason: "target could not be resolved" };
        }
        const gate = getClosedTargetGate(target.ip, target.host);
        if (gate) return { ok: false, reason: gate.message ?? "target is not reachable from the current route", target };
        const module = this.getModule(moduleId);
        if (!module) return { ok: false, reason: "module not found", target };
        if (module.requiresRport && options?.rport === undefined) return { ok: false, reason: "RPORT is required for this module", target, module };
        if (module.requiresUser && !options?.user) return { ok: false, reason: "USER is required for this module", target, module };
        if (module.requiresWordlist && !options?.wordlist) return { ok: false, reason: "WORDLIST is required for this module", target, module };
        if (module.access === "user-enum" && !findUserEnumTarget(target)) return { ok: false, reason: "target does not expose an enumerable SSH account surface", target, module };
        if (!moduleMatches(target, module, options?.rport)) {
            console.warn("[reconng-check] no match", JSON.stringify({
                input,
                resolvedIp: target.ip,
                host: target.host,
                targetPorts: target.ports,
                targetVulns: target.vulnerabilities,
                module: { id: module.id, service: module.service, port: module.port, versions: module.versions, vulnerabilities: module.vulnerabilities },
            }));
            return { ok: false, reason: "service, version, port, or vulnerability state does not match", target, module };
        }
        // Hit the same number we matched on (player RPORT, else module classic port).
        // Do not auto-select a remapped external when RPORT was not supplied.
        const requestPort = effectiveAttemptPort(module, options?.rport)
            ?? target.ports.find((port) => portActive(port) && servicesCompatible(port.service, module.service))?.external
            ?? target.ports.find((port) => portActive(port) && servicesCompatible(port.service, module.service))?.port;
        if (requestPort && Network.isRequestBlocked(target.ip, requestPort)) {
            return { ok: false, reason: `connection blocked by firewall on port ${requestPort}`, target, module };
        }
        if (module.requiresUser && !target.users.includes(String(options?.user ?? "").toLowerCase())) {
            return { ok: false, reason: "no account matches that username on the target", target, module };
        }
        if (module.requiresWordlist) {
            const spec = resolveWordlist(String(options?.wordlist ?? ""));
            if (!spec) return { ok: false, reason: "no wordlist by that name is available", target, module };
            if (spec.tier < requiredWordlistTier(target)) {
                return { ok: false, reason: "wordlist exhausted without recovering a password. a stronger list is needed", target, module };
            }
        }
        return { ok: true, reason: "target appears vulnerable", target, module };
    },

    enumerateUsers(input: string, moduleId: string, options?: { rport?: number }): { ok: true; target: BreachResolvedTarget; module: BreachModule; users: string[]; observation: UserEnumObservation } | { ok: false; reason: string } {
        const check = this.check(input, moduleId, options);
        if (!check.ok || !check.target || !check.module) return { ok: false, reason: check.reason };
        if (check.module.access !== "user-enum") return { ok: false, reason: "selected module does not enumerate users" };
        const record = findUserEnumTarget(check.target);
        if (!record) return { ok: false, reason: "target does not expose an enumerable SSH account surface" };
        const users = Array.from(new Set(record.users.map((user) => String(user ?? "").trim()).filter(Boolean)));
        if (users.length === 0) return { ok: false, reason: "no account names recovered" };
        ReconNgEvents.emit("ReconNg.UserEnum.Complete", {
            ip: check.target.ip,
            host: check.target.host,
            moduleId: check.module.id,
            users,
        });
        return {
            ok: true,
            target: check.target,
            module: check.module,
            users,
            observation: buildUserEnumObservation(check.target, record, users),
        };
    },

    openSession(input: string, moduleId: string, options?: { rport?: number; user?: string; wordlist?: string }): { ok: true; session: BreachSession; module: BreachModule } | { ok: false; reason: string } {
        const check = this.check(input, moduleId, options);
        if (!check.ok || !check.target || !check.module) return { ok: false, reason: check.reason };

        const lock = getActiveSessionLock(check.target.ip, check.target.host);
        if (lock) return { ok: false, reason: lock.message ?? "connection refused - host unreachable" };

        const state = getState();
        const sessionUser = check.module.requiresUser && options?.user
            ? options.user
            : defaultUserForPrivilege(check.module.privilege);
        const filesystem = mergeOverlays(
            genericFilesystem(check.target, check.module.privilege, sessionUser),
            getOverlaysForTarget(state, check.target),
        );
        const session: BreachSession = {
            id: String(state.nextSessionId++),
            target: input,
            ip: check.target.ip,
            host: check.target.host,
            moduleId: check.module.id,
            privilege: check.module.privilege,
            user: sessionUser,
            cwd: "/",
            openedAt: Date.now(),
            access: check.module.access ?? "shell",
            desktop: check.module.desktop ? createDesktopSession(check.module.desktop, check.module.access === "desktop", check.module.id) : undefined,
            filesystem,
        };
        state.sessions.push(session);
        setState(state);
        ReconNgEvents.emit("ReconNg.Breach.SessionOpened", {
            sessionId: session.id,
            ip: session.ip,
            host: session.host,
            moduleId: session.moduleId,
            privilege: session.privilege,
            access: session.access,
            desktop: session.desktop ? {
                os: session.desktop.os,
                profile: session.desktop.profile,
                label: session.desktop.label,
                hwid: session.desktop.hwid,
                opened: session.desktop.opened,
            } : undefined,
        });
        if (session.access === "desktop" && session.desktop) {
            ReconNgEvents.emit("ReconNg.Breach.DesktopOpened", {
                sessionId: session.id,
                ip: session.ip,
                host: session.host,
                moduleId: session.moduleId,
                os: session.desktop.os,
                profile: session.desktop.profile,
                label: session.desktop.label,
                hwid: session.desktop.hwid,
            });
        }
        return { ok: true, session, module: check.module };
    },

    openReverseSession(input: string, options: { user: string; tier?: string; payloadId?: string; desktop?: DesktopProfile }): { ok: true; session: BreachSession } | { ok: false; reason: string } {
        const target = this.resolveTarget(input);
        if (!target) return { ok: false, reason: "callback host could not be resolved" };

        const gate = getClosedTargetGate(target.ip, target.host);
        if (gate) return { ok: false, reason: gate.message ?? "target is not reachable from the current route" };

        const lock = getActiveSessionLock(target.ip, target.host);
        if (lock) return { ok: false, reason: lock.message ?? "connection refused - host unreachable" };

        const state = getState();
        const privilege: BreachPrivilege = tierToPrivilege(options.tier);
        const filesystem = mergeOverlays(
            genericFilesystem(target, privilege, options.user),
            getOverlaysForTarget(state, target),
        );
        const session: BreachSession = {
            id: String(state.nextSessionId++),
            target: input,
            ip: target.ip,
            host: target.host,
            moduleId: options.payloadId ?? "payload/reverse",
            privilege,
            user: options.user,
            cwd: "/",
            openedAt: Date.now(),
            access: "shell",
            filesystem,
            desktop: options.desktop
                ? createDesktopSession(options.desktop, false, options.payloadId ?? "payload/reverse")
                : undefined,
        };
        state.sessions.push(session);
        setState(state);
        ReconNgEvents.emit("ReconNg.Breach.SessionOpened", {
            sessionId: session.id,
            ip: session.ip,
            host: session.host,
            moduleId: session.moduleId,
            privilege: session.privilege,
            access: session.access,
            via: "reverse",
        });
        return { ok: true, session };
    },

    listSessions(): BreachSession[] {
        return getState().sessions;
    },

    getSession(id: string): BreachSession | undefined {
        return getState().sessions.find((session) => session.id === id);
    },

    updateSession(session: BreachSession): void {
        const state = getState();
        state.sessions = state.sessions.map((item) => item.id === session.id ? session : item);
        setState(state);
    },

    escalateSession(sessionId: string, user: string, password: string): { ok: true; session: BreachSession } | { ok: false; reason: string } {
        const state = getState();
        const session = state.sessions.find((item) => item.id === sessionId);
        if (!session) return { ok: false, reason: "session not found" };
        const targetUser = user.trim() || "root";
        const entry = passwdHashEntries(session).find((item) => item.user === targetUser);
        if (!entry) return { ok: false, reason: `${targetUser}: no usable passwd hash in this session` };
        if (!passwordMatchesHash(entry.hash, password)) return { ok: false, reason: "authentication failure" };
        session.user = targetUser;
        session.privilege = targetUser === "root" ? "root" : "user";
        setState(state);
        return { ok: true, session };
    },

    closeSession(id: string, reason = "closed"): boolean {
        const state = getState();
        const session = state.sessions.find((item) => item.id === id);
        state.sessions = state.sessions.filter((item) => item.id !== id);
        setState(state);
        if (!session) return false;
        ReconNgEvents.emit("ReconNg.Breach.SessionClosed", {
            sessionId: session.id,
            ip: session.ip,
            host: session.host,
            reason,
        });
        return true;
    },

    clearSessions(reason = "cleared"): number {
        const state = getState();
        const sessions = state.sessions;
        state.sessions = [];
        state.nextSessionId = 1;
        setState(state);

        for (const session of sessions) {
            ReconNgEvents.emit("ReconNg.Breach.SessionClosed", {
                sessionId: session.id,
                ip: session.ip,
                host: session.host,
                reason,
            });
        }

        return sessions.length;
    },

    list(session: BreachSession, path = "."): string[] | null {
        const dir = normalizePath(path, session.cwd);
        const node = session.filesystem[dir];
        if (!node || node.type !== "dir") return null;
        const prefix = dir === "/" ? "/" : `${dir}/`;
        const names = new Set<string>();
        for (const candidate of Object.keys(session.filesystem)) {
            if (candidate === dir || !candidate.startsWith(prefix)) continue;
            const rest = candidate.slice(prefix.length);
            if (!rest || rest.includes("/")) continue;
            const child = session.filesystem[candidate];
            names.add(child.type === "dir" ? `${rest}/` : rest);
        }
        const listing = [...names].sort((a, b) => a.localeCompare(b));
        this.noteAccess(session, "opendir", dir);
        ReconNgEvents.emit("ReconNg.Breach.DirListed", {
            sessionId: session.id,
            ip: session.ip,
            host: session.host,
            path: dir,
        });
        return listing;
    },

    readQuiet(session: BreachSession, path: string): { path: string; data: string } | null {
        const fullPath = normalizePath(path, session.cwd);
        const node = session.filesystem[fullPath];
        if (!node || node.type !== "file" || node.readable === false) return null;
        return { path: fullPath, data: node.data ?? "" };
    },

    noteAccess(session: BreachSession, action: AccessLogAction, path: string): void {
        if (!appendAccessLog(session, action, path)) return;
        this.updateSession(session);
    },

    read(session: BreachSession, path: string): { path: string; data: string } | null {
        const result = this.readQuiet(session, path);
        if (!result) return null;
        ReconNgEvents.emit("ReconNg.Breach.FileRead", {
            sessionId: session.id,
            ip: session.ip,
            host: session.host,
            path: result.path,
            name: baseName(result.path),
        });
        this.noteAccess(session, "open", result.path);
        return result;
    },

    remove(session: BreachSession, path: string): { ok: boolean; path: string; reason?: string } {
        const fullPath = normalizePath(path, session.cwd);
        const node = session.filesystem[fullPath];
        if (!node) return { ok: false, path: fullPath, reason: "file not found" };
        if (node.type !== "file") return { ok: false, path: fullPath, reason: "not a file" };
        if (!node.deletable && session.privilege !== "root") return { ok: false, path: fullPath, reason: "permission denied" };
        delete session.filesystem[fullPath];
        this.updateSession(session);
        const state = getState();
        markPathDeleted(state, { ip: session.ip, host: session.host }, fullPath);
        setState(state);
        ReconNgEvents.emit("ReconNg.Breach.FileDeleted", {
            sessionId: session.id,
            ip: session.ip,
            host: session.host,
            path: fullPath,
            name: baseName(fullPath),
        });
        if (fullPath !== ACCESS_LOG_PATH) this.noteAccess(session, "remove", fullPath);
        return { ok: true, path: fullPath };
    },

    cd(session: BreachSession, path: string): { ok: boolean; cwd: string; reason?: string } {
        const fullPath = normalizePath(path, session.cwd);
        const node = session.filesystem[fullPath];
        if (!node || node.type !== "dir") return { ok: false, cwd: session.cwd, reason: "directory not found" };
        session.cwd = fullPath;
        this.updateSession(session);
        return { ok: true, cwd: fullPath };
    },
};
