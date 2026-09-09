import {
    Command,
    Files,
    RegisterCommand,
    type CommandAutoComplete,
    type CommandTools,
} from "@hotbunny/hackhub-content-sdk";
import { BreachBackend, type BreachModule, type BreachSession, type BreachPrivilege, type BreachResolvedTarget, type DesktopProfile } from "../world/BreachBackend";
import { ReconNgEvents } from "../world/ReconNgEvents";
import {
    resolveServiceBinary,
    getServiceBinaryOverride,
    describeFunction,
    isVulnerableTo,
    VULN_ACTIONS,
    type VulnType,
    type ServiceBinaryModel,
    type BinaryFunction,
} from "../world/ServiceBinary";
import { syncExternalServiceBinaries } from "../world/ServiceBinarySync";
import { getAccessProfile, type AccessCommand } from "../world/SessionAccess";
import { syncExternalAccessProfiles } from "../world/SessionAccessSync";
import { syncExternalBreachContent } from "../world/BreachContentSync";
import { registerExploitShop } from "../world/ExampleExploitShop";
import { registerLabWordlists } from "../world/ReconNgTestLab";
import {
    armReverseListener,
    checkReverseListenerNetwork,
    clearArmedReverseListener,
    findReversePayload,
    getArmedReverseListener,
    getReverseTarget,
    findReversePayloadPackageEntitlement,
    listReversePayloads,
    registerReversePayload,
    reverseCallbackUrl,
    syncExternalReversePayloads,
    type ReversePayloadDefinition,
} from "../world/ReversePayloads";
import { clearReverseDeliveries, consumeReverseDeliveries } from "../world/ReverseCallback";
import { consumeSessionTermination } from "../world/SessionControl";

const PROMPT = "rng6";
const PROMPT_COLOR = "cyan";
const TICK = 420;
const BEAT = 850;
const REVERSE_LISTENER_INTERVAL_MS = 1200;
const REVERSE_LISTENER_TIMEOUT_MS = 10 * 60 * 1000;

interface LabState {
    service: string;
    version: string;
    port: number;
    vulns: VulnType[];
    binary: ServiceBinaryModel;
    access?: string;
    desktop?: DesktopProfile;
}

interface ConsoleState {
    rhost: string;
    rport?: number;
    user?: string;
    wordlist?: string;
    module?: BreachModule;
    payload?: ReversePayloadDefinition;
    lhost?: string;
    lport?: number;
    target?: string;
    lastList?: "modules" | "payloads";
    activeSessionId?: string;
    lab?: LabState;
    buildChain?: string[];
}

const VALID_VULNS = Object.keys(VULN_ACTIONS) as VulnType[];

const CRAFT_PRIVILEGE: Record<VulnType, BreachPrivilege> = {
    RCE: "www-data",
    SQL_INJECTION: "user",
    LFI: "www-data",
    RFI: "www-data",
    SSRF: "user",
    CORS: "user",
    XSS: "user",
};

async function runReconNg(tools: CommandTools, commandName: string): Promise<void> {
    tools.lock();
    try {
        if (tools.getArgs().length > 0) {
            tools.printError(`usage: ${commandName}`);
            return;
        }
        syncExternalBreachContent();
        syncExternalAccessProfiles();
        syncExternalReversePayloads();
        consumeReverseDeliveries();
        registerExploitShop();
        registerLabWordlists();
        const state: ConsoleState = { rhost: "" };
        printSplash(tools, commandName);

        while (true) {
            const line = (await tools.prompt({ label: promptLabel(state), color: PROMPT_COLOR })).trim();
            if (!line) continue;
            syncExternalBreachContent();
            if (state.activeSessionId) {
                const active = BreachBackend.getSession(state.activeSessionId);
                if (active) {
                    const termination = consumeSessionTermination(active.ip, active.host);
                    if (termination) {
                        tools.printError(termination.message ?? "connection terminated.");
                        BreachBackend.closeSession(active.id, "terminated");
                        state.activeSessionId = undefined;
                        continue;
                    }
                }
            }
            const shouldExit = state.activeSessionId
                ? await runSessionCommand(tools, state, line)
                : await runTopLevelCommand(tools, state, line);
            if (shouldExit) return;
        }
    } finally {
        tools.unlock();
    }
}

async function runTopLevelCommand(tools: CommandTools, state: ConsoleState, line: string): Promise<boolean> {
    const [commandRaw, ...args] = splitArgs(line);
    const command = commandRaw.toLowerCase();

    if (["exit", "quit", "q"].includes(command)) {
        tools.println("closing workspace.");
        return true;
    }
    if (["help", "?"].includes(command)) {
        printHelp(tools);
        return false;
    }
    if (command === "clear") {
        tools.clear();
        return false;
    }
    if (command === "search") {
        const query = args.join(" ");
        const modules = BreachBackend.searchModules(query);
        printModules(tools, modules, query || "all modules");
        state.lastList = "modules";
        return false;
    }
    if (command === "payloads" || command === "payload") {
        await handlePayloads(tools, args);
        if (["", "list", "ls"].includes(String(args[0] ?? "").toLowerCase())) state.lastList = "payloads";
        return false;
    }
    if (command === "info") {
        const query = args.join(" ");
        const numeric = query.trim() !== "" && Number.isInteger(Number(query)) && Number(query) >= 0;
        if (query.toLowerCase().startsWith("payload/") || (numeric && state.lastList === "payloads")) {
            const payload = findReversePayload(query);
            if (!payload) tools.printError("payload not found.");
            else printPayloadInfo(tools, payload);
            return false;
        }
        if (!query && state.payload) {
            printPayloadInfo(tools, state.payload);
            return false;
        }
        const module = BreachBackend.getModule(query || state.module?.id || "");
        if (module) {
            printModuleInfo(tools, module);
            return false;
        }
        const namedPayload = findReversePayload(query);
        if (namedPayload) printPayloadInfo(tools, namedPayload);
        else tools.printError("module or payload not found.");
        return false;
    }
    if (command === "use") {
        const query = args.join(" ");
        const needle = query.toLowerCase();
        const numeric = query.trim() !== "" && Number.isInteger(Number(query)) && Number(query) >= 0;

        // Explicit payload id, or a numbered pick right after listing payloads.
        if (needle.startsWith("payload/") || (numeric && state.lastList === "payloads")) {
            const payload = findReversePayload(query);
            if (!payload) {
                tools.printError(`payload not found: ${query}. run 'payloads' to list installed payloads.`);
                return false;
            }
            state.payload = payload;
            state.module = undefined;
            tools.printSuccess(`loaded ${payload.id}`);
            return false;
        }

        // Module by name or index (numbers default here).
        const module = BreachBackend.getModule(query);
        if (module) {
            state.module = module;
            state.payload = undefined;
            // Seed RPORT with the module's classic port so options shows the default
            // until the player overrides it (e.g. after nmap shows a remapped external).
            if (module.port !== undefined) {
                state.rport = module.port;
                tools.printSuccess(`loaded ${module.id}`);
                tools.printInfo(`RPORT => ${module.port} (module default)`);
            } else {
                state.rport = undefined;
                tools.printSuccess(`loaded ${module.id}`);
            }
            return false;
        }

        // Fallback: a payload matched by name/suffix.
        const namedPayload = findReversePayload(query);
        if (namedPayload) {
            state.payload = namedPayload;
            state.module = undefined;
            tools.printSuccess(`loaded ${namedPayload.id}`);
            return false;
        }

        const locked = BreachBackend.getCatalog().find((item) =>
            item.locked && !BreachBackend.ownsExploit(item.id) &&
            (item.id.toLowerCase() === needle || item.id.toLowerCase().endsWith(needle) || item.name.toLowerCase() === needle),
        );
        if (locked) tools.printError(`${locked.id} is locked. acquire it first.`);
        else tools.printError("module or payload not found.");
        return false;
    }
    if (command === "back") {
        state.module = undefined;
        state.payload = undefined;
        state.rport = undefined;
        tools.printInfo("module cleared.");
        return false;
    }
    if (command === "set") {
        const key = String(args[0] ?? "").toUpperCase();
        const value = args.slice(1).join(" ");
        if (key === "RHOST" && value) {
            state.rhost = value;
            tools.printSuccess(`RHOST => ${value}`);
            return false;
        }
        if (key === "RPORT" && value) {
            const port = Number(value);
            if (!Number.isInteger(port) || port < 1 || port > 65535) {
                tools.printError("RPORT must be a TCP port between 1 and 65535.");
                return false;
            }
            state.rport = port;
            tools.printSuccess(`RPORT => ${port}`);
            return false;
        }
        if (key === "USER" && value) {
            state.user = value;
            tools.printSuccess(`USER => ${value}`);
            return false;
        }
        if (key === "WORDLIST" && value) {
            state.wordlist = value;
            tools.printSuccess(`WORDLIST => ${value}`);
            return false;
        }
        if (key === "LHOST" && value) {
            state.lhost = value;
            tools.printSuccess(`LHOST => ${value}`);
            return false;
        }
        if (key === "LPORT" && value) {
            const port = Number(value);
            if (!Number.isInteger(port) || port < 1 || port > 65535) {
                tools.printError("LPORT must be a TCP port between 1 and 65535.");
                return false;
            }
            state.lport = port;
            tools.printSuccess(`LPORT => ${port}`);
            return false;
        }
        if (key === "TARGET" && value) {
            state.target = value;
            tools.printSuccess(`TARGET => ${value}`);
            return false;
        }
        tools.printError("usage: set RHOST <ip-or-domain> | set RPORT <port> | set USER <username> | set WORDLIST <path> | set LHOST <ip> | set LPORT <port> | set TARGET <person>");
        return false;
    }
    if (command === "show") {
        if (String(args[0] ?? "").toLowerCase() === "options") printOptions(tools, state);
        else if (String(args[0] ?? "").toLowerCase() === "modules") {
            printModules(tools, BreachBackend.getModules(), "all modules");
            state.lastList = "modules";
        } else tools.println("usage: show options | show modules");
        return false;
    }
    if (command === "check") {
        await checkTarget(tools, state);
        return false;
    }
    if (["run", "exploit"].includes(command)) {
        if (state.payload) {
            await armReversePayload(tools, state);
            return false;
        }
        await runExploit(tools, state);
        return false;
    }
    if (command === "sessions") {
        handleSessions(tools, state, args);
        return false;
    }
    if (command === "interact") {
        const id = args[0];
        if (!id) tools.printError("usage: interact <session-id>");
        else activateSession(tools, state, id);
        return false;
    }
    if (command === "disasm" || command === "analyze") {
        await doDisasm(tools, state, args[0]);
        return false;
    }
    if (command === "inspect") {
        doInspect(tools, state, args[0]);
        return false;
    }
    if (command === "build" || command === "develop") {
        await doBuild(tools, state, args);
        return false;
    }

    tools.printError(`unknown command: ${commandRaw}`);
    tools.println("type 'help' for commands.");
    return false;
}

async function checkTarget(tools: CommandTools, state: ConsoleState): Promise<void> {
    if (!state.rhost) {
        tools.printError("RHOST is not set.");
        return;
    }
    if (!state.module) {
        tools.printError("no module selected.");
        return;
    }
    if (state.module.requiresRport && state.rport === undefined) {
        tools.printError("RPORT is required for this module.");
        return;
    }
    if (state.module.requiresUser && !state.user) {
        tools.printError("USER is required for this module.");
        return;
    }
    if (state.module.requiresWordlist && !state.wordlist) {
        tools.printError("WORDLIST is required for this module.");
        return;
    }
    tools.println([{ text: "[*] ", color: "cyan" }, { text: "checking target fingerprint ...", color: "gray" }]);
    await tools.sleep(BEAT);
    const result = BreachBackend.check(state.rhost, state.module.id, { rport: state.rport, user: state.user, wordlist: state.wordlist });
    if (result.ok) {
        tools.println([{ text: "[+] ", color: "green", bold: true }, { text: result.module?.access === "user-enum" ? "enumeration surface is reachable" : result.reason, color: "white" }]);
        tools.println([{ text: "    host: ", color: "gray" }, { text: `${result.target?.host} (${result.target?.ip})`, color: "white" }]);
        if (state.rport !== undefined) tools.println([{ text: "    port: ", color: "gray" }, { text: String(state.rport), color: "white" }]);
    } else {
        tools.println([{ text: "[-] ", color: "red", bold: true }, { text: result.reason, color: "white" }]);
    }
}

async function armReversePayload(tools: CommandTools, state: ConsoleState): Promise<void> {
    const payload = state.payload;
    if (!payload) {
        tools.printError("no payload selected.");
        return;
    }
    if (!state.lhost) {
        tools.printError("LHOST is not set.");
        return;
    }
    if (state.lport === undefined) {
        tools.printError("LPORT is not set.");
        return;
    }
    if (!state.target) {
        tools.printError("TARGET is not set (the person to lure).");
        return;
    }

    const listener = { payloadId: payload.id, lhost: state.lhost, lport: state.lport, target: state.target };
    const network = checkReverseListenerNetwork(listener);
    if (!network.ok) {
        tools.printError(network.reason ?? "reverse listener is not reachable.");
        return;
    }

    clearReverseDeliveries();
    armReverseListener(listener);

    tools.println([{ text: "[*] ", color: "cyan" }, { text: "staging payload ....... ", color: "gray" }, { text: payload.id, color: "white" }]);
    await tools.sleep(TICK);
    tools.println([{ text: "[*] ", color: "cyan" }, { text: "reverse handler ....... ", color: "gray" }, { text: `${state.lhost}:${state.lport}`, color: "white", bold: true }]);
    tools.println([{ text: "[*] ", color: "cyan" }, { text: "callback URL .......... ", color: "gray" }, { text: reverseCallbackUrl(listener), color: "white", bold: true }]);
    await tools.sleep(BEAT);
    tools.println([{ text: "[*] ", color: "cyan" }, { text: `listening for a callback from ${state.target} ...`, color: "gray" }]);
    tools.println([{ text: "    ", color: "gray" }, { text: "leave recon-ng open while the message is delivered. listener timeout: 10 minutes.", color: "gray" }]);

    const expected = getReverseTarget(state.target);
    const before = new Set(BreachBackend.listSessions().map((session) => session.id));
    const maxTicks = Math.ceil(REVERSE_LISTENER_TIMEOUT_MS / REVERSE_LISTENER_INTERVAL_MS);
    for (let i = 0; i < maxTicks; i += 1) {
        await tools.sleep(REVERSE_LISTENER_INTERVAL_MS);
        consumeReverseDeliveries();
        const fresh = BreachBackend.listSessions().find((session) => !before.has(session.id) && (!expected || session.ip === expected.ip));
        if (fresh) {
            tools.println([{ text: "[+] ", color: "green", bold: true }, { text: `session ${fresh.id} opened`, color: "white", bold: true }, { text: ` (${fresh.user}@${fresh.host})`, color: "gray" }]);
            tools.println([{ text: "    ", color: "gray" }, { text: `type 'sessions -i ${fresh.id}' to enter.`, color: "gray" }]);
            state.payload = undefined;
            return;
        }
        if (!getArmedReverseListener()) {
            tools.println([{ text: "[-] ", color: "red", bold: true }, { text: "callback bounced - the payload didn't fit the target, or it wasn't reachable.", color: "white" }]);
            state.payload = undefined;
            return;
        }
    }
    clearArmedReverseListener();
    tools.println([{ text: "[-] ", color: "red", bold: true }, { text: "listener timed out. run the payload again to reopen it.", color: "white" }]);
}

async function runExploit(tools: CommandTools, state: ConsoleState): Promise<void> {
    if (!state.rhost) {
        tools.printError("RHOST is not set.");
        return;
    }
    if (!state.module) {
        tools.printError("no module selected.");
        return;
    }
    if (state.module.requiresRport && state.rport === undefined) {
        tools.printError("RPORT is required for this module.");
        return;
    }
    if (state.module.requiresUser && !state.user) {
        tools.printError("USER is required for this module.");
        return;
    }
    if (state.module.requiresWordlist && !state.wordlist) {
        tools.printError("WORDLIST is required for this module.");
        return;
    }

    tools.println([{ text: "[*] ", color: "cyan" }, { text: "loading module ........ ", color: "gray" }, { text: state.module.id, color: "white" }]);
    await tools.sleep(TICK);
    tools.println([{ text: "[*] ", color: "cyan" }, { text: "target ............... ", color: "gray" }, { text: state.rhost, color: "white", bold: true }]);
    if (state.rport !== undefined) tools.println([{ text: "[*] ", color: "cyan" }, { text: "target port .......... ", color: "gray" }, { text: String(state.rport), color: "white", bold: true }]);
    await tools.sleep(BEAT);

    if (state.module.access === "user-enum") {
        await runUserEnumeration(tools, state);
        return;
    }

    if (state.module.requiresWordlist) {
        await runBruteforce(tools, state);
        return;
    }

    tools.println([{ text: "[*] ", color: "cyan" }, { text: "negotiating transport .", color: "gray" }]);
    await tools.sleep(BEAT);
    tools.println([{ text: "[*] ", color: "cyan" }, { text: "probing service state ..", color: "gray" }]);
    await tools.sleep(BEAT);

    const opened = BreachBackend.openSession(state.rhost, state.module.id, { rport: state.rport, user: state.user, wordlist: state.wordlist });
    if (!opened.ok) {
        tools.println([{ text: "[-] ", color: "red", bold: true }, { text: `exploit failed: ${opened.reason}`, color: "white" }]);
        return;
    }

    tools.println([{ text: "[+] ", color: "green", bold: true }, { text: "exploit accepted.", color: "white" }]);
    await tools.sleep(TICK);
    tools.println([{ text: "[+] ", color: "green", bold: true }, { text: `session ${opened.session.id} opened`, color: "white", bold: true }, { text: ` (${opened.session.user}@${opened.session.host})`, color: "gray" }]);
    if (opened.session.access === "desktop") {
        tools.println([{ text: "    ", color: "gray" }, { text: "desktop access granted.", color: "cyan" }]);
    } else {
        const profile = getAccessProfile(opened.session.access);
        if (profile) tools.println([{ text: "    ", color: "gray" }, { text: `${profile.role} session.`, color: "cyan" }]);
    }
    tools.println([{ text: "    ", color: "gray" }, { text: `type 'interact ${opened.session.id}' to enter the session.`, color: "gray" }]);
}

async function runUserEnumeration(tools: CommandTools, state: ConsoleState): Promise<void> {
    tools.println([{ text: "[*] ", color: "cyan" }, { text: "sampling ssh banner ....", color: "gray" }]);
    await tools.sleep(BEAT);
    tools.println([{ text: "[*] ", color: "cyan" }, { text: "probing auth timing ...", color: "gray" }]);
    await tools.sleep(BEAT);
    tools.println([{ text: "[*] ", color: "cyan" }, { text: "comparing failures ....", color: "gray" }]);
    await tools.sleep(BEAT);

    const result = BreachBackend.enumerateUsers(state.rhost, state.module!.id, { rport: state.rport });
    if (!result.ok) {
        tools.println([{ text: "[-] ", color: "red", bold: true }, { text: `enumeration failed: ${result.reason}`, color: "white" }]);
        return;
    }

    tools.println([{ text: "[+] ", color: "green", bold: true }, { text: result.observation.summary, color: "white" }]);
    if (result.observation.detail) {
        tools.println([{ text: "    ", color: "gray" }, { text: result.observation.detail, color: "gray" }]);
    }
    tools.println("");
    tools.println([{ text: "[+] ", color: "green", bold: true }, { text: "candidate account names recovered.", color: "white" }]);
    tools.printTable(
        ["#", "Username", "Target"],
        result.users.map((user, index) => [String(index + 1), user, result.target.host]),
    );
}

function formatCount(value: number): string {
    return String(Math.max(0, Math.floor(value))).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

const BRUTE_SPINNER = ["|", "/", "-", "\\"];
const BRUTE_CANDIDATES = ["123456", "password", "qwerty", "letmein", "dragon", "monkey", "summer2019", "hunter2", "trustno1", "iloveyou", "admin123", "changeme"];

async function runBruteforce(tools: CommandTools, state: ConsoleState): Promise<void> {
    const module = state.module!;
    const spec = BreachBackend.resolveWordlist(state.wordlist ?? "");
    const result = BreachBackend.check(state.rhost, module.id, { rport: state.rport, user: state.user, wordlist: state.wordlist });

    const listName = spec?.name ?? (state.wordlist ?? "").split(/[\\/]/).pop() ?? "wordlist";
    tools.println([
        { text: "[*] ", color: "cyan" },
        { text: "loading wordlist ..... ", color: "gray" },
        { text: listName, color: "white", bold: true },
        { text: spec ? ` (${formatCount(spec.entries)} entries)` : " (unrecognized)", color: "gray" },
    ]);
    await tools.sleep(TICK);
    tools.println([{ text: "[*] ", color: "cyan" }, { text: "attacking ftp auth ... ", color: "gray" }, { text: `${state.user}@${state.rhost}`, color: "white" }]);
    await tools.sleep(BEAT);

    if (!spec) {
        tools.println([{ text: "[-] ", color: "red", bold: true }, { text: result.reason || "wordlist not recognized.", color: "white" }]);
        return;
    }

    const total = spec.entries;
    const success = result.ok;
    const hitAt = success ? Math.max(1, Math.floor(total * (0.28 + Math.random() * 0.55))) : total;
    const steps = 7;
    for (let i = 1; i <= steps; i += 1) {
        const tried = Math.round((hitAt / steps) * i);
        const guess = BRUTE_CANDIDATES[(i - 1) % BRUTE_CANDIDATES.length];
        tools.println([
            { text: `[${BRUTE_SPINNER[i % BRUTE_SPINNER.length]}] `, color: "cyan" },
            { text: `${formatCount(tried)}/${formatCount(total)}  `, color: "gray" },
            { text: `${state.user}:${guess}`, color: "gray" },
        ]);
        await tools.sleep(300);
    }

    if (!success) {
        tools.println([{ text: "[-] ", color: "red", bold: true }, { text: `${formatCount(total)} candidates exhausted - ${result.reason}`, color: "white" }]);
        return;
    }

    tools.println([
        { text: "[+] ", color: "green", bold: true },
        { text: "password recovered  ", color: "white" },
        { text: `${state.user}:********`, color: "green", bold: true },
        { text: ` (after ${formatCount(hitAt)} attempts)`, color: "gray" },
    ]);
    await tools.sleep(TICK);

    const opened = BreachBackend.openSession(state.rhost, module.id, { rport: state.rport, user: state.user, wordlist: state.wordlist });
    if (!opened.ok) {
        tools.println([{ text: "[-] ", color: "red", bold: true }, { text: `exploit failed: ${opened.reason}`, color: "white" }]);
        return;
    }
    tools.println([{ text: "[+] ", color: "green", bold: true }, { text: `session ${opened.session.id} opened`, color: "white", bold: true }, { text: ` (${opened.session.user}@${opened.session.host})`, color: "gray" }]);
    const profile = getAccessProfile(opened.session.access);
    if (profile) tools.println([{ text: "    ", color: "gray" }, { text: `${profile.role} session.`, color: "cyan" }]);
    tools.println([{ text: "    ", color: "gray" }, { text: `type 'interact ${opened.session.id}' to enter the session.`, color: "gray" }]);
}

function asVulnTypes(list: string[]): VulnType[] {
    return list.filter((v): v is VulnType => (VALID_VULNS as string[]).includes(v));
}

function fingerprintedPorts(target: BreachResolvedTarget) {
    return target.ports.filter((p) => {
        const active = p.active === true || String(p.status ?? "").toUpperCase() === "OPEN";
        return active && p.service && p.version;
    });
}

function portLabel(port: { external?: number; port?: number; service?: string; version?: string }): string {
    return `${port.external ?? port.port ?? "-"}/${port.service ?? "unknown"} ${port.version ?? "unknown"}`;
}

function usablePort(target: BreachResolvedTarget, want?: string) {
    const ports = fingerprintedPorts(target);
    if (want) {
        const lower = want.toLowerCase();
        const asIndex = Number(want);
        if (Number.isInteger(asIndex) && asIndex >= 0 && asIndex < ports.length) return ports[asIndex];
        return ports.find((p) =>
            String(p.service).toLowerCase() === lower ||
            String(p.external ?? p.port) === want ||
            `${p.service ?? ""}/${p.external ?? p.port ?? ""}`.toLowerCase() === lower ||
            portLabel(p).toLowerCase().includes(lower)
        );
    }
    return ports.length === 1 ? ports[0] : undefined;
}

async function doDisasm(tools: CommandTools, state: ConsoleState, arg?: string): Promise<void> {
    if (!state.rhost) {
        tools.printError("RHOST is not set.");
        return;
    }
    const target = BreachBackend.resolveTarget(state.rhost);
    if (!target) {
        tools.printError("target could not be resolved.");
        return;
    }
    const candidates = fingerprintedPorts(target);
    const port = usablePort(target, arg);
    if (!port) {
        if (candidates.length === 0) {
            tools.printError("no fingerprinted service to analyze. scan it with 'nmap <ip> -sV' first.");
            return;
        }
        tools.printWarning("multiple fingerprinted services found. choose one to disassemble.");
        tools.printTable(
            ["#", "Port", "Service", "Version"],
            candidates.map((candidate, index) => [
                String(index),
                String(candidate.external ?? candidate.port ?? "-"),
                String(candidate.service ?? "unknown"),
                String(candidate.version ?? "unknown"),
            ]),
        );
        tools.println("usage: disasm <#|port|service>");
        tools.println("examples: disasm 0    disasm 8080    disasm http");
        return;
    }
    const service = String(port.service);
    const version = String(port.version);
    const portNum = port.external ?? port.port ?? 0;
    const override = getServiceBinaryOverride(service, version);
    const declaredVulns = asVulnTypes(target.vulnerabilities);
    const vulns = override?.vulns ? declaredVulns.filter((v) => override.vulns!.includes(v)) : declaredVulns;
    if (vulns.length === 0) {
        tools.printError("this service has no known weakness. nothing to develop here.");
        return;
    }

    tools.println([{ text: "[*] ", color: "cyan" }, { text: "pulling binary for ", color: "gray" }, { text: `${service} ${version}`, color: "white", bold: true }, { text: " ...", color: "gray" }]);
    await tools.sleep(BEAT);

    syncExternalServiceBinaries();
    const binary = resolveServiceBinary(service, version, vulns);
    state.lab = { service, version, port: portNum, vulns, binary, access: override?.access, desktop: override?.desktop };
    state.buildChain = [];

    tools.println([{ text: "[+] ", color: "green", bold: true }, { text: `${binary.functions.length} functions`, color: "white" }, { text: "    class ", color: "gray" }, { text: vulns.join(", "), color: "cyan" }]);
    if (binary.recipes && binary.recipes.length > 0) {
        tools.println([{ text: "[!] ", color: "yellow", bold: true }, { text: "This service needs multiple weak points chained together.", color: "white" }]);
    }
    tools.printTable(
        ["Function", "Action"],
        binary.functions.map((fn) => [fn.name, describeFunction(fn).action]),
    );
    tools.println("  inspect <function>    show source, action, safety step");
    tools.println("  build add <function>  add a function to the build chain");
    tools.println("  build compile         craft the exploit");
}

function findLabFunction(lab: LabState, name: string): BinaryFunction | undefined {
    return lab.binary.functions.find((fn) => fn.name.toLowerCase() === name.toLowerCase());
}

function doInspect(tools: CommandTools, state: ConsoleState, name?: string): void {
    if (!state.lab) {
        tools.printError("nothing disassembled. run 'disasm' first.");
        return;
    }
    if (!name) {
        tools.printError("usage: inspect <function>");
        return;
    }
    const fn = findLabFunction(state.lab, name);
    if (!fn) {
        tools.printError(`no function named ${name}.`);
        return;
    }
    const facts = describeFunction(fn);
    tools.println([{ text: facts.name, color: "white", bold: true }]);
    tools.println(`  Source ......... ${facts.source}`);
    tools.println(`  Action ......... ${facts.action}`);
    tools.println(`  Safety step .... ${facts.safety}`);
}

function craftModule(lab: LabState, functions: BinaryFunction[], vuln: VulnType): BreachModule {
    const slug = `${lab.service}_${lab.version}`.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
    const sourceNames = functions.map((fn) => fn.name).join("+");
    return {
        id: `exploit/crafted/${slug}_${vuln.toLowerCase()}`,
        name: `${lab.service} ${lab.version} ${vuln} (crafted)`,
        family: "exploit",
        service: lab.service,
        port: lab.port,
        versions: [lab.version],
        vulnerabilities: [vuln],
        privilege: CRAFT_PRIVILEGE[vuln],
        description: `Crafted from ${sourceNames} via exploit development against ${lab.service} ${lab.version}.`,
        access: lab.access,
        desktop: lab.desktop,
    };
}

function sameFunctionSet(a: string[], b: string[]): boolean {
    if (a.length !== b.length) return false;
    const left = [...a].map((item) => item.toLowerCase()).sort();
    const right = [...b].map((item) => item.toLowerCase()).sort();
    return left.every((item, index) => item === right[index]);
}

function recipeContaining(lab: LabState, name: string) {
    const lower = name.toLowerCase();
    const fn = findLabFunction(lab, name);
    return lab.binary.recipes?.find((recipe) => {
        if (recipe.functions?.some((item) => item.toLowerCase() === lower)) return true;
        if (!fn || !recipe.requirements) return false;
        return recipe.requirements.some((requirement) => requirementSatisfiedBy(fn, requirement));
    });
}

function requirementSatisfiedBy(fn: BinaryFunction, requirement: { actions: string[] }): boolean {
    return fn.source === "request" && !fn.guarded && requirement.actions.includes(fn.action);
}

function requirementsMatch(functions: BinaryFunction[], requirements: Array<{ actions: string[] }>): boolean {
    if (functions.length !== requirements.length) return false;
    const used = new Set<number>();

    function visit(index: number): boolean {
        if (index >= requirements.length) return true;
        const requirement = requirements[index];
        for (let i = 0; i < functions.length; i += 1) {
            if (used.has(i) || !requirementSatisfiedBy(functions[i], requirement)) continue;
            used.add(i);
            if (visit(index + 1)) return true;
            used.delete(i);
        }
        return false;
    }

    return visit(0);
}

function recipeMatches(recipe: NonNullable<ServiceBinaryModel["recipes"]>[number], functions: BinaryFunction[]): boolean {
    const selectedNames = functions.map((fn) => fn.name);
    if (recipe.functions && sameFunctionSet(recipe.functions, selectedNames)) return true;
    if (recipe.requirements && requirementsMatch(functions, recipe.requirements)) return true;
    return false;
}

function selectedBuildFunctions(lab: LabState, names: string[]): { ok: true; functions: BinaryFunction[] } | { ok: false; reason: string } {
    const functions: BinaryFunction[] = [];
    for (const name of names) {
        const fn = findLabFunction(lab, name);
        if (!fn) return { ok: false, reason: `no function named ${name}.` };
        functions.push(fn);
    }
    return { ok: true, functions };
}

function resolveBuildPlan(lab: LabState, functions: BinaryFunction[]) {
    if (functions.length === 0) return { ok: false as const, reason: "build chain is empty." };
    const selectedNames = functions.map((fn) => fn.name);
    const recipe = lab.binary.recipes?.find((item) => recipeMatches(item, functions));
    if (functions.length > 1 && !recipe) return { ok: false as const, reason: "selected functions do not form a valid exploit chain." };

    const requiredRecipe = functions.length === 1 ? recipeContaining(lab, functions[0].name) : undefined;
    if (requiredRecipe) {
        return {
            ok: false as const,
            reason: `${functions[0].name} is only one part of the ${requiredRecipe.vuln} chain. Add the missing weak points before compiling.`,
        };
    }

    const vuln = recipe?.vuln ?? lab.vulns.find((v) => isVulnerableTo(functions[0], v));
    if (!vuln) return { ok: false as const, reason: `${functions[0].name} is not exploitable for ${lab.vulns.join("/")}.` };

    return { ok: true as const, vuln, selectedNames };
}

function showBuildChain(tools: CommandTools, state: ConsoleState): void {
    if (!state.lab) {
        tools.printError("nothing disassembled. run 'disasm' first.");
        return;
    }
    const names = state.buildChain ?? [];
    if (names.length === 0) {
        tools.printInfo("build chain is empty.");
        tools.println("  build add <function>");
        return;
    }
    const resolved = selectedBuildFunctions(state.lab, names);
    if (!resolved.ok) {
        tools.printError(resolved.reason);
        return;
    }
    tools.println([{ text: "Build chain: ", color: "gray" }, { text: names.join(" + "), color: "white", bold: true }]);
    const plan = resolveBuildPlan(state.lab, resolved.functions);
    if (plan.ok) tools.println([{ text: "[+] ", color: "green", bold: true }, { text: `ready to compile ${plan.vuln}`, color: "white" }]);
    else tools.println([{ text: "[!] ", color: "yellow", bold: true }, { text: plan.reason, color: "white" }]);
}

async function compileBuildChain(tools: CommandTools, state: ConsoleState, names: string[]): Promise<void> {
    if (!state.lab) {
        tools.printError("nothing disassembled. run 'disasm' first.");
        return;
    }
    if (names.length === 0) {
        tools.printError("build chain is empty. use 'build add <function>' first.");
        return;
    }
    const lab = state.lab;
    const resolved = selectedBuildFunctions(lab, names);
    if (!resolved.ok) {
        tools.printError(resolved.reason);
        return;
    }
    const functions = resolved.functions;
    const plan = resolveBuildPlan(lab, functions);
    if (!plan.ok) {
        tools.println([{ text: "[-] ", color: "red", bold: true }, { text: plan.reason, color: "white" }]);
        return;
    }

    tools.println([{ text: "[*] ", color: "cyan" }, { text: `compiling ${plan.vuln} exploit from ${plan.selectedNames.join(" + ")} ...`, color: "gray" }]);
    await tools.sleep(BEAT);

    const result = BreachBackend.registerModule(craftModule(lab, functions, plan.vuln));
    if (!result.ok) {
        tools.printError(`build failed: ${result.reason}`);
        return;
    }
    tools.println([{ text: "[+] ", color: "green", bold: true }, { text: result.module.id, color: "white", bold: true }, { text: " crafted", color: "green" }]);
    tools.println([{ text: "    ", color: "gray" }, { text: `matches ${lab.service} ${lab.version}    use ${result.module.id}`, color: "gray" }]);
    state.buildChain = [];
}

async function doBuild(tools: CommandTools, state: ConsoleState, args: string[]): Promise<void> {
    if (!state.lab) {
        tools.printError("nothing disassembled. run 'disasm' first.");
        return;
    }
    const sub = String(args[0] ?? "").toLowerCase();
    const chain = state.buildChain ?? [];
    state.buildChain = chain;

    if (sub === "add") {
        const name = args[1];
        if (!name) {
            tools.printError("usage: build add <function>");
            return;
        }
        const fn = findLabFunction(state.lab, name);
        if (!fn) {
            tools.printError(`no function named ${name}.`);
            return;
        }
        if (!chain.some((item) => item.toLowerCase() === fn.name.toLowerCase())) chain.push(fn.name);
        tools.printSuccess(`added ${fn.name}`);
        showBuildChain(tools, state);
        return;
    }
    if (sub === "remove" || sub === "rm") {
        const name = args[1];
        if (!name) {
            tools.printError("usage: build remove <function>");
            return;
        }
        state.buildChain = chain.filter((item) => item.toLowerCase() !== name.toLowerCase());
        tools.printSuccess(`removed ${name}`);
        showBuildChain(tools, state);
        return;
    }
    if (sub === "show" || sub === "list") {
        showBuildChain(tools, state);
        return;
    }
    if (sub === "clear" || sub === "reset") {
        state.buildChain = [];
        tools.printInfo("build chain cleared.");
        return;
    }
    if (sub === "compile" || sub === "run") {
        await compileBuildChain(tools, state, chain);
        return;
    }
    tools.println("usage: build add <function> | build remove <function> | build show | build clear | build compile");
}

async function handlePayloads(tools: CommandTools, args: string[]): Promise<void> {
    const sub = String(args[0] ?? "list").toLowerCase();
    if (sub === "list" || sub === "ls") {
        printPayloads(tools, listReversePayloads());
        return;
    }
    if (sub === "info") {
        const payload = findReversePayload(args.slice(1).join(" "));
        if (!payload) tools.printError("payload not found.");
        else printPayloadInfo(tools, payload);
        return;
    }
    if (sub === "import" || sub === "install") {
        await importPayloadPackage(tools, args[1]);
        return;
    }
    tools.println("usage: payloads | payloads info <payload> | payloads import <package.rpkg>");
}

async function importPayloadPackage(tools: CommandTools, path?: string): Promise<void> {
    if (!path) {
        tools.printError("usage: payloads import <package.rpkg>");
        return;
    }
    const packageName = path.replace(/\\/g, "/").split("/").pop() ?? "";
    if (!packageName.toLowerCase().endsWith(".rpkg")) {
        tools.printError("payload import: expected an .rpkg package item.");
        return;
    }

    const candidates = [path, `~/downloads/${path}`, `~/desktop/${path}`, `~/documents/${path}`];
    let loadedPath = "";
    for (const candidate of candidates) {
        const file = await Files.getByPath(candidate);
        if (!file) continue;
        loadedPath = candidate;
        break;
    }
    if (!loadedPath) {
        tools.printError(`payload import: file not found: ${path}`);
        return;
    }

    const entitlement = findReversePayloadPackageEntitlement(packageName);
    if (!entitlement.ok) {
        tools.printError(`payload import: ${entitlement.reason}`);
        return;
    }

    registerReversePayload(entitlement.entitlement.payload);
    tools.printSuccess(`installed ${entitlement.entitlement.payload.id}`);
    tools.println([{ text: "provider: ", color: "gray" }, { text: entitlement.entitlement.providerId, color: "white" }]);
    tools.println([{ text: "source: ", color: "gray" }, { text: loadedPath, color: "white" }]);
}

function printPayloads(tools: CommandTools, payloads: ReversePayloadDefinition[]): void {
    tools.println([{ text: "Reverse payloads", color: "white", bold: true }]);
    if (payloads.length === 0) {
        tools.printWarning("no reverse payloads installed.");
        return;
    }
    tools.printTable(
        ["#", "Payload", "Family", "Delivery"],
        payloads.map((payload, index) => [String(index), payload.id, payload.family, payload.delivery]),
    );
}

function printPayloadInfo(tools: CommandTools, payload: ReversePayloadDefinition): void {
    tools.println([{ text: payload.id, color: "white", bold: true }]);
    tools.println(`name ........ ${payload.label}`);
    tools.println(`family ...... ${payload.family}`);
    tools.println(`delivery .... ${payload.delivery}`);
    tools.println(`fits ........ ${payload.affinities.join(", ")}`);
    tools.println(`notes ....... ${payload.summary}`);
}

function handleSessions(tools: CommandTools, state: ConsoleState, args: string[]): void {
    if (args[0] === "clear") {
        const count = BreachBackend.clearSessions("cleared");
        state.activeSessionId = undefined;
        tools.printSuccess(count === 1 ? "closed 1 session." : `closed ${count} sessions.`);
        return;
    }
    if (args[0] === "close") {
        const id = args[1];
        if (!id) {
            tools.printError("usage: sessions close <session-id>");
            return;
        }
        if (BreachBackend.closeSession(id, "closed")) {
            if (state.activeSessionId === id) state.activeSessionId = undefined;
            tools.printSuccess(`closed session ${id}.`);
        } else {
            tools.printError(`session ${id} not found.`);
        }
        return;
    }
    if (args[0] === "-i" || args[0] === "interact") {
        const id = args[1];
        if (!id) tools.printError("usage: sessions -i <session-id>");
        else activateSession(tools, state, id);
        return;
    }

    const sessions = BreachBackend.listSessions();
    if (sessions.length === 0) {
        tools.printWarning("no active sessions.");
        return;
    }

    tools.printTable(
        ["ID", "Target", "User", "Module", "CWD"],
        sessions.map((session) => [session.id, `${session.host} (${session.ip})`, session.user, shortModule(session.moduleId), session.cwd]),
    );
    tools.println("cleanup: sessions close <id>    sessions clear");
}

function activateSession(tools: CommandTools, state: ConsoleState, id: string): void {
    const session = BreachBackend.getSession(id);
    if (!session) {
        tools.printError(`session ${id} not found.`);
        return;
    }

    state.activeSessionId = session.id;
    tools.println([{ text: "[*] ", color: "cyan" }, { text: `interacting with session ${session.id}. type 'background' to return.`, color: "gray" }]);
}

async function runSessionCommand(tools: CommandTools, state: ConsoleState, line: string): Promise<boolean> {
    const sessionId = state.activeSessionId;
    const session = sessionId ? BreachBackend.getSession(sessionId) : undefined;
    if (!session) {
        state.activeSessionId = undefined;
        tools.printWarning("session closed.");
        return false;
    }

    const [commandRaw, ...args] = splitArgs(line);
    const command = commandRaw.toLowerCase();

    if (["background", "bg", "exit"].includes(command)) {
        state.activeSessionId = undefined;
        tools.printInfo("backgrounded session.");
        return false;
    }
    if (command === "help" || command === "-") {
        printSessionHelp(tools, session.access);
        return false;
    }
    if (command === "close") {
        BreachBackend.closeSession(session.id);
        state.activeSessionId = undefined;
        tools.printWarning(`session ${session.id} closed.`);
        return false;
    }
    if (["shutdown", "poweroff", "halt"].includes(command)) {
        tools.println([{ text: "[*] ", color: "cyan" }, { text: `issuing shutdown on ${session.host} ...`, color: "gray" }]);
        await tools.sleep(BEAT);
        ReconNgEvents.emit("ReconNg.Breach.Shutdown", { sessionId: session.id, ip: session.ip, host: session.host });
        BreachBackend.closeSession(session.id);
        state.activeSessionId = undefined;
        tools.println([{ text: "[+] ", color: "green", bold: true }, { text: `${session.host} is going dark - connection lost.`, color: "white" }]);
        return false;
    }

    const profile = getAccessProfile(session.access);
    if (profile) {
        const entry = profile.commands.find((item) => item.name.toLowerCase() === command);
        if (!entry) {
            tools.printError(`${commandRaw}: not available in a ${profile.role} session.`);
            return false;
        }
        runAccessCommand(tools, session, entry, args);
        return false;
    }

    if (command === "pwd") {
        tools.println(session.cwd);
        return false;
    }
    if (command === "whoami") {
        tools.println(session.user);
        return false;
    }
    if (command === "su") {
        const user = args[0] || "root";
        const password = await tools.prompt({ label: "Password >", password: true });
        const result = BreachBackend.escalateSession(session.id, user, password);
        if (!result.ok) tools.printError(`su: ${result.reason}`);
        else tools.printSuccess(`session user switched to ${result.session.user}`);
        return false;
    }
    if (command === "sudo") {
        const password = args[0];
        if (!password) {
            tools.printError("usage: sudo <password>");
            return false;
        }
        const result = BreachBackend.escalateSession(session.id, "root", password);
        if (!result.ok) tools.printError(`sudo: ${result.reason}`);
        else tools.printSuccess("root privileges acquired");
        return false;
    }
    if (command === "ls") {
        const names = BreachBackend.list(session, args[0] ?? ".");
        if (!names) tools.printError("ls: directory not found");
        else if (names.length === 0) tools.println("* empty");
        else tools.println(names.join("  "));
        return false;
    }
    if (command === "cd") {
        const result = BreachBackend.cd(session, args[0] ?? "/");
        if (!result.ok) tools.printError(`cd: ${result.reason}`);
        return false;
    }
    if (command === "cat") {
        const path = args[0];
        if (!path) {
            tools.printError("usage: cat <file>");
            return false;
        }
        const file = BreachBackend.read(session, path);
        if (!file) tools.printError("cat: unable to read file");
        else {
            tools.println([{ text: `--- ${file.path} `, color: "gray" }, { text: "-----------", color: "gray" }]);
            printFileContent(tools, file.data);
        }
        return false;
    }
    if (command === "download" || command === "pull") {
        await downloadFile(tools, session, args[0]);
        return false;
    }
    if (command === "rm" || command === "delete") {
        const path = args[0];
        if (!path) {
            tools.printError("usage: rm <file>");
            return false;
        }
        const result = BreachBackend.remove(session, path);
        if (!result.ok) tools.printError(`rm: ${result.reason}`);
        else tools.printSuccess(`removed ${result.path}`);
        return false;
    }
    if (command === "post") {
        const id = args[0];
        if (!id) {
            const mods = BreachBackend.getPostModules();
            if (mods.length === 0) {
                tools.printWarning("no post modules available.");
                return false;
            }
            tools.printTable(
                ["#", "Post module", "Grants"],
                mods.map((module, index) => [String(index), module.id, module.access === "desktop" ? "desktop" : module.privilege]),
            );
            return false;
        }
        const result = BreachBackend.runPost(session.id, id);
        if (!result.ok) {
            tools.printError(`post: ${result.reason}`);
            return false;
        }
        tools.println([{ text: "[+] ", color: "green", bold: true }, { text: result.module.id, color: "white", bold: true }, { text: " ran", color: "green" }]);
        for (const effect of result.effects) {
            tools.println([{ text: "    ", color: "gray" }, { text: effect, color: "cyan" }]);
        }
        return false;
    }

    tools.printError(`${commandRaw}: command not found in session`);
    return false;
}

function runAccessCommand(tools: CommandTools, session: BreachSession, entry: AccessCommand, args: string[]): void {
    if (entry.kind === "list") {
        const names = BreachBackend.list(session, entry.path);
        if (!names) tools.printError(`${entry.name}: nothing here.`);
        else if (names.length === 0) tools.println("* empty");
        else tools.println(names.join("  "));
        return;
    }
    const arg = args[0] ?? "";
    const path = entry.path.replace("{arg}", arg);
    const file = BreachBackend.read(session, path);
    if (!file) {
        tools.printError(`${entry.name}: not found.`);
        return;
    }
    tools.println([{ text: `--- ${file.path} `, color: "gray" }, { text: "-----------", color: "gray" }]);
    printFileContent(tools, file.data);
}

function printFileContent(tools: CommandTools, data: string): void {
    for (const line of String(data ?? "").split("\n")) {
        tools.println(line.length ? line : " ");
    }
}

async function downloadFile(tools: CommandTools, session: BreachSession, path?: string): Promise<void> {
    if (!path) {
        tools.printError("usage: download <file>");
        return;
    }
    const file = BreachBackend.readQuiet(session, path);
    if (!file) {
        tools.printError("download: unable to read file");
        return;
    }
    const fullName = safeDownloadName(session, file.path);
    const existing = await Files.getByPath(`~/downloads/${fullName}`);
    if (existing) Files.write(existing.id, file.data);
    else {
        const { name, extension } = splitFileName(fullName);
        await Files.create({ name, extension, parentPath: "~/downloads", data: file.data });
    }
    const localPath = `~/downloads/${fullName}`;
    ReconNgEvents.emit("ReconNg.Breach.FileDownloaded", {
        sessionId: session.id,
        ip: session.ip,
        host: session.host,
        path: file.path,
        name: file.path.split("/").pop() ?? fullName,
        localPath,
    });
    BreachBackend.noteAccess(session, "get", file.path);
    tools.printSuccess(`saved ${localPath}`);
}

function splitArgs(input: string): string[] {
    const result: string[] = [];
    const pattern = /"([^"]*)"|'([^']*)'|(\S+)/g;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(input))) result.push(match[1] ?? match[2] ?? match[3] ?? "");
    return result;
}

function promptLabel(state: ConsoleState): string {
    if (state.activeSessionId) {
        const session = BreachBackend.getSession(state.activeSessionId);
        if (session) return `session(${session.id}) ${session.user}@${session.host}:${session.cwd}$ `;
    }
    if (state.module) return `${PROMPT} ${shortModule(state.module.id)} > `;
    if (state.payload) return `${PROMPT} ${shortModule(state.payload.id)} > `;
    return `${PROMPT} > `;
}

function printSplash(tools: CommandTools, commandName: string): void {
    const banner = [
        " ____  _____  ____ ___  _   _       _   _  ____ ",
        "|  _ \\| ____|/ ___/ _ \\| \\ | |     | \\ | |/ ___|",
        "| |_) |  _| | |  | | | |  \\| |_____|  \\| | |  _ ",
        "|  _ <| |___| |__| |_| | |\\  |_____| |\\  | |_| |",
        "|_| \\_\\_____|\\____\\___/|_| \\_|     |_| \\_|\\____|",
    ];
    for (const line of banner) tools.println([{ text: line, color: "cyan" }]);
    tools.println([
        { text: "recon-ng", color: "white", bold: true },
        { text: " // breach workspace", color: "gray" },
        { text: " // rng6", color: "cyan" },
    ]);
    tools.println([
        { text: "entry: ", color: "gray" },
        { text: commandName === "rng" ? "rng" : "recon-ng", color: "white" },
        { text: "    resolver: ", color: "gray" },
        { text: "service/version/vuln", color: "white" },
        { text: "    fs: ", color: "gray" },
        { text: "synthetic", color: "white" },
    ]);
    tools.println([{ text: "type ", color: "gray" }, { text: "help", color: "white", bold: true }, { text: " to list commands.", color: "gray" }]);
    tools.newLine();
}

function printHelp(tools: CommandTools): void {
    tools.println("Core commands");
    tools.println("  set RHOST <ip-or-domain>      choose target");
    tools.println("  set RPORT <port>              target port (defaults to the service's default port on use)");
    tools.println("  set USER <username>           supply an account when a module needs one");
    tools.println("  set WORDLIST <path>           supply a password list for brute modules");
    tools.println("  search [service/module]       list exploit modules");
    tools.println("  payloads                      list reverse callback payloads");
    tools.println("  payloads import <file>        install a reverse payload package");
    tools.println("  payloads info <payload>       show payload fit and delivery details");
    tools.println("  use <module|index>            select module");
    tools.println("  info [module]                 show module detail");
    tools.println("  show options                  show selected target/module");
    tools.println("  check                         verify target match");
    tools.println("  run                           launch selected module");
    tools.println("  sessions                      list sessions");
    tools.println("  sessions close <id>           close a saved session");
    tools.println("  sessions clear                 close all saved sessions");
    tools.println("  interact <id>                 enter a session");
    tools.println("  back                          unload module");
    tools.println("  exit                          close recon-ng");
    tools.newLine();
    tools.println("Exploit development");
    tools.println("  disasm [#|port|service]       pull and analyze the selected service binary");
    tools.println("  inspect <function>            read what a function does with input");
    tools.println("  build add <function>          add a function to the build chain");
    tools.println("  build remove <function>       remove a function from the build chain");
    tools.println("  build show                    show the current build chain");
    tools.println("  build clear                   clear the current build chain");
    tools.println("  build compile                 develop an exploit from the build chain");
}

function printSessionHelp(tools: CommandTools, access?: string): void {
    const profile = access ? getAccessProfile(access) : undefined;
    if (profile) {
        tools.println(`${profile.role} session`);
        for (const entry of profile.commands) {
            const usage = entry.kind === "read" ? `${entry.name} <id>` : entry.name;
            tools.println(`  ${usage.padEnd(18)}${entry.description ?? ""}`);
        }
        tools.println("  background         return to recon-ng");
        tools.println("  close             close this session");
        return;
    }
    tools.println("Session commands");
    tools.println("  ls [path]          list files");
    tools.println("  cd <path>          change directory");
    tools.println("  pwd                print current directory");
    tools.println("  whoami             print session user");
    tools.println("  su [user]          switch user with a cracked password");
    tools.println("  sudo <password>    switch to root with a cracked password");
    tools.println("  cat <file>         read file");
    tools.println("  download <file>    save file to ~/downloads");
    tools.println("  rm <file>          remove file when permitted");
    tools.println("  post [module]      list or run post-exploitation modules");
    tools.println("  background         return to recon-ng");
    tools.println("  close              close this session");
}

function printModules(tools: CommandTools, modules: BreachModule[], label: string): void {
    tools.println([{ text: "Modules: ", color: "white", bold: true }, { text: label, color: "gray" }]);
    if (modules.length === 0) {
        tools.printWarning("no matching modules.");
        return;
    }
    tools.printTable(
        ["#", "Module", "Service", "Priv"],
        modules.map((module) => [
            String(BreachBackend.getModules().findIndex((item) => item.id === module.id)),
            module.id,
            module.service,
            module.privilege,
        ]),
    );
}

function printModuleInfo(tools: CommandTools, module: BreachModule): void {
    tools.println([{ text: module.id, color: "white", bold: true }]);
    tools.println(`name ........ ${module.name}`);
    tools.println(`service ..... ${module.service}${module.port ? `/${module.port}` : ""}`);
    tools.println(`rport ...... ${module.requiresRport ? "required" : "optional"}`);
    tools.println(`user ....... ${module.requiresUser ? "required" : "optional"}`);
    tools.println(`wordlist ... ${module.requiresWordlist ? "required" : "optional"}`);
    tools.println(`versions .... ${(module.versions ?? ["any"]).join(", ")}`);
    tools.println(`vulns ....... ${(module.vulnerabilities ?? ["service-match"]).join(", ")}`);
    tools.println(`privilege ... ${module.privilege}`);
    tools.println(`notes ....... ${module.description}`);
}

function printOptions(tools: CommandTools, state: ConsoleState): void {
    if (state.payload) {
        tools.printTable(
            ["Name", "Current Setting", "Required", "Description"],
            [
                ["LHOST", state.lhost ?? "", "yes", "Your callback address"],
                ["LPORT", state.lport !== undefined ? String(state.lport) : "", "yes", "Your callback port"],
                ["TARGET", state.target ?? "", "yes", "Person to lure (email or profile)"],
                ["PAYLOAD", state.payload.id, "yes", "Loaded reverse payload"],
            ],
        );
        return;
    }
    const rportRequired = state.module?.requiresRport ? "yes" : "no";
    const userRequired = state.module?.requiresUser ? "yes" : "no";
    const wordlistRequired = state.module?.requiresWordlist ? "yes" : "no";
    tools.printTable(
        ["Name", "Current Setting", "Required", "Description"],
        [
            ["RHOST", state.rhost || "", "yes", "Target IP or domain"],
            ["RPORT", state.rport !== undefined ? String(state.rport) : "", rportRequired, "Target port (module default until changed)"],
            ["USER", state.user ?? "", userRequired, "Target account username"],
            ["WORDLIST", state.wordlist ?? "", wordlistRequired, "Password list to brute with"],
            ["MODULE", state.module?.id ?? "", "yes", "Loaded exploit module"],
        ],
    );
}

function shortModule(moduleId: string): string {
    return moduleId.split("/").slice(-1)[0] ?? moduleId;
}

function safeDownloadName(session: BreachSession, path: string): string {
    const base = path.replace(/[\\/]+$/, "").split(/[\\/]/).pop() ?? "";
    return base.replace(/[^a-z0-9._-]/gi, "_").slice(0, 72) || `session_${session.id}_download.txt`;
}

function splitFileName(fullName: string): { name: string; extension: string } {
    const idx = fullName.lastIndexOf(".");
    if (idx <= 0 || idx === fullName.length - 1) return { name: fullName, extension: "txt" };
    return { name: fullName.slice(0, idx), extension: fullName.slice(idx + 1) };
}

@RegisterCommand
export class ReconNgCommand extends Command {
    CommandName = "recon-ng";
    Description = "Interactive exploitation workspace. Alias: rng";
    PackageName = "recon-ng";

    Autocomplete: CommandAutoComplete[] = [
        { label: "recon-ng", type: "STRING" },
    ];

    Run(tools: CommandTools): Promise<void> {
        return runReconNg(tools, this.CommandName);
    }
}

@RegisterCommand
export class RngCommand extends Command {
    CommandName = "rng";
    Description = "Alias for recon-ng.";
    PackageName = "recon-ng";

    Autocomplete: CommandAutoComplete[] = [
        { label: "rng", type: "STRING" },
    ];

    Run(tools: CommandTools): Promise<void> {
        return runReconNg(tools, this.CommandName);
    }
}
