export type VulnType =
    | "SQL_INJECTION"
    | "XSS"
    | "CORS"
    | "SSRF"
    | "LFI"
    | "RFI"
    | "RCE";

export type FunctionSource = "request" | "config" | "disk" | "internal";

export type FunctionAction =
    | "parse_header"
    | "parse_cookie"
    | "parse_body"
    | "decode_param"
    | "read_multipart"
    | "parse_json"
    | "read_query_param"
    | "concat_path"
    | "format_template"
    | "merge_config"
    | "deserialize_blob"
    | "expand_macro"
    | "normalize_partial_path"
    | "redirect_follow"
    | "tenant_config_merge"
    | "filter_builder"
    | "report_template"
    | "profile_store"
    | "archive_resolver"
    | "scheme_parser"
    | "metadata_route_builder"
    | "allowlist_merge"
    | "load_plugin"
    | "spawn_worker"
    | "write_header"
    | "exec_command"
    | "copy_fixed_buffer"
    | "db_query"
    | "render_page"
    | "open_file"
    | "include_remote"
    | "fetch_url"
    | "reflect_origin"
    | "log_write"
    | "count_metric"
    | "store_session"
    | "copy_dynamic_buffer";

export interface BinaryFunction {
    name: string;
    source: FunctionSource;
    action: FunctionAction;
    guarded: boolean;
    param: number;
}

export interface ExploitRecipe {
    vuln: VulnType;
    functions?: string[];
    requirements?: ExploitRequirement[];
    label?: string;
}

export interface ExploitRequirement {
    role: string;
    actions: FunctionAction[];
}

export interface ServiceBinaryModel {
    service: string;
    version: string;
    functions: BinaryFunction[];
    recipes?: ExploitRecipe[];
}

export interface FunctionFacts {
    name: string;
    source: string;
    action: string;
    safety: string;
}

const UNTRUSTED_SOURCES: FunctionSource[] = ["request"];
const TRUSTED_SOURCES: FunctionSource[] = ["config", "disk", "internal"];

export const VULN_ACTIONS: Record<VulnType, FunctionAction[]> = {
    RCE: ["exec_command", "copy_fixed_buffer", "deserialize_blob", "load_plugin", "spawn_worker"],
    SQL_INJECTION: ["db_query", "filter_builder"],
    XSS: ["render_page", "format_template", "profile_store"],
    LFI: ["open_file", "concat_path", "archive_resolver", "normalize_partial_path"],
    // Every action here must map back to the same class in ACTION_VULN, because that is what
    // isVulnerableTo checks when a single function is compiled on its own. redirect_follow belongs
    // to SSRF there, and metadata_route_builder maps to nothing, so neither can stand alone as an
    // RFI or SSRF sink. Both remain valid intermediate steps in CHAIN_PATTERNS.
    RFI: ["include_remote", "scheme_parser"],
    SSRF: ["fetch_url", "redirect_follow"],
    CORS: ["reflect_origin", "write_header", "allowlist_merge", "tenant_config_merge"],
};

export const ACTION_VULN: Partial<Record<FunctionAction, VulnType>> = {
    exec_command: "RCE",
    copy_fixed_buffer: "RCE",
    deserialize_blob: "RCE",
    load_plugin: "RCE",
    spawn_worker: "RCE",
    db_query: "SQL_INJECTION",
    filter_builder: "SQL_INJECTION",
    render_page: "XSS",
    format_template: "XSS",
    profile_store: "XSS",
    open_file: "LFI",
    concat_path: "LFI",
    archive_resolver: "LFI",
    normalize_partial_path: "LFI",
    include_remote: "RFI",
    scheme_parser: "RFI",
    redirect_follow: "SSRF",
    fetch_url: "SSRF",
    metadata_route_builder: "SSRF",
    reflect_origin: "CORS",
    write_header: "CORS",
    allowlist_merge: "CORS",
    tenant_config_merge: "CORS",
};

// Two invariants the player depends on, checked at load because breaking either one produces a
// target that looks solvable and is not. Warns rather than throws: a mismatch spoils some targets
// but is not worth taking the mod down over.
function auditActionTables(): void {
    for (const [vuln, actions] of Object.entries(VULN_ACTIONS)) {
        for (const action of actions) {
            // A single function can only be compiled if its action maps back to the class that
            // produced it, so a sink that maps elsewhere is an unsolvable target.
            if (ACTION_VULN[action] !== vuln) {
                console.warn(
                    `[recon-ng] ${action} is a ${vuln} sink but ACTION_VULN maps it to ${ACTION_VULN[action] ?? "nothing"}. `
                    + "Single-vector services using it cannot be compiled.",
                );
            }
        }
    }
    for (const action of DANGEROUS_ACTIONS) {
        // Off-type decoys are only fair if the player can look the action up and see it belongs to
        // another class. An unmapped one is dangerous-looking, unguarded, and unclassifiable.
        if (!ACTION_VULN[action]) {
            console.warn(
                `[recon-ng] ${action} is used as a decoy but belongs to no class, so nothing tells `
                + "the player why it fails.",
            );
        }
    }
}

const DANGEROUS_ACTIONS: FunctionAction[] = [
    "exec_command",
    "copy_fixed_buffer",
    "db_query",
    "render_page",
    "open_file",
    "include_remote",
    "fetch_url",
    "reflect_origin",
    "deserialize_blob",
    "load_plugin",
    "spawn_worker",
    "filter_builder",
    "format_template",
    "profile_store",
    "concat_path",
    "archive_resolver",
    "normalize_partial_path",
    "scheme_parser",
    "redirect_follow",
    "metadata_route_builder",
    "write_header",
    "allowlist_merge",
    "tenant_config_merge",
];

const HARMLESS_ACTIONS: FunctionAction[] = [
    "log_write",
    "count_metric",
    "store_session",
    "copy_dynamic_buffer",
];

auditActionTables();

export const SOURCE_TEXT: Record<FunctionSource, string> = {
    request: "request",
    config: "config",
    disk: "disk",
    internal: "internal",
};

export const ACTION_TEXT: Record<FunctionAction, string> = {
    parse_header: "parses a request header",
    parse_cookie: "parses a request cookie",
    parse_body: "parses the request body",
    decode_param: "decodes a request parameter",
    read_multipart: "reads a multipart upload",
    parse_json: "parses JSON from the request",
    read_query_param: "reads a query parameter",
    concat_path: "concatenates it into a filesystem path",
    format_template: "formats it into a template",
    merge_config: "merges it into runtime config",
    deserialize_blob: "deserializes it into an object",
    expand_macro: "expands it as a macro",
    normalize_partial_path: "partially normalizes a file path",
    redirect_follow: "follows it as a redirect target",
    tenant_config_merge: "merges it into tenant CORS config",
    filter_builder: "builds a database filter with it",
    report_template: "formats it into a report template",
    profile_store: "stores it in a profile field",
    archive_resolver: "resolves it inside an archive path",
    scheme_parser: "parses it as a remote resource scheme",
    metadata_route_builder: "builds a metadata service route",
    allowlist_merge: "merges it into an origin allowlist",
    exec_command: "executes it as a shell command",
    copy_fixed_buffer: "copies it into a fixed-size buffer",
    db_query: "builds a database query with it",
    render_page: "writes it into the HTTP response",
    open_file: "opens it as a local file",
    include_remote: "includes it as a remote resource",
    fetch_url: "fetches it as a server-side URL",
    reflect_origin: "reflects it to the requesting origin",
    log_write: "writes it to the log",
    count_metric: "counts it as a metric",
    store_session: "stores it in the session",
    copy_dynamic_buffer: "copies it into a growable buffer",
    load_plugin: "loads it as a plugin target",
    spawn_worker: "spawns it as a worker task",
    write_header: "writes it into a response header",
};

export const GUARD_TEXT: Partial<Record<FunctionAction, string>> = {
    parse_header: "validates the header name",
    parse_cookie: "validates the cookie format",
    parse_body: "validates the body schema",
    decode_param: "validates decoded characters",
    read_multipart: "validates multipart boundaries",
    parse_json: "validates JSON schema",
    read_query_param: "validates query keys",
    concat_path: "normalizes the path",
    format_template: "escapes template variables",
    merge_config: "rejects unsafe keys",
    deserialize_blob: "requires a signed payload",
    expand_macro: "restricts macro names",
    normalize_partial_path: "rejects traversal segments",
    redirect_follow: "validates redirect hosts",
    tenant_config_merge: "validates tenant policy",
    filter_builder: "parameterizes filter values",
    report_template: "encodes report fields",
    profile_store: "encodes stored profile fields",
    archive_resolver: "restricts archive roots",
    scheme_parser: "restricts remote schemes",
    metadata_route_builder: "blocks metadata ranges",
    allowlist_merge: "validates the allowlist entry",
    exec_command: "sanitizes shell metacharacters",
    copy_fixed_buffer: "bounds-checks the length",
    db_query: "parameterizes the query",
    render_page: "encodes the output",
    open_file: "normalizes the path",
    include_remote: "restricts to local paths",
    fetch_url: "blocks internal addresses",
    reflect_origin: "validates the origin",
    load_plugin: "verifies the plugin signature",
    spawn_worker: "validates worker names",
    write_header: "validates the header value",
};

export function isUntrusted(source: FunctionSource): boolean {
    return UNTRUSTED_SOURCES.includes(source);
}

export function isVulnerableTo(fn: BinaryFunction, vuln: VulnType): boolean {
    return isUntrusted(fn.source) && ACTION_VULN[fn.action] === vuln && !fn.guarded;
}

export function findTargets(model: ServiceBinaryModel, vuln: VulnType): BinaryFunction[] {
    return model.functions.filter((fn) => isVulnerableTo(fn, vuln));
}

export function describeFunction(fn: BinaryFunction): FunctionFacts {
    const guardLabel = GUARD_TEXT[fn.action];
    const safety = fn.guarded && guardLabel ? guardLabel : "none";
    return {
        name: fn.name,
        source: SOURCE_TEXT[fn.source],
        action: ACTION_TEXT[fn.action],
        safety,
    };
}

function xmur3(str: string): () => number {
    let h = 1779033703 ^ str.length;
    for (let i = 0; i < str.length; i += 1) {
        h = Math.imul(h ^ str.charCodeAt(i), 3432918353);
        h = (h << 13) | (h >>> 19);
    }
    return () => {
        h = Math.imul(h ^ (h >>> 16), 2246822507);
        h = Math.imul(h ^ (h >>> 13), 3266489909);
        h ^= h >>> 16;
        return h >>> 0;
    };
}

function mulberry32(seed: number): () => number {
    let a = seed >>> 0;
    return () => {
        a = (a + 0x6d2b79f5) | 0;
        let t = Math.imul(a ^ (a >>> 15), 1 | a);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

const VERBS = [
    "parse", "handle", "read", "load", "write", "render", "fetch", "store",
    "check", "copy", "route", "decode", "validate", "lookup", "serve", "queue",
    "apply", "map", "build", "scan",
];

const NOUNS = [
    "request", "header", "cookie", "token", "session", "query", "path", "url",
    "body", "param", "field", "user", "config", "page", "file", "log",
    "profile", "upload", "search", "auth", "record", "entry",
];

function pick<T>(rng: () => number, arr: readonly T[]): T {
    return arr[Math.floor(rng() * arr.length)];
}

function intBetween(rng: () => number, min: number, max: number): number {
    return min + Math.floor(rng() * (max - min + 1));
}

function uniqueName(rng: () => number, used: Set<string>): string {
    for (let i = 0; i < 200; i += 1) {
        const name = `${pick(rng, VERBS)}_${pick(rng, NOUNS)}`;
        if (!used.has(name)) {
            used.add(name);
            return name;
        }
    }
    const base = `${pick(rng, VERBS)}_${pick(rng, NOUNS)}`;
    let suffix = 1;
    let name = base;
    while (used.has(name)) {
        name = `${base}_${suffix}`;
        suffix += 1;
    }
    used.add(name);
    return name;
}

function paramFor(rng: () => number, action: FunctionAction): number {
    if (action === "copy_fixed_buffer") {
        return pick(rng, [32, 48, 64, 96, 128, 192, 256, 384, 512]);
    }
    return intBetween(rng, 0x1000, 0xffff);
}

function shuffle<T>(rng: () => number, arr: T[]): void {
    for (let i = arr.length - 1; i > 0; i -= 1) {
        const j = Math.floor(rng() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
}

function dedupe(types: VulnType[]): VulnType[] {
    return [...new Set(types)];
}

const INPUT_ACTIONS: FunctionAction[] = [
    "parse_header",
    "parse_cookie",
    "parse_body",
    "decode_param",
    "read_multipart",
    "parse_json",
    "read_query_param",
];

const CHAIN_PATTERNS: Record<VulnType, ExploitRequirement[][]> = {
    RCE: [
        [{ role: "input", actions: INPUT_ACTIONS }, { role: "memory vector", actions: ["copy_fixed_buffer", "deserialize_blob"] }],
        [{ role: "input", actions: INPUT_ACTIONS }, { role: "dispatch", actions: ["load_plugin", "spawn_worker"] }, { role: "execution sink", actions: ["exec_command"] }],
        [{ role: "input", actions: INPUT_ACTIONS }, { role: "decoder", actions: ["deserialize_blob"] }, { role: "loader", actions: ["load_plugin"] }, { role: "execution sink", actions: ["exec_command"] }],
    ],
    SQL_INJECTION: [
        [{ role: "input", actions: INPUT_ACTIONS }, { role: "query sink", actions: ["db_query"] }],
        [{ role: "input", actions: INPUT_ACTIONS }, { role: "filter builder", actions: ["filter_builder"] }, { role: "query sink", actions: ["db_query"] }],
        [{ role: "input", actions: INPUT_ACTIONS }, { role: "report template", actions: ["report_template"] }, { role: "filter builder", actions: ["filter_builder"] }, { role: "query sink", actions: ["db_query"] }],
    ],
    XSS: [
        [{ role: "input", actions: INPUT_ACTIONS }, { role: "render sink", actions: ["render_page"] }],
        [{ role: "input", actions: INPUT_ACTIONS }, { role: "template formatter", actions: ["format_template"] }, { role: "render sink", actions: ["render_page"] }],
        [{ role: "input", actions: INPUT_ACTIONS }, { role: "stored field", actions: ["profile_store"] }, { role: "template formatter", actions: ["format_template"] }, { role: "render sink", actions: ["render_page"] }],
    ],
    LFI: [
        [{ role: "input", actions: INPUT_ACTIONS }, { role: "file sink", actions: ["open_file"] }],
        [{ role: "input", actions: INPUT_ACTIONS }, { role: "path builder", actions: ["concat_path", "normalize_partial_path"] }, { role: "file sink", actions: ["open_file"] }],
        [{ role: "input", actions: INPUT_ACTIONS }, { role: "archive resolver", actions: ["archive_resolver"] }, { role: "path builder", actions: ["concat_path", "normalize_partial_path"] }, { role: "file sink", actions: ["open_file"] }],
    ],
    RFI: [
        [{ role: "input", actions: INPUT_ACTIONS }, { role: "remote include sink", actions: ["include_remote"] }],
        [{ role: "input", actions: INPUT_ACTIONS }, { role: "scheme parser", actions: ["scheme_parser"] }, { role: "remote include sink", actions: ["include_remote"] }],
        [{ role: "input", actions: INPUT_ACTIONS }, { role: "redirect resolver", actions: ["redirect_follow"] }, { role: "scheme parser", actions: ["scheme_parser"] }, { role: "remote include sink", actions: ["include_remote"] }],
    ],
    SSRF: [
        [{ role: "input", actions: INPUT_ACTIONS }, { role: "fetch sink", actions: ["fetch_url"] }],
        [{ role: "input", actions: INPUT_ACTIONS }, { role: "redirect resolver", actions: ["redirect_follow"] }, { role: "fetch sink", actions: ["fetch_url"] }],
        [{ role: "input", actions: INPUT_ACTIONS }, { role: "metadata route", actions: ["metadata_route_builder"] }, { role: "redirect resolver", actions: ["redirect_follow"] }, { role: "fetch sink", actions: ["fetch_url"] }],
    ],
    CORS: [
        [{ role: "input", actions: INPUT_ACTIONS }, { role: "origin sink", actions: ["reflect_origin", "write_header"] }],
        [{ role: "input", actions: INPUT_ACTIONS }, { role: "allowlist merge", actions: ["allowlist_merge"] }, { role: "origin sink", actions: ["reflect_origin", "write_header"] }],
        [{ role: "input", actions: INPUT_ACTIONS }, { role: "tenant config", actions: ["tenant_config_merge"] }, { role: "allowlist merge", actions: ["allowlist_merge"] }, { role: "origin sink", actions: ["reflect_origin", "write_header"] }],
    ],
};

function chainSize(rng: () => number): number {
    const roll = rng();
    if (roll < 0.80) return 1;
    if (roll < 0.94) return 2;
    if (roll < 0.99) return 3;
    return 4;
}

function requirementsFor(vuln: VulnType, size: number): ExploitRequirement[] {
    if (size <= 1) return [];
    const patterns = CHAIN_PATTERNS[vuln];
    return patterns[Math.min(Math.max(size - 2, 0), patterns.length - 1)].map((requirement) => ({
        ...requirement,
        actions: [...requirement.actions],
    }));
}

type DecoyKind = "guard" | "source" | "harmless" | "offtype";

export interface GenerateOptions {
    decoys?: number;
    seed?: string;
    exploitable?: boolean;
}

export function generateServiceBinary(
    service: string,
    version: string,
    vulnTypes: VulnType[],
    opts: GenerateOptions = {},
): ServiceBinaryModel {
    const seedSource = opts.seed ?? `${service.toLowerCase()}@${version.toLowerCase()}`;
    const seed = xmur3(seedSource)();
    const rng = mulberry32(seed);
    const declared = dedupe(vulnTypes);
    const exploitable = opts.exploitable ?? true;
    const functions: BinaryFunction[] = [];
    const recipes: ExploitRecipe[] = [];
    const used = new Set<string>();

    for (const vuln of declared) {
        const size = exploitable ? chainSize(rng) : 1;
        const requirements = requirementsFor(vuln, size);
        const steps = requirements.length > 0
            ? requirements
            : [{ role: "sink", actions: VULN_ACTIONS[vuln] }];
        for (const step of steps) {
            const action = pick(rng, step.actions);
            const name = uniqueName(rng, used);
            functions.push({
                name,
                source: "request",
                action,
                guarded: !exploitable,
                param: paramFor(rng, action),
            });
        }
        if (requirements.length > 0) {
            recipes.push({ vuln, requirements, label: `${vuln.toLowerCase()} chain` });
        }
    }

    const offtypeActions = DANGEROUS_ACTIONS.filter(
        (action) => !declared.includes(ACTION_VULN[action] as VulnType),
    );
    const kinds: DecoyKind[] = ["guard", "source", "harmless"];
    if (offtypeActions.length > 0) kinds.push("offtype");

    const targetFunctionCount = opts.decoys
        ? functions.length + opts.decoys
        : recipes.length > 0 ? intBetween(rng, 12, 18) : intBetween(rng, 8, 14);
    const decoyCount = Math.max(3, targetFunctionCount - functions.length);
    for (let i = 0; i < decoyCount; i += 1) {
        const kind = pick(rng, kinds);
        let fn: BinaryFunction;
        if (kind === "guard") {
            const action = pick(rng, DANGEROUS_ACTIONS);
            fn = { name: uniqueName(rng, used), source: "request", action, guarded: true, param: paramFor(rng, action) };
        } else if (kind === "source") {
            const action = pick(rng, DANGEROUS_ACTIONS);
            fn = { name: uniqueName(rng, used), source: pick(rng, TRUSTED_SOURCES), action, guarded: false, param: paramFor(rng, action) };
        } else if (kind === "harmless") {
            const action = pick(rng, HARMLESS_ACTIONS);
            fn = { name: uniqueName(rng, used), source: "request", action, guarded: false, param: paramFor(rng, action) };
        } else {
            const action = pick(rng, offtypeActions);
            fn = { name: uniqueName(rng, used), source: "request", action, guarded: false, param: paramFor(rng, action) };
        }
        functions.push(fn);
    }

    shuffle(rng, functions);
    return { service, version, functions, recipes: recipes.length > 0 ? recipes : undefined };
}

export interface ServiceBinaryOverride {
    service: string;
    version: string;
    functions?: BinaryFunction[];
    recipes?: ExploitRecipe[];
    decoys?: number;
    seed?: string;
    exploitable?: boolean;
    access?: string;
    vulns?: VulnType[];
    desktop?: { os: "linux" | "windows"; profile: string; label?: string };
}

const overrideRegistry = new Map<string, ServiceBinaryOverride>();

function overrideKey(service: string, version: string): string {
    return `${service.toLowerCase()}@${version.toLowerCase()}`;
}

export function registerServiceBinary(override: ServiceBinaryOverride): void {
    overrideRegistry.set(overrideKey(override.service, override.version), override);
}

export function unregisterServiceBinary(service: string, version: string): void {
    overrideRegistry.delete(overrideKey(service, version));
}

export function getServiceBinaryOverride(service: string, version: string): ServiceBinaryOverride | undefined {
    return overrideRegistry.get(overrideKey(service, version));
}

export function clearServiceBinaryOverrides(): void {
    overrideRegistry.clear();
}

function ensureSolvable(model: ServiceBinaryModel, declared: VulnType[]): ServiceBinaryModel {
    const rng = mulberry32(xmur3(`${overrideKey(model.service, model.version)}@fill`)());
    const used = new Set(model.functions.map((fn) => fn.name));
    for (const vuln of declared) {
        const recipe = model.recipes?.find((item) => item.vuln === vuln);
        if (!recipe && findTargets(model, vuln).length === 0) {
            const action = pick(rng, VULN_ACTIONS[vuln]);
            model.functions.push({
                name: uniqueName(rng, used),
                source: "request",
                action,
                guarded: false,
                param: paramFor(rng, action),
            });
        }
    }
    return model;
}

export function resolveServiceBinary(
    service: string,
    version: string,
    vulnTypes: VulnType[],
): ServiceBinaryModel {
    const declared = dedupe(vulnTypes);
    const override = getServiceBinaryOverride(service, version);
    if (override?.functions && override.functions.length > 0) {
        const functions = override.functions.map((fn) => ({ ...fn }));
        const recipes = override.recipes?.map((recipe) => ({
            ...recipe,
            functions: recipe.functions ? [...recipe.functions] : undefined,
            requirements: recipe.requirements?.map((requirement) => ({ ...requirement, actions: [...requirement.actions] })),
        }));
        if (override.exploitable === false) return { service, version, functions, recipes };
        return ensureSolvable({ service, version, functions, recipes }, declared);
    }
    return generateServiceBinary(service, version, declared, {
        decoys: override?.decoys,
        seed: override?.seed,
        exploitable: override?.exploitable,
    });
}
