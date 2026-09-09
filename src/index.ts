import { Bootstrap, RegisterModPackage, Handbook } from "@hotbunny/hackhub-content-sdk";
import "./commands/ReconNgCommand";
import "./apps/HawkEyeApp";
import { registerHawkEyeAppBridge } from "./apps/HawkEyeApp";
import { registerHostFileBridge } from "./world/HostFileBridge";
import "./quests/ReconNgDemoQuest";
import { deactivateReconNgTestLab, registerReconNgTestLab, unregisterLabWordlists } from "./world/ReconNgTestLab";
import { deactivateExampleTarget, registerExampleTarget } from "./world/ExampleTarget";
import { registerExploitShop, unregisterExploitShop } from "./world/ExampleExploitShop";
import { registerBuiltInAccessProfiles } from "./world/SessionAccess";
import { deactivateExampleAccessTarget, registerExampleAccessTarget } from "./world/ExampleAccessTarget";
import { DEMO_CONTENT_SETTING_KEY, initDemoContent, isDemoContentEnabled } from "./world/DemoContent";
import { deactivateReconNgDemoWorld } from "./world/ReconNgDemoWorld";
import { installReconNgStorageGateway } from "./world/ReconNgStorage";
import { syncExternalBreachContent } from "./world/BreachContentSync";
import { syncExternalAccessProfiles } from "./world/SessionAccessSync";
import { syncExternalServiceBinaries } from "./world/ServiceBinarySync";
import { syncExternalReversePayloads } from "./world/ReversePayloads";

const HANDBOOK_ENTRY_ID = "recon-ng-guide";
const SSH_ENUM_ENTRY_ID = "recon-ng-ssh-user-enum";

const HANDBOOK_CONTENT = `
# recon-ng

recon-ng is an interactive exploitation workspace for exploit modules, remote
sessions, and post-exploitation tools.

## Starting recon-ng

\`\`\`
recon-ng
rng
\`\`\`

## Exploit modules

Use \`search <service-or-module>\` to narrow the module catalogue. Use \`search\`
without a query to list every module.

\`\`\`
search <service-or-module>
info <module-or-index>
use <module-or-index>
set RHOST <ip-or-domain>
show options
check
run
\`\`\`

\`use\` sets \`RPORT\` to the service's default port (for example 22 for SSH).
If the scan shows that service on another reachable port, set \`RPORT\` to that
port. Some modules also require \`USER\` or \`WORDLIST\`. Use \`info\` or
\`show options\` to review the required settings.

## Reverse payloads

Install a downloaded payload package with \`payloads import\`.

\`\`\`
payloads import <package.rpkg>
\`\`\`

## Choosing a payload

Use \`payloads\` to list the payloads currently installed.

\`\`\`
payloads
payloads info <payload-or-index>
\`\`\`

\`payloads info\` shows three details:

- **Delivery:** how the callback is presented.
- **Fits:** the pretexts the payload is designed to support.
- **Notes:** a summary of the payload and its intended use.

Choose a payload whose \`fits\` entries match the pretext used for the target, then
load it:

\`\`\`
use <payload-or-index>
\`\`\`

## Starting a callback

Forward a port through your router to the LAN address of your current device. Keep
that forwarding rule active until the callback arrives.

Configure the listener inside recon-ng:

\`\`\`
set LHOST <lan-address>
set LPORT <forwarded-port>
set TARGET <target-email>
show options
run
\`\`\`

\`run\` prints the callback URL and begins listening. Place that exact URL into the
message being sent to the target.

A successful callback opens a new session. If it does not arrive immediately, the
listener remains active in the background:

\`\`\`
sessions
sessions -i <session-id>
\`\`\`

The payload must fit the chosen pretext, the recipient must match \`TARGET\`, and
the callback port must remain reachable.

## Sessions

Use \`sessions\` to list open sessions and \`interact <id>\` or
\`sessions -i <id>\` to enter one. \`sessions close <id>\` closes one saved session,
while \`sessions clear\` closes all of them.

Inside a normal shell session, use \`ls\`, \`cd\`, \`pwd\`, \`whoami\`,
\`su [user]\`, \`sudo <password>\`, \`cat <file>\`, \`download <file>\`,
\`rm <file>\`, \`post [module]\`, \`background\`, and \`close\`.

Downloaded files are saved to \`~/downloads\`.

## Post-exploitation modules

| Module | Effect |
|---|---|
| \`post/multi/gui/desktop_implant\` | Opens desktop access when the target supports it |
| \`post/loot/passwd_dump\` | Reads hash entries from \`/etc/passwd\` |
`.trim();

const EXPLOIT_DEV_ENTRY_ID = "recon-ng-exploit-dev";

const SSH_ENUM_CONTENT = `
# SSH Username Enumeration

The SSH username enumeration module probes a remote SSH service for valid account
names.

\`\`\`
set RHOST <target>
use auxiliary/scanner/ssh/user_enum
show options
check
run
\`\`\`
`.trim();

const EXPLOIT_DEV_CONTENT = `
# Exploit Development

Exploit development builds a module for a specific service version. Crafted modules
are saved in the module catalogue.

## Disassembly

Set \`RHOST\`, then run \`disasm\` to analyze a service.

\`\`\`
set RHOST <ip-or-domain>
disasm
\`\`\`

If several services are exposed, select one by list number, port, or service name:

\`\`\`
disasm 0
disasm 8080
disasm http
\`\`\`

## Build commands

| Command | Effect |
|---|---|
| \`disasm [#\\|port\\|service]\` | Analyze the selected service and list its functions |
| \`inspect <function>\` | Show a function's source, action, and safety step |
| \`build add <function>\` | Add a function to the build chain |
| \`build remove <function>\` | Remove a function from the build chain |
| \`build show\` | Review the current chain |
| \`build clear\` | Empty the current chain |
| \`build compile\` | Compile the selected functions into an exploit |

## Reading a function

\`inspect\` reports three facts:

- **Source:** \`request\` means the input can be controlled remotely. \`config\`,
  \`disk\`, and \`internal\` are trusted sources.
- **Action:** what the function does with that input.
- **Safety step:** the check that blocks unsafe input. \`none\` means no protection
  was found at that function.

Select a function with a \`request\` source, no safety step, and an action that belongs
to the reported weakness class.

## Dangerous actions by class

| Class | Dangerous action |
|---|---|
| RCE | Functions that execute shell commands, write into a fixed memory buffer, load as a plugin target, spawn a worker task or deserialize into an object |
| SQL_INJECTION | Functions that affect the database by building a query or filter, or by formatting into a report template |
| XSS | Functions that write into HTTP responses, format into a template or store as a field within a profile |
| LFI | Functions that interact with files by opening a local file, concatenating a path, resolving inside an archive path or partially normalizing a path |
| RFI | Functions that are included as a remote resource, get parsed as a remote resource scheme or follow as redirect target |
| SSRF | Functions that operate on the server by fetching as a server-side URL, following a redirect target or building a metadata service route |
| CORS | Functions that reflect to the requesting origin, write into the response header or merge either into an origin allowlist or a tenant CORS config |

## Chained weaknesses

When \`disasm\` reports multiple weak points, a single function is not enough to build
an exploit. Instead, you will have to build a chain consisting of a function that
takes in data, in addition to one or more dangerous actions.

Functions that take in data handle or parse request headers, cookies, bodies,
multipart uploads, JSON or query parameters.

## Spotting decoys

Near-miss functions usually fail for one of these reasons:

- The action looks useful, but its source is trusted and cannot be controlled.
- The source is a request, but a safety step guards the action.
- The source is a request and no safety step appears, but the action is harmless.
- The function belongs to a different weakness class than the one reported.

## Single-vector example

One function carries the whole weakness, so only the dangerous one is added.

\`\`\`
disasm 0
inspect handle_login
inspect run_task
build add run_task
build show
build compile
[+] exploit/crafted/litehttp_2_0_rce crafted
\`\`\`

## Chained example

The dangerous action is out of reach on its own, so a function that reads the
request is added alongside it.

\`\`\`
disasm 0
inspect read_header
inspect copy_frame
build add read_header
build add copy_frame
build show
build compile
[+] exploit/crafted/litehttp_2_1_rce crafted
\`\`\`

## Guarded functions

A guarded function cannot be used, alone or in a chain. If every function matching
the reported class is guarded, the service cannot be developed against.

## After compiling

Use the crafted module like any other exploit:

\`\`\`
use <crafted-module>
check
run
\`\`\`
`.trim();

@RegisterModPackage
export default class ReconNg extends Bootstrap {
    Settings = [
        {
            key: DEMO_CONTENT_SETTING_KEY,
            label: "Practice targets",
            type: "toggle" as const,
            default: false,
        },
    ];

    OnModPackageLoaded() {
        installReconNgStorageGateway();
        initDemoContent();
        registerHawkEyeAppBridge();
        registerHostFileBridge();
        registerBuiltInAccessProfiles();
        syncExternalBreachContent();
        syncExternalAccessProfiles();
        syncExternalServiceBinaries();
        syncExternalReversePayloads();
        if (isDemoContentEnabled()) {
            registerReconNgTestLab();
            registerExampleTarget();
            registerExampleAccessTarget();
            registerExploitShop();
        } else {
            unregisterExploitShop();
            unregisterLabWordlists();
            deactivateReconNgDemoWorld();
            deactivateReconNgTestLab();
            deactivateExampleTarget();
            deactivateExampleAccessTarget();
        }
        Handbook.registerEntry({
            id: HANDBOOK_ENTRY_ID,
            category: "recon-ng",
            title: "Recon-NG Workspace",
            content: HANDBOOK_CONTENT,
            order: 0,
        });
        Handbook.registerEntry({
            id: SSH_ENUM_ENTRY_ID,
            category: "recon-ng",
            title: "SSH Username Enumeration",
            content: SSH_ENUM_CONTENT,
            order: 1,
        });
        Handbook.registerEntry({
            id: EXPLOIT_DEV_ENTRY_ID,
            category: "recon-ng",
            title: "Exploit Development",
            content: EXPLOIT_DEV_CONTENT,
            order: 2,
        });
    }

    OnModPackageUnloaded() {
        // Unload runs without a mod context, so these permission gated calls can throw. Guarding
        // each one keeps a failure from stranding the entries that come after it.
        for (const id of [HANDBOOK_ENTRY_ID, SSH_ENUM_ENTRY_ID, EXPLOIT_DEV_ENTRY_ID]) {
            try {
                Handbook.unregisterEntry(id);
            } catch { }
        }
    }
}
