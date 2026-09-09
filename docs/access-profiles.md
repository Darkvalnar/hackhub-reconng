# Session Access Profiles

## Documentation Pages

- [recon-ng Mod Author SDK](index.md)
- [Quick Integration](quick-integration.md)
- [Player Guide](player-guide.md)
- [Source Layout](source-layout.md)
- [How Matching Works](matching.md)
- [Modules](modules.md)
- [Authoring an Exploit](authoring-exploits.md)
- [Exploit Development](exploit-development.md)
- [Standing Up a Target](targets.md)
- [Events](events.md)
- [Quest Loot Overlays](loot-overlays.md)
- [SSH Username Enumeration](user-enumeration.md)
- [Session Control](session-control.md)
- [Wordlists](wordlists.md)
- [Reverse Payloads](reverse-payloads.md)
- [Session Access Profiles](access-profiles.md)
- [Generated Filesystem](generated-filesystem.md)
- [Troubleshooting](troubleshooting.md)
- [HawkEye Desktop Contract](hawkeye.md)

---

## Session access profiles

By default a breached session is a shell: `ls`, `cd`, `cat`, `download`, `rm`,
`post`. An exploit can instead open a **scoped session** with its own limited
command set, driven by an **access profile**. This is how you make an RCE open a
memory-fragment viewer, an SSRF open a packet monitor, an LFI open a route-map
reader, and so on.

A profile session is **scoped**: only `background`, `help`, and `close` carry over.
The generic shell commands are gone; the only other commands are the ones the
profile declares. So a profile is a small, self-contained environment, not the
shell with extra verbs.

### The shape

A profile is plain data:

```ts
interface AccessProfile {
    id: string;                 // referenced by an exploit's `access` field
    role: string;               // shown as "<role> session" and in the prompt
    commands: AccessCommand[];
}

interface AccessCommand {
    name: string;               // the verb the player types
    kind: "list" | "read";      // list a directory, or read one file
    path: string;               // list: a directory; read: a template with {arg}
    description-: string;        // shown in the session `help`
}
```

- A `list` command runs like `ls <path>` over the session's files.
- A `read` command runs like `cat`, substituting the player's argument into
  `{arg}`. `readmem 004` with path `/mem/fragments/memory_leak_{arg}.bin` reads
  `/mem/fragments/memory_leak_004.bin`.

Both read the session's own filesystem, so they fire the normal
`ReconNg.Breach.FileRead` event and respect per-file `readable`.

### Built-in profiles

Five ship ready to use:

| id | role | commands |
|---|---|---|
| `memory-leak` | memory-gill | `memlist`, `readmem <id>` |
| `packet-tap` | packet-tap | `captures`, `capread <name>` |
| `firmware-extract` | firmware-extract | `fwlist`, `fwread <name>` |
| `process-view` | process-lantern | `ps`, `penv <pid>` |
| `route-map` | route-reef | `routes`, `routeread <name>` |

### Making an exploit open a profile

Set the exploit's `access` to a profile `id` (default is `shell`; `desktop` is
reserved for the GUI signal):

```ts
// an authored module
{ id: "exploit/tcp/whalesync_1_4_rce", /* ... */, access: "memory-leak" }
```

For a **player-crafted** exploit, put `access` on the target's binary override so
the crafted module inherits it:

```ts
registerServiceBinary({
    service: "tcp",
    version: "WhaleSync 1.4",
    access: "memory-leak",
    functions: [ /* ... */ ],
});
```

Now when the player develops and runs that exploit, `run` reports
`memory-gill session.` and the session exposes only `memlist` / `readmem`.

### Putting the files in place

Profiles only surface files that exist in the session. Plant the reward/view
files with `attachLoot`, at the paths the profile reads:

```ts
BreachBackend.attachLoot("whaleSync.lab", [
    { path: "/mem/fragments/memory_leak_004.bin", data: "LAST_SYNC_HOST=krakenGate.hadal\n..." },
]);
```

### Registering your own profile

In this mod's bundle:

```ts
import { registerAccessProfile } from "../world/SessionAccess";

registerAccessProfile({
    id: "camera-feed",
    role: "lens-tap",
    commands: [
        { name: "feeds", kind: "list", path: "/dev/video" },
        { name: "snap",  kind: "read", path: "/dev/video/{arg}.frame" },
    ],
});
```

From a **separate mod** (no import needed): recon-ng reads profiles from the
`SharedStorage` key **`reconng.access.profiles`** each time the workspace opens,
so it is load-order independent. Append your profile (all JSON):

```ts
import { SharedStorage } from "@hotbunny/hackhub-content-sdk";

const KEY = "reconng.access.profiles";
const current = SharedStorage.get<any[]>(KEY) ?? [];
SharedStorage.set(KEY, [
    ...current.filter((p) => p.id !== "camera-feed"),
    { id: "camera-feed", role: "lens-tap", commands: [
        { name: "feeds", kind: "list", path: "/dev/video" },
        { name: "snap",  kind: "read", path: "/dev/video/{arg}.frame" },
    ]},
]);
```

Because profiles are pure data, the cross-mod path supports the `list` and `read`
command kinds only (which read the session's files). A command that runs custom
logic would need an in-bundle profile, not a `SharedStorage` one.

### Complete example

A whole mission outcome, in-bundle: the scoped session type, an exploit that opens
it, the reward file it reads, and a quest reacting to the read.

```ts
import { Events } from "@hotbunny/hackhub-content-sdk";
import { BreachBackend } from "../world/BreachBackend";
import { registerAccessProfile } from "../world/SessionAccess";

// 1. the scoped session type (memory-leak also ships built-in; shown for clarity)
registerAccessProfile({
    id: "memory-leak",
    role: "memory-gill",
    commands: [
        { name: "memlist", kind: "list", path: "/mem/fragments" },
        { name: "readmem", kind: "read", path: "/mem/fragments/memory_leak_{arg}.bin" },
    ],
});

// 2. an exploit that opens it (set `access` to the profile id)
BreachBackend.registerModule({
    id: "exploit/sync/whalesync_1_4_rce",
    name: "WhaleSync 1.4 packet RCE",
    family: "exploit",
    service: "sync",
    port: 9001,
    versions: ["WhaleSync 1.4"],
    vulnerabilities: ["RCE"],
    privilege: "user",
    description: "Overflows the WhaleSync packet parser.",
    access: "memory-leak",
});

// 3. plant the reward file the profile reads (attach by host or IP)
BreachBackend.attachLoot("whaleSync.lab", [
    { path: "/mem/fragments/memory_leak_004.bin", data: "LAST_SYNC_HOST=krakenGate.hadal\n" },
]);

// 4. react when the player reads it
Events.on("ReconNg.Breach.FileRead", (event: any) => {
    if (event.name === "memory_leak_004.bin") {
        // complete the objective
    }
});
```

In-game, against a `whaleSync.lab` running `WhaleSync 1.4` on 9001:
`use exploit/sync/whalesync_1_4_rce` then `run` then `interact 1` then `memlist`
then `readmem 004`. The session exposes only `memlist` / `readmem`, and `readmem`
fires `FileRead`. For a **player-crafted** version, drop the `access` onto the
target's binary override instead (see [Making an exploit open a
profile](#making-an-exploit-open-a-profile)) so the crafted module inherits it.
