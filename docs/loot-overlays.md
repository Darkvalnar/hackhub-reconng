# Quest Loot Overlays

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

## Quest loot overlays

Loot overlays add files onto a host's generated filesystem. Overlays key by host
or IP and merge into every session opened on that target, so you can plant quest
evidence.

From another mod, publish overlays to `SharedStorage` key `reconng.loot`:

```ts
import { SharedStorage } from "@hotbunny/hackhub-content-sdk";

const KEY = "reconng.loot";
const current = SharedStorage.get<any[]>(KEY) ?? [];

SharedStorage.set(KEY, [
    ...current.filter((overlay) => overlay?.target !== "demo-target.example"),
    {
        target: "demo-target.example",
        files: [
            {
                path: "/opt/case/evidence.txt",
                data: "case-specific evidence\n",
                readable: true,
                downloadable: true,
                deletable: false,
            },
        ],
    },
]);
```

recon-ng reads shared overlays when a session opens. Shared overlays are not
copied into recon-ng's per-save backend state, so large generated worlds do not
inflate the player's save file just because they exist. If the same target/path
is published again, the newest shared file for that path wins when the session
filesystem is built.

Inside recon-ng's own bundle, `BreachBackend.attachLoot(target, files)` and
`BreachBackend.clearLoot(target)` are also available.
