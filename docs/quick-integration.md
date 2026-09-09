# Quick Integration

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

## Quick integration (start here)

The smallest useful integration from a **separate mod**: stand up a hackable box
and react when the player breaches it. No recon-ng import required, everything here
is SDK plus events.

```ts
import { Network, NetworkDeviceType, Events } from "@hotbunny/hackhub-content-sdk";

export function registerMyTarget(): void {
    const ip = "203.0.113.50";
    const vulns = [{ type: "RCE" as const }];
    if (!Network.getSubnet(ip)) {
        Network.createSubnetNetwork({
            ip,
            type: NetworkDeviceType.Router,
            accessable: true,
            name: "My Box",
            domain: { name: "my-box.test", vulnerabilities: vulns },
            ports: [{ external: 80, internal: 80, active: true, service: "http", version: "nginx 1.18.0" }],
            users: [Network.createUser({ username: "operator", password: "operator", online: true })],
            children: [],
        });
    }
    Network.registerDomain("my-box.test", ip, vulns);
    Network.setVulnerabilities(ip, vulns);
}

Events.on("ReconNg.Breach.SessionOpened", (event: any) => {
    if (event.host === "my-box.test") {
        // your quest logic: the player just breached your box
    }
});
```

Call `registerMyTarget()` from your `OnModPackageLoaded`. `nginx 1.18.0` is covered
by a built-in exploit, so the player can breach it immediately; your mod reacts to
the event. That is a complete loop with zero recon-ng code.

From there, the surfaces most mods reach for next are
[Quest loot overlays](loot-overlays.md) to plant files on a host,
[Session control](session-control.md) to close a host off or kick the player out
of it, and [Wordlists](wordlists.md) to put a brute-forceable host behind a list
the player has to earn. Each is a SharedStorage key.

### API surfaces: cross-mod vs in-bundle

Two surfaces, and every page in this documentation belongs to one of them:

| Cross-mod (any mod, SDK only) | In-bundle (only if you bundle or fork recon-ng and import its TypeScript) |
|---|---|
| Create targets with `Network.*` | `BreachBackend.*` (`registerModule`, `grantExploit`, `attachLoot`, sessions) |
| Listen to `ReconNg.Breach.*` events | Edit `BREACH_MODULES` / `POST_MODULES` |
| Register authored exploits via `SharedStorage` key `reconng.modules` | `registerServiceBinary()`, `registerAccessProfile()` |
| Register loot overlays via `SharedStorage` key `reconng.loot` | |
| Register SSH username-enumeration targets via `SharedStorage` key `reconng.user.enum.targets` | `BreachBackend.registerUserEnumTarget()` |
| Ship optional `.rng` JSON files the player can `load` manually | |
| Register binary overrides via `SharedStorage` key `reconng.binary.overrides` | |
| Register access profiles via `SharedStorage` key `reconng.access.profiles` | |

Rule of thumb: if an example imports from `../world/...` or calls `BreachBackend`,
it is in-bundle. If it only uses the SDK (`Network`, `Events`, `SharedStorage`,
`Files`), it is cross-mod.
