# Standing Up a Target

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

## Standing up a target

Any mod can create targets with the Network SDK, and recon-ng matches them against
every installed module automatically. A breach-able target needs an active port
with a canonical `service` and a `version`, plus the required vulnerability types
on its domain.

```ts
const ip = Network.randomIp();
const domain = "demo-target.example";
const vulns = [{ type: "RCE" as const }];

Network.createSubnetNetwork({
    ip,
    type: NetworkDeviceType.Device,
    name: "Demo Target",
    domain: { name: domain, vulnerabilities: vulns },
    ports: [
        { external: 80, internal: 80, active: true, service: "http", version: "nginx 1.18.0" },
    ],
    users: [Network.createUser({ username: "operator", password: "operator", online: true })],
});

Network.registerDomain(domain, ip, vulns);
Network.setVulnerabilities(ip, vulns);
```

This target matches the built-in `exploit/http/nginx_chunked_size` (http, port 80,
`nginx 1.18.0`, RCE).

### Register targets at quest runtime

Register quest targets from `OnStart` or `OnObjectivesStart`, which run on claim
and on every game load, not from `OnModPackageLoaded`. A network created at
mod-load resolves by name but loses its ports and vulnerabilities through a save
load, so `check` then fails with "service, version, or vulnerability state does
not match".

```ts
OnObjectivesStart(): void {
    registerMyQuestTarget();
}
```

Guard subnet creation with `if (!Network.getSubnet(ip))` and re-attach the domain
and vulnerabilities every call. Do not `destroyNetwork` then recreate without
awaiting, because `destroyNetwork` is async and can tear down the fresh subnet.

## The network types recon-ng reads

These are the SDK types recon-ng depends on, from `@hotbunny/hackhub-content-sdk`:

```ts
enum NetworkDeviceType { Router = "ROUTER", Device = "DEVICE", Firewall = "FIREWALL", Splitter = "SPLITTER", Printer = "PRINTER" }

interface NetworkVulnerability {
    type: "SQL_INJECTION" | "XSS" | "CORS" | "SSRF" | "LFI" | "RFI" | "RCE";
    version-: string;
}

interface NetworkDomain {
    name: string;
    vulnerabilities-: NetworkVulnerability[];
}

// Passed to Network.createSubnetNetwork()
interface NetworkPort {
    external: number;
    internal: number;
    active-: boolean;
    locked-: boolean;
    service-: string;
    version-: string;
}

// Returned by Network.getSubnet() and getSubnetByDomain()
interface SubnetInfo {
    ip: string;
    lanIp-: string;
    type: string;
    domain-: { name: string; vulnerabilities-: NetworkVulnerability[] };
    online-: boolean;
    ports: { port: number; service-: string; version-: string; active-: boolean }[];
    users: { username: string }[];
}
```

The creation shape uses `external` and `internal`. The resolved shape exposes
`port`. recon-ng reads `external -- port`, so target definitions written either way
match.
