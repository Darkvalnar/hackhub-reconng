# HawkEye Desktop Contract

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

HawkEye is a generic desktop viewer for ReconNG sessions. Do not hardcode quest or open-world content into `hawkeye.html`.

The intended contract is:

1. Register a real network target.
2. Publish a ReconNG module that grants desktop access.
3. Publish ReconNG loot files for the same target domain and/or IP.
4. Let HawkEye render the resulting ReconNG session filesystem.

## Desktop Module Contract

A module becomes HawkEye-compatible when it grants desktop access and includes a desktop profile:

```ts
publishBreachModule({
  id: "exploit/windows/rdp/example_desktop_rce",
  name: "Example Desktop RCE",
  family: "exploit",
  service: "rdp",
  port: 3389,
  versions: ["Example RDP 1.0"],
  vulnerabilities: ["RCE"],
  privilege: "user",
  access: "desktop",
  description: "Opens a desktop-capable ReconNG session.",
  desktop: {
    os: "windows",
    profile: "win10-ws",
    label: "EXAMPLE-WORKSTATION",
  },
});
```

Supported desktop OS values:

- `windows`
- `linux`

`desktop.label` is the machine label shown in HawkEye.

## File/Loot Contract

HawkEye reads the ReconNG session filesystem. Files come from:

- ReconNG's generic filesystem for the target/service.
- Loot overlays published through `reconng.loot`.

Publish loot against every identifier the player may use:

```ts
const files = [
  {
    path: "/Users/rcade/Desktop/review_queue.txt",
    data: "pending review queue...",
  },
  {
    path: "/Users/rcade/Documents/remote_access_notes.txt",
    data: "gateway=vpn.example.net\nprofile=rcade-review-ws\n",
  },
];

publishReconNgLoot("workstation.example.net", files);
publishReconNgLoot("104.16.250.130", files);
```

HawkEye lists files where `readable !== false`.

Optional file flags:

```ts
{
  path: "/Users/rcade/Documents/private_note.txt",
  data: "text",
  readable: true,
  downloadable: true,
  deletable: false,
}
```

HawkEye currently uses `readable`. The other flags are useful for ReconNG shell behavior.

## Windows Path Mapping

ReconNG stores all session paths as normalized slash paths. HawkEye maps those paths into Windows-looking paths for Windows desktops.

Default Windows mapping:

```ts
"/Users/rcade/Documents/file.txt"
```

renders as:

```text
C:\Users\rcade\Documents\file.txt
```

## Adding Another Drive

To show a new drive, publish files under:

```text
/drives/<letter>/...
```

Example:

```ts
publishReconNgLoot("workstation.example.net", [
  {
    path: "/drives/d/Evidence/case_index.txt",
    data: "case_id,status\nMC-7721,review\n",
  },
  {
    path: "/drives/d/Evidence/exports/claims_batch.csv",
    data: "claim_id,policy,status\nMC-7721,HQ-1183,review\n",
  },
]);
```

HawkEye renders those as:

```text
D:\Evidence\case_index.txt
D:\Evidence\exports\claims_batch.csv
```

The `D:` drive appears automatically in:

- `This PC`
- The Explorer sidebar
- The desktop shortcut area, when at least one non-`C:` drive exists

This is display mapping only. The underlying ReconNG shell path remains `/drives/d/...`.

## Linux Path Mapping

Linux desktops render paths directly:

```ts
{
  path: "/home/relay/Documents/ops_notes.txt",
  data: "notes...",
}
```

renders as:

```text
/home/relay/Documents/ops_notes.txt
```

## Cleanup

HawkEye targets are derived from active ReconNG sessions.

These commands remove HawkEye access by closing sessions:

```text
sessions close <id>
sessions clear
```

No separate HawkEye cleanup API is needed.

## Current Scope

Supported today:

- Custom desktop-capable modules.
- Custom machine labels.
- Custom files/folders.
- Extra Windows drive letters through `/drives/<letter>/...`.
- Windows and Linux desktop shells.

Not currently supported:

- Per-target custom desktop apps.
- Per-target custom icons beyond drive/folder/file rendering.
- Quest-specific behavior inside HawkEye HTML.

If per-target apps are needed later, add a separate desktop manifest contract instead of hardcoding behavior into `hawkeye.html`.
