# recon-ng Mod Author SDK

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

## Overview

`recon-ng` adds an interactive exploitation workspace to HackHub. Players select
an exploit module, validate it against a real in-game network target, launch it,
and on success drop into a synthetic post-exploitation session with a generated
remote filesystem they can read, download from, and modify.

There are three things mod authors do with it:

1. Stand up targets that recon-ng can breach (pure Network SDK, works from any mod).
2. Author exploit modules with their own service, version, and vulnerability
   requirements (JSON files, or the backend API if you bundle recon-ng).
3. React to breaches through the `ReconNg.Breach.*` events (works from any mod).

If you are editing the mod source, the one file you will touch most is
`src/world/BreachBackend.ts`. The shipped exploits and the matching logic both
live there. See [Source layout](source-layout.md).
