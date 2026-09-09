# Source Layout

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

## Source layout: where to change things

```txt
src/
  index.ts                     registers the command, demo quest, and handbook entry
  commands/ReconNgCommand.ts   the recon-ng / rng terminal command and session shell
  world/BreachBackend.ts       shipped modules + matching engine + sessions + filesystem
  world/ExampleExploitShop.ts  example locked exploit + purchase helper
  world/ExampleTarget.ts       example target for locked/desktop access flow
  world/ReconNgDemoWorld.ts    the demo target (breach-demo.io)
  world/ReconNgEvents.ts       the ReconNg.Breach.* event names and payloads
  world/ReconNgStorage.ts      per-save storage wrapper
  world/ReconNgTestLab.ts      optional multi-service test lab targets
  world/ServiceBinary.ts       exploit-development binary generator
  world/ServiceBinarySync.ts   shared binary override bridge
  world/SessionAccess.ts       scoped session access profiles + built-ins
  world/SessionAccessSync.ts   shared access-profile bridge
  quests/ReconNgDemoQuest.ts   the "Proof of Foothold" demo quest
```

Almost everything about exploits and matching is in `src/world/BreachBackend.ts`:

| To do this | Edit in `src/world/BreachBackend.ts` |
|---|---|
| Add a shipped (built-in) exploit | `BREACH_MODULES` array (around line 65): add a `BreachModule` object |
| Change a shipped module's port, service, versions, vulnerabilities, or privilege | that module's entry in `BREACH_MODULES` |
| Remove a shipped module | delete its object from `BREACH_MODULES` |
| Change the service compatibility aliases | `servicesCompatible()` (around line 291) |
| Change version matching | `matchesVersion()` (around line 285) |
| Change which ports count as active | `portActive()` (around line 280) |
| Change the overall match algorithm | `moduleMatches()` (around line 300) |
| Change the generated session filesystem | `genericFilesystem()` (around line 354) |
| Change custom-module validation | `validateModule()` (around line 317) |

Other files:

| To do this | Edit |
|---|---|
| Change the demo target | `src/world/ReconNgDemoWorld.ts` |
| Change the demo quest, its post, or objectives | `src/quests/ReconNgDemoQuest.ts` |
| Change command names, output, or session commands | `src/commands/ReconNgCommand.ts` |
| Change event names or payload shapes | `src/world/ReconNgEvents.ts` |
| Change the example purchasable exploit | `src/world/ExampleExploitShop.ts` |
| Change the example shop target | `src/world/ExampleTarget.ts` |
| Change exploit-development binary generation | `src/world/ServiceBinary.ts` |
| Change cross-mod binary override syncing | `src/world/ServiceBinarySync.ts` |
| Add or change a session access profile | `src/world/SessionAccess.ts` |
| Change cross-mod access-profile syncing | `src/world/SessionAccessSync.ts` |

After any source change, rebuild with `npm run build` (or `npm run dev` to watch).
