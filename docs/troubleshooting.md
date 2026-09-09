# Troubleshooting

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

## Troubleshooting

"target could not be resolved":

- The domain was never registered (`Network.registerDomain`), or the subnet was
  never created (`Network.createSubnetNetwork`).
- The target was registered at mod-load and dropped on save load. Register it at
  quest runtime instead.

"service, version, or vulnerability state does not match", one of:

- the matched port is not active;
- the module `port` does not equal the active port number;
- the port `service` is not compatible with the module `service` (server name in
  `service` instead of `version` is the usual cause);
- the port `version` contains none of the module's version strings;
- the target carries none of the module's vuln types. Check that the same vuln
  array went to the domain definition, `registerDomain`, and `setVulnerabilities`.

Session opens but the objective never completes:

- Listen for `ReconNg.Breach.SessionOpened`, `FileRead`, `FileDownloaded`, or
  `FileDeleted`, and compare `event.ip`, `event.host`, and `event.path`.
- Do not gate completion on opening recon-ng or typing `run`.

## Checklist

1. Add `"recon-ng"` to your manifest `dependencies` if you require the standalone mod.
2. Create the subnet and register the domain for your target.
3. Give each port an `active` flag, a canonical `service`, and a `version`.
4. Put the required vuln types on the domain definition, `registerDomain`, and `setVulnerabilities`.
5. Confirm at least one module can match, using `info <module>` to compare requirements.
6. Run `check` before `run` while testing.
7. Register quest targets at quest runtime.
8. Drive quest progress from `ReconNg.Breach.*` events.
