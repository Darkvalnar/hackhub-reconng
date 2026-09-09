# SSH Username Enumeration

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

## SSH username enumeration targets

The built-in `auxiliary/scanner/ssh/user_enum` module only succeeds against
targets explicitly registered for enumeration. The target must also expose an
active SSH service on the configured port with an OpenSSH, Dropbear, or libssh
version string.

From another mod, publish records to SharedStorage key
`reconng.user.enum.targets`:

```ts
import { SharedStorage } from "@hotbunny/hackhub-content-sdk";

const KEY = "reconng.user.enum.targets";
const current = SharedStorage.get<any[]>(KEY) ?? [];

SharedStorage.set(KEY, [
    ...current.filter((record) => record?.target !== "203.0.113.50"),
    {
        target: "203.0.113.50",
        users: ["svc.backup"],
        service: "ssh", // optional; defaults to ssh
        port: 22,       // optional; defaults to 22
    },
]);
```

After probing the target, recon-ng generates a deterministic technical
observation from the target hostname, IP, SSH version, and recovered usernames.
It prints that observation before the result table. The same target therefore
produces the same explanation on every run.

An optional `observationProfile` can constrain the mechanism without supplying
player-facing prose:

```ts
type UserEnumObservationProfile =
    | "preauth"
    | "timing"
    | "auth-methods"
    | "keyboard-interactive"
    | "key-parse";
```

If omitted, recon-ng selects a profile compatible with the SSH implementation:
OpenSSH uses pre-auth, timing, keyboard-interactive, or authentication-method
observations; Dropbear uses key-parsing, timing, or pre-auth observations;
libssh uses authentication-method, pre-auth, or timing observations.

For an exceptional authored target, `observation` may supply one custom summary
line. Prefer a technical finding rather than quest guidance. The legacy `note`
field is still accepted for compatibility and is rendered in the same pre-table
position, but new integrations should use `observation`.

Example player output:

```text
[*] sampling ssh banner ....
[*] probing auth timing ...
[*] comparing failures ....
[+] alternate pre-auth failure reproduced across 5/5 candidate probes.
    control names were rejected before account lookup.

[+] candidate account names recovered.
+---+------------+--------------------+
| # | Username   | Target             |
+---+------------+--------------------+
| 1 | svc.backup | backup.example.net |
+---+------------+--------------------+
```

Inside recon-ng's own bundle, use
`BreachBackend.registerUserEnumTarget(record)` instead of SharedStorage.
