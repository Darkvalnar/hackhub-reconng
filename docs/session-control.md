# Session Control

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

## Session control

Three keys let your mod end a breach session, refuse new ones, and close a host
off entirely. recon-ng enforces the requests without knowing why you made them,
so the same primitives cover a trace mechanic, an admin kick, a scripted story
beat, or a cooldown.

In every record below, `target` matches a session's `ip` **or** `host`,
case-insensitively.

### `reconng.session.terminations` closes the active session

```ts
Array<{ target: string; message?: string }>
```

recon-ng checks this on the player's next action inside a session. The console
is a blocking prompt, so there is no idle kick: if you need the player to feel it
immediately, pair the record with your own toast. On a match recon-ng prints
`message` (default `"connection terminated."`), closes the session, emits
`ReconNg.Breach.SessionClosed` with `reason: "terminated"`, and removes the
entry.

### `reconng.session.locks` refuses new sessions

```ts
Array<{ target: string; until: number; message?: string }>   // until = epoch ms
```

Checked when a session opens, through either `openSession` or
`openReverseSession`. An unexpired matching lock refuses the breach with
`message` (default `"connection refused - host unreachable"`). Expired entries
are pruned lazily, so a lock self-clears at `until` even if you never remove it.

### `reconng.target.gates` closes a host off

```ts
Array<{ target: string; open: boolean; message?: string }>
```

While `open` is false the target is refused at recon, check, and session time
alike, so it behaves as though it is not reachable at all. Use this for a host
that should not exist yet, rather than a lock, which is for a host the player has
already found and is being kept out of.

### Example

```ts
import { SharedStorage } from "@hotbunny/hackhub-content-sdk";

function kickAndLock(ip: string, cooldownMs: number) {
    const until = Date.now() + cooldownMs;

    const terms = SharedStorage.get<any[]>("reconng.session.terminations") ?? [];
    SharedStorage.set("reconng.session.terminations", [
        ...terms.filter((entry) => entry.target?.toLowerCase() !== ip),
        { target: ip, message: "Connection traced. Session terminated." },
    ]);

    const locks = SharedStorage.get<any[]>("reconng.session.locks") ?? [];
    SharedStorage.set("reconng.session.locks", [
        ...locks.filter((entry) => entry.target?.toLowerCase() !== ip),
        { target: ip, until, message: "Connection refused. Host flagged your address." },
    ]);
}
```

When the cooldown ends, remove the lock and any unconsumed termination for that
target so a stale request cannot close a later, legitimate session. Letting the
lock expire on its own through `until` is equally fine.

Observe `ReconNg.Breach.SessionOpened` and `ReconNg.Breach.SessionClosed` to
drive your own per-session logic. `SessionClosed` fires whenever a session ends
for any reason, including the player closing it and an external termination.
