# Wordlists

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

## Wordlists

Modules declaring `requiresWordlist` refuse to run without a wordlist, and refuse
to run against a gated target unless the supplied list meets that target's tier.
recon-ng ships `wordlist.lst` at tier 1 with 14344 entries, and the built-in
`exploit/ftp/ftp_brute` module uses it, so the mechanic works with no content mod
installed. That module also sets `requiresUser`, so the player supplies both a
`USER` and a `WORDLIST` before it will run.

### What you have to do

Three steps, and all three are required. Miss the gate and the list you sell opens
nothing. Miss the grant and the player cannot use what they bought.

1. **Describe the list** once at boot, in `reconng.wordlists`. Safe to do for your
   whole catalogue: describing is not giving.
2. **Gate the hosts** it is meant to open, in `reconng.wordlist.gates`. An ungated
   host requires tier 1, which the stock list already satisfies, so a list only
   means something once something is gated above it.
3. **Grant it** when the player earns or buys it, in `reconng.wordlist.grants`.

```ts
import { SharedStorage } from "@hotbunny/hackhub-content-sdk";

const push = (key: string, value: unknown) =>
    SharedStorage.set(key, [...(SharedStorage.get<any[]>(key) ?? []), value]);

// 1. at boot
push("reconng.wordlists", { name: "rockyou-trimmed.lst", tier: 2, entries: 128000 });

// 2. when you build the host you want it to open
push("reconng.wordlist.gates", { target: "203.0.113.50", tier: 2 });

// 3. when the player earns it
push("reconng.wordlist.grants", "rockyou-trimmed.lst");
```

The player then runs `set WORDLIST rockyou-trimmed.lst` against that host and the
brute module proceeds. The rest of this section is the detail behind each step.

Publish extra lists to `reconng.wordlists`:

```ts
import { SharedStorage } from "@hotbunny/hackhub-content-sdk";

const KEY = "reconng.wordlists";
const current = SharedStorage.get<any[]>(KEY) ?? [];

SharedStorage.set(KEY, [
    ...current.filter((list) => list?.name !== "rockyou-trimmed.lst"),
    { name: "rockyou-trimmed.lst", tier: 2, entries: 128000 },
]);
```

`tier` is the only field that gates anything. `entries` is presentation: it is
what the player sees while the brute force runs, so a larger number reads as a
longer, heavier list.

### How a player comes to own one

Publishing a spec describes a list. It does not hand it over. Ownership is a
second, explicit step, so registering your whole catalogue at boot is safe: the
player still cannot use any of it.

Grant a list by pushing its name to `reconng.wordlist.grants`:

```ts
const KEY = "reconng.wordlist.grants";
const current = SharedStorage.get<string[]>(KEY) ?? [];

if (!current.includes("rockyou-trimmed.lst")) {
    SharedStorage.set(KEY, [...current, "rockyou-trimmed.lst"]);
}
```

Names are matched case-insensitively and must match the spec `name` exactly
otherwise. `wordlist.lst` is always owned and never needs granting.

The player supplies one with `set WORDLIST <path>`, and only the basename is
matched, case-insensitively. `set WORDLIST rockyou-trimmed.lst`,
`set WORDLIST ~/downloads/rockyou-trimmed.lst`, and
`set WORDLIST /any/made/up/path/rockyou-trimmed.lst` all resolve to the same
granted spec, and all three work whether or not a file exists at that path.
A name that has not been granted fails with
`no wordlist by that name is available`, however real the file is and however
correctly the player spells it. Knowing the name of a list is not the same as
having it.

There is also no command that lists the lists a player owns, so nothing in
recon-ng will ever tell them the name. Your mod has to. If you want acquisition
to feel like getting a file rather than a silent capability unlock, create the
file yourself for flavour and publish the spec in the same step:

```ts
import { Files, SharedStorage } from "@hotbunny/hackhub-content-sdk";

async function grantWordlist() {
    await Files.create({
        name: "rockyou-trimmed",
        extension: "lst",
        parentPath: "~/downloads",
        data: "hunter2\npassw0rd\n...\n",
    });

    const grants = SharedStorage.get<string[]>("reconng.wordlist.grants") ?? [];
    SharedStorage.set("reconng.wordlist.grants", [...grants, "rockyou-trimmed.lst"]);
}
```

The file is doing no mechanical work there. It exists so the player can find the
name by looking, and so the reward reads as an object. Keep the two names in
step: the spec `name` must be the filename including its extension.

Inside recon-ng's own bundle, `BreachBackend.grantWordlist(name)`,
`BreachBackend.revokeWordlist(name)`, and `BreachBackend.isWordlistGranted(name)`
are also available.

Gate a target with `reconng.wordlist.gates`:

```ts
const KEY = "reconng.wordlist.gates";
const current = SharedStorage.get<any[]>(KEY) ?? [];

SharedStorage.set(KEY, [
    ...current.filter((gate) => gate?.target !== "203.0.113.50"),
    { target: "203.0.113.50", tier: 2 },
]);
```

An ungated target requires tier 1, so the base list always works everywhere by
default. Setting tier 2 on a target rejects the base list there, and the player
cannot proceed until your mod has published a tier 2 spec to them. Gate the host
first and grant the list later and the host is simply impassable in between,
which is a fine way to hold a route shut if that is what you meant. It is a bug
if it is not.

Inside recon-ng's own bundle, `BreachBackend.registerWordlist(spec)`,
`BreachBackend.setWordlistGate(target, tier)`, and
`BreachBackend.clearWordlistGate(target)` are also available.
