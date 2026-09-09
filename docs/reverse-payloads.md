# Reverse Payloads

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

## Reverse payload inventory

recon-ng can receive reverse-callback payloads from other mods. Payloads are not
exploit modules. They are installed callback kits that can be paired with a
provider mod's social-engineering or delivery system.

Installed payloads are listed inside recon-ng:

```txt
payloads
payloads info <payload-or-index>
```

Payload package items can be imported from downloads, desktop, documents, or an
explicit path:

```txt
payloads import branded_confirm.rpkg
payloads import ~/downloads/branded_confirm.rpkg
```

An `.rpkg` is an inventory item, not executable configuration. Its file data may
be empty. recon-ng never parses code or JSON from it. Import succeeds only when
the file exists, its name ends in `.rpkg`, and a provider mod has published an
entitlement for that exact file name.

Creating or renaming a file does not create an entitlement. Deleting an imported
or purchased package does not revoke an already installed payload.

### Payload definition

```ts
interface ReversePayloadDefinition {
  id: string;
  family: "portal_link" | "doc_macro" | "fake_update" | "script_drop";
  label: string;
  delivery: "link" | "attachment" | "archive";
  affinities: string[];
  summary: string;
}
```

`affinities` are matched against the delivered lure id, label, and tags. Use
specific, stable values rather than broad words that make one payload fit most
targets.

### Direct grants

Use `reconng.reverse.payloads` for payloads the current player should already own,
such as a free starter payload or an explicit quest reward. Do not publish a shop
catalogue here.

```ts
import { Files, SharedStorage } from "@hotbunny/hackhub-content-sdk";

const directGrant = {
  id: "payload/portal_link/branded_confirm",
  family: "portal_link",
  label: "Branded Confirmation Portal",
  delivery: "link",
  affinities: ["portal-confirmation", "maintenance-window-confirmation"],
  summary: "Cleaner callback link for confirmation-style lures.",
};

const currentGrants = SharedStorage.get<any[]>("reconng.reverse.payloads") ?? [];
SharedStorage.set("reconng.reverse.payloads", [
  ...currentGrants.filter((entry) => entry?.id !== directGrant.id),
  directGrant,
]);
```

Shared storage is common to every mod. Read the existing array, remove only the
payload ids owned by your mod, preserve unrelated entries, then append the direct
grants for the current save.

### Purchasable package entitlements

Use `reconng.reverse.payload.packages` when the player must acquire an `.rpkg` and
import it manually.

```ts
interface ReversePayloadPackageEntitlement {
  providerId: string;
  packageName: string;
  payload: ReversePayloadDefinition;
}
```

After a successful purchase, record it in your mod's save storage, create an empty
package item, and publish this save's purchased entitlements:

```ts
const entitlement = {
  providerId: "example-provider",
  packageName: "branded_confirm.rpkg",
  payload: brandedConfirmPayload,
};

const current = SharedStorage.get<any[]>("reconng.reverse.payload.packages") ?? [];
SharedStorage.set("reconng.reverse.payload.packages", [
  ...current.filter((entry) => entry?.providerId !== "example-provider"),
  entitlement,
]);

await Files.create({
  name: "branded_confirm",
  extension: "rpkg",
  parentPath: "~/downloads",
  data: "",
});
```

Republish entitlements on mod load from the current save. Preserve entries from
other provider ids. Package names must be unique across providers; recon-ng rejects
conflicting entitlements for the same package name. A purchased package may be
downloaded again without charging again.

### Running a reverse payload

A payload is *armed*, not *run against a service*. `run` on a loaded payload starts
a listener and waits for a delivery:

```txt
use payload/portal_link/basic_callback
set LHOST <your current LAN address>
set LPORT 4444
set TARGET <the person's email, profile id, or name>
run
```

The player must first forward `LPORT` to their current device in the router UI.
When `run` succeeds, recon-ng prints the exact callback URL. The provider's delivery
flow must place that URL in the delivered message.

The callback only fires when all of these conditions hold:

- the delivered target matches `TARGET` (by email, id, or name),
- the target email exists in `reconng.reverse.targets`,
- the payload affinities match the delivered lure context,
- the provider reports `lureOutcome: "success"`,
- the delivered message body contains the exact callback URL,
- `LHOST` still matches the player's current LAN address, and
- `LPORT` is still active for the player device.

The resulting session is an ordinary shell session (`sessions`, `sessions -i`, `ls`,
`cat`, `download`) and emits `ReconNg.Breach.SessionOpened` with `via: "reverse"`.

### Making a target reverse-exploitable

Create the network host normally, then publish an email-to-host record through
`reconng.reverse.targets`:

```ts
interface ReverseTargetRecord {
  providerId: string;
  ip: string;
  username: string;
  tier: string;
  desktop?: { os: "linux" | "windows"; profile: string; label?: string };
}

const targets = SharedStorage.get<Record<string, ReverseTargetRecord>>(
  "reconng.reverse.targets",
) ?? {};

targets["dana.reeve@example.net"] = {
  providerId: "example-provider",
  ip: hostIp,
  username: "dreeve",
  tier: "user",
};

SharedStorage.set("reconng.reverse.targets", targets);
```

The target host must also exist in the game network so recon-ng can resolve it.
Network query methods sanitize user email fields, which is why the explicit target
registry is required. Use a unique email key, tag records with a stable provider
id, and preserve records owned by other mods when republishing your save-scoped
entries. `root` and `www-data` map to those privileges; other tier strings
currently open a user session.

### Publishing a delivered lure

Only publish after the player actually performs the delivery action. Preparing a
template or selecting a lure is not delivery.

Append one record to `reconng.reverse.deliveries`:

```ts
const deliveries = SharedStorage.get<any[]>("reconng.reverse.deliveries") ?? [];
deliveries.push({
  email: "dana.reeve@example.net",
  role: "Support Coordinator",
  id: "dana.reeve",
  name: "Dana Reeve",
  lureId: "portal-confirmation",
  lureLabel: "Portal confirmation",
  lureTags: ["portal-confirmation", "support"],
  lureOutcome: "success",
  messageBody: sentMessageBody,
  t: Date.now(),
});
SharedStorage.set("reconng.reverse.deliveries", deliveries.slice(-100));
```

`lureOutcome` supports `success`, `not_interested`, and `bounce`. A bounce records
the target email and lure id in `reconng.reverse.burnedlures`; a provider may use
that shared list to hide a burned pretext from later attempts.
