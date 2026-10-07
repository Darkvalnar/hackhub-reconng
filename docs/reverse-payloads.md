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

### Orchestrating a listener from another mod

A campaign or delivery mod may control the same listener lifecycle through the
cross-mod listener API. This is useful when that mod owns the player-facing
campaign console and needs to keep it open until recon-ng returns a session or a
failure. The API is not required for the normal interactive `recon-ng` workflow.

Requests are emitted on `ReconNg.ReverseListener.Request.v1`. Correlated responses
are appended to `SharedStorage` key `reconng.reverse.listener.responses.v1` and the
most recent 50 responses are retained.

```ts
import { Events, Random, SharedStorage } from "@hotbunny/hackhub-content-sdk";

const REQUEST_EVENT = "ReconNg.ReverseListener.Request.v1";
const RESPONSES_KEY = "reconng.reverse.listener.responses.v1";

function request(operation: string, values: Record<string, unknown> = {}) {
  const requestId = `my-mod-${Random.id(12).toLowerCase()}`;
  Events.emit(REQUEST_EVENT as any, { requestId, operation, ...values });
  const responses = SharedStorage.get<any[]>(RESPONSES_KEY) ?? [];
  return responses.find((entry) => entry?.requestId === requestId);
}
```

The supported operations are:

| Operation | Required values | Purpose |
|---|---|---|
| `inspect` | none | Return installed payloads, suggested LAN address, and an externally controlled active listener, if present. |
| `arm` | `payloadId`, `lhost`, `lport`, `target` | Validate and start one listener. Returns its generated `listenerId` and callback URL. |
| `status` | `listenerId` | Return `listening`, `opened`, `failed`, `cancelled`, or `timed_out`. Successful results include the session id and host. |
| `cancel` | `listenerId` | Stop a matching active listener and record a terminal result. |

An `arm` request fails when the payload is not installed, the callback network is
not reachable, required values are invalid, or another listener is active. A
listener expires after ten minutes. Keep the controlling campaign UI open and
poll `status`; do not tell the player to open recon-ng merely to trigger delivery
processing.

The inspection snapshot sets `busy: true` whenever any reverse listener is active,
including one started interactively inside recon-ng. A controlling mod should stop
before presenting its campaign configuration when that flag is set.

```ts
const inspection = request("inspect");
const payload = inspection?.snapshot.payloads[0];

const armed = request("arm", {
  payloadId: payload.id,
  lhost: inspection.snapshot.suggestedLhost,
  lport: 4444,
  target: "dana.reeve@example.net",
});

const listenerId = armed.snapshot.listener.listenerId;
const status = request("status", { listenerId });
```

The response snapshot has this shape:

```ts
interface ReverseListenerApiResponse {
  requestId: string;
  ok: boolean;
  reason?: string;
  snapshot: {
    protocol: 1;
    providerId: "recon-ng";
    payloads: ReversePayloadDefinition[];
    suggestedLhost?: string;
    busy: boolean;
    listener?: {
      listenerId: string;
      payloadId: string;
      lhost: string;
      lport: number;
      target: string;
      callbackUrl: string;
      state: "listening" | "opened" | "failed" | "cancelled" | "timed_out";
      startedAt: number;
      expiresAt: number;
      reason?: string;
      sessionId?: string;
      sessionHost?: string;
    };
  };
}
```

Recon-ng owns payload inventory, network validation, callback matching, listener
state, and sessions. The controlling mod owns its campaign UI and must use the
returned callback URL in the effective delivered content. Display payload labels
and summaries to the player, but do not expose payload affinity scores or target
records as recommendations.

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
import { Events, SharedStorage } from "@hotbunny/hackhub-content-sdk";

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
Events.emit("ReconNg.ReverseDelivery.Available.v1" as any, {
  providerId: "example-provider",
  t: Date.now(),
});
```

Emit `ReconNg.ReverseDelivery.Available.v1` after writing the completed delivery.
Recon-ng uses this signal to process deliveries immediately for a listener armed
through the orchestration API. Interactive listeners continue polling the same
queue while `run` is open. The event carries no delivery payload; shared storage
remains the authoritative delivery contract.

`lureOutcome` supports `success`, `not_interested`, and `bounce`. A bounce records
the target email and lure id in `reconng.reverse.burnedlures`; a provider may use
that shared list to hide a burned pretext from later attempts.
