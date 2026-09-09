# Modules

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

## Built-in module reference

16 modules ship by default, defined in the `BREACH_MODULES` array in
`src/world/BreachBackend.ts`. Edit that array to add, change, or remove them.
Indices are stable and accepted by `use <index>`.
This table is everything you need to build a matching target: a target matches a
row when it has an active port at that number, a compatible service, a version
that contains one of the listed strings (or any version when the column says
`any`), and at least one of the listed vulnerabilities.

| # | Module id | Port | Service | Version contains (any) | Vuln (any) | Priv |
|---|---|---|---|---|---|---|
| 0 | `exploit/unix/ftp/vsftpd_234_backdoor` | 21 | ftp | `vsftpd 2.3.4`, `vsftpd 2.3.5` | RCE | root |
| 1 | `exploit/unix/ftp/proftpd_modcopy` | 21 | ftp | `ProFTPD 1.3.5` | RCE, LFI | user |
| 2 | `exploit/http/nginx_chunked_size` | 80 | http | `nginx 1.18`, `nginx 1.18.0` | RCE | www-data |
| 3 | `exploit/http/nginx_alias_traversal` | 80 | http | `nginx 1.16`/`1.17`/`1.18`/`1.20` | LFI | www-data |
| 4 | `exploit/http/apache_path_traversal` | 80 | http | `Apache 2.4.49` | LFI, RCE | www-data |
| 5 | `exploit/http/apache_cgi_shellshock` | 80 | http | `Apache`, `Apache 2` | RCE | www-data |
| 6 | `exploit/webapp/php_include` | 80 | http | any | RFI, RCE | www-data |
| 7 | `exploit/webapp/php_lfi_log_poison` | 80 | http | any | LFI | www-data |
| 8 | `exploit/webapp/ssrf_metadata_leak` | 80 | http | any | SSRF | user |
| 9 | `exploit/webapp/cors_token_grab` | 80 | http | any | CORS, XSS | user |
| 10 | `exploit/webapp/tomcat_manager_upload` | 8080 | http | `Tomcat`, `Apache Tomcat` | RCE | www-data |
| 11 | `exploit/ssh/weak_maintenance_key` | 22 | ssh | `OpenSSH` | RCE | user |
| 12 | `exploit/database/mysql_udf_loader` | 3306 | database | `MySQL`, `MariaDB` | RCE, SQL_INJECTION | user |
| 13 | `exploit/cache/redis_unauth_write` | 6379 | redis | `Redis` | RCE | user |
| 14 | `exploit/smb/samba_usermap_script` | 445 | smb | `Samba 3.0` | RCE | root |
| 15 | `exploit/mail/postfix_pipe_escape` | 25 | smtp | `Postfix` | RCE | user |

What each one represents:

- **0 vsftpd_234_backdoor**: backdoor handler in old vsftpd builds, opens a root shell.
- **1 proftpd_modcopy**: ProFTPD mod_copy path handling stages files outside the FTP root.
- **2 nginx_chunked_size**: vulnerable chunked transfer parsing in exposed nginx workers.
- **3 nginx_alias_traversal**: unsafe alias path normalization discloses files.
- **4 apache_path_traversal**: traversal bug reads app files and, on weak hosts, runs helpers.
- **5 apache_cgi_shellshock**: CGI handlers pass attacker headers into bash.
- **6 php_include**: unsafe include parameter loads a remote PHP helper.
- **7 php_lfi_log_poison**: local file inclusion plus poisoned access logs yields a shell.
- **8 ssrf_metadata_leak**: server-side fetch reads local metadata and service credentials.
- **9 cors_token_grab**: permissive CORS and a reflected page pull session material.
- **10 tomcat_manager_upload**: WAR helper uploaded through an exposed manager interface.
- **11 weak_maintenance_key**: old maintenance key material opens a restricted shell.
- **12 mysql_udf_loader**: writable plugin paths load a command helper via the database.
- **13 redis_unauth_write**: controlled content written through an unauthenticated Redis.
- **14 samba_usermap_script**: command execution through unsafe username mapping.
- **15 postfix_pipe_escape**: misconfigured pipe transport writes and runs a helper.

Modules with version `any` (6 through 9) match any HTTP host on port 80 that has
the listed vulnerability, regardless of server version. Run `show modules` in-game
for the live set and `info <module>` for a single module's fields.

### Targets for each built-in

A few complete targets that match the rows above. Each uses the runtime setup
described in [Standing up a target](targets.md).

Matches module 0 (`vsftpd_234_backdoor`):

```ts
ports: [{ external: 21, internal: 21, active: true, service: "ftp", version: "vsftpd 2.3.4" }],
domain: { name, vulnerabilities: [{ type: "RCE" }] }
```

Matches module 2 (`nginx_chunked_size`):

```ts
ports: [{ external: 80, internal: 80, active: true, service: "http", version: "nginx 1.18.0" }],
domain: { name, vulnerabilities: [{ type: "RCE" }] }
```

Matches modules 6 through 9 (any HTTP 80 with the right vuln). For
`ssrf_metadata_leak`:

```ts
ports: [{ external: 80, internal: 80, active: true, service: "http", version: "any-build/1.0" }],
domain: { name, vulnerabilities: [{ type: "SSRF" }] }
```

Matches module 12 (`mysql_udf_loader`). Note the canonical service is `database`,
and `mysql` is an accepted alias:

```ts
ports: [{ external: 3306, internal: 3306, active: true, service: "database", version: "MySQL 8.0" }],
domain: { name, vulnerabilities: [{ type: "RCE" }] }
```

## Module schema

```ts
type BreachPrivilege = "guest" | "user" | "www-data" | "root";

interface BreachModule {
    id: string;                 // "exploit/<area>/<name>"
    name: string;
    family: "exploit" | "auxiliary" | "post";
    service: string;            // canonical service: http, ftp, ssh, database, ...
    port-: number;              // compatible target port, if the module is port-specific
    requiresRport-: boolean;    // true = player must set RPORT before check/run
    versions-: string[];        // accepted version substrings; omit = any
    vulnerabilities-: string[]; // required vuln types; omit = none required
    privilege: BreachPrivilege; // privilege granted by a successful session
    description: string;
    locked-: boolean;           // true = purchasable, not usable until granted; omit = owned from the start
    price-: number;             // shop price, used when locked
    access-: string;              // "shell", "desktop", or a registered access profile id; omit = "shell"
    desktop-: {                 // marks the session as compatible with desktop UI access
        os: "linux" | "windows";
        profile: string;        // frontend profile/app layout to open
        label-: string;         // optional human-readable target label
    };
}
```

`access` rides along on the session and on the `ReconNg.Breach.SessionOpened`
event. `shell` opens the normal file shell, `desktop` marks a GUI-grade session,
and any other string is treated as a registered access profile id.
Ownership: unlocked modules are usable immediately; a `locked` module becomes
usable after `BreachBackend.grantExploit(id)` (call it from a shop once the player
pays via `Bank.withdraw`).

`port` is the module's **classic** service port (SSH 22, FTP 21, HTTP 80, …).
Loading a module with `use` seeds `RPORT` to that value so `show options` shows
the default until the player changes it.

Matching rules:

- With `RPORT` still at the classic port (or unset, treated the same): the target
  must expose that number as an **active external** port, with compatible service,
  version, and vulnerabilities.
- After `set RPORT <external>` to a different number (what `nmap` showed): that
  **external** must be active, and the row's **internal** must equal the module's
  classic `port` (remapped SSH: external 38471 → internal 22).

recon-ng never auto-picks a remapped external when `RPORT` was left at the
default. The firewall check uses the same attempt number (`RPORT` / classic port).

`requiresRport`, when true, still means the player must have an explicit `RPORT`
before `check` / `run` (already satisfied by the `use` default when `port` is set).

`desktop` is the HawkEye-style bridge. If an exploit has `desktop` but keeps
`access` omitted or set to `shell`, it opens a normal recon-ng session that is
eligible for a later desktop post module. Running
`post/multi/gui/desktop_implant` upgrades only those compatible sessions and
emits `ReconNg.Breach.DesktopOpened`. If `access: "desktop"` is set directly,
the session opens desktop-grade immediately and emits both `SessionOpened` and
`DesktopOpened`.

Post-exploitation modules use the same `BreachModule` shape with
`family: "post"`. They are not selected with top-level `use`; they are listed and
run from an active session with `post`:

```txt
interact 1
post
post post/multi/gui/desktop_implant
post post/loot/passwd_dump
```

The bundled `post/multi/gui/desktop_implant` upgrades a shell session to
`access: "desktop"` and emits `ReconNg.Breach.DesktopOpened`.

The bundled `post/loot/passwd_dump` reads `/etc/passwd` from the active
recon-ng session and prints any hash entries it finds. It does not write a local
download file. Quest authors can combine this with `john` by planting a readable
`/etc/passwd` through the normal generated filesystem or a loot overlay.

After cracking a printed hash with `john`, the player can stay inside the
recon-ng session and run `su root` or `sudo <password>`. recon-ng checks the
password against the registered `john` result for the hash and upgrades the
simulated session user if it matches. This supports hosts where SSH is closed or
not part of the intended route.

`registerModule` and external module synchronization reject a spec, returning a
`reason`, when:

- `id`, `name`, `service`, or `description` is missing or not a string;
- `family` is not `exploit`, `auxiliary`, or `post`;
- `privilege` is not `guest`, `user`, `www-data`, or `root`;
- `port` is present but not a number;
- `versions` or `vulnerabilities` is present but not an array;
- `locked` is present but not a boolean;
- `price` is present but not a number;
- `access` is present but not a string;
- `desktop` is malformed;
- an exploit uses `access: "desktop"` without a `desktop` profile.

A module whose `id` already exists replaces the previous one.

## Purchasable exploits

In-bundle surface. Mark a module `locked: true` and it stays in the catalog but is
hidden from `search` / `use` / `run` until granted. A shop grants it after taking
payment through the Bank SDK.

```ts
import { Bank, UI } from "@hotbunny/hackhub-content-sdk";
import { BreachBackend } from "../world/BreachBackend";

BreachBackend.registerModule({
    id: "exploit/shop/acmeweb_rce",
    name: "AcmeWeb 1.0 RCE",
    family: "exploit",
    service: "http",
    port: 8080,
    versions: ["AcmeWeb 1.0"],
    vulnerabilities: ["RCE"],
    privilege: "www-data",
    description: "Off-the-shelf exploit for AcmeWeb 1.0.",
    locked: true,
    price: 25000,
});

export function purchaseExploit(id: string): boolean {
    if (BreachBackend.ownsExploit(id)) return true;
    const module = BreachBackend.getCatalog().find((item) => item.id === id);
    if (!module) return false;
    if (Bank.getBalance() < (module.price -- 0)) {
        UI.toast("Insufficient funds.", "warning");
        return false;
    }
    Bank.withdraw({ amount: module.price -- 0, description: `exploit: ${module.name}` });
    BreachBackend.grantExploit(id);
    return true;
}
```

Your shop UI (a website, app, or command) lists `BreachBackend.getLockedExploits()`
and calls `purchaseExploit(id)` on buy. Ownership persists per save;
`revokeExploit(id)` removes it. A crafted exploit is always owned. The full working
version is `src/world/ExampleExploitShop.ts`.
