# How Matching Works

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

## How matching works

recon-ng never infers state from command text. When the player runs `check` or
`run`, it resolves `RHOST` against live network state:

```ts
Network.getSubnetByDomain(rhost) -- Network.getSubnet(rhost)
```

The selected module then has to match the resolved target. A module matches when
all of these hold:

1. Vulnerability: the module lists no `vulnerabilities`, or the target's domain
   carries at least one of them.
2. Active port: the target has a port that is active (`active: true`, or
   `status: "OPEN"`).
3. Port number: if the module sets `port`, that port number is the active one.
4. Service: the module `service` is compatible with the port's service.
5. Version: the module lists no `versions`, or one of them is a case-insensitive
   substring of the port's version.

When every check passes, recon-ng opens a session and grants the module's
`privilege`. The session filesystem is generated from the target's services.

## Matching rules in detail

### Resolution

`RHOST` resolves with `getSubnetByDomain(rhost) -- getSubnet(rhost)`, so a domain
or a bare IP both work. The target's vulnerability list comes from the resolved
subnet's `domain.vulnerabilities`, mapped to their `type` strings.

### Port

If a module sets `port`, the target needs an active port whose number matches.
recon-ng reads the number as `external -- port`, so both the creation shape
(`{ external, internal }`) and the resolved shape (`{ port }`) work. A port counts
as active when `active === true` or `status === "OPEN"`. A module with no `port`
matches on any active port that satisfies the other rules.

### Service

The module `service` must be compatible with the port `service`. Compatibility is
an exact match plus these aliases:

```txt
http      matches  http, https, web
database  matches  database, mysql, mariadb, postgres
others    exact match only
```

Use a canonical service name on the port (`http`, `ftp`, `ssh`, `database`,
`redis`, `smb`, `smtp`). Put the product or server name in the version, not the
service. A port with `service: "nginx"` will not match an `http` module. Write:

```ts
{ service: "http", version: "nginx 1.18.0" }
```

### Version

No `versions` on the module means any version matches. Otherwise the port's
version string must contain one of the module versions (case-insensitive):

```txt
module ["nginx 1.18"]   vs target "nginx 1.18.0"   match (substring)
module ["nginx 1.18.0"] vs target "nginx 1.18.0"   match
module ["nginx 1.18.0"] vs target "Apache 2.4.49"  no match
```

### Vulnerability

No `vulnerabilities` on the module means none are required. Otherwise the target
must carry at least one of the module's types. See
[Vulnerability types](#vulnerability-types) for the seven valid values. Attach
them to the target in three places for reliability, all with the same array:

```ts
const vulns = [{ type: "RCE" }, { type: "LFI" }];

domain: { name, vulnerabilities: vulns }      // subnet domain definition
Network.registerDomain(name, ip, vulns);      // domain registration
Network.setVulnerabilities(ip, vulns);        // by IP
```

## Vulnerability types

A target carries vulnerabilities on its domain, and a module lists the types it
needs. The SDK accepts exactly seven types. All seven are usable in your own
modules and targets:

| Type | Meaning | Built-in modules that require it |
|---|---|---|
| `RCE` | Remote code execution | vsftpd_234_backdoor, proftpd_modcopy, nginx_chunked_size, apache_path_traversal, apache_cgi_shellshock, php_include, tomcat_manager_upload, weak_maintenance_key, mysql_udf_loader, redis_unauth_write, samba_usermap_script, postfix_pipe_escape |
| `LFI` | Local file inclusion | proftpd_modcopy, nginx_alias_traversal, apache_path_traversal, php_lfi_log_poison |
| `RFI` | Remote file inclusion | php_include |
| `SSRF` | Server-side request forgery | ssrf_metadata_leak |
| `CORS` | Permissive cross-origin sharing | cors_token_grab |
| `XSS` | Cross-site scripting | cors_token_grab |
| `SQL_INJECTION` | SQL injection | mysql_udf_loader |

A module's `vulnerabilities` are matched with OR: the target needs at least one of
them, not all. A module with no `vulnerabilities` requires none.
