# Player Guide

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

## Player quick start

Practice targets are **off by default**. Turn on **Practice targets** in the mod's
settings, then **restart the game**. The setting is read once while the mod loads,
so toggling it mid-session has no effect until the next load. They stay off by
default so a content mod that depends on recon-ng does not inherit lab hosts in
the middle of its own world.

With the setting on, the mod ships a demo quest (`Proof of Foothold`) that
registers a demo target. Claim it from the HackHub feed, then:

```txt
recon-ng                       (alias: rng)
set RHOST breach-demo.io
search                         lists modules matching the target
info 0
use 0
show options
check                          "target appears vulnerable"
run
interact 1
ls /
cat /etc/passwd
download /var/www/config.env
background
```

Downloaded files land in the player's `~/downloads` folder.

### What each practice target is for

| Flow | Target | How |
|---|---|---|
| Prebuilt exploit | `breach-demo.io` | `vsftpd 2.3.4` on 21 and `nginx 1.18.0` on 80, both covered by built-in modules. The vsftpd route lands a root shell. |
| Exploit development | `198.51.100.10` to `.21` (`webnode.lab`, `portal.lab`, `shopdb.lab`, and the rest) | Versions no built-in module covers, each with a declared weakness. `disasm <port>`, pick functions, `build compile`. `bastion.lab` is deliberately not exploitable, and `edge.lab` carries a different weakness per port. |
| Desktop session and HawkEye | `acme-labs.test` | `use exploit/shop/acmeweb_rce` against `AcmeWeb 1.0` on 8080. It opens a desktop session, which is what HawkEye attaches to. The module is a locked, priced exploit, but practice content grants it outright so you are not buying it to see the flow. |
| Wordlist tiers | `archive.lab` and `edge.lab` | Both run ftp on 21 with an `operator` account. `archive.lab` is gated at tier 2 and you are granted `labdeep.lst`, so the stock list refuses and the granted one works. `edge.lab` is gated at tier 3, which nothing grants, so the refusal is visible with no way around it. |

```txt
use exploit/ftp/ftp_brute
set RHOST archive.lab
set USER operator
set WORDLIST wordlist.lst      refused, the host is gated above tier 1
set WORDLIST labdeep.lst       tier 2, proceeds
run
```

## Command reference

Workspace commands:

```txt
set RHOST <ip-or-domain>     choose the target
set RPORT <port>             target port (seeded from the module default on `use`)
search [query]               list modules; with RHOST set and no query, lists matches
use <module-or-index>        select a module
info [module-or-index]       show a module's requirements
show options                 show current target and module
show modules                 list all modules
check                        validate the module against the target
run | exploit                launch the module, opening a session on success
disasm [#|port|service]      analyze one fingerprinted service for exploit development
inspect <function>           show a disassembled function's source/action/safety
build add <function>         add a function to the exploit build chain
build remove <function>      remove a function from the build chain
build show                   show the current build chain
build clear                  clear the current build chain
build compile                craft an exploit from the current build chain
sessions                     list open sessions (sessions -i <id> to enter)
interact <session-id>        enter a session
back                         unload the current module
clear                        clear the screen
help | -                     command help
exit | quit | q              close recon-ng
```

Session commands (after `interact`):

```txt
ls [path]          list files
cd <path>          change directory
pwd                print working directory
whoami             print the session user
su [user]          switch user with a cracked password prompt
sudo <password>    switch to root with a cracked password
cat <file>         read a file        (emits ReconNg.Breach.FileRead)
download <file>    save to ~/downloads (emits ReconNg.Breach.FileDownloaded)
rm <file>          remove a file       (emits ReconNg.Breach.FileDeleted)
post [module]      list or run post-exploitation modules
background | bg    return to the workspace
close              close the session
help | -           session help
```
