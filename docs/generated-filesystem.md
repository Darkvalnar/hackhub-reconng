# Generated Filesystem

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

## Generated filesystem

A successful exploit generates a filesystem from the target's services.

```txt
base:   /  /etc  /etc/hostname  /etc/issue  /etc/passwd
        /home  /tmp  /var  /var/log  /var/log/auth.log

http:   /var/www/index.html  /var/www/config.env
        /etc/nginx/site.conf  /etc/httpd/site.conf  /var/log/access.log

ftp:    /srv/ftp/readme.txt  /srv/ftp/incoming  /etc/vsftpd.conf  /var/log/vsftpd.log

db:     /etc/mysql/my.cnf  /var/lib/mysql  /var/log/mysql.log
```

ssh, redis, smb, and smtp add their own config and log files. Layer
quest-specific files on top with [loot overlays](loot-overlays.md).
