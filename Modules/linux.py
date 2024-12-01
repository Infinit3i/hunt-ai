def get_linux_content():
    return [
        {
            "title": "Common Malware Names",
            "content": """
kworker
kinsing
xmrig
cryptonight
apache2 (unexpected locations)
mysql (unexpected locations)
            """,
            "resources": [
                "https://www.trendmicro.com/vinfo/",
                "https://unit42.paloaltonetworks.com/"
            ]
        },
        {
            "title": "Common Malware Locations",
            "content": """
/tmp
/var/tmp
/dev/shm
/etc/cron.*
/lib/systemd/system/
~/.ssh/
/usr/local/bin/
/usr/bin/
/var/spool/cron/crontabs/
            """,
            "resources": [
                "https://www.linuxsecurity.com/",
                "https://attack.mitre.org/"
            ]
        },
        {
            "title": "Interesting Search Terms",
            "content": """
### Shell Scripts
.sh, .bash

### Executable Files
.out, .bin, .elf

### Archives
.tar.gz, .zip, .xz, .bz2, .7z

### Strings in Logs
"sudo"
"su root"
"chmod 777"
"wget" or "curl"
"base64"
            """,
            "resources": []
        },
        {
            "title": "Locations of Persistence",
            "content": """
Cron Jobs
    - `/etc/crontab`
    - `/var/spool/cron/crontabs/`
Autostart
    - `~/.config/autostart/`
System Services
    - `/etc/systemd/system/`
    - `/lib/systemd/system/`
Network Configuration Files
    - `/etc/network/interfaces`
    - `/etc/hosts`
SSH Keys
    - `~/.ssh/`
    - `/root/.ssh/`
            """,
            "resources": [
                "https://www.tecmint.com/",
                "https://www.cyberciti.biz/"
            ]
        },
        {
            "title": "Types of Persistence",
            "content": """
Cron Jobs
Modified SSH Keys
Custom Systemd Services
Kernel Module Hijacking
Backdoor Network Configurations
LD_PRELOAD Hijacking
            """,
            "resources": [
                "https://www.linux.com/",
                "https://redhat.com/"
            ]
        },
        {
            "title": "Advanced Persistence",
            "content": """
Rootkits
Live Kernel Patching
Custom Kernel Modules
Firmware Tampering
Hidden Partitions or Volumes
            """,
            "resources": [
                "https://www.kernel.org/",
                "https://www.sans.org/"
            ]
        },
        {
            "title": "Event IDs to Watch",
            "content": """
Monitor important Linux system logs:
/var/log/auth.log for authentication attempts
/var/log/secure for privileged access
/var/log/syslog for suspicious processes or activity
/var/log/messages for kernel-level logs
            """,
            "resources": [
                "https://www.linuxjournal.com/",
                "https://www.securityfocus.com/"
            ]
        },
        {
            "title": "Memory Acquisition",
            "content": """
### Tools for Live RAM Capture
- AVML (Azure Virtual Machine Live)
- LiME (Linux Memory Extractor)

### File Locations
- `/dev/mem` for memory dump
- `/proc/<pid>/maps` for process memory mapping
            """,
            "resources": [
                "https://volatilityfoundation.org/",
                "https://github.com/504ensicslabs/LiME"
            ]
        },
        {
            "title": "Filesystem Artifacts",
            "content": """
### Look for:
Recent Modifications: `find / -type f -mtime -1`
Hidden Files: `find / -name ".*"`
Unusual Permissions: `find / -perm 777`
Root-level Scripts or Configurations: `/etc/`, `/usr/local/`
            """,
            "resources": [
                "https://www.loggly.com/",
                "https://splunk.com/"
            ]
        },
    ]
