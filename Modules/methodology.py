def get_methodology_content():
    """
    Returns structured content for the Methodology page with sections containing resources.
    """
    return [
        {
            "title": "Baseline",
            "description": "",
            "link": "https://docs.google.com/spreadsheets/d/1s2ggAq69Z5UcZen1Q-o8gBHBv6UiJHaeFW3QwtTLnq4/edit?usp=sharing",
        },
        {
            "title": "MITRE TIE",
            "description": "MITRE AI to predict next T-Code.",
            "link": "https://center-for-threat-informed-defense.github.io/technique-inference-engine/#/",
        },
        {
            "title": "Linux Basics",
            "content": """
- Understand typical file paths and permission settings.
- Monitor unexpected or unplanned cron jobs.
- Investigate binaries with SUID or SGID bits set (`find / -perm -4000`).
- Look for rogue or uncommon processes running as root.
- Analyze .bash_history for suspicious commands.
- Investigate `/var/log/auth.log` for failed or unauthorized access.
- Check for hidden files and directories using `find / -type f -name ".*"`.
            """,
            "resources": [
                "https://www.linux.org/",
                "https://www.cyberciti.biz/",
                "https://www.linuxsecurity.com/"
            ]
        },
        {
            "title": "Windows Basics",
            "content": """
- Look for file extensions.
- look for files that can be used in phishing.
- look for users with many failed login attempts then successful.
- Initial access and lateral movement are the loudest.
- Understand how PID and PPID relate.
- Look for 1-2 character .exe (e.g., a.exe, ab.exe).
- C2 exploits are native in 32-bit.
- Files should not have read, write, and execute simultaneously
  - Should be RW- ro --X.
- Know where attackers store files.
- C:\\windows\\system32: Exe files are not usually stored here.
            """,
            "resources": [
                "https://www.microsoft.com/en-us/security",
                "https://attack.mitre.org/",
                "https://learn.microsoft.com/en-us/sysinternals/"
            ]
        },
        {
            "title": "Time of Incident",
            "content": """
- SIEM/IDS/AV alert
- what happened around what you are looking at?
- 3rd Party Notification
            """,
            "resources": [
                "https://www.splunk.com/",
                "https://owasp.org/www-project-intrusion-detection-systems/"
            ]
        },
        {
            "title": "Network Activity",
            "content": """
- Malicious URLs accessed
- where is the malicious ip?
- what port is it using?
- what is it reaching out to?
- is it touching multiple of your systems?
- DNS requests for bad domains
            """,
            "resources": [
                "https://www.virustotal.com/gui/home/url",
                "https://www.cloudflare.com/dns/"
            ]
        },
        {
            "title": "Process Activity",
            "content": """
- Running process related to incident
- DLL injection detected
            """,
            "resources": [
                "https://processhacker.sourceforge.io/",
                "https://www.sciencedirect.com/topics/computer-science/dll-injection"
            ]
        },
        {
            "title": "Name of a File",
            "content": """
- File name of interest (e.g., p.exe, r1.exe)
- File type of interest (e.g., .rar, .py, .ps1)
            """,
            "resources": [
                "https://fileinfo.com/",
                "https://www.hybrid-analysis.com/"
            ]
        }
    ]
