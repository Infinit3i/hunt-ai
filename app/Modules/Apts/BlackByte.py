def get_content():
    return {
        "id": "G1043",
        "url_id": "BlackByte",
        "title": "BlackByte",
        "tags": ["ransomware", "north-america", "critical-infrastructure", "privilege-escalation", "data-exfiltration", "financial"],
        "description": "BlackByte is a ransomware threat group active since at least 2021, known for targeting critical infrastructure and organizations across North America. It has evolved from early variants with weak encryption to more advanced versions like BlackByte 2.0, incorporating stronger encryption and new tools such as Exbyte. The group employs a mix of public exploits, credential dumping, remote access tools, and stealthy exfiltration techniques.",
        "associated_groups": ["Hecamede"],
        "campaigns": [],
        "techniques": [
            "T1134.003", "T1087.002", "T1583.003", "T1071.001", "T1560", "T1547.001", "T1059.001", "T1059.003",
            "T1136.002", "T1543.003", "T1486", "T1491.001", "T1140", "T1482", "T1480", "T1041", "T1567",
            "T1190", "T1068", "T1562", "T1562.001", "T1562.004", "T1070.004", "T1105", "T1490", "T1570",
            "T1036.008", "T1112", "T1046", "T1135", "T1003", "T1055", "T1055.012", "T1012", "T1219",
            "T1021.001", "T1021.002", "T1018", "T1053.005", "T1505.003", "T1518.001", "T1608.001",
            "T1082", "T1614.001", "T1016", "T1569.002", "T1078", "T1078.002", "T1047"
        ],
        "contributors": ["Kaung Zaw Hein"],
        "version": "1.0",
        "created": "16 December 2024",
        "last_modified": "09 March 2025",
        "navigator": "",
        "references": [
            {
                "source": "FBI & USSS",
                "url": "https://www.ic3.gov/Media/News/2022/220211.pdf"
            },
            {
                "source": "Symantec",
                "url": "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/blackbyte-exbyte-ransomware"
            },
            {
                "source": "Microsoft Incident Response",
                "url": "https://www.microsoft.com/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/"
            },
            {
                "source": "James Nutland et al.",
                "url": "https://www.redcanary.com/blog/blackbyte-ransomware-2024-report/"
            },
            {
                "source": "Trend Micro",
                "url": "https://www.trendmicro.com/en_us/research/21/j/blackbyte-ransomware-in-depth-analysis.html"
            }
        ],
        "resources": [],
        "remediation": "Ensure patch management covers vulnerabilities such as ProxyLogon, ProxyShell, and CVE-2024-37085. Disable or restrict scripting tools (e.g., PowerShell, WMI), limit SMB access, enforce multi-factor authentication for VPN access, and implement strong EDR tools with rollback capabilities for ransomware scenarios.",
        "improvements": "Deploy monitoring for use of scheduled tasks, base64 PowerShell patterns, registry modifications, and unauthorized domain account creation. Segment networks to limit lateral movement, and monitor public file sharing services for potential staging or exfiltration behavior.",
        "hunt_steps": [
            "Look for PowerShell and WMI activity associated with Volume Shadow Copy deletion",
            "Identify unauthorized domain accounts and persistence via registry run keys",
            "Hunt for use of AnyDesk, Cobalt Strike, and Exbyte in unusual directories or services",
            "Review logs for file uploads to anonymfiles.com, file.io, and similar services",
            "Trace network traffic for masqueraded file types (e.g., .png files containing configs)"
        ],
        "expected_outcomes": [
            "Detection of ransomware activity via unusual process behavior",
            "Identification of pre-encryption exfiltration events",
            "Discovery of adversary staging tools on public file sharing platforms",
            "Blocking of lateral movement via SMB or PsExec",
            "Recovery planning through early detection of defacement and system manipulation"
        ],
        "false_positive": "Some base64 PowerShell activity may be legitimate. Investigate parent processes and user context. Scheduled tasks from known update agents can resemble malicious behavior.",
        "clearing_steps": [
            "Delete malicious scheduled tasks and services",
            "Purge dropped payloads and disable backdoor access tools like AnyDesk",
            "Restore Volume Shadow Copies where possible using backups",
            "Rotate compromised credentials and revoke unauthorized domain accounts",
            "Check for staged data in temp folders or exfil logs and block outbound access to paste and file-sharing services"
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
