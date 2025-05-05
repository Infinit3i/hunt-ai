def get_content():
    return {
        "id": "G0068",
        "url_id": "PLATINUM",
        "title": "PLATINUM",
        "tags": [
            "APT", "South Asia", "Southeast Asia", "Intel AMT", "Keylogging", "Credential Dumping",
            "Process Injection", "Spearphishing", "Drive-by", "Microsoft report", "Cyber espionage"
        ],
        "description": (
            "PLATINUM is a cyber espionage group that has operated since at least 2009, "
            "focusing on government and related targets in South and Southeast Asia. "
            "The group is notable for its sophisticated techniques, including use of Intel® AMT "
            "Serial-over-LAN (SOL) for covert communications, advanced credential dumping, process injection, "
            "and a wide array of malware families. PLATINUM relies heavily on spearphishing campaigns and masquerading "
            "to gain initial access and maintain persistence within target environments."
        ),
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1189",  # Drive-by Compromise
            "T1068",  # Exploitation for Privilege Escalation
            "T1105",  # Ingress Tool Transfer
            "T1056.001",  # Input Capture: Keylogging
            "T1056.004",  # Input Capture: Credential API Hooking
            "T1036",  # Masquerading
            "T1095",  # Non-Application Layer Protocol
            "T1003.001",  # OS Credential Dumping: LSASS Memory
            "T1566.001",  # Phishing: Spearphishing Attachment
            "T1055",  # Process Injection
            "T1204.002"  # User Execution: Malicious File
        ],
        "contributors": ["Ryan Becwar"],
        "version": "1.3",
        "created": "18 April 2018",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {
                "source": "Microsoft Defender ATP",
                "url": "https://www.microsoft.com/security/blog/2016/04/29/platinum-targeted-attacks-in-south-and-southeast-asia/"
            },
            {
                "source": "Microsoft Research",
                "url": "https://www.microsoft.com/security/blog/2017/06/07/platinum-continues-to-evolve-find-ways-to-maintain-invisibility/"
            },
            {
                "source": "FireEye Nick Carr",
                "url": "https://twitter.com/nickandreacarr/status/1055599355057553409"
            }
        ],
        "resources": [],
        "remediation": (
            "Block access to unused hardware interfaces including Intel AMT via BIOS settings. "
            "Enforce email security controls and sandboxing for file attachments. "
            "Monitor for masquerading behavior such as renamed system binaries (e.g., rar.exe) "
            "and unauthorized use of WMI event subscriptions."
        ),
        "improvements": (
            "Deploy endpoint behavior analytics to detect injection and credential access patterns. "
            "Incorporate detections for Serial-over-LAN traffic and monitor execution of renamed binaries. "
            "Strengthen user training against phishing and regularly rotate administrative credentials."
        ),
        "hunt_steps": [
            "Search for renamed binaries like rar.exe in user directories.",
            "Inspect SOL (Serial-over-LAN) traffic or Intel AMT configuration changes.",
            "Check for unusual process injection or hot patching indicators in memory.",
            "Identify WMI subscriptions that trigger rare scripts or binaries."
        ],
        "expected_outcomes": [
            "Detection of unauthorized AMT usage for file transfers.",
            "Identification of keylogger deployment and credential theft.",
            "Discovery of process injection and lateral movement methods."
        ],
        "false_positive": (
            "Renamed binaries or command-line activity may resemble administrative actions. "
            "AMT may be used in enterprise settings—validate usage with asset teams before response."
        ),
        "clearing_steps": [
            "Disable Intel AMT or restrict SOL usage via BIOS/firmware settings.",
            "Delete malicious WMI subscriptions and injected DLLs or processes.",
            "Change credentials stored on affected systems and reset LSASS memory protections."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
