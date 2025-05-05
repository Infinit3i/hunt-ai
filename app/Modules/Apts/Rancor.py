def get_content():
    return {
        "id": "G0075",
        "url_id": "Rancor",
        "title": "Rancor",
        "tags": ["espionage", "southeast-asia", "targeted-attacks", "phishing", "custom-malware"],
        "description": (
            "Rancor is a threat group that has conducted cyber espionage operations primarily targeting the South East Asia region. "
            "The group is known for delivering custom malware families through politically-motivated lures, including spearphishing attachments with embedded macros. "
            "Their toolkit includes malware such as PLAINTEE and DDKONG, and they have leveraged techniques like WMI persistence, scheduled tasks, and use of system binaries for stealth."
        ),
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1071.001",  # Application Layer Protocol: Web Protocols
            "T1059.003",  # Windows Command Shell
            "T1059.005",  # Visual Basic
            "T1546.003",  # WMI Event Subscription
            "T1105",      # Ingress Tool Transfer
            "T1566.001",  # Spearphishing Attachment
            "T1053.005",  # Scheduled Task
            "T1218.007",  # Msiexec
            "T1204.002"   # User Execution: Malicious File
        ],
        "contributors": ["MITRE ATT&CK Team"],
        "version": "1.3",
        "created": "17 October 2018",
        "last_modified": "09 February 2024",
        "navigator": "",
        "references": [
            {
                "source": "Palo Alto Networks - Unit 42",
                "url": "https://unit42.paloaltonetworks.com/rancor-targeted-attacks-in-southeast-asia-using-plaintee-and-ddkong/"
            },
            {
                "source": "Palo Alto Networks - Update",
                "url": "https://unit42.paloaltonetworks.com/rancor-cyber-espionage-group-uses-new-custom-malware-to-attack-southeast-asia/"
            }
        ],
        "resources": [],
        "remediation": (
            "Block execution of embedded macros in Office documents from untrusted sources, implement email gateway filtering to detect phishing attempts, "
            "and monitor scheduled tasks and WMI subscriptions for suspicious entries. Deploy application control policies to restrict msiexec usage for unauthorized installations."
        ),
        "improvements": (
            "Add detection rules for script execution via cmd.exe and VBScript. Monitor unusual msiexec network activity and enforce stricter macro policy across the enterprise. "
            "Harden registry permissions to prevent abuse and enable logging of WMI activity."
        ),
        "hunt_steps": [
            "Review email logs for attachments with Office macros sent from suspicious domains.",
            "Search for recent scheduled task creations via `schtasks /create` with non-standard binaries.",
            "Check for WMI Event Subscription modifications, especially involving MOF files.",
            "Inspect msiexec network traffic and command-line usage for unexpected downloads.",
            "Hunt for command-line activity from cmd.exe and wscript/cscript tied to user profiles."
        ],
        "expected_outcomes": [
            "Identification of spearphishing delivery mechanisms.",
            "Detection of persistence methods via WMI and scheduled tasks.",
            "Recognition of custom malware dropped via system binary abuse (e.g., msiexec).",
            "Understanding of attacker command execution patterns using Windows scripting environments."
        ],
        "false_positive": (
            "Macros, scheduled tasks, and msiexec may be used by legitimate administrators or installers. "
            "Contextual analysis is required—verify origin, execution chain, and behavioral indicators."
        ),
        "clearing_steps": [
            "Delete malicious scheduled tasks and unregister WMI subscriptions.",
            "Remove any downloaded payloads and clean up temp or staging directories.",
            "Block domains and IPs associated with malware C2 used by Rancor.",
            "Reimage compromised hosts if persistence or credential theft is suspected."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
