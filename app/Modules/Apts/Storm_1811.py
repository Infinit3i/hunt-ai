def get_content():
    return {
        "id": "G1046",
        "url_id": "Storm_1811",
        "title": "Storm-1811",
        "tags": ["financially-motivated", "ransomware", "Black Basta", "phishing", "social engineering"],
        "description": (
            "Storm-1811 is a financially motivated threat group associated with the deployment of "
            "Black Basta ransomware. The group is notable for its creative initial access techniques, "
            "including email bombing campaigns that overwhelm user inboxes with spam to trigger user interaction "
            "with fake IT helpdesk actors. These social engineering tactics are often followed by the use of RMM tools, "
            "malicious scripts, and tools like Cobalt Strike for post-compromise activities."
        ),
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1087.002", "T1583.001", "T1547.001", "T1059.001", "T1059.003", "T1486", "T1074.001",
            "T1140", "T1482", "T1667", "T1585.003", "T1048.002", "T1222.001", "T1574.001", "T1656",
            "T1105", "T1056", "T1570", "T1036", "T1036.005", "T1036.010", "T1027.013", "T1588.002",
            "T1566.002", "T1566.003", "T1566.004", "T1219.002", "T1021.002", "T1021.004", "T1033",
            "T1204.002"
        ],
        "contributors": ["Liran Ravich, CardinalOps", "Joe Gumke, U.S. Bank"],
        "version": "1.0",
        "created": "14 March 2025",
        "last_modified": "14 March 2025",
        "navigator": "",
        "references": [
            {
                "source": "Microsoft Threat Intelligence",
                "url": "https://www.microsoft.com/security/blog/2024/05/15/threat-actors-misusing-quick-assist-in-social-engineering-attacks"
            },
            {
                "source": "Red Canary",
                "url": "https://redcanary.com/blog/black-basta-rmm-tools/"
            }
        ],
        "resources": [],
        "remediation": (
            "Educate users on social engineering and phishing tactics, especially those impersonating IT helpdesks. "
            "Disable unnecessary RMM tools, monitor for BITSAdmin and suspicious PowerShell activity, and enforce multi-factor authentication. "
            "Block known malicious domains and closely monitor Teams activity for spoofed accounts."
        ),
        "improvements": (
            "Deploy behavior-based detection for scripting engines and lateral movement tools like Impacket. "
            "Implement monitoring for anomalous Teams activity and identity spoofing behaviors. "
            "Harden privilege use policies and limit domain account enumeration."
        ),
        "hunt_steps": [
            "Detect spam campaigns targeting inboxes followed by IT support impersonation attempts.",
            "Look for registry keys linked to startup execution (e.g., batch scripts under Run keys).",
            "Monitor Teams communications for unusual sender patterns mimicking internal support.",
            "Trace BITSAdmin or cURL-based tool downloads and subsequent script executions.",
            "Search for PowerShell loops or SSH tunnels not associated with standard operations."
        ],
        "expected_outcomes": [
            "Identification of social engineering footholds via email or Teams.",
            "Detection of lateral movement and persistence mechanisms using DLL hijacking or SMB.",
            "Uncovering of obfuscated files or credential harvesting scripts in endpoint logs."
        ],
        "false_positive": (
            "Legitimate IT tools like Quick Assist or Teams messages may cause false positives. "
            "Review context, user role, and timing when investigating alerts from these sources."
        ),
        "clearing_steps": [
            "Remove malicious scheduled tasks, scripts, or RMM installs.",
            "Revoke compromised credentials and investigate Teams impersonations.",
            "Purge suspicious registry keys and quarantine affected systems.",
            "Conduct full memory and disk scans for beacons or credential harvesting tools."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
