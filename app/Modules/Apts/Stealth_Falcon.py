def get_content():
    return {
        "id": "G0038",
        "url_id": "Stealth_Falcon",
        "title": "Stealth Falcon",
        "tags": ["state-sponsored", "Middle East", "surveillance", "UAE-linked"],
        "description": (
            "Stealth Falcon is a threat group that has conducted targeted spyware attacks "
            "against Emirati journalists, activists, and dissidents since at least 2012. "
            "Circumstantial evidence suggests potential links to the United Arab Emirates "
            "(UAE) government, though not confirmed."
        ),
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1071.001",  # Web Protocols
            "T1059",       # Command and Scripting Interpreter
            "T1059.001",   # PowerShell
            "T1555",       # Credentials from Password Stores
            "T1555.003",   # Credentials from Web Browsers
            "T1555.004",   # Windows Credential Manager
            "T1005",       # Data from Local System
            "T1573.001",   # Encrypted Channel: Symmetric Cryptography
            "T1041",       # Exfiltration Over C2 Channel
            "T1057",       # Process Discovery
            "T1012",       # Query Registry
            "T1053.005",   # Scheduled Task
            "T1082",       # System Information Discovery
            "T1016",       # System Network Configuration Discovery
            "T1033",       # System Owner/User Discovery
            "T1047"        # Windows Management Instrumentation
        ],
        "contributors": [],
        "version": "1.2",
        "created": "31 May 2017",
        "last_modified": "16 April 2025",
        "navigator": "",  # You can populate this if there's a MITRE ATT&CK Navigator layer
        "references": [
            {
                "source": "Citizen Lab",
                "url": "https://citizenlab.ca/2016/05/stealth-falcon/"
            }
        ],
        "resources": [],
        "remediation": (
            "Monitor for abnormal WMI, PowerShell, and scheduled task usage. "
            "Implement network monitoring for suspicious HTTPS traffic to known C2 domains. "
            "Educate at-risk users about phishing and macro-enabled documents."
        ),
        "improvements": (
            "Deploy behavioral analytics to detect misuse of native Windows tools such as WMI "
            "and PowerShell. Enhance visibility into credential store access events and registry queries."
        ),
        "hunt_steps": [
            "Search for scheduled task creation with names like 'IE Web Cache'.",
            "Look for outbound HTTPS traffic to unknown or suspicious domains.",
            "Monitor PowerShell scripts that collect system or user data.",
            "Identify WMI usage not tied to legitimate system administration activity."
        ],
        "expected_outcomes": [
            "Identification of anomalous scripting and task scheduling behavior.",
            "Detection of unauthorized access to credential stores and browser-stored passwords.",
            "Discovery of encrypted C2 communications and lateral movement indicators."
        ],
        "false_positive": (
            "Legitimate administrative scripts and tools may exhibit similar behavior; "
            "baseline normal usage to reduce noise."
        ),
        "clearing_steps": [
            "Remove malicious scheduled tasks.",
            "Terminate associated malicious processes.",
            "Revoke and reset stolen credentials.",
            "Isolate and reimage compromised systems if necessary."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
