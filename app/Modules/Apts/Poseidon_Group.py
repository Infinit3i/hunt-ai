def get_content():
    return {
        "id": "G0033",
        "url_id": "Poseidon_Group",
        "title": "Poseidon Group",
        "tags": ["financially-motivated", "portuguese-speaking", "espionage", "blackmail"],
        "description": (
            "Poseidon Group is a Portuguese-speaking threat actor active since at least 2005. "
            "The group is known for conducting targeted espionage campaigns against businesses, "
            "primarily in Brazil and Latin America. A unique tactic employed by the group is "
            "the use of exfiltrated data to blackmail victims into hiring Poseidon as a security contractor. "
            "Their operations suggest a blend of financial motivation and opportunistic coercion."
        ),
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1087.001",  # Account Discovery: Local Account
            "T1087.002",  # Account Discovery: Domain Account
            "T1059.001",  # Command and Scripting Interpreter: PowerShell
            "T1036.005",  # Masquerading: Match Legitimate Resource Name or Location
            "T1003",      # OS Credential Dumping
            "T1057",      # Process Discovery
            "T1049",      # System Network Connections Discovery
            "T1007"       # System Service Discovery
        ],
        "contributors": ["MITRE ATT&CK Team"],
        "version": "1.1",
        "created": "31 May 2017",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {
                "source": "Kaspersky Lab's Global Research and Analysis Team",
                "url": "https://securelist.com/poseidon-group-a-targeted-attack-boutique-specializing-in-global-cyber-espionage/73751/"
            }
        ],
        "resources": [],
        "remediation": (
            "Organizations should employ least privilege principles, disable PowerShell where unnecessary, "
            "implement EDR solutions to monitor process and service enumeration, and regularly audit accounts for suspicious activity."
        ),
        "improvements": (
            "Enhance behavioral detections around PowerShell usage, mimicry of antivirus process names, "
            "and large-scale credential access or service enumeration. Consider anomaly-based detections for process discovery patterns."
        ),
        "hunt_steps": [
            "Search for PowerShell executions using encoded commands or unusual parent-child relationships.",
            "Look for masquerading attempts where process names resemble known AV tools.",
            "Hunt for abnormal system discovery activities, especially during off-hours.",
            "Investigate repeated account enumeration attempts across hosts."
        ],
        "expected_outcomes": [
            "Identification of potential pre-exploitation reconnaissance activity.",
            "Detection of anomalous PowerShell execution indicative of toolkits like IGT.",
            "Discovery of process or network enumeration suggestive of post-compromise movement."
        ],
        "false_positive": (
            "Legitimate administrative activity may resemble discovery behavior. Contextualize findings with user roles, "
            "system baselines, and timing."
        ),
        "clearing_steps": [
            "Isolate and reimage affected systems.",
            "Revoke and rotate compromised credentials.",
            "Audit and clean up any unauthorized persistence mechanisms.",
            "Conduct forensic analysis to determine the extent of access and exfiltration."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
