def get_content():
    return {
        "id": "G0036",
        "url_id": "GCMAN",
        "title": "GCMAN",
        "tags": ["financial", "e-currency", "banking", "APT", "cybercrime"],
        "description": "GCMAN is a cyber threat group that targets financial institutions, particularly banks, with the objective of illicitly transferring funds to e-currency services. The group is known for using legitimate remote access tools to move laterally within compromised environments.",
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1021.004",  # SSH
            "T1021.005"   # VNC
        ],
        "contributors": [],
        "version": "1.1",
        "created": "31 May 2017",
        "last_modified": "16 April 2025",
        "navigator": "",  # You can add ATT&CK Navigator layer URL if available
        "references": [
            {
                "source": "Kaspersky Lab's Global Research & Analysis Team",
                "url": "https://securelist.com/apt-style-bank-robberies-metel-gcman-and-carbanak-2-0/73860/"
            }
        ],
        "resources": [],
        "remediation": "Restrict and monitor use of remote administration tools such as PuTTY and VNC. Implement network segmentation to limit lateral movement and monitor outbound transactions to e-currency services.",
        "improvements": "Deploy behavior-based detection for SSH/VNC anomalies and unusual transaction patterns. Implement SIEM alerts for non-standard remote access behaviors.",
        "hunt_steps": [
            "Search for unauthorized use of PuTTY and VNC tools on endpoints.",
            "Correlate internal lateral movement events with financial transaction attempts.",
            "Review logs for SSH/VNC usage from unfamiliar IP ranges or user accounts."
        ],
        "expected_outcomes": [
            "Detection of lateral movement via PuTTY or VNC.",
            "Identification of unusual patterns in internal bank transaction workflows.",
            "Improved visibility into remote access tool usage."
        ],
        "false_positive": "Administrators may legitimately use SSH and VNC. Validate context through correlating user behavior, timing, and target systems.",
        "clearing_steps": [
            "Terminate unauthorized remote sessions.",
            "Remove unapproved remote access tools.",
            "Audit and rotate credentials used during compromise."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
