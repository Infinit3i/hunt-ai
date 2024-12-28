def get_mitre_content():
    return [
        {
            "title": "Initial Access",
            "description": """
                Techniques used by attackers to gain initial access to a target network or system.
            """,
            "resources": [
                "https://attack.mitre.org/tactics/TA0001/",
                "https://www.cisa.gov/"
            ],
        },
        {
            "title": "Execution",
            "description": """
                Methods used by attackers to execute malicious code on a target system.
            """,
            "resources": [
                "https://attack.mitre.org/tactics/TA0002/",
                "https://www.cyber.gov.au/"
            ],
        },
        {
            "title": "Persistence",
            "description": """
                Techniques that allow attackers to maintain their foothold in a network even after a reboot or credential changes.
            """,
            "resources": [
                "https://attack.mitre.org/tactics/TA0003/",
                "https://www.ncsc.gov.uk/"
            ],
        },
        {
            "title": "Privilege Escalation",
            "description": """
                Methods used to gain higher-level permissions on a system.
            """,
            "resources": [
                "https://attack.mitre.org/tactics/TA0004/",
                "https://www.sans.org/"
            ],
        },
        {
            "title": "Defense Evasion",
            "description": """
                Techniques employed to avoid detection and hide activities.
            """,
            "resources": [
                "https://attack.mitre.org/tactics/TA0005/",
                "https://securityboulevard.com/"
            ],
        },
        {
            "title": "Credential Access",
            "description": """
                Techniques used to steal account credentials such as passwords or keys.
            """,
            "resources": [
                "https://attack.mitre.org/tactics/TA0006/",
                "https://www.kaspersky.com/"
            ],
        },
        {
            "title": "Discovery",
            "description": """
                Methods to gather information about the system, network, or domain.
            """,
            "resources": [
                "https://attack.mitre.org/tactics/TA0007/",
                "https://www.symantec.com/"
            ],
        },
        {
            "title": "Lateral Movement",
            "description": """
                Techniques used to move through a network from one system to another.
            """,
            "resources": [
                "https://attack.mitre.org/tactics/TA0008/",
                "https://www.paloaltonetworks.com/"
            ],
        },
        {
            "title": "Collection",
            "description": """
                Techniques used to gather data of interest from a target network or system.
            """,
            "resources": [
                "https://attack.mitre.org/tactics/TA0009/",
                "https://www.trendmicro.com/"
            ],
        },
        {
            "title": "Exfiltration",
            "description": """
                Methods to transfer data from a target network to an external system.
            """,
            "resources": [
                "https://attack.mitre.org/tactics/TA0010/",
                "https://www.darkreading.com/"
            ],
        },
        {
            "title": "Command and Control",
            "description": """
                Techniques that enable attackers to communicate with systems under their control within a target network.
            """,
            "resources": [
                "https://attack.mitre.org/tactics/TA0011/",
                "https://www.fireeye.com/"
            ],
        },
    ]
