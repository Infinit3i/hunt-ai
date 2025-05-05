def get_content():
    return {
        "id": "G0041",
        "url_id": "Strider",
        "title": "Strider",
        "tags": ["cyberespionage", "stealth", "Remsec", "ProjectSauron"],
        "description": (
            "Strider is a threat group that has been active since at least 2011 and has targeted organizations "
            "in countries including Russia, China, Sweden, Belgium, Iran, and Rwanda. The group is known for using "
            "custom malware called Remsec (S0125) and for operating with a high level of sophistication aimed at long-term espionage."
        ),
        "associated_groups": ["ProjectSauron"],
        "campaigns": [],
        "techniques": [
            "T1564.005",  # Hidden File System
            "T1556.002",  # Password Filter DLL
            "T1090.001"   # Internal Proxy
        ],
        "contributors": [],
        "version": "1.1",
        "created": "31 May 2017",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {
                "source": "Symantec Security Response",
                "url": "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/strider-eye-saureon"
            },
            {
                "source": "Kaspersky GReAT",
                "url": "https://securelist.com/apt-projectsauron/75533/"
            }
        ],
        "resources": [],
        "remediation": (
            "Audit systems for unauthorized password filter DLLs and hidden file systems. "
            "Segment networks and block lateral movement paths using internal proxy behavior. "
            "Use endpoint detection and response (EDR) tools to uncover hidden artifacts and stealth malware like Remsec."
        ),
        "improvements": (
            "Deploy kernel-level integrity checks to identify hidden file systems. "
            "Improve visibility on domain controllers for unauthorized authentication modules. "
            "Strengthen internal monitoring of proxy behavior and data exfiltration routes."
        ),
        "hunt_steps": [
            "Search domain controllers for non-standard password filter DLLs.",
            "Identify files stored in unusual or hidden formats on disk.",
            "Look for internal proxies relaying data from isolated segments to Internet-connected hosts."
        ],
        "expected_outcomes": [
            "Detection of unauthorized credential harvesting mechanisms.",
            "Exposure of stealthy data exfiltration techniques via internal proxies.",
            "Uncovering of hidden file containers used for persistence or staging."
        ],
        "false_positive": (
            "Custom password filters or backup proxy services in enterprise environments may resemble some TTPs. "
            "Validate legitimacy before escalation."
        ),
        "clearing_steps": [
            "Remove unauthorized password filter DLLs and associated registry entries.",
            "Clean up hidden file systems or suspicious file containers.",
            "Block and monitor hosts acting as unauthorized internal proxy nodes."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
