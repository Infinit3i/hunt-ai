def get_content():
    return {
        "id": "",  # APT Group ID (e.g., G1017)
        "url_id": "",  # URL segment for group reference (e.g., "G1017")
        "title": "",  # Name of the APT group (e.g., "Volt Typhoon")
        "tags": [],  # Tags associated with the group (e.g., ["state-sponsored", "critical infrastructure"])
        "description": "",  # Overview/description of the APT group and its objectives
        "associated_groups": [],  # Other groups associated with this APT (e.g., ["BRONZE SILHOUETTE", "Vanguard Panda", ...])
        "campaigns": [  # Campaigns attributed to this APT
            {
                "id": "",  # Campaign ID (e.g., "C0035")
                "name": "",  # Campaign name (e.g., "KV Botnet Activity")
                "first_seen": "",  # First seen date (e.g., "October 2022")
                "last_seen": "",  # Last seen date (e.g., "January 2024")
                "references": []  # List of references or URLs for the campaign details
            }
        ],
        "techniques": [],  # List of techniques employed by this APT group (e.g., ["T1087", "T1059", ...])
        "contributors": [],  # Contributors of the intel (e.g., names and organizations)
        "version": "",  # Version of this APT entry (e.g., "2.0")
        "created": "",  # Date when this entry was created (e.g., "27 July 2023")
        "last_modified": "",  # Date when this entry was last modified (e.g., "21 May 2024")
        "navigator": "", # Reference to the MITRE ATT&CK Navigator of the APT
        "references": [  # References and source documents
            {"source": "", "url": ""}
        ],
        "resources": [],  # Additional resources (e.g., CTI reports, blog posts, external sites)
        "remediation": "",  # Recommended actions to mitigate risks posed by this APT
        "improvements": "",  # Suggestions for enhancing detection and response related to this APT
        "hunt_steps": [],  # Proactive threat hunting steps to look for indicators of this APT
        "expected_outcomes": [],  # Expected outcomes/results from threat hunting against this APT
        "false_positive": "",  # Known false positives and guidance on handling them
        "clearing_steps": [],  # Steps for remediation and clearing traces from affected systems
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [],  # List of SHA256 hash values
            "md5": [],  # List of MD5 hash values
            "ip": [],  # List of IP addresses associated with the APT
            "domain": [],  # List of domains associated with the APT
            "resources": []  # Additional resources or references for IOCs if applicable
        }
    }
