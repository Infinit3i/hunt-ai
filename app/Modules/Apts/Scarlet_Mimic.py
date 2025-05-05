def get_content():
    return {
        "id": "G0029",
        "url_id": "Scarlet_Mimic",
        "title": "Scarlet Mimic",
        "tags": ["espionage", "activist targeting", "China-linked"],
        "description": (
            "Scarlet Mimic is a threat group that has targeted minority rights activists. "
            "Although not directly linked to a specific nation-state, the group’s motivations align with those of the Chinese government. "
            "There is some IP address overlap with Putter Panda, but it has not been concluded that they are the same group."
        ),
        "associated_groups": ["Putter Panda"],
        "campaigns": [],
        "techniques": ["T1036.002"],  # Masquerading: Right-to-Left Override
        "contributors": [],
        "version": "1.2",
        "created": "31 May 2017",
        "last_modified": "16 April 2025",
        "navigator": "",  # None provided by source
        "references": [
            {
                "source": "Palo Alto Networks - Scarlet Mimic",
                "url": "https://unit42.paloaltonetworks.com/scarlet-mimic-years-long-espionage-campaign-targets-minority-activists/"
            }
        ],
        "resources": [],
        "remediation": (
            "Implement robust email filtering and security awareness training to defend against spearphishing attachments. "
            "Monitor for use of right-to-left override characters in file names. "
            "Restrict execution of self-extracting archives via group policies."
        ),
        "improvements": (
            "Deploy endpoint detection and response (EDR) tools capable of identifying timestomping, keylogging, and protocol impersonation. "
            "Update detection rules to monitor uncommon character usage in filenames."
        ),
        "hunt_steps": [
            "Search for filenames using right-to-left override characters (e.g., \u202E).",
            "Review process execution logs for self-extracting RAR archives.",
            "Monitor for tools known to be used by Scarlet Mimic (CallMe, FakeM, MobileOrder, Psylo)."
        ],
        "expected_outcomes": [
            "Identification of masquerading spearphishing attachments.",
            "Detection of unauthorized tool usage related to data exfiltration.",
            "Visibility into attacker use of encryption and protocol obfuscation techniques."
        ],
        "false_positive": "Use of right-to-left override characters may occur in multilingual environments; confirm intent before response.",
        "clearing_steps": [
            "Isolate and reimage affected systems.",
            "Purge all persistence mechanisms established by Scarlet Mimic malware.",
            "Change passwords and credentials on affected user accounts."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
