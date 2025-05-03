def get_content():
    return {
        "id": "G0043",
        "url_id": "Group5",
        "title": "Group5",
        "tags": ["Middle East", "Iran", "Syria", "espionage", "RATs", "spearphishing"],
        "description": "Group5 is a cyber threat group suspected to have ties to Iran, although attribution remains uncertain. The group has primarily targeted individuals associated with the Syrian opposition using spearphishing and watering hole techniques. Their campaigns often include Syrian or Iranian themes. Group5 commonly uses remote access tools such as njRAT, NanoCore, and the Android-based DroidJack RAT.",
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1070.004",  # File Deletion
            "T1056.001",  # Keylogging
            "T1027.013",  # Encrypted/Encoded File
            "T1113"       # Screen Capture
        ],
        "contributors": [],
        "version": "1.3",
        "created": "31 May 2017",
        "last_modified": "11 April 2024",
        "navigator": "",  # Insert ATT&CK Navigator reference if applicable
        "references": [
            {
                "source": "Scott-Railton, J., et al.",
                "url": "https://citizenlab.ca/2016/08/group5-syria-iran-connection/"
            }
        ],
        "resources": [],
        "remediation": "Implement endpoint protections against commodity RATs. Educate high-risk targets on phishing techniques and enforce file execution restrictions on Android devices. Monitor for abnormal keylogging or screen capture behaviors.",
        "improvements": "Enhance monitoring of encoded executable files. Detect unauthorized use of remote screen viewing tools. Review outbound connections for RAT communication signatures.",
        "hunt_steps": [
            "Search for file deletion events triggered by remote processes.",
            "Hunt for registry or filesystem indicators related to njRAT and NanoCore.",
            "Scan for encrypted/obfuscated binaries dropped from spearphishing payloads.",
            "Detect screen capture or keylogging behavior on endpoints."
        ],
        "expected_outcomes": [
            "Early detection of commodity RATs in user environments.",
            "Identification of spearphishing or watering hole-based infections.",
            "Interruption of attacker surveillance capabilities through keylogger/screen grabber mitigation."
        ],
        "false_positive": "Legitimate admin tools or encrypted installers may trigger obfuscation detections. Context and source validation are key.",
        "clearing_steps": [
            "Terminate malicious RAT processes (e.g., njRAT, NanoCore).",
            "Remove any registry keys and startup entries used for persistence.",
            "Reimage or restore compromised Android devices if DroidJack is present.",
            "Delete encrypted or obfuscated binaries dropped by the group."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
