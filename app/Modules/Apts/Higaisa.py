def get_content():
    return {
        "id": "G0126",
        "url_id": "Higaisa",
        "title": "Higaisa",
        "tags": ["APT", "espionage", "South Korea", "government targeting", "long-term operations"],
        "description": (
            "Higaisa is a threat group suspected to have South Korean origins. They have primarily targeted government, "
            "public, and trade organizations in North Korea, but their campaigns have also reached China, Japan, Russia, "
            "Poland, and other countries. First publicly disclosed in 2019, evidence suggests Higaisa has been operational "
            "since at least 2009."
        ),
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1071.001", "T1547.001", "T1059.003", "T1059.005", "T1059.007",
            "T1001.003", "T1140", "T1573.001", "T1041", "T1203", "T1564.003",
            "T1574.001", "T1036.004", "T1106", "T1027.001", "T1027.013",
            "T1027.015", "T1566.001", "T1057", "T1090.001", "T1053.005",
            "T1029", "T1082", "T1016", "T1124", "T1204.002", "T1220"
        ],
        "contributors": ["Daniyal Naeem", "BT Security"],
        "version": "1.1",
        "created": "05 March 2021",
        "last_modified": "11 April 2024",
        "navigator": "",
        "references": [
            {
                "source": "Malwarebytes Threat Intelligence Team",
                "url": "https://blog.malwarebytes.com/threat-intelligence/2020/06/new-lnk-attack-tied-to-higaisa-apt-discovered/"
            },
            {
                "source": "The Return on the Higaisa APT",
                "url": "https://research.checkpoint.com/2020/the-return-on-the-higaisa-apt/"
            },
            {
                "source": "PT ESC Threat Intelligence",
                "url": "https://www.ptsecurity.com/ww-en/analytics/cyberattacks/covid-19-and-new-year-greetings-investigation-into-higaisa/"
            }
        ],
        "resources": [],
        "remediation": (
            "Implement layered detection for scripting languages (e.g., VBScript, JavaScript), regularly update software to "
            "patch known vulnerabilities such as CVE-2018-0798, and monitor for use of living-off-the-land binaries like certutil. "
            "Restrict execution of LNK files from emails and enhance email security filtering."
        ),
        "improvements": (
            "Enhance behavioral analytics to detect obfuscated file execution, monitor registry persistence attempts, "
            "and establish anomaly detection baselines for web protocol traffic."
        ),
        "hunt_steps": [
            "Search for unexpected certutil usage with base64 decoding flags.",
            "Monitor for scheduled tasks named 'officeupdate.exe' or similar spoofed binaries.",
            "Review registry Run keys for uncommon executables or locations.",
            "Look for usage of cmd.exe, JavaScript, or VBScript in unusual contexts."
        ],
        "expected_outcomes": [
            "Identification of persistence mechanisms linked to registry or startup folders.",
            "Detection of LNK file execution from phishing emails.",
            "Flagging of anomalous HTTPS traffic patterns indicative of encrypted C2."
        ],
        "false_positive": (
            "Some use of certutil and cmd.exe may be legitimate; verify the context and parent processes to reduce false positives."
        ),
        "clearing_steps": [
            "Delete identified scheduled tasks and spoofed startup folder binaries.",
            "Revoke malicious persistence mechanisms in registry keys.",
            "Isolate affected systems and conduct forensic imaging for deeper analysis."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
