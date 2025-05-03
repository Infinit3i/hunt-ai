def get_content():
    return {
        "id": "G0140",
        "url_id": "LazyScripter",
        "title": "LazyScripter",
        "tags": ["cybercrime", "open-source tools", "aviation sector", "email phishing"],
        "description": (
            "LazyScripter is a cyber threat group active since at least 2018, known for targeting the airline industry. "
            "The group heavily relies on open-source malware, phishing with malicious attachments or links, and legitimate services like GitHub for payload hosting. "
            "Their operations demonstrate moderate technical sophistication, often combining multiple scripting languages and tools such as Empire and Koadic to achieve persistent access."
        ),
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1583.001", "T1583.006", "T1071.004", "T1547.001", "T1059.001", "T1059.003", "T1059.005", "T1059.007",
            "T1105", "T1036", "T1027.010", "T1588.001", "T1566.001", "T1566.002", "T1608.001", "T1218.005", "T1218.011",
            "T1204.001", "T1204.002", "T1102"
        ],
        "contributors": [
            "Manikantan Srinivasan, NEC Corporation India",
            "Pooja Natarajan, NEC Corporation India",
            "Hiroki Nagahama, NEC Corporation"
        ],
        "version": "1.1",
        "created": "24 November 2021",
        "last_modified": "17 November 2024",
        "navigator": "https://attack.mitre.org/groups/G0140/",
        "references": [
            {
                "source": "MITRE ATT&CK",
                "url": "https://attack.mitre.org/groups/G0140/"
            },
            {
                "source": "H. Jazi",
                "url": "https://www.intezer.com/blog/research/lazyscripter-from-empire-to-double-rat/"
            }
        ],
        "resources": [
            "https://attack.mitre.org/groups/G0140/",
            "https://www.intezer.com/blog/research/lazyscripter-from-empire-to-double-rat/"
        ],
        "remediation": (
            "Block execution of mshta.exe and rundll32.exe where unnecessary, monitor PowerShell activity, and restrict access to GitHub or other public code repositories used for payload delivery. "
            "Use EDR to monitor registry autorun keys and detect signs of staged malware delivery."
        ),
        "improvements": (
            "Improve detection for obfuscated batch or VB scripts, implement email gateway protections to block spearphishing attachments, and educate users to recognize phishing lures."
        ),
        "hunt_steps": [
            "Identify PowerShell or VBScript invoking payloads from unusual registry keys",
            "Detect usage of mshta.exe and rundll32.exe executing payloads from web-based stagers",
            "Audit GitHub access patterns from internal systems",
            "Correlate spearphishing indicators with mail attachments or hyperlinks to executables"
        ],
        "expected_outcomes": [
            "Detection of persistence mechanisms via autorun keys",
            "Identification of dynamic DNS or GitHub-based C2 infrastructure",
            "Mitigation of phishing entry points through content inspection and user training"
        ],
        "false_positive": (
            "PowerShell and rundll32 usage may be legitimate—investigate command-line context and parent-child process relationships for signs of abuse."
        ),
        "clearing_steps": [
            "Delete persistence entries from autorun registry keys",
            "Remove downloaded tools or scripts from compromised endpoints",
            "Revoke access to external services used for staging malware",
            "Reset credentials on impacted user accounts"
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": [
                "https://attack.mitre.org/groups/G0140/",
                "https://www.intezer.com/blog/research/lazyscripter-from-empire-to-double-rat/"
            ]
        }
    }
