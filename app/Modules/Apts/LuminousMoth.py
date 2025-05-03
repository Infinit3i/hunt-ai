def get_content():
    return {
        "id": "G1014",
        "url_id": "LuminousMoth",
        "title": "LuminousMoth",
        "tags": ["state-sponsored", "espionage", "Southeast Asia", "China-linked", "government targeting"],
        "description": (
            "LuminousMoth is a Chinese-speaking cyber espionage group active since at least October 2020. "
            "They have targeted high-profile government entities across Myanmar, the Philippines, Thailand, and surrounding regions. "
            "There is reported overlap in TTPs, infrastructure, and strategic objectives with Mustang Panda. "
            "LuminousMoth is known for spearphishing, USB propagation, credential theft, and exfiltration via cloud services like Google Drive."
        ),
        "associated_groups": ["Mustang Panda"],
        "campaigns": [],
        "techniques": [
            "T1557.002", "T1071.001", "T1560", "T1547.001", "T1005", "T1030", "T1587.001", "T1041",
            "T1567.002", "T1083", "T1564.001", "T1574.001", "T1105", "T1036.005", "T1112",
            "T1588.001", "T1588.002", "T1588.004", "T1566.002", "T1091", "T1053.005", "T1608.001",
            "T1608.004", "T1608.005", "T1539", "T1553.002", "T1033", "T1204.001"
        ],
        "contributors": ["Kyaw Pyiyt Htet (@KyawPyiytHtet)", "Zaw Min Htun (@Z3TAE)"],
        "version": "1.0",
        "created": "23 February 2023",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {
                "source": "Kaspersky",
                "url": "https://securelist.com/luminousmoth-apt-sweeping-attacks/103341/"
            },
            {
                "source": "Bitdefender",
                "url": "https://www.bitdefender.com/blog/labs/luminousmoth-plugx-exfiltration/"
            }
        ],
        "resources": [],
        "remediation": (
            "Disable autorun for removable media, monitor access to Google Drive and Dropbox, block known phishing domains, "
            "and detect DLL side-loading attempts using whitelisted executables."
        ),
        "improvements": (
            "Create rules to detect ARP cache poisoning attempts, hidden file creation on USBs, and PlugX/Cobalt Strike C2 patterns. "
            "Correlate registry run key creations with unsigned binaries. Employ behavior-based detection for lateral movement via media."
        ),
        "hunt_steps": [
            "Search for unauthorized scheduled tasks involving uncommon DLLs",
            "Identify ARP poisoning activity from endpoints",
            "Trace spearphishing email links to Dropbox or other cloud storage",
            "Monitor removable device file transfers containing DLLs or executables"
        ],
        "expected_outcomes": [
            "Identification of spearphishing and malware staging attempts",
            "Detection of data theft via cloud storage providers",
            "Confirmation of malware persistence via registry keys"
        ],
        "false_positive": "Cloud storage use and scheduled tasks may be legitimate; validate source, context, and behavior profiles.",
        "clearing_steps": [
            "Remove malicious DLLs and clear registry autorun keys",
            "Scan removable drives and sanitize affected endpoints",
            "Block malicious domains and reimage compromised hosts if needed"
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": [
                "https://securelist.com/luminousmoth-apt-sweeping-attacks/103341/",
                "https://www.bitdefender.com/blog/labs/luminousmoth-plugx-exfiltration/"
            ]
        }
    }
