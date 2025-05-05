def get_content():
    return {
        "id": "G1008",
        "url_id": "SideCopy",
        "title": "SideCopy",
        "tags": ["Pakistan", "South Asia", "espionage", "government targeting", "spearphishing"],
        "description": (
            "SideCopy is a Pakistani threat group active since at least 2019, primarily targeting South Asian nations, "
            "notably Indian and Afghani government personnel. The group is known for its deceptive infection chains that mimic "
            "Sidewinder, a suspected Indian threat group. SideCopy commonly uses spearphishing attachments, remote access tools, "
            "and compromised infrastructure to gain and maintain access to target environments."
        ),
        "associated_groups": ["Sidewinder (mimicked)"],
        "campaigns": [],
        "techniques": [
            "T1059.005", "T1584.001", "T1574.001", "T1105", "T1036.005", "T1106",
            "T1566.001", "T1598.002", "T1518", "T1518.001", "T1608.001", "T1218.005",
            "T1082", "T1614", "T1016", "T1204.002"
        ],
        "contributors": [
            "Pooja Natarajan, NEC Corporation India",
            "Hiroki Nagahama, NEC Corporation",
            "Manikantan Srinivasan, NEC Corporation India"
        ],
        "version": "1.0",
        "created": "07 August 2022",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {
                "source": "Threat Intelligence Team",
                "url": "https://www.quickheal.com/blog/sidecopy-apt-connecting-lures-victims-payloads-to-infrastructure"
            }
        ],
        "resources": [],
        "remediation": (
            "Disable macros in Office applications and block execution of system tools like mshta.exe when not needed. "
            "Monitor DLL side-loading attempts and unauthorized external domain connections. "
            "Harden endpoint defenses against malicious HTA files and remote payload downloads."
        ),
        "improvements": (
            "Deploy sandbox-based email attachment inspection and monitor for process chains involving Office apps spawning mshta.exe. "
            "Use DNS filtering to block access to known SideCopy infrastructure and enable EDR logging of DLL load paths."
        ),
        "hunt_steps": [
            "Look for mshta.exe execution events with arguments pointing to HTA files.",
            "Identify uncommon use of CreateProcessW API in scripting or Office processes.",
            "Search for network connections to recently registered or suspicious domains serving DLL payloads."
        ],
        "expected_outcomes": [
            "Detection of spearphishing attempts using Office Publisher and HTA-based loaders.",
            "Identification of masquerading or DLL side-loading behavior linked to custom RATs.",
            "Visibility into post-exploitation staging and credential collection activities."
        ],
        "false_positive": "Legitimate use of mshta.exe or CreateProcessW may occur in enterprise environments; verify contextual usage and source.",
        "clearing_steps": [
            "Terminate malicious processes and quarantine dropped HTA and DLL payloads.",
            "Remove persistence mechanisms (e.g., startup entries, registry keys).",
            "Reset credentials, particularly those stored in browser sessions or system memory."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": [
                "https://www.quickheal.com/blog/sidecopy-apt-connecting-lures-victims-payloads-to-infrastructure"
            ]
        }
    }
