def get_content():
    return {
        "id": "G1034",
        "url_id": "Daggerfly",
        "title": "Daggerfly",
        "tags": ["chinese", "state-sponsored", "supply-chain", "espionage", "telecom", "africa", "asia"],
        "description": "Daggerfly is a People's Republic of China-linked APT group active since at least 2012. It targets individuals, governments, NGOs, and telecoms in Asia and Africa. Daggerfly is known for its exclusive use of MgBot malware and is associated with supply chain attacks using compromised software updates.",
        "associated_groups": ["Evasive Panda", "BRONZE HIGHLAND"],
        "campaigns": [],
        "techniques": [
            "T1071.001", "T1059.001", "T1584.004", "T1136.001", "T1587.002", "T1189", "T1574.001",
            "T1105", "T1036.003", "T1003.002", "T1012", "T1053.005", "T1553.002", "T1195.002",
            "T1218.011", "T1082", "T1204.001"
        ],
        "contributors": ["Furkan Celik", "PURE7"],
        "version": "1.0",
        "created": "25 July 2024",
        "last_modified": "31 October 2024",
        "navigator": "",
        "references": [
            {"source": "Threat Hunter Team", "url": "https://www.example.com/daggerfly-targets-telecoms-africa"},
            {"source": "Facundo Muñoz", "url": "https://www.example.com/evasive-panda-malware-chinese-software"},
            {"source": "Threat Hunter Team", "url": "https://www.example.com/daggerfly-major-toolset-update"},
            {"source": "Ahn Ho, Facundo Muñoz, & Marc-Etienne M.Léveillé", "url": "https://www.example.com/evasive-panda-targets-tibetans"}
        ],
        "resources": ["MgBot analysis", "MacMa malware profile", "PlugX and Nightdoor usage reports"],
        "remediation": "Audit software update sources for tampering. Deploy application allowlisting to detect unauthorized DLL loading. Monitor PowerShell and BITSAdmin usage across endpoints.",
        "improvements": "Implement strict validation for software updates. Detect side-loaded DLLs and masqueraded binaries. Alert on suspicious scheduled task creation and use of renamed native binaries.",
        "hunt_steps": [
            "Search for renamed rundll32 binaries like 'dbengin.exe' in uncommon directories.",
            "Detect PowerShell and BITSAdmin usage downloading remote payloads.",
            "Look for signs of PlugX and MgBot payloads, including registry modifications and credential dumping attempts.",
            "Review creation of local accounts and usage of untrusted code signing certificates."
        ],
        "expected_outcomes": [
            "Detection of side-loading behavior and masquerading via renamed DLL loaders.",
            "Evidence of unauthorized persistence via scheduled tasks and registry keys.",
            "Identification of supply chain intrusion vectors from compromised software updates.",
            "Tracking of unique malware payloads like MgBot and Nightdoor."
        ],
        "false_positive": "Renamed binaries may occur in rare legitimate use cases. Validate binary hashes and locations. BITSAdmin use is rare in modern enterprise environments and should be investigated.",
        "clearing_steps": [
            "Revert or remove malicious DLLs and scheduled tasks.",
            "Delete unauthorized local accounts.",
            "Reimage or clean infected hosts with evidence of PlugX or MgBot.",
            "Revoke any discovered rogue code signing certificates."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
