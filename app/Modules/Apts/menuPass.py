def get_content():
    return {
        "id": "G0045",
        "url_id": "menuPass",
        "title": "menuPass",
        "tags": ["Chinese-state sponsored", "global espionage", "APT10", "MSS"],
        "description": "menuPass is a Chinese threat group active since at least 2006, known for its association with the Ministry of State Security (MSS) Tianjin State Security Bureau. The group has conducted cyber espionage against global targets across industries such as defense, healthcare, aerospace, energy, and education. It is particularly noted for extensive operations against Japanese organizations and global managed service providers (MSPs).",
        "associated_groups": [
            "Cicada", "POTASSIUM", "Stone Panda", "APT10",
            "Red Apollo", "CVNX", "HOGFISH", "BRONZE RIVERSIDE"
        ],
        "campaigns": [],
        "techniques": [
            "T1087.002", "T1583.001", "T1560", "T1560.001", "T1119", "T1059.001", "T1059.003",
            "T1005", "T1039", "T1074.001", "T1074.002", "T1140", "T1568.001", "T1190", "T1210",
            "T1083", "T1574.001", "T1070.003", "T1070.004", "T1105", "T1056.001", "T1036",
            "T1036.003", "T1036.005", "T1106", "T1046", "T1027.013", "T1588.002", "T1003.002",
            "T1003.003", "T1003.004", "T1566.001", "T1055.012", "T1090.002", "T1021.001",
            "T1021.004", "T1018", "T1053.005", "T1553.002", "T1218.004", "T1016", "T1049",
            "T1199", "T1204.002", "T1078", "T1047"
        ],
        "contributors": ["Edward Millington", "Michael Cox"],
        "version": "3.0",
        "created": "31 May 2017",
        "last_modified": "17 November 2024",
        "navigator": "",  # Can be filled with a valid MITRE Navigator layer URL
        "references": [
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0045/"},
            {"source": "USDC SDNY", "url": "https://www.justice.gov/opa/press-release/file/1116411/download"},
            {"source": "Operation Cloud Hopper", "url": "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"}
        ],
        "resources": [
            "https://attack.mitre.org/groups/G0045/",
            "https://www.justice.gov/opa/pr/two-chinese-hackers-associated-ministry-state-security-charged-global-computer-intrusion",
            "https://www.pwc.co.uk/operation-cloud-hopper"
        ],
        "remediation": "Enforce strong segmentation between MSP and client networks, monitor for suspicious use of PowerShell and certutil, restrict outbound DNS and HTTP traffic where not required, and deploy behavioral endpoint detection tools.",
        "improvements": "Enhance SOC visibility into scheduled task execution, process injection, and DLL sideloading behaviors. Enable script block logging and deep PowerShell logging. Detect abuse of signed tools (Living off the Land Binaries).",
        "hunt_steps": [
            "Search for certutil execution with base64 or decode arguments",
            "Identify suspicious scheduled tasks or use of atexec.py",
            "Review for DLL sideloading activity and renamed tools like InstallUtil",
            "Detect command execution from Office macros or .lnk files"
        ],
        "expected_outcomes": [
            "Discovery of masqueraded and encoded dropper scripts",
            "Detection of credential dumping and NTDS staging",
            "Identification of lateral movement via RDP, PSCP, or WMI",
            "Alerting on PlugX, PoisonIvy, or RedLeaves malware artifacts"
        ],
        "false_positive": "Legitimate administrative tools such as net use, csvde, or certutil may be used in valid workflows. Verify user intent and baseline behavior before taking action.",
        "clearing_steps": [
            "Remove scheduled tasks created by attackers",
            "Delete DLLs used in sideloading (e.g., renamed versions of certutil)",
            "Purge encoded scripts or macros from startup folders",
            "Revoke any compromised credentials and reset passwords"
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": [
                "https://attack.mitre.org/groups/G0045/",
                "https://www.justice.gov/opa/press-release/file/1116411/download",
                "https://www.baesystems.com/en-media-centre/operation-cloud-hopper"
            ]
        }
    }
