def get_content():
    return {
        "id": "G1006",
        "url_id": "Earth_Lusca",
        "title": "Earth Lusca",
        "tags": ["espionage", "financial", "state-sponsored", "China", "APT41 cluster"],
        "description": (
            "Earth Lusca is a suspected China-based cyber espionage group active since at least April 2019. "
            "It has targeted a broad range of organizations, including government institutions, media, gambling companies, "
            "educational institutions, COVID-19 research facilities, religious groups banned in China, and cryptocurrency platforms. "
            "While it shares some malware with APT41 and the Winnti Group, Earth Lusca operates with distinct infrastructure and techniques."
        ),
        "associated_groups": ["TAG-22", "Charcoal Typhoon", "CHROMIUM", "ControlX"],
        "campaigns": [],
        "techniques": [
            "T1548.002", "T1098.004", "T1583.001", "T1583.004", "T1583.006", "T1595.002", "T1560.001", "T1547.012",
            "T1059.001", "T1059.005", "T1059.006", "T1059.007", "T1584.004", "T1584.006", "T1543.003", "T1140", "T1482",
            "T1189", "T1567.002", "T1190", "T1210", "T1574.001", "T1036.005", "T1112", "T1027", "T1027.003",
            "T1588.001", "T1588.002", "T1003.001", "T1003.006", "T1566.002", "T1057", "T1090", "T1018", "T1053",
            "T1608.001", "T1218.005", "T1016", "T1049", "T1033", "T1007", "T1204.001", "T1204.002", "T1047"
        ],
        "contributors": [],
        "version": "2.0",
        "created": "01 July 2022",
        "last_modified": "16 September 2024",
        "navigator": "",
        "references": [
            {
                "source": "Delving Deep: An Analysis of Earth Lusca’s Operations",
                "url": "https://example.com/earth-lusca-deep-analysis"
            },
            {
                "source": "Chinese State-Sponsored Activity Group TAG-22 Targets Nepal, the Philippines, and Taiwan",
                "url": "https://example.com/tag-22-report"
            },
            {
                "source": "Microsoft Threat Actor Naming Guidance",
                "url": "https://example.com/microsoft-threat-naming"
            },
            {
                "source": "RedHotel: Chinese State Group at Global Scale",
                "url": "https://example.com/redhotel-insikt"
            }
        ],
        "resources": [],
        "remediation": (
            "Apply strict network segmentation, patch externally exposed applications promptly, monitor PowerShell and Python execution, "
            "and use behavior-based detection for uncommon DLL sideloading and registry persistence methods."
        ),
        "improvements": (
            "Enhance visibility into user account changes and scheduled task creation. Expand logging for cloud storage uploads and proxy abuse "
            "from tools like megacmd and mshta."
        ),
        "hunt_steps": [
            "Search for unauthorized DLLs registered as Print Processors.",
            "Review scheduled tasks created for persistence with suspicious command lines.",
            "Investigate any use of certutil or PowerShell downloading encoded files.",
            "Audit Google Drive and MEGA-related traffic and cloud storage tool usage.",
            "Look for Mimikatz or ZeroLogon activity targeting domain controllers."
        ],
        "expected_outcomes": [
            "Identification of compromised infrastructure and persistence mechanisms.",
            "Detection of credential dumping or lateral movement activity.",
            "Exposure of exfiltration paths using cloud services or staged web content."
        ],
        "false_positive": (
            "Legitimate use of PowerShell, mshta, or scheduled tasks may appear similar. Context and behavior correlation are essential."
        ),
        "clearing_steps": [
            "Remove malicious print processors and registry entries.",
            "Terminate unauthorized scheduled tasks and services.",
            "Revoke credentials and replace SSH keys dropped in root/.ssh.",
            "Clean up any MEGA or GitHub-sourced artifacts and audit exfiltration history."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
