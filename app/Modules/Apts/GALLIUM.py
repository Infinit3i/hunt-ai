def get_content():
    return {
        "id": "G0093",
        "url_id": "GALLIUM",
        "title": "GALLIUM",
        "tags": ["china", "telecom", "espionage", "APT", "operation-soft-cell"],
        "description": "GALLIUM is a cyberespionage group assessed to be Chinese state-sponsored, active since at least 2012. The group is known for targeting telecommunications, government, and financial sectors across Asia, Africa, Europe, and Oceania. GALLIUM conducted Operation Soft Cell, a multi-year campaign aimed at infiltrating global telecom networks. The group employs a wide range of custom and commodity tools, including PoisonIvy and HTRAN, and leverages stolen credentials, public-facing exploits, and lateral movement to maintain long-term access and exfiltrate sensitive data.",
        "associated_groups": ["Granite Typhoon"],
        "campaigns": ["Operation Soft Cell"],
        "techniques": [
            "T1583.004", "T1560.001", "T1059.001", "T1059.003", "T1136.002", "T1005", "T1074.001", "T1041",
            "T1190", "T1133", "T1574.001", "T1105", "T1570", "T1036.003", "T1027", "T1027.002", "T1027.005",
            "T1588.002", "T1003.001", "T1003.002", "T1090.002", "T1018", "T1053.005", "T1505.003", "T1553.002",
            "T1016", "T1049", "T1033", "T1550.002", "T1078", "T1047"
        ],
        "contributors": ["Daniyal Naeem, BT Security", "Cybereason Nocturnus"],
        "version": "4.0",
        "created": "18 July 2019",
        "last_modified": "17 April 2024",
        "navigator": "",
        "references": [
            {"source": "Cybereason Nocturnus", "url": "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"},
            {"source": "Microsoft", "url": "https://www.microsoft.com/security/blog/2019/12/12/gallium-targeting-global-telecom/"},
            {"source": "Unit 42", "url": "https://unit42.paloaltonetworks.com/gallium-expands-targeting-across-telecommunications-government-and-finance-sectors-with-new-pingpull-tool/"},
            {"source": "Microsoft Threat Intelligence", "url": "https://www.microsoft.com/en-us/security/blog/2023/07/12/how-microsoft-names-threat-actors/"}
        ],
        "resources": [],
        "remediation": "Patch and harden public-facing applications like JBoss/Wildfly and VPN services. Monitor for unauthorized scheduled tasks and user account creations. Review system services and registry modifications linked to tools like PoisonIvy and Mimikatz.",
        "improvements": "Deploy network segmentation and enforce least privilege. Monitor for renamed binaries (e.g., cmd.exe), and baseline usage of tools like HTRAN and PingPull. Alert on suspicious DLL sideloading activity and credential dumping behaviors.",
        "hunt_steps": [
            "Look for signs of DLL sideloading and execution from unusual paths.",
            "Check for use of SoftEther VPN or unexpected VPN activity.",
            "Scan for scheduled tasks associated with known toolsets like PoisonIvy.",
            "Hunt for compressed files in unusual directories like Recycle Bin.",
            "Correlate external proxy use (e.g., HTRAN) with exfiltration events."
        ],
        "expected_outcomes": [
            "Identification of persistent access methods such as web shells and VPNs.",
            "Detection of credential dumping tools and stolen account use.",
            "Discovery of obfuscated and packed malware used by GALLIUM.",
            "Recognition of data staging and multi-part file exfiltration tactics."
        ],
        "false_positive": "Tools like PowerShell, Net, and WinRAR are used legitimately; review in context with unusual paths, parameters, or timing. Credential access or proxy behaviors should correlate with user roles and access levels.",
        "clearing_steps": [
            "Revoke all exposed credentials and audit group memberships.",
            "Remove scheduled tasks, web shells, and implanted utilities.",
            "Kill lingering malicious processes such as PoisonIvy or renamed binaries.",
            "Reimage infected systems and update all exposed services.",
            "Harden access with MFA and restrict command-line tool usage."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
