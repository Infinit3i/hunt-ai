def get_content():
    return {
        "id": "G0030",
        "url_id": "Lotus_Blossom",
        "title": "Lotus Blossom",
        "tags": ["state-sponsored", "Asia", "espionage", "long-term", "critical infrastructure"],
        "description": "Lotus Blossom is a long-standing threat group largely targeting various entities in Asia since at least 2009. The group has focused its espionage operations on government organizations, military sectors, and digital certificate issuers. Lotus Blossom is known for developing and using custom tools like Sagerunex and Elise while also leveraging publicly available utilities for staging, compression, and exfiltration.",
        "associated_groups": ["DRAGONFISH", "Spring Dragon", "RADIUM", "Raspberry Typhoon", "Bilbug", "Thrip"],
        "campaigns": [],
        "techniques": [
            "T1134", "T1087.001", "T1087.002", "T1560.001", "T1560.003", "T1543.003", "T1074.001", "T1482",
            "T1083", "T1112", "T1046", "T1588.002", "T1090.001", "T1090.003", "T1012", "T1018", "T1539",
            "T1016", "T1016.001", "T1049", "T1047"
        ],
        "contributors": [],
        "version": "4.0",
        "created": "31 May 2017",
        "last_modified": "04 April 2025",
        "navigator": "",
        "references": [
            {"source": "Falcone et al.", "url": "https://www.unit42.paloaltonetworks.com/operation-lotus-blossom"},
            {"source": "Symantec Threat Hunter Team", "url": "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/billbug-cert-authority-attacks"},
            {"source": "Cisco Talos", "url": "https://blog.talosintelligence.com/lotus-blossom-sagerunex/"},
            {"source": "Accenture Security", "url": "https://www.accenture.com/us-en/blogs/blogs-dragonfish-elise-asean"},
            {"source": "Kaspersky", "url": "https://securelist.com/the-spring-dragon-apt/"},
            {"source": "Microsoft", "url": "https://www.microsoft.com/en-us/security/blog/2023/07/12/how-microsoft-names-threat-actors/"},
            {"source": "Palo Alto Networks", "url": "https://www.unit42.paloaltonetworks.com/attack-on-french-diplomat-operation-lotus-blossom/"},
            {"source": "Unit42", "url": "https://www.unit42.paloaltonetworks.com/emissary-trojan-changelog/"}
        ],
        "resources": [],
        "remediation": "Harden Active Directory, monitor for usage of tools like WinRAR, AdFind, and unusual registry changes. Disable unused Windows services and ensure traffic is segmented and monitored with proxy alerts and WMI tracing.",
        "improvements": "Enhance detection rules for proxy tool usage (Venom, HTran), Sagerunex signatures, and PowerShell/registry anomalies. Integrate behavioral analytics and endpoint logging for all sensitive hosts.",
        "hunt_steps": [
            "Search for Sagerunex activity or file drops",
            "Trace registry modifications related to service installation",
            "Identify usage of AdFind and WinRAR",
            "Monitor for DLL injections and abnormal Rundll32 usage"
        ],
        "expected_outcomes": [
            "Detection of custom tool usage and staging behavior",
            "Discovery of lateral movement using WMI or Impacket",
            "Correlation of remote discovery commands with login events"
        ],
        "false_positive": "Some commands like `netstat`, `ipconfig`, or `net` may be executed by legitimate users or admins. Validate via user context and frequency.",
        "clearing_steps": [
            "Remove Sagerunex binaries and registry entries",
            "Reset credentials for affected users",
            "Purge collected archives and block exfiltration endpoints",
            "Apply YARA rules to sweep file systems for known indicators"
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": [
                "https://www.talosintelligence.com/reports/2025-02-27/lotus-blossom-sagerunex.html",
                "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/billbug-cert-authority-attacks"
            ]
        }
    }
