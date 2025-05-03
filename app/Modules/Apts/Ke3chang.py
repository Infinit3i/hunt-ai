def get_content():
    return {
        "id": "G0004",
        "url_id": "Ke3chang",
        "title": "Ke3chang",
        "tags": ["APT", "China", "espionage", "government", "NGO", "military", "RoyalAPT", "APT15", "NICKEL"],
        "description": (
            "Ke3chang is a Chinese state-sponsored threat group active since at least 2010, targeting diplomatic, government, oil, "
            "military, and non-governmental organizations across the Americas, Europe, Asia, and the Caribbean. Ke3chang is known "
            "for custom malware development and sophisticated spearphishing campaigns. Its infrastructure includes VPNs, ORB relay "
            "networks, and multi-hop proxies, with observed use of malware families like RoyalDNS, RoyalCli, and MirageFox."
        ),
        "associated_groups": ["APT15", "Mirage", "Vixen Panda", "GREF", "Playful Dragon", "RoyalAPT", "NICKEL", "Nylon Typhoon"],
        "campaigns": [
            {
                "id": "C0052",
                "name": "SPACEHOP Activity",
                "first_seen": "January 2019",
                "last_seen": "May 2024",
                "references": [
                    "https://www.recordedfuture.com/blog/chinese-orb-network-spacehop"
                ]
            }
        ],
        "techniques": [
            "T1087.001", "T1087.002", "T1583.003", "T1583.005", "T1071.001", "T1071.004", "T1560", "T1560.001", "T1119",
            "T1020", "T1547.001", "T1059", "T1059.003", "T1543.003", "T1213.002", "T1005", "T1140", "T1587.001",
            "T1114.002", "T1041", "T1190", "T1133", "T1083", "T1105", "T1056.001", "T1036.002", "T1036.005",
            "T1027", "T1588.002", "T1003.001", "T1003.002", "T1003.003", "T1003.004", "T1069.002", "T1057", "T1090.003",
            "T1021.002", "T1018", "T1558.001", "T1082", "T1614.001", "T1016", "T1049", "T1033", "T1007", "T1569.002",
            "T1078", "T1078.004"
        ],
        "contributors": [
            "Pooja Natarajan, NEC Corporation India", "Manikantan Srinivasan, NEC Corporation India",
            "Hiroki Nagahama, NEC Corporation"
        ],
        "version": "3.1",
        "created": "31 May 2017",
        "last_modified": "04 April 2025",
        "navigator": "",
        "references": [
            {"source": "FireEye", "url": "https://www.fireeye.com/blog/threat-research/2014/11/operation-ke3chang.html"},
            {"source": "Palo Alto Networks", "url": "https://unit42.paloaltonetworks.com/apt15-royalcli-royaldns-analysis/"},
            {"source": "Check Point", "url": "https://blog.checkpoint.com/2018/06/14/miragefox-apt15/"},
            {"source": "Microsoft MSTIC", "url": "https://www.microsoft.com/security/blog/2021/12/06/nickel-targeting-governments/"},
            {"source": "Microsoft", "url": "https://www.microsoft.com/security/blog/2023/07/12/how-microsoft-names-threat-actors/"},
            {"source": "Recorded Future", "url": "https://www.recordedfuture.com/blog/chinese-orb-network-spacehop"},
            {"source": "NSA", "url": "https://media.defense.gov/2022/Dec/15/2003126794/-1/-1/1/CSA_APT5_CITRIX_ADC.PDF"},
            {"source": "ESET", "url": "https://www.welivesecurity.com/2019/07/17/okrums-ketrican-overview-recent-ke3chang/"}
        ],
        "resources": [],
        "remediation": (
            "Segment networks and monitor external service usage including VPNs, RDP, and Exchange/SharePoint access. Harden endpoint "
            "security through EDR policies, restrict execution of unauthorized binaries, and apply patches for known exploited vulnerabilities "
            "like CVE-2022-27518. Monitor for abnormal file movements, registry modifications, and service creations."
        ),
        "improvements": (
            "Implement detections for Base64 obfuscation and LSASS access. Watch for SMB lateral movement, registry run key creation, and "
            "anomalous service installs. Enhance phishing protections and enforce MFA across cloud accounts and VPN."
        ),
        "hunt_steps": [
            "Search for Mimikatz behavior in LSASS, SAM, and LSA secrets.",
            "Correlate 7Zip/RAR encryption followed by outbound connections.",
            "Detect known malware dropped in legitimate directories like Adobe/Foxit.",
            "Hunt for process creation of tools like RemoteExec and spwebmember."
        ],
        "expected_outcomes": [
            "Identification of credential theft and SharePoint data access.",
            "Discovery of malware persistence mechanisms via registry keys and services.",
            "Detection of phishing techniques using filename obfuscation (.scr/.exe)."
        ],
        "false_positive": (
            "Use of legitimate tools like netstat, ipconfig, net.exe, and RAR/7Zip may create noise. Combine tool usage with execution context, "
            "e.g., signed binary misuse or execution from unexpected paths."
        ),
        "clearing_steps": [
            "Terminate malicious services and delete unauthorized binaries from trusted paths.",
            "Revoke compromised credentials and reset all domain credentials.",
            "Audit and remove registry persistence keys and restore secure GPO policies."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
