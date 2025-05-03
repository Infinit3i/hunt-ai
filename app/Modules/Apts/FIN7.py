def get_content():
    return {
        "id": "G0046",
        "url_id": "FIN7",
        "title": "FIN7",
        "tags": ["cybercrime", "financial", "ransomware", "big-game hunting", "raas"],
        "description": "FIN7 is a financially-motivated threat group active since 2013, known for targeting a broad range of industries including retail, hospitality, and financial services. Originally operating through point-of-sale malware campaigns, the group has since evolved into big game hunting (BGH), leveraging ransomware including REvil and Darkside. They have also utilized a front company called Combi Security and maintain links to other known groups.",
        "associated_groups": ["GOLD NIAGARA", "ITG14", "Carbon Spider", "ELBRUS", "Sangria Tempest"],
        "campaigns": [],
        "techniques": [
            "T1583.001", "T1583.006", "T1071.004", "T1547.001", "T1059", "T1059.001", "T1059.003",
            "T1059.005", "T1059.007", "T1543.003", "T1486", "T1005", "T1587.001", "T1546.011",
            "T1567.002", "T1190", "T1210", "T1008", "T1105", "T1674", "T1559.002", "T1036.004",
            "T1036.005", "T1571", "T1027.010", "T1027.016", "T1588.002", "T1069.002", "T1566.001",
            "T1566.002", "T1219", "T1021.001", "T1021.004", "T1021.005", "T1091", "T1053.005",
            "T1113", "T1608.001", "T1608.004", "T1558.003", "T1553.002", "T1195.002", "T1218.005",
            "T1218.011", "T1033", "T1204.001", "T1204.002", "T1078", "T1078.003", "T1125", "T1497.002",
            "T1102.002", "T1047"
        ],
        "contributors": ["Edward Millington"],
        "version": "4.0",
        "created": "31 May 2017",
        "last_modified": "17 April 2024",
        "navigator": "",
        "references": [
            {"source": "FireEye", "url": "https://www.fireeye.com/blog/threat-research/2017/03/fin7-spear-phishing-campaign.html"},
            {"source": "CrowdStrike", "url": "https://www.crowdstrike.com/blog/carbon-spider-embraces-big-game-hunting/"},
            {"source": "eSentire", "url": "https://www.esentire.com/blog/notorious-cybercrime-gang-fin7-lands-malware-in-law-firm"},
            {"source": "Abdo et al.", "url": "https://www.sentinelone.com/blog/fin7-power-hour-adversary-archaeology/"},
            {"source": "Microsoft", "url": "https://www.microsoft.com/security/blog/2022/05/09/ransomware-as-a-service-the-cybercrime-gig-economy/"},
        ],
        "resources": [],
        "remediation": "Implement endpoint protection, restrict PowerShell and scripting tools, apply patching policies to mitigate known exploits (e.g., CVE-2020-1472, CVE-2021-31207), monitor scheduled tasks and unusual service creations, and restrict removable media usage.",
        "improvements": "Deploy behavioral analytics to identify abnormal PowerShell and scheduled task usage, monitor S3 and MEGA uploads, and integrate DNS tunneling and obfuscation detection capabilities.",
        "hunt_steps": [
            "Identify use of mshta.exe or rundll32.exe with obfuscated payloads.",
            "Track domain registration and hosting of trojanized files on Amazon S3.",
            "Search for registry key modifications under Run/RunOnce or shim database usage."
        ],
        "expected_outcomes": [
            "Detection of staged payloads and unauthorized data uploads to cloud services.",
            "Identification of remote desktop or VNC access from uncommon sources.",
            "Evidence of phishing lure documents exploiting DDE or drive-by links."
        ],
        "false_positive": "Use of PowerShell or RDP may be legitimate. Validate use against user role, scheduled task origin, and domain registration patterns.",
        "clearing_steps": [
            "Remove persistence mechanisms (scheduled tasks, startup folder entries).",
            "Revoke code-signing certificates used by adversary payloads.",
            "Reset credentials and remove unused local or domain accounts.",
            "Purge trojanized software packages from download repositories."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
