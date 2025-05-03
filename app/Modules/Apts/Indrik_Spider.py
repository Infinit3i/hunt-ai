def get_content():
    return {
        "id": "G0119",
        "url_id": "Indrik_Spider",
        "title": "Indrik Spider",
        "tags": ["Russia", "cybercrime", "ransomware", "Evil Corp", "financially-motivated", "APT", "2014+"],
        "description": (
            "Indrik Spider is a Russia-based cybercriminal group active since at least 2014. They began with the Dridex banking "
            "Trojan and evolved into ransomware operations using BitPaymer, WastedLocker, Hades, and LockBit. Indrik Spider, "
            "also known as Evil Corp, adapted its tactics following sanctions and indictments by U.S. authorities, demonstrating "
            "resilience through infrastructure compromise, credential abuse, tool development, and lateral movement via "
            "PowerShell, PsExec, and WMI."
        ),
        "associated_groups": ["Evil Corp", "Manatee Tempest", "DEV-0243", "UNC2165"],
        "campaigns": [],
        "techniques": [
            "T1583", "T1059.001", "T1059.003", "T1059.007", "T1584.004", "T1136", "T1136.001", "T1555.005", "T1486",
            "T1074.001", "T1587.001", "T1484.001", "T1585.002", "T1567.002", "T1590", "T1562.001", "T1070.001", "T1105",
            "T1036.005", "T1112", "T1003.001", "T1012", "T1021.001", "T1021.004", "T1018", "T1489", "T1558.003",
            "T1007", "T1552.001", "T1204.002", "T1078", "T1078.002", "T1047"
        ],
        "contributors": ["Jennifer Kim Roman, CrowdStrike", "Liran Ravich, CardinalOps"],
        "version": "4.1",
        "created": "06 January 2021",
        "last_modified": "28 October 2024",
        "navigator": "",
        "references": [
            {"source": "CrowdStrike", "url": "https://www.crowdstrike.com/blog/big-game-hunting-the-evolution-of-indrik-spider/"},
            {"source": "McAfee", "url": "https://www.mcafee.com/blogs/enterprise/mcafee-labs/wastedlocker-evolution-of-evil-corp/"},
            {"source": "U.S. Department of Treasury", "url": "https://home.treasury.gov/news/press-releases/sm845"},
            {"source": "Microsoft", "url": "https://www.microsoft.com/en-us/security/blog/2023/07/12/how-microsoft-names-threat-actors/"},
            {"source": "Mandiant", "url": "https://www.mandiant.com/resources/blog/unc2165-shifts-to-lockbit-to-evade-sanctions"},
            {"source": "Symantec", "url": "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/wastedlocker-ransomware"},
            {"source": "Microsoft", "url": "https://www.microsoft.com/security/blog/2022/05/09/ransomware-as-a-service-understanding-the-cybercrime-gig-economy/"},
            {"source": "SentinelOne", "url": "https://www.sentinelone.com/blog/wastedlocker-new-ransomware-variant-developed-by-evil-corp/"},
            {"source": "DFIR Report", "url": "https://thedfirreport.com/2022/11/07/socgholish-malware-infrastructure-expansion/"}
        ],
        "resources": [],
        "remediation": (
            "Implement EDR and threat detection rules for behavior associated with PsExec, WMIC, PowerShell Empire, and credential "
            "dumping tools. Segment networks to limit lateral movement, and enforce application whitelisting to block unauthorized scripts. "
            "Regularly audit for newly created accounts and monitor registry and service configuration changes."
        ),
        "improvements": (
            "Develop detection pipelines to flag group policy modification and event log clearing behaviors. "
            "Monitor use of known LOLBins like MpCmdRun and wevutil in non-standard contexts. "
            "Harden VPN access and alert on anomalous RDP and SSH usage by service accounts."
        ),
        "hunt_steps": [
            "Query for use of ProcDump and LSASS access.",
            "Hunt for use of wevutil and PsExec scripts related to ransomware payloads.",
            "Look for Rclone or MEGASync processes with elevated privileges before ransomware deployment.",
            "Identify batch scripts deployed via Group Policy or via suspicious registry keys."
        ],
        "expected_outcomes": [
            "Early detection of credential dumping and privilege escalation activity.",
            "Identification of ransomware staging and lateral tool transfer.",
            "Forensic artifacts pointing to infrastructure acquisition and tooling evolution."
        ],
        "false_positive": (
            "Legitimate use of admin tools like PsExec and WMI can overlap with attacker behavior. Correlate with timing, payloads, and "
            "access patterns to validate intent."
        ),
        "clearing_steps": [
            "Disable compromised accounts and remove unauthorized registry/service entries.",
            "Block external tools and reset all credentials post-incident.",
            "Isolate infected hosts and perform a full forensic triage using memory and disk artifacts."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
