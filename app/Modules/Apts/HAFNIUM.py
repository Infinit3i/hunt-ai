def get_content():
    return {
        "id": "G0125",
        "url_id": "HAFNIUM",
        "title": "HAFNIUM",
        "tags": ["China", "state-sponsored", "espionage", "Exchange vulnerabilities", "APT", "cloud", "RCE", "credential access"],
        "description": "HAFNIUM is a likely state-sponsored cyber espionage group operating from China, first publicly observed in January 2021. The group has aggressively targeted U.S.-based organizations across sectors such as defense, law, higher education, infectious disease research, policy, and NGOs. HAFNIUM is notorious for exploiting Microsoft Exchange Server zero-days (Operation Exchange Marauder), rapid exploitation of edge vulnerabilities, use of open-source tools like Covenant and PowerCat, and abuse of cloud services and web shells for persistent access and exfiltration.",
        "associated_groups": ["Operation Exchange Marauder", "Silk Typhoon"],
        "campaigns": [],
        "techniques": [
            "T1098", "T1583.003", "T1583.005", "T1583.006", "T1071.001", "T1560.001", "T1119", "T1110.003",
            "T1059.001", "T1059.003", "T1584.005", "T1136.002", "T1555.006", "T1132.001", "T1530", "T1213.002",
            "T1005", "T1114.002", "T1567.002", "T1190", "T1068", "T1083", "T1592.004", "T1589.002", "T1590",
            "T1590.005", "T1564.001", "T1070.001", "T1105", "T1095", "T1003.001", "T1003.003", "T1057", "T1018",
            "T1593.003", "T1505.003", "T1218.011", "T1016", "T1016.001", "T1033", "T1199", "T1550.001",
            "T1078.003", "T1078.004"
        ],
        "contributors": [
            "Daniyal Naeem, BT Security", "Matt Brenton, Zurich Insurance Group",
            "Mayuresh Dani, Qualys", "Harshal Tupsamudre, Qualys", "Vinayak Wadhwa, SAFE Security"
        ],
        "version": "3.0",
        "created": "03 March 2021",
        "last_modified": "25 March 2025",
        "navigator": "",  # Optionally include MITRE Navigator layer link
        "references": [
            {
                "source": "Microsoft Threat Intelligence Center (MSTIC)",
                "url": "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
            },
            {
                "source": "CrowdStrike - Operation Exchange Marauder",
                "url": "https://www.crowdstrike.com/blog/operation-exchange-marauder/"
            },
            {
                "source": "Microsoft Threat Intelligence (2025)",
                "url": "https://www.microsoft.com/security/blog/2025/03/05/silk-typhoon-targeting-it-supply-chain/"
            },
            {
                "source": "Microsoft DART + Threat Intelligence Team",
                "url": "https://www.microsoft.com/security/blog/2022/04/12/tarrask-malware-defense-evasion/"
            }
        ],
        "resources": [],
        "remediation": "Immediately apply patches for known Exchange and edge vulnerabilities. Monitor for web shell deployment and post-exploitation tools. Enforce least privilege in hybrid/on-prem cloud environments. Audit service principal usage and tighten PAM practices.",
        "improvements": "Implement alerting for suspicious Exchange PowerShell use. Enhance visibility into SharePoint/OneDrive access patterns. Monitor for unauthorized MSI package installs, and defend against credential theft via LSASS and NTDS dumps.",
        "hunt_steps": [
            "Identify unusual uses of `Set-OabVirtualDirectory` and Exchange PowerShell modules.",
            "Search for web shells like China Chopper, ASPXSpy, and SPORTSBALL on Exchange servers.",
            "Monitor outbound data to MEGA and file-sharing services.",
            "Look for use of tools like Nishang, PowerCat, and Covenant in cloud and hybrid logs."
        ],
        "expected_outcomes": [
            "Detection of post-exploitation tooling and Exchange abuse.",
            "Prevention of cloud-to-on-prem lateral movement.",
            "Exfiltration disruption via enhanced cloud telemetry and alerts."
        ],
        "false_positive": "Administrative PowerShell commands and file compression utilities may resemble attacker behavior. Validation requires correlation with access timing and source IP reputation.",
        "clearing_steps": [
            "Remove dropped web shells from Exchange directories.",
            "Reset affected credentials and audit access tokens.",
            "Patch and isolate affected Exchange servers.",
            "Purge malicious scheduled tasks and DLLs launched via rundll32."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
