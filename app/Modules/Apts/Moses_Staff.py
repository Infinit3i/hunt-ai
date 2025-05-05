def get_content():
    return {
        "id": "G1009",
        "url_id": "Moses_Staff",
        "title": "Moses Staff",
        "tags": ["iran", "politically motivated", "no ransom", "destructive", "data leak", "israel"],
        "description": (
            "Moses Staff is a suspected Iranian threat group active since at least September 2021. "
            "They have primarily targeted Israeli companies but also struck victims in Europe, Asia, and the Americas. "
            "Their tactics include leaking stolen data and encrypting victim networks without issuing ransom demands. "
            "The group's operations appear ideologically motivated and span across industries such as finance, energy, travel, and manufacturing."
        ),
        "associated_groups": ["DEV-0500", "Marigold Sandstorm"],
        "campaigns": [],
        "techniques": [
            "T1087.001", "T1587.001", "T1190", "T1562.004", "T1105",
            "T1027.013", "T1588.002", "T1021.002", "T1505.003", "T1553.002",
            "T1082", "T1016"
        ],
        "contributors": [
            "Hiroki Nagahama, NEC Corporation",
            "Pooja Natarajan, NEC Corporation India",
            "Manikantan Srinivasan, NEC Corporation India"
        ],
        "version": "2.0",
        "created": "11 August 2022",
        "last_modified": "11 April 2024",
        "navigator": "",
        "references": [
            {
                "source": "Checkpoint Research",
                "url": "https://research.checkpoint.com/2021/uncovering-mosesstaff-techniques-ideology-over-money/"
            },
            {
                "source": "Cybereason Nocturnus",
                "url": "https://www.cybereason.com/blog/strifewater-rat-iranian-apt-moses-staff-adds-new-trojan"
            },
            {
                "source": "Microsoft",
                "url": "https://www.microsoft.com/security/blog/2023/07/12/how-microsoft-names-threat-actors/"
            }
        ],
        "resources": [],
        "remediation": (
            "Patch public-facing systems promptly, especially Microsoft Exchange. Monitor SMB and firewall configurations, "
            "and restrict remote access services. Implement web shell detection mechanisms and ensure encrypted payloads are thoroughly inspected."
        ),
        "improvements": (
            "Deploy tools that detect unauthorized service creation, signed binaries, and firewall changes. Use behavioral threat detection "
            "to flag obfuscated batch scripts or admin share modifications."
        ),
        "hunt_steps": [
            "Check for batch scripts disabling Windows Firewall or enabling SMB remotely.",
            "Scan IIS directories for obfuscated web shells (e.g., IISpool.aspx).",
            "Search for use of DiskCryptor binaries and signed drivers in unexpected contexts."
        ],
        "expected_outcomes": [
            "Detection of network intrusion via public-facing Exchange servers.",
            "Identification of firewall evasion scripts or unauthorized file transfers.",
            "Insight into usage of destructive tools like DCSrv and PyDCrypt."
        ],
        "false_positive": (
            "Firewall or SMB script modifications may occur during legitimate administrative maintenance. Cross-reference "
            "with expected change windows or maintenance logs."
        ),
        "clearing_steps": [
            "Remove dropped web shells and clean up modified firewall rules.",
            "Reimage systems compromised with DiskCryptor-based tools.",
            "Audit and reset admin credentials collected by the attacker.",
            "Verify and restore Windows services affected by DCSrv or PsExec abuse."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
