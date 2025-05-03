def get_content():
    return {
        "id": "G1003",
        "url_id": "Ember_Bear",
        "title": "Ember Bear",
        "tags": ["Russia", "state-sponsored", "destructive", "GRU", "Ukraine", "WhisperGate"],
        "description": (
            "Ember Bear is a Russian state-sponsored cyber espionage group affiliated with the GRU 161st Specialist Training Center (Unit 29155). "
            "Active since at least 2020, Ember Bear has focused on Ukrainian government and telecommunications targets, and has also impacted critical infrastructure in Europe and the Americas. "
            "The group is responsible for WhisperGate, a destructive wiper campaign executed in early 2022 against Ukrainian systems. "
            "Although sometimes conflated with Saint Bear, current evidence suggests Ember Bear is a distinct operational entity with unique tactics and infrastructure."
        ),
        "associated_groups": ["UNC2589", "Bleeding Bear", "DEV-0586", "Cadet Blizzard", "Frozenvista", "UAC-0056"],
        "campaigns": [],
        "techniques": [
            "T1583", "T1583.003", "T1595.001", "T1595.002", "T1071.004", "T1560", "T1119", "T1110", "T1110.003", "T1059.001",
            "T1005", "T1491.002", "T1561.002", "T1114", "T1585", "T1567.002", "T1190", "T1203", "T1210", "T1133",
            "T1562.001", "T1070.004", "T1570", "T1654", "T1036", "T1036.005", "T1112", "T1046", "T1095", "T1571",
            "T1588.001", "T1588.005", "T1003", "T1003.001", "T1003.002", "T1003.004", "T1572", "T1090.003", "T1021",
            "T1018", "T1053.005", "T1505.003", "T1195", "T1552.001", "T1550.002", "T1078.001", "T1125", "T1047"
        ],
        "contributors": ["Hannah Simes", "BT Security"],
        "version": "2.1",
        "created": "09 June 2022",
        "last_modified": "03 December 2024",
        "navigator": "",
        "references": [
            {
                "source": "CISA et al. (2024)",
                "url": "https://example.com/russian-military-cyber-actors"
            },
            {
                "source": "Microsoft Threat Intelligence (2023)",
                "url": "https://example.com/cadet-blizzard-report"
            },
            {
                "source": "CrowdStrike (2022)",
                "url": "https://example.com/who-is-ember-bear"
            },
            {
                "source": "Sadowski & Hall (2022)",
                "url": "https://example.com/russia-invasion-response"
            },
            {
                "source": "Unit 42 (2022)",
                "url": "https://example.com/ukraine-saintbot-outsteel"
            }
        ],
        "resources": [],
        "remediation": (
            "Apply segmentation and threat intelligence-led blocking to detect VPN abuse and dark web toolkits. "
            "Monitor for use of DNS tunneling, web shells, and scheduled tasks in cloud and enterprise environments. "
            "Enable robust logging and restrict PowerShell, Rclone, and unauthorized registry modifications."
        ),
        "improvements": (
            "Deploy EDR solutions with behavioral anomaly detection, particularly for proxy tunneling tools like GOST, "
            "and cloud data exfiltration via Rclone. Increase WMI monitoring and disable unused external services."
        ),
        "hunt_steps": [
            "Investigate any LSASS memory dumps or uses of renamed procdump.exe.",
            "Review logs for DNS tunneling indicators using dnscat2 or Iodine.",
            "Identify web shell deployments and correlate with CVE exploitation on public-facing services.",
            "Search for ProxyChains, Impacket, and CrackMapExec activity in lateral movement paths.",
            "Monitor for abuse of scheduled tasks or registry keys altering AV behavior."
        ],
        "expected_outcomes": [
            "Discovery of compromised edge infrastructure and stealthy pivoting tools.",
            "Detection of credential dumping, password spraying, and privilege escalation attempts.",
            "Identification of destructive malware (e.g., WhisperGate) and mitigation of active campaigns."
        ],
        "false_positive": (
            "Tools like Rclone, PowerShell, or scheduled tasks may be used legitimately—validate with user behavior and environment context."
        ),
        "clearing_steps": [
            "Eliminate malicious scheduled tasks and registry alterations.",
            "Re-image machines where destructive malware like WhisperGate was active.",
            "Block known C2 infrastructure, reset exposed credentials, and audit lateral movement paths."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
