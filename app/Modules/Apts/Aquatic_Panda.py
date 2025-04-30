def get_content():
    return {
        "id": "G0143",
        "url_id": "Aquatic_Panda",
        "title": "Aquatic Panda",
        "tags": ["china", "espionage", "dual-mission", "telecom", "technology", "government"],
        "description": "Aquatic Panda is a suspected China-based threat group active since at least May 2020. It operates with a dual mission of intelligence collection and industrial espionage. Primary targets have included telecommunications, technology, and government sectors.",
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1087", "T1595.002", "T1560.001", "T1059.001", "T1059.003", "T1059.004", "T1543.003",
            "T1005", "T1574.001", "T1574.006", "T1562.001", "T1070.001", "T1070.003", "T1070.004",
            "T1105", "T1654", "T1036.004", "T1036.005", "T1112", "T1027.010", "T1588.001", "T1588.002",
            "T1003.001", "T1021", "T1021.001", "T1021.002", "T1021.004", "T1518.001", "T1218.011",
            "T1082", "T1033", "T1007", "T1550.002", "T1078.002", "T1047"
        ],
        "contributors": [
            "NST Assure Research Team", "NetSentries Technologies", "Pooja Natarajan (NEC India)",
            "Hiroki Nagahama (NEC Corporation)", "Manikantan Srinivasan (NEC India)",
            "Jai Minton (CrowdStrike)", "Jennifer Kim Roman (CrowdStrike)"
        ],
        "version": "2.0",
        "created": "18 January 2022",
        "last_modified": "10 October 2024",
        "navigator": "",
        "references": [
            {"source": "CrowdStrike", "url": "https://www.crowdstrike.com/resources/reports/2022-falcon-overwatch-threat-hunting-report/"},
            {"source": "Wiley, B. et al.", "url": "https://www.crowdstrike.com/blog/overwatch-exposes-aquatic-panda-in-possession-of-log4shell-exploit-tools/"}
        ],
        "resources": [],
        "remediation": "Organizations should deploy endpoint detection and response tools, implement PowerShell logging, monitor for DLL hijacking patterns, and restrict use of administrative tools like rundll32. Linux systems should disable root SSH login and monitor shell scripts for persistence mechanisms.",
        "improvements": "Enhance monitoring for `cmd /C`, Base64-encoded PowerShell commands, and registry modifications related to RestrictedAdmin. Implement behavior-based alerts for suspicious service creations and command obfuscation.",
        "hunt_steps": [
            "Search for abnormal DLL loads into SecurityHealthService.exe",
            "Detect clear event log deletion using wevtutil",
            "Hunt for rundll32.exe spawning uncommon binaries",
            "Investigate modifications to ld.so.preload on Linux systems",
            "Track creation of services with suspicious naming patterns"
        ],
        "expected_outcomes": [
            "Identification of suspicious persistence mechanisms",
            "Detection of credential harvesting and lateral movement via RDP/SSH",
            "Uncovering tool transfers such as njRAT, Cobalt Strike, and Winnti variants",
            "Understanding of obfuscation techniques used by Aquatic Panda"
        ],
        "false_positive": "Encoded PowerShell commands may occur in administrative scripts. Confirm intent and context before escalation.",
        "clearing_steps": [
            "Delete malicious services and binaries",
            "Clear registry edits enabling RestrictedAdmin",
            "Reinstate EDR/AV configurations if disabled",
            "Purge unauthorized SSH keys and cron jobs from Linux systems"
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
