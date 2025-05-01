def get_content():
    return {
        "id": "G0035",
        "url_id": "Dragonfly",
        "title": "Dragonfly",
        "tags": ["russian", "fsb", "critical-infrastructure", "ics", "energy-sector", "dragonfly2", "berserk-bear", "ghost-blizzard"],
        "description": "Dragonfly is a Russian cyber espionage group attributed to the FSB Center 16. Active since at least 2010, the group targets critical infrastructure worldwide, especially in the energy and industrial sectors. Dragonfly is known for leveraging supply chain attacks, spearphishing, strategic web compromises, and credential harvesting to gain and maintain access to victim environments.",
        "associated_groups": [
            "TEMP.Isotope", "DYMALLOY", "Berserk Bear", "TG-4192", "Crouching Yeti", 
            "IRON LIBERTY", "Energetic Bear", "Ghost Blizzard", "BROMINE"
        ],
        "campaigns": [],
        "techniques": [
            "T1087.002", "T1098.007", "T1583.001", "T1583.003", "T1595.002", "T1071.002",
            "T1560", "T1547.001", "T1110", "T1110.002", "T1059", "T1059.001", "T1059.003",
            "T1059.006", "T1584.004", "T1136.001", "T1005", "T1074.001", "T1189", "T1114.002",
            "T1190", "T1203", "T1210", "T1133", "T1083", "T1187", "T1591.002", "T1564.002",
            "T1562.004", "T1070.001", "T1070.004", "T1105", "T1036.010", "T1112", "T1135",
            "T1588.002", "T1003.002", "T1003.003", "T1003.004", "T1069.002", "T1566.001",
            "T1598.002", "T1598.003", "T1012", "T1021.001", "T1018", "T1053.005", "T1113",
            "T1505.003", "T1608.004", "T1195.002", "T1016", "T1033", "T1221", "T1204.002",
            "T1078", "T0817", "T0862"
        ],
        "contributors": ["Dragos Threat Intelligence"],
        "version": "4.0",
        "created": "31 May 2017",
        "last_modified": "08 January 2024",
        "navigator": "",
        "references": [
            {"source": "DOJ", "url": "https://www.justice.gov/opa/pr/four-russian-government-employees-charged-hacking-campaigns"},
            {"source": "UK Government", "url": "https://www.gov.uk/government/publications/russias-fsb-malign-activity-factsheet"},
            {"source": "Symantec", "url": "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/dragonfly-energy-sector"},
            {"source": "Secureworks", "url": "https://www.secureworks.com/research/resurgent-iron-liberty-targeting-energy-sector"},
            {"source": "Symantec Flash Report", "url": "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/western-energy-sector-attack"},
            {"source": "Fortune", "url": "https://fortune.com/2017/09/06/energy-grid-hack-symantec/"},
            {"source": "Slowik, J.", "url": "https://www.dragos.com/blog/the-baffling-berserk-bear/"},
            {"source": "CISA", "url": "https://www.cisa.gov/news-events/alerts/2020/12/01/russian-state-sponsored-apt-activity"},
            {"source": "Microsoft", "url": "https://www.microsoft.com/security/blog/2023/07/12/how-microsoft-names-threat-actors/"}
        ],
        "resources": ["Berserk Bear report", "Backdoor.Oldrea and Karagany malware profiles"],
        "remediation": "Segment critical ICS/SCADA systems, disable external access unless absolutely necessary, and implement behavioral detection for known malware behaviors including SecretsDump, PowerShell misuse, and supply chain artifacts.",
        "improvements": "Deploy robust log retention policies. Monitor scheduled tasks and privilege escalation attempts. Detect excessive use of tools like PsExec, CrackMapExec, and Impacket.",
        "hunt_steps": [
            "Review registry keys for persistence entries like Run values referencing 'ntdll'.",
            "Search logs for scheduled tasks that execute unknown binaries.",
            "Hunt for credential dumping behavior involving SecretsDump or LSASS memory access.",
            "Monitor file staging directories like %AppData%\\out.",
            "Check for lateral movement via RDP and SMB with anomalous account names."
        ],
        "expected_outcomes": [
            "Detection of stealthy persistence and staged data for exfiltration.",
            "Identification of lateral movement using PsExec and valid accounts.",
            "Uncovering masqueraded user accounts and remote infrastructure.",
            "Trace supply chain origin of malware installers or compromised software updates."
        ],
        "false_positive": "Some discovery techniques and file compressions may be used by administrators. Evaluate based on context, frequency, and correlations to confirmed intrusion activity.",
        "clearing_steps": [
            "Delete all malicious scheduled tasks and registry persistence entries.",
            "Revoke compromised credentials and change domain admin passwords.",
            "Rebuild systems with known malware presence (Karagany, Oldrea, etc.).",
            "Isolate and resecure externally facing web servers with signs of web shell access."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
