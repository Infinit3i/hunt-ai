def get_content():
    return {
        "id": "G0117",
        "url_id": "Fox_Kitten",
        "title": "Fox Kitten",
        "tags": ["iranian", "state-sponsored", "vpn-exploitation", "espionage", "industrial"],
        "description": "Fox Kitten is a suspected Iranian state-sponsored threat actor active since at least 2017. It has targeted entities across multiple regions including the Middle East, North Africa, Europe, Australia, and North America. Its targets span numerous sectors such as oil and gas, defense, government, healthcare, and technology. The group is known for exploiting VPN appliances, establishing persistent access via web shells, and conducting extensive internal reconnaissance and data exfiltration operations.",
        "associated_groups": ["UNC757", "Parisite", "Pioneer Kitten", "RUBIDIUM", "Lemon Sandstorm"],
        "campaigns": [],
        "techniques": [
            "T1087.001", "T1087.002", "T1560.001", "T1217", "T1110", "T1059", "T1059.001", "T1059.003",
            "T1136.001", "T1555.005", "T1530", "T1213.005", "T1005", "T1039", "T1585", "T1585.001",
            "T1546.008", "T1190", "T1210", "T1083", "T1105", "T1036.004", "T1036.005", "T1046",
            "T1027.010", "T1027.013", "T1003.001", "T1003.003", "T1572", "T1090", "T1012", "T1021.001",
            "T1021.002", "T1021.004", "T1021.005", "T1018", "T1053.005", "T1505.003", "T1552.001",
            "T1078", "T1102"
        ],
        "contributors": [],
        "version": "2.0",
        "created": "21 December 2020",
        "last_modified": "08 January 2024",
        "navigator": "",
        "references": [
            {"source": "ClearSky", "url": "https://www.clearskysec.com/fox-kitten/"},
            {"source": "ClearSky", "url": "https://www.clearskysec.com/pay2key/"},
            {"source": "Dragos", "url": "https://www.dragos.com/blog/parisite/"},
            {"source": "Check Point", "url": "https://research.checkpoint.com/2020/ransomware-alert-pay2key/"},
            {"source": "CISA", "url": "https://www.cisa.gov/news-events/alerts/2020/09/15/iran-based-threat-actor-exploits-vpn-vulnerabilities"},
            {"source": "Microsoft", "url": "https://www.microsoft.com/en-us/security/blog/2023/07/12/how-microsoft-names-threat-actors/"}
        ],
        "resources": [],
        "remediation": "Patch VPN appliances and public-facing applications immediately. Disable unnecessary remote services and review scheduled tasks and WMI subscriptions for persistence. Enforce multi-factor authentication for all remote access services.",
        "improvements": "Implement behavioral monitoring for PowerShell, cmd.exe, and known tunneling tools such as ngrok and SSHMinion. Track creation of accounts and modifications to system services and registry entries.",
        "hunt_steps": [
            "Search for base64-encoded PowerShell commands and unusual cmd.exe invocations.",
            "Monitor for lateral movement via RDP, VNC, and Plink activity.",
            "Audit ntuser.dat and UserClass.dat access for signs of credential harvesting.",
            "Look for PsExec and FRPC execution across internal hosts."
        ],
        "expected_outcomes": [
            "Discovery of unauthorized VPN exploitation or abuse of remote services.",
            "Identification of data archiving using 7-Zip or exfiltration via proxies.",
            "Detection of persistence mechanisms via scheduled tasks or web shells."
        ],
        "false_positive": "Use of tools like PowerShell, 7-Zip, or PsExec may be common in enterprise environments. Correlate with context such as timing, user accounts, and remote access behavior.",
        "clearing_steps": [
            "Revoke and rotate credentials used by the attacker.",
            "Remove malicious scheduled tasks, registry entries, and local accounts.",
            "Delete unauthorized web shells and binaries like svhost/dllhost.",
            "Audit firewall and proxy logs to identify and cut off C2 paths."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
