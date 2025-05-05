def get_content():
    return {
        "id": "G0106",
        "url_id": "Rocke",
        "title": "Rocke",
        "tags": ["china", "cryptojacking", "monero", "resource-hijacking", "cloud-infrastructure", "linux"],
        "description": (
            "Rocke is a Chinese-speaking threat actor group primarily focused on **cryptojacking**, leveraging infected systems to mine Monero cryptocurrency. "
            "It gained attention due to its aggressive use of Linux-targeted malware, persistence techniques, and obfuscation methods. The group exploited public-facing applications such as Apache Struts, "
            "Oracle WebLogic (CVE-2017-10271), and Adobe ColdFusion (CVE-2017-3066), deploying UPX-packed and Python-based malware. Rocke has been associated with advanced techniques for evasion, "
            "persistence, and resource hijacking, often modifying system binaries, logs, and using rootkits to remain hidden."
        ),
        "associated_groups": ["Iron Cybercrime Group (unconfirmed)"],
        "campaigns": [],
        "techniques": [
            "T1071", "T1071.001", "T1547.001", "T1037", "T1059.004", "T1059.006", "T1543.002",
            "T1140", "T1190", "T1222.002", "T1564.001", "T1574.006", "T1562.001", "T1562.004",
            "T1070.002", "T1070.004", "T1070.006", "T1105", "T1036.005", "T1046", "T1571", "T1027",
            "T1027.002", "T1027.004", "T1057", "T1055.002", "T1021.004", "T1018", "T1496.001", "T1014",
            "T1053.003", "T1518.001", "T1082", "T1552.004", "T1102", "T1102.001"
        ],
        "contributors": ["Liebenberg, D.", "Anomali Labs", "Xingyu, J."],
        "version": "1.0",
        "created": "26 May 2020",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {
                "source": "Liebenberg, D. (Palo Alto Networks Unit 42)",
                "url": "https://unit42.paloaltonetworks.com/rocke-the-champion-of-monero-miners/"
            },
            {
                "source": "Anomali Labs",
                "url": "https://www.anomali.com/blog/rocke-evolves-its-arsenal-with-a-new-malware-family-written-in-golang"
            },
            {
                "source": "Xingyu, J. (Alibabacloud Security)",
                "url": "https://www.alibabacloud.com/blog/malware-used-by-rocke-group-evolves-to-evade-detection_594258"
            }
        ],
        "resources": [],
        "remediation": (
            "Patch public-facing applications (e.g., Apache Struts, WebLogic) and block outbound connections to known cryptominer infrastructure. "
            "Implement strict execution controls for scripts, detect rootkit installations, and use behavioral EDR to monitor for UPX-packed binaries, "
            "modified init scripts, and unauthorized systemd/crontab entries."
        ),
        "improvements": (
            "Deploy log integrity monitoring, detect tampering in /var/log and /etc directories, "
            "and monitor for tampering of /etc/ld.so.preload and changes in cron/systemd services. "
            "Use threat intelligence to block known miner wallet addresses and Pastebin/GitLab abuse indicators."
        ),
        "hunt_steps": [
            "Inspect for unauthorized UPX-packed binaries in user and system directories.",
            "Search for unauthorized changes to `/etc/ld.so.preload`, `init.d`, and cron/systemd entries.",
            "Check for known malicious wget/curl patterns and obfuscated `java`-named binaries.",
            "Review logs for signs of privilege escalation and execution of GCC for local compilation.",
            "Identify network connections over port 51640 or to Pastebin/Gitee used as C2.",
            "Trace spread via SSH keys and inspect `.ssh/known_hosts` across systems."
        ],
        "expected_outcomes": [
            "Detection of mining malware and associated persistence.",
            "Identification of privilege escalation and rootkit hiding mechanisms.",
            "Prevention of future lateral movement via SSH and credential reuse.",
            "Mitigation of performance degradation and infrastructure resource theft."
        ],
        "false_positive": (
            "System administrators may occasionally use tools like wget, curl, or cron jobs legitimately. Validate against expected patterns, file hashes, and behavior context."
        ),
        "clearing_steps": [
            "Kill malicious cron/systemd processes and remove dropped binaries.",
            "Delete unauthorized SSH keys and reset credentials.",
            "Restore modified startup scripts and remove rootkit entries from `/etc/ld.so.preload`.",
            "Clear altered logs and enable tamper-proof log storage.",
            "Perform full system scans using trusted recovery media and reimage if necessary."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
