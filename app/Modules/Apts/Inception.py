def get_content():
    return {
        "id": "G0100",
        "url_id": "Inception",
        "title": "Inception",
        "tags": ["cyber espionage", "Cloud Atlas", "Inception Framework", "multi-regional", "2014+"],
        "description": (
            "Inception is a cyber espionage group active since at least 2014. The group has targeted governmental entities and "
            "various industries, primarily in Russia but also operating across the United States, Europe, Asia, Africa, and the Middle East. "
            "They use a modular framework and often leverage cloud-based services and obfuscated payload delivery methods."
        ),
        "associated_groups": ["Inception Framework", "Cloud Atlas"],
        "campaigns": [],
        "techniques": [
            "T1071.001", "T1547.001", "T1059.001", "T1059.005", "T1555.003", "T1005", "T1573.001", "T1203", "T1083",
            "T1027.013", "T1588.002", "T1069.002", "T1566.001", "T1057", "T1090.003", "T1518", "T1218.005", "T1218.010",
            "T1082", "T1221", "T1204.002", "T1102"
        ],
        "contributors": ["Oleg Skulkin", "Group-IB"],
        "version": "1.2",
        "created": "08 May 2020",
        "last_modified": "11 April 2024",
        "navigator": "",
        "references": [
            {"source": "Lancaster, T.", "url": "https://www.f-secure.com/en/newsroom/inception-attackers-target-europe"},
            {"source": "Symantec", "url": "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/inception-framework-espionage"},
            {"source": "GReAT (2014)", "url": "https://securelist.com/cloud-atlas-redoctober-apt-is-back-in-style/"},
            {"source": "GReAT (2019)", "url": "https://securelist.com/recent-cloud-atlas-activity/"}
        ],
        "resources": [],
        "remediation": (
            "Patch known Office vulnerabilities (e.g., CVE-2012-0158, CVE-2014-1761, CVE-2017-11882, CVE-2018-0802), "
            "restrict use of HTA/Regsvr32, and monitor for suspicious registry run key modifications. Limit internet access "
            "for document readers and enforce network segmentation."
        ),
        "improvements": (
            "Deploy behavior-based detection for PowerShell and VBScript usage in user-mode processes, enhance proxy monitoring "
            "for unusual multi-hop traffic chains, and establish alerting for unauthorized software enumeration and credential dumping."
        ),
        "hunt_steps": [
            "Search for regsvr32 executions referencing uncommon DLLs.",
            "Scan for encoded or encrypted PowerShell/VBScript content in Office or HTA files.",
            "Query for connections to known abused cloud providers like CloudMe.",
            "Hunt for credential stealing activity from browsers across multiple vendors."
        ],
        "expected_outcomes": [
            "Detection of early-stage phishing and remote payload loading.",
            "Identification of lateral movement via proxy chaining and encrypted communications.",
            "Evidence of credential harvesting and exfiltration preparations."
        ],
        "false_positive": (
            "Usage of PowerShell and Regsvr32 may be legitimate in enterprise environments; validate with context such as "
            "execution path, parent processes, and network activity."
        ),
        "clearing_steps": [
            "Terminate related processes and remove persistence from registry run keys.",
            "Block C2 domains and reset exposed credentials.",
            "Quarantine affected hosts and perform full memory analysis for embedded modules."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
