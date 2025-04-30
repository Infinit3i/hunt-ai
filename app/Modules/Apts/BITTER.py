def get_content():
    return {
        "id": "G1002",
        "url_id": "BITTER",
        "title": "BITTER",
        "tags": ["south-asia", "cyberespionage", "government", "energy", "engineering", "mobile", "china", "pakistan", "bangladesh", "saudi-arabia"],
        "description": "BITTER is a suspected South Asian cyber espionage threat group active since at least 2013. It has targeted government, energy, and engineering organizations in Pakistan, China, Bangladesh, and Saudi Arabia. BITTER is known for its spearphishing campaigns and use of both desktop and mobile malware.",
        "associated_groups": ["T-APT-17"],
        "campaigns": [],
        "techniques": [
            "T1583.001", "T1071.001", "T1568", "T1573", "T1203", "T1068", "T1105", "T1559.002",
            "T1036.004", "T1095", "T1027.013", "T1588.002", "T1566.001", "T1053.005", "T1608.001",
            "T1204.002", "T1660"
        ],
        "contributors": [],
        "version": "1.1",
        "created": "01 June 2022",
        "last_modified": "11 April 2024",
        "navigator": "",
        "references": [
            {
                "source": "Raghuprasad, C.",
                "url": "https://www.secpod.com/blog/bitter-apt-adds-bangladesh-to-their-targets/"
            },
            {
                "source": "Trend Micro",
                "url": "https://www.trendmicro.com/en_us/research/16/j/bitter-a-targeted-attack-against-pakistan.html"
            },
            {
                "source": "QiAnXin",
                "url": "https://mp.weixin.qq.com/s/Z-windows-kernel-zero-day-cve-2021-1732-used-by-bitter-apt"
            },
            {
                "source": "Microsoft",
                "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1732"
            },
            {
                "source": "BlackBerry",
                "url": "https://www.blackberry.com/us/en/forms/enterprise/report-mobile-malware-and-apt-espionage"
            }
        ],
        "resources": [],
        "remediation": "Disable DDE in Office applications, ensure users do not have administrative rights by default, and apply patches for CVE-2012-0158, CVE-2017-11882, CVE-2018-0798, CVE-2018-0802, and CVE-2021-1732. Implement email filtering for spearphishing attachments and monitor for RAR SFX archive execution.",
        "improvements": "Deploy detection signatures for RTF-based exploits and Equation Editor abuse. Monitor HTTP POST behavior from non-browser processes and apply DNS monitoring to catch DDNS usage. Enhance scheduled task logging and monitor registry changes made by unknown executables.",
        "hunt_steps": [
            "Identify use of malicious RTF or Excel documents in email attachments",
            "Track outbound HTTP POST requests to unknown domains",
            "Hunt for RAR SFX dropper executions on endpoints",
            "Monitor scheduled task creation linked to suspicious binaries",
            "Search mobile environments for apps linked to SMS-distributed APKs"
        ],
        "expected_outcomes": [
            "Detection of spearphishing attachments exploiting Office vulnerabilities",
            "Uncovering of scheduled tasks used for persistence",
            "Identification of network indicators such as DDNS domains and encrypted C2",
            "Detection of mobile delivery mechanisms via social platforms"
        ],
        "false_positive": "Some legitimate Office documents use DDE or POST requests. Validate the source and intent of the file before escalation.",
        "clearing_steps": [
            "Remove scheduled tasks tied to unauthorized binaries",
            "Clear staged malware from %AppData%, temp, and other persistence locations",
            "Block and sinkhole known C2 domains used by BITTER",
            "Purge unauthorized mobile apps and scan for sideloaded APKs",
            "Disable or restrict the Microsoft Equation Editor if not needed"
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
