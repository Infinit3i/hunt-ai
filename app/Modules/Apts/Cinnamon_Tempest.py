def get_content():
    return {
        "id": "G1021",
        "url_id": "Cinnamon_Tempest",
        "title": "Cinnamon Tempest",
        "tags": [
            "china-based",
            "ransomware",
            "babuk-derivative",
            "cobalt-strike",
            "espionage-motivated"
        ],
        "description": "Cinnamon Tempest is a China-based threat group active since at least 2021 that deploys ransomware variants derived from the Babuk source code. The group appears to operate independently in all stages of the attack lifecycle, suggesting a potential focus on intellectual property theft or espionage.",
        "associated_groups": ["DEV-0401", "Emperor Dragonfly", "BRONZE STARLIGHT"],
        "campaigns": [],
        "techniques": [
            "T1059.001", "T1059.003", "T1059.006", "T1543.003", "T1140", "T1484.001", "T1567.002", "T1190",
            "T1657", "T1574.001", "T1105", "T1588.002", "T1572", "T1090", "T1021.002", "T1080", "T1078",
            "T1078.002", "T1047"
        ],
        "contributors": [],
        "version": "1.0",
        "created": "06 December 2023",
        "last_modified": "04 April 2024",
        "navigator": "",
        "references": [
            {"source": "Microsoft", "url": "https://www.microsoft.com/security/blog/2022/05/09/ransomware-as-a-service-understanding-the-cybercrime-gig-economy"},
            {"source": "Microsoft", "url": "https://learn.microsoft.com/en-us/security-updates/microsoft-names-threat-actors"},
            {"source": "Trend Micro", "url": "https://www.trendmicro.com/en_us/research/22/e/cheerscrypt-linux-esxi-ransomware.html"},
            {"source": "SecureWorks CTU", "url": "https://www.secureworks.com/research/bronze-starlight-ransomware-operations"},
            {"source": "Check Point Research", "url": "https://research.checkpoint.com/2022/revealing-emperor-dragonfly-night-sky-and-cheerscrypt"},
            {"source": "SecureWorks", "url": "https://www.secureworks.com/research/bronze-starlight"},
            {"source": "Microsoft Threat Intelligence", "url": "https://www.microsoft.com/security/blog/2021/12/11/guidance-log4j-2-vulnerability"}
        ],
        "resources": [],
        "remediation": "",
        "improvements": "",
        "hunt_steps": [],
        "expected_outcomes": [],
        "false_positive": "",
        "clearing_steps": [],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
