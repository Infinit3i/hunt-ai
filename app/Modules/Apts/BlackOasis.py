def get_content():
    return {
        "id": "G0063",
        "url_id": "BlackOasis",
        "title": "BlackOasis",
        "tags": ["middle-east", "espionage", "activists", "finfisher", "opposition", "journalists", "think-tanks", "zero-day"],
        "description": "BlackOasis is a Middle Eastern cyber threat group believed to be a customer of Gamma Group. The group has targeted individuals including opposition bloggers, regional activists, United Nations personnel, news correspondents, and think tanks. The group's operations suggest a strong focus on political surveillance, often employing sophisticated spyware such as FinFisher and zero-day exploits.",
        "associated_groups": ["NEODYMIUM"],
        "campaigns": [],
        "techniques": [
            "T1027"
        ],
        "contributors": [],
        "version": "1.0",
        "created": "18 April 2018",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {
                "source": "Kaspersky Lab – BlackOasis APT Report",
                "url": "https://securelist.com/blackoasis-apt-and-new-targeted-attacks-leveraging-zero-day-exploit/82851/"
            },
            {
                "source": "Kaspersky Lab – APT Trends Q2 2017",
                "url": "https://securelist.com/apt-trends-report-q2-2017/79432/"
            },
            {
                "source": "Cyberscoop – FinFisher Espionage",
                "url": "https://cyberscoop.com/blackoasis-finfisher-middle-east-united-nations/"
            }
        ],
        "resources": [],
        "remediation": "Update and patch systems to mitigate exploitation through zero-day vulnerabilities. Implement behavior-based AV/EDR capable of detecting obfuscation techniques like NOP sled variants. Restrict execution of shellcode within document files and enhance monitoring around FinFisher-related activity.",
        "improvements": "Deploy heuristic-based memory scanning to detect shellcode execution patterns. Flag documents with embedded alternative instruction sleds. Monitor communications with known C2 domains used by FinFisher spyware infrastructure.",
        "hunt_steps": [
            "Inspect document files for unusual shellcode patterns and NOP sleds",
            "Review AV logs for potential bypass attempts involving alternate opcode sequences",
            "Trace DNS and network activity related to known FinFisher C2 infrastructure"
        ],
        "expected_outcomes": [
            "Detection of early-stage shellcode with obfuscation",
            "Identification of FinFisher spyware deployment attempts",
            "Increased visibility into politically motivated espionage targeting high-profile individuals"
        ],
        "false_positive": "Custom shellcode patterns may resemble legitimate pentesting tools. Validate process lineage and context before taking action.",
        "clearing_steps": [
            "Remove detected FinFisher binaries or any dropped payloads",
            "Patch any exploited software vulnerabilities used for delivery",
            "Harden systems against document-based shellcode injection vectors"
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
