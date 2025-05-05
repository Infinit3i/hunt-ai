def get_content():
    return {
        "id": "G1036",
        "url_id": "Moonstone_Sleet",
        "title": "Moonstone Sleet",
        "tags": ["north-korea", "espionage", "ransomware", "fake companies", "supply-chain", "financially-motivated"],
        "description": (
            "Moonstone Sleet is a North Korean-linked threat actor conducting both financially motivated and espionage-related "
            "campaigns. Previously overlapping with Lazarus Group, it has demonstrated increasingly distinct tradecraft since 2023. "
            "The group is known for creating fake companies and personas, engaging targets through social media and email, "
            "and distributing malware disguised as legitimate software and games."
        ),
        "associated_groups": ["Storm-1789"],
        "campaigns": [],
        "techniques": [
            "T1583.001", "T1583.003", "T1071.001", "T1547.001", "T1217", "T1486",
            "T1140", "T1587", "T1587.001", "T1585.001", "T1585.002", "T1589.002",
            "T1591", "T1105", "T1027", "T1027.009", "T1027.013", "T1003.001",
            "T1566.001", "T1566.003", "T1598", "T1598.003", "T1053.005", "T1608.001",
            "T1195.002", "T1082", "T1016", "T1033", "T1569.002", "T1204.002"
        ],
        "contributors": ["Aung Kyaw Min Naing", "@Nolan"],
        "version": "1.0",
        "created": "26 August 2024",
        "last_modified": "01 October 2024",
        "navigator": "",
        "references": [
            {
                "source": "Microsoft Threat Intelligence",
                "url": "https://www.microsoft.com/security/blog/2024/05/28/moonstone-sleet-emerges-as-new-north-korean-threat-actor-with-new-bag-of-tricks/"
            }
        ],
        "resources": [],
        "remediation": (
            "Harden defenses against social engineering and spearphishing by enabling security awareness training. "
            "Deploy behavior-based endpoint detection, and validate software supply chain integrity for tools like PuTTY. "
            "Apply application control to restrict unauthorized service creation and executable launches."
        ),
        "improvements": (
            "Implement stricter email filtering and domain validation policies. Monitor for indicators of fake company infrastructure "
            "or social media interaction with external users. Employ sandbox analysis on any unknown installers or games downloaded "
            "from third-party sources."
        ),
        "hunt_steps": [
            "Identify use of trojanized installers such as PuTTY or gaming software during initial access.",
            "Detect outbound connections using curl or other command-line tools to unknown infrastructure.",
            "Review registry persistence mechanisms and creation of unauthorized services."
        ],
        "expected_outcomes": [
            "Detection of spearphishing vectors delivered via email or social media.",
            "Correlated artifacts showing malicious infrastructure registration and staged payload delivery.",
            "Identification of ransomware behavior or credential theft via LSASS access."
        ],
        "false_positive": (
            "Usage of legitimate tools such as PuTTY or curl may trigger alerts. Validate download sources and verify "
            "associated domain/IP reputation before action."
        ),
        "clearing_steps": [
            "Reimage compromised endpoints where trojanized installers or loaders have executed.",
            "Revoke any exposed credentials harvested via LSASS dumping.",
            "Remove scheduled tasks or malicious services tied to loader malware.",
            "Perform domain-wide audit for persistence techniques, including registry modifications and file-based startup entries."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
