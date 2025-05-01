def get_content():
    return {
        "id": "G0012",
        "url_id": "Darkhotel",
        "title": "Darkhotel",
        "tags": ["south-korean", "state-sponsored", "espionage", "travel", "hotels", "dubnium", "zigzag-hail"],
        "description": "Darkhotel is a suspected South Korean threat group that has operated since at least 2004. It is known for targeting high-profile individuals, particularly traveling executives in East Asia, using hotel Wi-Fi networks, spearphishing emails, and file-sharing networks. Their malware, often disguised or encrypted, is designed for espionage and persistence.",
        "associated_groups": ["DUBNIUM", "Zigzag Hail"],
        "campaigns": [],
        "techniques": [
            "T1547.001", "T1059.003", "T1140", "T1189", "T1573.001", "T1203", "T1083", "T1105",
            "T1056.001", "T1036.005", "T1027.013", "T1566.001", "T1057", "T1091", "T1518.001",
            "T1553.002", "T1082", "T1016", "T1124", "T1080", "T1204.002", "T1497", "T1497.001", "T1497.002"
        ],
        "contributors": ["Harry Kim", "CODEMIZE"],
        "version": "3.0",
        "created": "31 May 2017",
        "last_modified": "08 January 2024",
        "navigator": "",
        "references": [
            {"source": "Kaspersky Lab", "url": "https://securelist.com/darkhotel-the-story-of-unusual-hospitality/67740/"},
            {"source": "Kaspersky Lab", "url": "https://securelist.com/darkhotels-attacks-in-2015/71729/"},
            {"source": "Microsoft", "url": "https://www.microsoft.com/security/blog/2020/09/29/microsoft-digital-defense-report/"},
            {"source": "Microsoft", "url": "https://www.microsoft.com/security/blog/2016/06/09/reverse-engineering-dubnium/"},
            {"source": "Microsoft", "url": "https://www.microsoft.com/security/blog/2016/06/20/reverse-engineering-dubniums-flash-targeting-exploit/"},
            {"source": "Microsoft", "url": "https://www.microsoft.com/security/blog/2016/07/14/reverse-engineering-dubnium-stage-2-payload-analysis/"},
            {"source": "Microsoft", "url": "https://www.microsoft.com/security/blog/2023/07/12/how-microsoft-names-threat-actors/"},
            {"source": "Arunpreet Singh, Clemens Kolbitsch", "url": "https://www.blackhat.com/docs/eu-15/materials/eu-15-Singh-Darkhotel-Just-In-Time-Decryption.pdf"}
        ],
        "resources": ["Darkhotel APT Reports", "Dubnium malware analysis", "Decryption evasion techniques"],
        "remediation": "Isolate environments with access to sensitive networks. Prevent execution of CHM, LNK, and unsigned executable files from email or shared drives. Patch systems, especially against known Flash vulnerabilities.",
        "improvements": "Implement endpoint detection for RC4, XOR, and just-in-time decryption behavior. Monitor for masqueraded binaries and persistence via Run keys. Use DNS filtering to block known C2 infrastructures.",
        "hunt_steps": [
            "Search for Run key persistence entries for suspicious executables.",
            "Scan for malware using AES, RC4, or XOR decryption schemes.",
            "Detect downloads initiated from hotel or captive portal environments.",
            "Look for usage of `mspaint.lnk` or other misused shortcuts initiating shells."
        ],
        "expected_outcomes": [
            "Identification of Darkhotel persistence mechanisms.",
            "Detection of encrypted C2 communication channels.",
            "Discovery of host reconnaissance and sandbox evasion techniques.",
            "Isolation of spearphishing and removable media propagation activity."
        ],
        "false_positive": "Encrypted traffic over common ports may mimic benign applications. Some portable apps may use self-extracting shortcuts similar to malicious LNK usage.",
        "clearing_steps": [
            "Delete persistence mechanisms and backdoors.",
            "Change all credentials that may have been captured via keyloggers.",
            "Update AV/EDR signatures to detect encrypted and obfuscated variants.",
            "Reimage systems if malware like Flash exploits or advanced rootkits were involved."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
