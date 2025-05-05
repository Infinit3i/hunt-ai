def get_content():
    return {
        "id": "G1041",
        "url_id": "Sea_Turtle",
        "title": "Sea Turtle",
        "tags": ["espionage", "dns-hijacking", "middle-east", "infrastructure targeting", "Türkiye-linked"],
        "description": (
            "Sea Turtle is a Türkiye-linked threat actor active since at least 2017, known for espionage operations targeting entities "
            "across Asia, Europe, and North America. The group is most notable for compromising domain registrars and DNS service providers "
            "to hijack DNS resolution, allowing them to conduct adversary-in-the-middle attacks and credential theft."
        ),
        "associated_groups": ["Teal Kurma", "Marbled Dust", "Cosmic Wolf", "SILICON"],
        "campaigns": [],
        "techniques": [
            "T1583", "T1583.001", "T1583.002", "T1583.003", "T1557", "T1071.001", "T1560.001", "T1059.004",
            "T1584.002", "T1213", "T1074.002", "T1114.001", "T1190", "T1203", "T1133", "T1564.011", "T1562.003",
            "T1070.002", "T1027.004", "T1588.002", "T1588.004", "T1566", "T1505.003", "T1608.003", "T1199",
            "T1078", "T1078.003"
        ],
        "contributors": ["Inna Danilevich, U.S. Bank", "Joe Gumke, U.S. Bank"],
        "version": "1.0",
        "created": "20 November 2024",
        "last_modified": "28 March 2025",
        "navigator": "",
        "references": [
            {"source": "Cisco Talos", "url": "https://blog.talosintelligence.com/sea-turtle-dns-hijacking/"},
            {"source": "Paul Rascagneres", "url": "https://blog.talosintelligence.com/sea-turtle-keeps-on-swimming/"},
            {"source": "PwC Threat Intelligence", "url": "https://www.pwc.com/gx/en/issues/cybersecurity/tortoise-and-the-malware.html"},
            {"source": "Hunt & Hackett", "url": "https://huntandhackett.com/research/turkish-espionage-netherlands"},
            {"source": "Microsoft", "url": "https://www.microsoft.com/en-us/security/blog/2021/10/01/microsoft-digital-defense-report/"}
        ],
        "resources": [],
        "remediation": (
            "Monitor and alert for unauthorized DNS changes at registrars and internal resolvers. "
            "Use DNSSEC where possible. Harden external-facing systems against known vulnerabilities and restrict SSH access."
        ),
        "improvements": (
            "Deploy passive DNS monitoring, implement domain lock features at registrars, and monitor certificate issuance for typosquatting domains. "
            "Use behavior-based anomaly detection on DNS traffic to detect adversary-in-the-middle activity."
        ),
        "hunt_steps": [
            "Search for use of Adminer and other web database clients in access logs.",
            "Identify sudden changes to DNS records involving NS or A records redirecting to unknown infrastructure.",
            "Review SSL certificate issuance logs for certificate impersonation attempts."
        ],
        "expected_outcomes": [
            "Detection of DNS hijacking techniques targeting internal or registrar-controlled zones.",
            "Discovery of credential theft attempts using spoofed login portals.",
            "Uncover hidden shell activity like SnappyTCP post-compromise tooling."
        ],
        "false_positive": "Certificate changes or DNS modifications may occur during legitimate IT operations; validate with change management.",
        "clearing_steps": [
            "Revert unauthorized DNS record changes and reset credentials used during the compromise.",
            "Remove malicious tools such as SnappyTCP and shell scripts from affected hosts.",
            "Harden DNS and web servers and rotate any exposed private keys or certificates."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": [
                "https://blog.talosintelligence.com/sea-turtle-dns-hijacking/",
                "https://huntandhackett.com/research/turkish-espionage-netherlands"
            ]
        }
    }
