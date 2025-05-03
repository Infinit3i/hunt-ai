def get_content():
    return {
        "id": "G0053",
        "url_id": "FIN5",
        "title": "FIN5",
        "tags": ["financial", "Russian-speaking", "PII theft", "hospitality"],
        "description": "FIN5 is a financially motivated threat group that has targeted personally identifiable information (PII) and payment card data. Active since at least 2008, they have focused attacks on the restaurant, gaming, and hotel industries. The group is composed of actors who likely speak Russian and employ a wide range of post-compromise tools to move laterally and maintain persistence.",
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1119", "T1110", "T1059", "T1074.001", "T1133", "T1070.001",
            "T1070.004", "T1588.002", "T1090.002", "T1018", "T1078"
        ],
        "contributors": ["Walker Johnson"],
        "version": "1.2",
        "created": "16 January 2018",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {"source": "Scavella & Rifki (2017)", "url": "https://www.sans.org/webcasts/are-you-ready-to-respond-103467/"},
            {"source": "Bromiley & Lewis (2016)", "url": "https://www.sans.org/webcasts/attacking-hospitality-and-gaming-industries-102972/"},
            {"source": "Higgins (2015)", "url": "https://www.darkreading.com/attacks-breaches/prolific-cybercrime-gang-favors-legit-login-credentials"}
        ],
        "resources": [],
        "remediation": "Audit and restrict the use of administrative tools like PsExec and credential dumping utilities. Monitor for unusual VPN, Citrix, or VNC access patterns and use of external proxies.",
        "improvements": "Implement behavioral monitoring for process dumping and event log clearing. Regularly rotate credentials and monitor RDP/VPN sessions for anomalies.",
        "hunt_steps": [
            "Look for usage of tools like PsExec, pwdump, Windows Credential Editor, and SDelete.",
            "Monitor Windows Event Log clearing activities.",
            "Detect access via FLIPSIDE or other external proxies."
        ],
        "expected_outcomes": [
            "Detection of tools and scripts used for lateral movement and data staging.",
            "Identification of attempts to obscure activity via log or file deletion.",
            "Discovery of unauthorized access through remote services using valid credentials."
        ],
        "false_positive": "Use of PsExec or VPNs may be legitimate in some environments. Correlate with user behavior and access context.",
        "clearing_steps": [
            "Reset compromised credentials across affected systems.",
            "Delete malicious scripts and restore tampered configurations.",
            "Review access logs and investigate any persistence mechanisms or backdoors."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
