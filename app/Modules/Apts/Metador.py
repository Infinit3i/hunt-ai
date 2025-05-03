def get_content():
    return {
        "id": "G1013",
        "url_id": "Metador",
        "title": "Metador",
        "tags": ["espionage", "Middle East", "Africa", "telco", "stealth", "living-off-the-land"],
        "description": "Metador is a suspected cyber espionage group first reported in September 2022. It has primarily targeted telecommunications providers, ISPs, and universities in the Middle East and Africa. The name 'Metador' comes from the 'I am meta' string found in malware and anticipated Spanish-language responses from C2 servers. The group is known for advanced evasion tactics and long-term stealthy operations using custom malware like metaMain and Mafalda.",
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1071.001", "T1059.003", "T1546.003", "T1070.004", "T1105", "T1095",
            "T1027.013", "T1588.001", "T1588.002"
        ],
        "contributors": ["Massimiliano Romano, BT Security", "Sittikorn Sangrattanapitak"],
        "version": "1.1",
        "created": "25 January 2023",
        "last_modified": "11 April 2024",
        "navigator": "",
        "references": [
            {"source": "SentinelLabs", "url": "https://www.sentinelone.com/labs/the-mystery-of-metador/"},
            {"source": "SentinelLabs Technical Appendix", "url": "https://www.sentinelone.com/labs/metador-technical-appendix/"}
        ],
        "resources": [
            "https://attack.mitre.org/groups/G1013/",
            "https://www.sentinelone.com/labs/the-mystery-of-metador/",
            "https://www.sentinelone.com/labs/metador-technical-appendix/"
        ],
        "remediation": "Disable unnecessary WMI event subscriptions, monitor for Living-off-the-Land Binaries (LOLBins) like cdb.exe, and implement behavioral analysis to detect stealthy tool deployment. Enforce strict application allowlisting and deploy EDR solutions capable of detecting memory-based threats.",
        "improvements": "Enhance host logging to capture WMI subscription changes and event tracing. Correlate ingress tool transfer events with uncommon LOLBin execution. Improve detection of encrypted payloads being loaded into memory.",
        "hunt_steps": [
            "Look for execution of cdb.exe in non-debugging contexts",
            "Monitor for WMI event subscriptions linked to persistence",
            "Search for encrypted files or dropped binaries followed by deletion",
            "Correlate HTTP/TCP traffic with unknown malware samples named metaMain or Mafalda"
        ],
        "expected_outcomes": [
            "Identification of stealthy C2 over TCP/HTTP",
            "Detection of metaMain and Mafalda execution artifacts",
            "Discovery of post-exploitation persistence via WMI subscriptions",
            "Visibility into data staging and exfiltration activity"
        ],
        "false_positive": "Use of cdb.exe or WMI may occur in legitimate administrative or troubleshooting scenarios. Validation should consider context and behavioral chaining.",
        "clearing_steps": [
            "Delete WMI event subscriptions established by attacker malware",
            "Remove encrypted payloads and clean dropped tools (e.g., cdb.exe)",
            "Revoke any credentials or accounts accessed by Metador tools",
            "Conduct memory forensics to ensure no reflective code or hidden implants persist"
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": [
                "https://www.sentinelone.com/labs/the-mystery-of-metador/",
                "https://www.sentinelone.com/labs/metador-technical-appendix/"
            ]
        }
    }
