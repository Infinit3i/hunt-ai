def get_content():
    return {
        "id": "G1011",
        "url_id": "EXOTIC_LILY",
        "title": "EXOTIC LILY",
        "tags": ["financially motivated", "initial access broker", "Conti", "Diavol", "spearphishing", "ISO delivery"],
        "description": (
            "EXOTIC LILY is a financially motivated initial access broker active since at least September 2021. "
            "Closely tied to ransomware operations including Conti and Diavol, the group specializes in social engineering, spearphishing, and exploiting vulnerabilities like CVE-2021-40444. "
            "They target a range of sectors including IT, cybersecurity, and healthcare by impersonating company personnel, manipulating file-sharing services, and crafting well-disguised malicious payloads."
        ),
        "associated_groups": ["Wizard Spider"],
        "campaigns": [],
        "techniques": [
            "T1583.001", "T1585.001", "T1585.002", "T1203", "T1589.002",
            "T1566.001", "T1566.002", "T1566.003", "T1597", "T1593.001",
            "T1594", "T1608.001", "T1204.001", "T1204.002", "T1102"
        ],
        "contributors": ["Phill Taylor", "BT Security"],
        "version": "1.0",
        "created": "18 August 2022",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {
                "source": "Stolyarov, V. (2022). Exposing initial access broker with ties to Conti",
                "url": "https://example.com/exotic-lily-conti-link"
            },
            {
                "source": "Merriman & Trouerbach (2022). Bumblebee analysis",
                "url": "https://example.com/bumblebee-transformation"
            }
        ],
        "resources": [],
        "remediation": (
            "Block ISO file execution via email and restrict access to external file-sharing platforms. "
            "Apply mitigations for CVE-2021-40444 and monitor for domain registration spoofing. "
            "Use email filtering and domain authentication (SPF, DKIM, DMARC) to detect impersonation."
        ),
        "improvements": (
            "Integrate email thread hijack detection capabilities. Implement anomaly detection around document execution chains, especially .ISO or .LNK-based loaders. "
            "Automate social media and domain spoofing alerting tied to your brand."
        ),
        "hunt_steps": [
            "Scan for downloads and execution of ISO files containing LNK payloads.",
            "Monitor use of file-sharing services delivering DLLs or compressed malware payloads.",
            "Review domain creation logs and WHOIS data for similar brand impersonation.",
            "Track creation and use of new email/social accounts impersonating your organization.",
            "Search for CVE-2021-40444 exploitation in telemetry and endpoint logs."
        ],
        "expected_outcomes": [
            "Early detection of social engineering attempts involving impersonated employee profiles.",
            "Prevention of malware execution via blocked ISO/LNK vectors.",
            "Identification of malicious use of legitimate file-sharing services for payload staging."
        ],
        "false_positive": (
            "Use of public file-sharing tools and new email addresses may occur in legitimate business processes. "
            "Behavioral context and cross-source correlation are essential."
        ),
        "clearing_steps": [
            "Block or isolate malicious email threads and remove staged ISO/LNK content.",
            "Update endpoint detection signatures to reflect recent CVE exploits.",
            "Take down spoofed domains and impersonated social accounts through proper channels."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
