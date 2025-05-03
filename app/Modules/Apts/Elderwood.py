def get_content():
    return {
        "id": "G0066",
        "url_id": "Elderwood",
        "title": "Elderwood",
        "tags": ["espionage", "state-sponsored", "China", "Operation Aurora", "zero-day exploits"],
        "description": (
            "Elderwood is a suspected Chinese cyber espionage group believed to be behind the 2009 Google intrusion known as Operation Aurora. "
            "They have targeted defense contractors, supply chain manufacturers, human rights and NGO organizations, and IT service providers. "
            "The group is known for using zero-day vulnerabilities, spearphishing, and web-based exploits to deliver malware and establish access."
        ),
        "associated_groups": ["Elderwood Gang", "Beijing Group", "Sneaky Panda"],
        "campaigns": [],
        "techniques": [
            "T1189", "T1203", "T1105", "T1027.002", "T1027.013",
            "T1566.001", "T1566.002", "T1204.001", "T1204.002"
        ],
        "contributors": ["Valerii Marchuk", "Cybersecurity Help s.r.o."],
        "version": "1.3",
        "created": "18 April 2018",
        "last_modified": "17 November 2024",
        "navigator": "",
        "references": [
            {
                "source": "Paganini, P. (2012). Elderwood project, who is behind Op. Aurora and ongoing attacks?",
                "url": "https://example.com/elderwood-operation-aurora"
            },
            {
                "source": "O'Gorman, G. & McDonald, G. (2012). The Elderwood Project",
                "url": "https://example.com/elderwood-project-analysis"
            },
            {
                "source": "Clayton, M. (2012). Experts ID two huge cyber 'gangs' in China",
                "url": "https://example.com/stealing-us-secrets"
            },
            {
                "source": "Ladley, F. (2012). Backdoor.Ritsol",
                "url": "https://example.com/backdoor-ritsol"
            }
        ],
        "resources": [],
        "remediation": (
            "Apply robust browser and plugin patch management; disable unnecessary browser scripting features (e.g., Flash, JavaScript) in sensitive environments; "
            "harden email filtering to prevent spearphishing attachments and malicious links; deploy endpoint protection to detect software packing and obfuscation."
        ),
        "improvements": (
            "Deploy behavior-based detection tools capable of identifying exploitation of zero-days and use of packed binaries. Monitor ingress transfer patterns "
            "and establish alerting on anomalous file downloads and executions following browser sessions."
        ),
        "hunt_steps": [
            "Search for file downloads over non-standard web requests following browser or Flash activity.",
            "Inspect email logs for spearphishing patterns with uncommon attachment types or links to external exploits.",
            "Hunt for packed or encrypted executable payloads in temp directories and startup locations."
        ],
        "expected_outcomes": [
            "Detection of spearphishing and drive-by exploit delivery mechanisms.",
            "Identification of packed or obfuscated malware dropped by web-based loaders.",
            "Exposure of targeted users affected by phishing and exploitation campaigns."
        ],
        "false_positive": (
            "Packed files and obfuscated scripts may also be used in legitimate software deployment. Verification against user intent and origin is necessary."
        ),
        "clearing_steps": [
            "Remove malware from affected systems, including startup locations.",
            "Restore browser and system settings altered by exploits.",
            "Update all browser-based software and plugins to latest secure versions."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
