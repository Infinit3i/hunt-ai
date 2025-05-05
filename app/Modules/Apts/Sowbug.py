def get_content():
    return {
        "id": "G0054",
        "url_id": "Sowbug",
        "title": "Sowbug",
        "tags": ["espionage", "government targeting", "South America", "Southeast Asia", "Felismus", "Starloader"],
        "description": (
            "Sowbug is an espionage-focused threat group active since at least 2015, known for targeting government "
            "institutions primarily in South America and Southeast Asia. The group leverages custom malware, including Felismus, "
            "and uses stealthy techniques such as masquerading tools as legitimate software and extensive use of Windows command line. "
            "Sowbug’s activities include document exfiltration, credential harvesting, and system discovery, often focusing on sensitive data "
            "stored across network shares."
        ),
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1560.001", "T1059.003", "T1039", "T1083", "T1056.001", 
            "T1036.005", "T1135", "T1003", "T1082"
        ],
        "contributors": ["Alan Neville", "@abnev"],
        "version": "1.1",
        "created": "16 January 2018",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {"source": "Symantec", "url": "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/sowbug-espionage-south-america"}
        ],
        "resources": [],
        "remediation": (
            "Audit file shares and user access to sensitive directories. Implement least privilege and review credential "
            "storage practices. Monitor for suspicious RAR archiving or tools masquerading as known software (e.g., adobecms.exe)."
        ),
        "improvements": (
            "Deploy EDR tools to monitor command-line behavior and archive creation. Detect abnormal file access patterns, "
            "especially targeting Word documents across network shares. Block execution of unauthorized binaries from user directories."
        ),
        "hunt_steps": [
            "Look for use of `rar.exe` or similar tools in non-admin contexts.",
            "Hunt for filenames like `adobecms.exe` or executables in unusual `CSIDL_APPDATA` subpaths.",
            "Detect use of commands that enumerate `.doc` or `.docx` files across shares or time-based filtering."
        ],
        "expected_outcomes": [
            "Detection of unusual document access patterns and staging behaviors.",
            "Identification of command-line-based data collection and archiving activity.",
            "Alerting on credential dumping utilities and masquerading binaries."
        ],
        "false_positive": "Legitimate archiving tools or IT scripts may use similar commands; validate with context and execution origin.",
        "clearing_steps": [
            "Terminate malicious processes masquerading as system tools.",
            "Revoke and reset credentials of affected systems.",
            "Remove tools like Felismus and Starloader and verify persistence mechanisms are eliminated."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": [
                "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/sowbug-espionage-south-america"
            ]
        }
    }
