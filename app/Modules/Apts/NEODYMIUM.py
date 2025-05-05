def get_content():
    return {
        "id": "G0055",
        "url_id": "NEODYMIUM",
        "title": "NEODYMIUM",
        "tags": ["espionage", "zero-day", "Turkey", "Europe", "overlap-PROMETHIUM", "related-BlackOasis"],
        "description": (
            "NEODYMIUM is an activity group that conducted a known campaign in May 2016 and has heavily targeted Turkish victims. "
            "There are campaign and victim overlaps with another activity group, PROMETHIUM, although they are not confirmed to be aliases. "
            "NEODYMIUM is also reportedly associated with BlackOasis, though evidence of direct group equivalency is inconclusive."
        ),
        "associated_groups": ["PROMETHIUM", "BlackOasis"],
        "campaigns": [
            {
                "id": "Cxxxx",  # Placeholder ID
                "name": "May 2016 Targeting Campaign",
                "first_seen": "May 2016",
                "last_seen": "May 2016",
                "references": [
                    "https://www.microsoft.com/en-us/security/blog/2016/12/14/twin-zero-day-attacks-promethium-and-neodymium/"
                ]
            }
        ],
        "techniques": [
            "T1547",  # Boot or Logon Autostart Execution
            "T1543",  # Create or Modify System Process
            "T1068",  # Exploitation for Privilege Escalation
            "T1574",  # Hijack Execution Flow
            "T1070",  # Indicator Removal
            "T1055",  # Process Injection
            "T1518.001",  # Software Discovery: Security Software Discovery
            "T1082",  # System Information Discovery
            "T1569",  # System Services: Service Execution
        ],
        "contributors": [],
        "version": "1.0",
        "created": "16 January 2018",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {"source": "Microsoft", "url": "https://www.microsoft.com/en-us/security/blog/2016/12/14/twin-zero-day-attacks-promethium-and-neodymium/"},
            {"source": "Microsoft Security Intelligence Report", "url": "https://info.microsoft.com/ww-security-intelligence-report-volume-21.html"},
            {"source": "CyberScoop - FinFisher Espionage", "url": "https://cyberscoop.com/middle-eastern-hacking-finspy-finfisher-blackoasis/"}
        ],
        "resources": [],
        "remediation": (
            "Apply all security patches promptly, especially for zero-day vulnerabilities affecting Windows platforms. "
            "Monitor for DLL hijacking behaviors and unauthorized driver installations. "
            "Implement endpoint protection capable of detecting privilege escalation attempts and LSASS driver modifications."
        ),
        "improvements": (
            "Enhance driver and DLL signature validation. Enable tamper protection for LSASS and critical Windows services. "
            "Deploy advanced logging and anomaly detection for system service creations and driver load events."
        ),
        "hunt_steps": [
            "Scan for signed or unsigned drivers loaded in LSASS memory space.",
            "Audit service creation logs and driver installations during the campaign timeline.",
            "Search for known Wingbird behaviors such as DLL hijacking and obfuscated process injection."
        ],
        "expected_outcomes": [
            "Early detection of malware installation via LSASS driver manipulation.",
            "Attribution of privilege escalation attempts to NEODYMIUM tooling like Wingbird.",
            "Proactive blocking of vulnerable services or misused APIs related to system service creation."
        ],
        "false_positive": (
            "Some legitimate drivers and services may appear similar to NEODYMIUM tactics. "
            "Ensure context validation before alerting or blocking system-level operations."
        ),
        "clearing_steps": [
            "Remove malicious DLLs and service binaries.",
            "Reinstall or update affected drivers with trusted versions.",
            "Conduct forensic triage on systems interacting with LSASS or showing signs of unauthorized privilege escalation."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
