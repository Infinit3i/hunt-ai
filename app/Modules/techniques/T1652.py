def get_content():
    return {
        "id": "T1652",  # Tactic Technique ID
        "url_id": "1652",  # URL segment for technique reference
        "title": "Device Driver Discovery",  # Name of the attack technique
        "description": "Adversaries may attempt to enumerate local device drivers on a victim host to gain insights into the host's function, security tools, or potential vulnerabilities that could be exploited for privilege escalation or defense evasion. Utilities like driverquery.exe, EnumDeviceDrivers(), lsmod, and modinfo may be used to discover device drivers across Windows, Linux, and macOS.",  # Simple description
        "tags": [
            "Device Driver Discovery",
            "driverquery",
            "EnumDeviceDrivers",
            "lsmod",
            "modinfo",
            "Registry",
            "Windows",
            "Linux",
            "macOS",
            "Discovery"
        ],  # Up to 10 tags
        "tactic": "Discovery",  # Associated MITRE ATT&CK tactic
        "protocol": "N/A",  # Protocol used in the attack technique
        "os": "Linux, Windows, macOS",  # Targeted operating systems
        "tips": [
            "Monitor process execution for commands like driverquery.exe, lsmod, and modinfo",
            "Audit registry key access for references to device drivers on Windows",
            "Analyze API calls such as EnumDeviceDrivers() for anomalous usage"
        ],
        "data_sources": "Command: Command Execution, Process: OS API Execution, Process: Process Creation, Windows Registry: Windows Registry Key Access",
        "log_sources": [
            {
                "type": "Command",
                "source": "Process Monitoring",
                "destination": "SIEM"
            },
            {
                "type": "Process",
                "source": "Endpoint Monitoring",
                "destination": "SIEM"
            },
            {
                "type": "Windows Registry",
                "source": "Registry Auditing",
                "destination": "SIEM"
            }
        ],
        "source_artifacts": [
            {
                "type": "Driver Enumeration Commands",
                "location": "Host OS",
                "identify": "Use of driverquery, lsmod, modinfo, or EnumDeviceDrivers()"
            }
        ],
        "destination_artifacts": [
            {
                "type": "",
                "location": "",
                "identify": ""
            }
        ],
        "detection_methods": [
            "Monitor for driverquery.exe or API calls (EnumDeviceDrivers) in unexpected contexts",
            "Analyze command-line arguments for references to device driver directories or registry paths",
            "Look for lsmod, modinfo usage on Linux/macOS systems correlating with suspicious process behavior"
        ],
        "apt": [],  # No specific APT group listed
        "spl_query": [],
        "hunt_steps": [
            "Search for repeated or unauthorized usage of driver enumeration commands",
            "Correlate device driver enumeration events with subsequent privilege escalation attempts",
            "Review registry audits for suspicious driver references on Windows"
        ],
        "expected_outcomes": [
            "Detection of adversary efforts to gather driver information for further exploitation",
            "Identification of compromised systems that may be targeted for driver-based privilege escalation",
            "Increased visibility into potential tampering or enumeration of device drivers"
        ],
        "false_positive": "Legitimate IT troubleshooting or maintenance activities may involve enumerating device drivers. Validate user context and administrative approvals.",
        "clearing_steps": [
            "Terminate or isolate processes performing unauthorized driver enumeration",
            "Review system and registry permissions to restrict access to driver information",
            "Investigate potential follow-on exploitation attempts or suspicious driver modifications"
        ],
        "mitre_mapping": [
            {
                "tactic": "Discovery",
                "technique": "Device Driver Discovery (T1652)",
                "example": "Using driverquery.exe or lsmod to identify installed drivers for potential vulnerabilities"
            }
        ],
        "watchlist": [
            "Frequent or scripted driver enumeration commands",
            "Unexpected references to driver files or registry keys by non-admin processes",
            "Unusual correlation of device driver queries with privilege escalation attempts"
        ],
        "enhancements": [
            "Implement role-based access controls preventing unauthorized driver enumeration",
            "Deploy EDR solutions capable of alerting on suspicious command usage and registry queries",
            "Enforce least privilege principles to minimize driver-related information exposure"
        ],
        "summary": "Adversaries may enumerate device drivers to identify system functions, security tools, or vulnerabilities that can be exploited for further compromise. Monitoring for driver-related commands and registry access can help detect suspicious behavior.",
        "remediation": "Enforce strict access to driver information, monitor driver enumeration commands, and ensure device driver patches and updates are regularly applied to mitigate exploitable vulnerabilities.",
        "improvements": "Implement advanced threat detection for driver enumeration patterns, conduct regular vulnerability assessments on device drivers, and train security teams on detecting malicious driver discovery activities."
    }
