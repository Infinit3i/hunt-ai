def get_content():
    return {
        "id": "T1592.003",
        "url_id": "T1592/003",
        "title": "Gather Victim Host Information: Firmware",
        "description": "Adversaries may gather information about a victim's host firmware for targeting purposes. This includes data on firmware types and versions, which may indicate the host's configuration, function, security posture, or patch level. Such reconnaissance can support exploit development or identify vulnerable targets.",
        "tags": ["firmware", "reconnaissance", "target profiling"],
        "tactic": "Reconnaissance",
        "protocol": "",
        "os": "Windows, Linux, macOS, Network Appliances",
        "tips": [
            "Limit public exposure of device inventory and technical documentation.",
            "Scrub sensitive device data from online reports and job postings.",
            "Enable security event monitoring that detects unauthorized system information access."
        ],
        "data_sources": "Firmware, Application Log, Asset, Process",
        "log_sources": [
            {"type": "Firmware", "source": "", "destination": ""},
            {"type": "Application Log", "source": "", "destination": ""},
            {"type": "Asset", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Memory Dumps", "location": "Forensic Acquisition", "identify": "Firmware extraction or identification activity"},
            {"type": "Registry Hives (SYSTEM)", "location": "HKLM\\HARDWARE\\DESCRIPTION\\System", "identify": "Firmware or BIOS version fields"}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "Firewall Logs", "identify": "Connections to threat actor infrastructure for exfiltration"},
            {"type": "Process List", "location": "Sysmon Event ID 1", "identify": "Unexpected system probing or enumeration scripts"}
        ],
        "detection_methods": [
            "Monitor for unusual access to firmware-related registry keys.",
            "Detect processes that execute commands like `wmic bios get smbiosbiosversion` or UEFI-specific queries.",
            "Use behavioral analytics to correlate firmware enumeration with phishing or other pre-access tactics."
        ],
        "apt": ["HAFNIUM", "Lazarus Group"],
        "spl_query": [
            'index=sysmon\n| search Image=*wmic.exe* AND CommandLine="*bios*" OR CommandLine="*smbiosbiosversion*"\n| stats count by Hostname, CommandLine, User'
        ],
        "hunt_steps": [
            "Scan endpoints for execution of commands used to query firmware or BIOS/UEFI.",
            "Analyze outbound traffic for queries to device inventory services or threat actor C2 nodes.",
            "Review documents or metadata leaving the organization that may contain firmware details."
        ],
        "expected_outcomes": [
            "Detection of attempts to fingerprint firmware versioning.",
            "Evidence of host enumeration focused on firmware-level details.",
            "Identification of systems likely targeted for firmware-related exploits."
        ],
        "false_positive": "IT inventory or patch management tools may query firmware legitimately. Baseline activity by asset management platforms to reduce noise.",
        "clearing_steps": [
            "Remove unauthorized firmware querying tools/scripts.",
            "Re-image or re-flash firmware if integrity is in doubt.",
            "Reset administrative credentials and restrict access to BIOS/UEFI interfaces."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-device-compromise"
        ],
        "mitre_mapping": [
            {"tactic": "Resource Development", "technique": "T1587", "example": "Building firmware-specific exploits after identification"},
            {"tactic": "Initial Access", "technique": "T1190", "example": "Using firmware vulnerabilities to compromise public-facing appliances"}
        ],
        "watchlist": [
            "Firmware query commands executed outside patch windows",
            "Unexpected access to hardware inventory systems",
            "Sensitive document uploads containing device/firmware listings"
        ],
        "enhancements": [
            "Integrate firmware-level telemetry into SIEM platforms.",
            "Enable BIOS/UEFI protection and alerting in enterprise endpoint solutions.",
            "Tag asset metadata with expected firmware to detect anomalies."
        ],
        "summary": "This technique captures the adversary’s efforts to identify and profile host firmware, often for exploitation or supply chain compromise. Firmware-level weaknesses may provide persistent, stealthy attack vectors.",
        "remediation": "Segment sensitive firmware management interfaces, enforce strict access control, and actively monitor for signs of host profiling or enumeration.",
        "improvements": "Promote firmware visibility in risk assessments, implement automated firmware integrity checks, and train teams to redact such data from public disclosures.",
        "mitre_version": "16.1"
    }
