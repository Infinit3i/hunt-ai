def get_content():
    return {
        "id": "T1592.001",
        "url_id": "T1592/001",
        "title": "Gather Victim Host Information: Hardware",
        "description": "Adversaries may gather information about the victim's host hardware that can be used during targeting. Information may include types and versions of hardware or indicators of added security components such as biometric readers or encryption modules.",
        "tags": ["reconnaissance", "hardware inventory", "target profiling"],
        "tactic": "Reconnaissance",
        "protocol": "HTTP",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Inspect HTTP headers or payloads for hardware enumeration scripts.",
            "Use behavioral analytics to detect scanning patterns aimed at fingerprinting hosts."
        ],
        "data_sources": "Internet Scan",
        "log_sources": [
            {"type": "Internet Scan", "source": "", "destination": ""},
            {"type": "Sysmon", "source": "", "destination": ""},
            {"type": "Windows Security", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Network Connections", "location": "System Network Logs", "identify": "Outbound activity linked to recon domains"},
            {"type": "Memory Dumps", "location": "%SystemDrive%\\MemoryDumps", "identify": "Execution of hardware fingerprinting scripts"}
        ],
        "destination_artifacts": [
            {"type": "Event Logs", "location": "%SystemRoot%\\System32\\winevt\\Logs", "identify": "Host probing activity from unknown sources"}
        ],
        "detection_methods": [
            "Detect access to hardware API endpoints",
            "Monitor outbound traffic for signs of fingerprinting",
            "Correlate banner grabbing with non-standard ports"
        ],
        "apt": [
            "Andariel", "Sandworm"
        ],
        "spl_query": [
            "index=network_traffic uri_path=*hardware* OR uri_query=*bios* OR uri_query=*cpuinfo*\n| stats count by src_ip, uri_path, uri_query"
        ],
        "hunt_steps": [
            "Review outbound requests targeting known recon data collectors",
            "Investigate systems querying hardware profile endpoints",
            "Check for scripts using WMI or SMBIOS interfaces"
        ],
        "expected_outcomes": [
            "Identification of adversary collection behavior on hardware attributes",
            "Flagging of potentially compromised endpoints acting as sensors"
        ],
        "false_positive": "Internal monitoring tools or legitimate inventory scripts may access hardware details similarly.",
        "clearing_steps": [
            "Delete WMI log entries: del /f %SystemRoot%\\System32\\wbem\\Logs\\*",
            "Purge prefetch: del /q C:\\Windows\\Prefetch\\*",
            "Clear event logs: wevtutil cl System"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1195.003", "example": "Hardware supply chain compromise after recon"},
            {"tactic": "Resource Development", "technique": "T1588", "example": "Obtain specialized capabilities based on hardware profile"}
        ],
        "watchlist": [
            "Outbound connections to fingerprinting services",
            "Hosts accessing BIOS or TPM info over network"
        ],
        "enhancements": [
            "Deploy honeypots simulating hardware vulnerabilities",
            "Tune SIEM to alert on BIOS-level data access"
        ],
        "summary": "Adversaries may collect detailed host hardware information to inform follow-on actions such as supply chain or hardware-level compromise.",
        "remediation": "Isolate systems engaging in unexplained hardware information transmission, conduct firmware integrity checks, and review physical access logs.",
        "improvements": "Enrich traffic analysis with hardware-related IOCs and tighten controls on SMBIOS/WMI data retrieval.",
        "mitre_version": "16.1"
    }