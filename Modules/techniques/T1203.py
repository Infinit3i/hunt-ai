def get_content():
    """
    Returns structured content for the Exploitation for Client Execution technique (T1203).
    """
    return {
        "id": "T1203",
        "url_id": "T1203",
        "title": "Exploitation for Client Execution",
        "tactic": "Execution",
        "data_sources": "Process monitoring, File monitoring, Windows Event Logs",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "objective": "Adversaries may exploit client applications to execute malicious code on a system.",
        "scope": "Monitor for unauthorized execution of client application processes.",
        "threat_model": "Exploiting vulnerabilities in client applications to execute arbitrary code.",
        "hypothesis": [
            "Are client applications executing unexpected processes?",
            "Are known vulnerabilities in client applications being exploited?",
            "Are users being targeted with malicious documents or exploits?"
        ],
        "tips": [
            "Monitor application crash reports and exploit mitigation logs.",
            "Inspect logs for execution of unexpected processes spawned by client applications.",
            "Analyze suspicious document files or attachments that exploit vulnerabilities."
        ],
        "log_sources": [
            {"type": "Process Monitoring", "source": "Sysmon Event ID 1", "destination": "SIEM"},
            {"type": "File Monitoring", "source": "Windows Defender Logs", "destination": "Endpoint Security"},
            {"type": "Windows Event Logs", "source": "Event ID 4688", "destination": "SIEM"}
        ],
        "source_artifacts": [
            {"type": "File Artifacts", "location": "User Downloads Folder", "identify": "Malicious executables or documents"}
        ],
        "destination_artifacts": [
            {"type": "Process Execution", "location": "System Memory", "identify": "Injected shellcode or exploit payloads"}
        ],
        "detection_methods": [
            "Monitor process creation events for unusual parent-child process relationships.",
            "Analyze network traffic for exploit delivery mechanisms.",
            "Detect execution of known exploit payloads using behavioral analysis."
        ],
        "apt": ["G0016", "G0023"],
        "spl_query": [
            "index=windows EventCode=4688 NewProcessName=* | table _time, ParentProcessName, NewProcessName",
            "index=endpoint file_create=* exploit* | stats count by file_name, process_name"
        ],
        "hunt_steps": [
            "Review recent software vulnerabilities for targeted applications.",
            "Analyze exploit delivery mechanisms such as email attachments or malicious links.",
            "Investigate anomalous application behavior using memory forensics."
        ],
        "expected_outcomes": [
            "Exploitation attempts detected and mitigated.",
            "No suspicious activity found, refining detection strategies."
        ],
        "false_positive": "Legitimate software updates or installations may trigger alerts.",
        "clearing_steps": [
            "Terminate unauthorized processes.",
            "Remove malicious files and artifacts.",
            "Apply security patches to vulnerable client applications."
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059 (Command and Scripting Interpreter)", "example": "Adversaries may execute malicious scripts as part of an exploit payload."}
        ],
        "watchlist": [
            "Monitor execution of client applications for unusual behavior.",
            "Detect exploitation attempts by correlating security alerts with known vulnerabilities."
        ],
        "enhancements": [
            "Enable exploit protection mechanisms in endpoint security solutions.",
            "Implement application whitelisting to prevent unauthorized execution."
        ],
        "summary": "Adversaries exploit client applications to execute arbitrary code, often through crafted documents or malicious web content.",
        "remediation": "Apply patches for vulnerable software, educate users on phishing risks, and monitor execution activity.",
        "improvements": "Enhance endpoint monitoring, deploy behavioral analytics, and utilize sandboxing solutions to detect exploit attempts."
    }
