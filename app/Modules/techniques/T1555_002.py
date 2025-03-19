def get_content():
    return {
        "id": "T1555.002",
        "url_id": "1555/002",
        "title": "Credentials from Password Stores: Securityd Memory",
        "description": "An adversary with root access may gather credentials by reading 'securityd' memory. 'securityd' is a macOS service responsible for security protocols, including encryption and authorization. Attackers with privileged access may scan 'securityd' memory to extract stored credentials, such as user passwords, WiFi credentials, and certificates.",
        "tags": ["Credential Access", "macOS Security", "Memory Scanning"],
        "tactic": "Credential Access",
        "protocol": "Memory Analysis, OS API Calls",
        "os": ["macOS", "Linux"],
        "tips": [
            "Monitor access to 'securityd' memory to detect unauthorized credential extraction attempts.",
            "Detect automated tools scanning memory for sensitive data.",
            "Restrict root access and enforce system integrity protections."
        ],
        "data_sources": "Process Execution, OS API Calls, Memory Access Logs",
        "log_sources": [
            {"type": "Process", "source": "Memory Scanning Activity", "destination": "System Logs"},
            {"type": "Command", "source": "Credential Dumping Commands", "destination": "Audit Logs"}
        ],
        "source_artifacts": [
            {"type": "Memory", "location": "securityd Process Memory", "identify": "Extracted Keychain Credentials"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "Dumped Memory File", "identify": "Extracted Credentials from securityd"}
        ],
        "detection_methods": [
            "Monitor process execution logs for unusual access to 'securityd' memory.",
            "Analyze system logs for unauthorized root-level memory access.",
            "Detect attempts to extract plaintext credentials from system memory."
        ],
        "apt": ["Keydnap", "synack"],
        "spl_query": [
            "index=security (process_name=securityd OR command=*memory scan*) | table _time, process_name, user, command"
        ],
        "hunt_steps": [
            "Review process activity logs for unauthorized securityd memory access.",
            "Analyze execution history for memory scanning tools.",
            "Monitor for privilege escalation attempts related to credential dumping."
        ],
        "expected_outcomes": [
            "Detection of unauthorized attempts to extract credentials from securityd memory.",
            "Identification of processes attempting credential theft via memory analysis."
        ],
        "false_positive": "Legitimate system maintenance tasks accessing securityd memory.",
        "clearing_steps": [
            "Investigate unauthorized memory access to securityd.",
            "Restrict system access and enforce least privilege principles.",
            "Implement additional logging and alerting on memory access events."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "Extract Credentials from securityd Memory", "example": "An attacker scans securityd memory to retrieve stored user credentials."}
        ],
        "watchlist": ["Processes accessing securityd memory without proper authorization."],
        "enhancements": ["Enable system integrity protection (SIP) to restrict memory access.", "Implement kernel-level monitoring for suspicious memory access events."],
        "summary": "Attackers may extract credentials from 'securityd' memory to gain unauthorized access. Monitoring process execution and memory access can help detect this activity.",
        "remediation": "Restrict root-level access and enforce strict authentication controls.",
        "improvements": "Enhance monitoring for memory-related credential extraction attempts."
    }