def get_content():
    return {
        "id": "T1556",
        "url_id": "T1556",
        "title": "Modify Authentication Process",
        "tactic": "Credential Access",
        "data_sources": "Authentication logs, Process monitoring, Windows Registry, API monitoring, Endpoint detection",
        "protocol": "Various",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate unauthorized modifications to authentication mechanisms, which may indicate credential theft or privilege escalation attempts.",
        "scope": "Monitor authentication-related processes, registry modifications, and API calls that may indicate tampering with credential validation.",
        "threat_model": "Adversaries modify authentication processes to intercept credentials, bypass security controls, or escalate privileges.",
        "hypothesis": [
            "Are there unauthorized modifications to authentication mechanisms?",
            "Are credential validation processes being hijacked or altered?",
            "Are adversaries injecting malicious code into authentication modules?"
        ],
        "log_sources": [
            {"type": "Authentication Logs", "source": "Windows Event Logs (Event ID 4625, 4776), Linux Authentication Logs"},
            {"type": "Process Monitoring", "source": "Sysmon (Event ID 1, 10), EDR solutions"},
            {"type": "Registry Monitoring", "source": "Sysmon (Event ID 13) for Windows authentication registry changes"},
            {"type": "API Monitoring", "source": "Logging of authentication-related API calls such as LogonUser, CredEnumerate"}
        ],
        "detection_methods": [
            "Monitor for unauthorized registry modifications related to authentication.",
            "Detect suspicious process injections into authentication modules.",
            "Identify anomalies in authentication logs, such as multiple failed login attempts.",
            "Analyze API calls related to credential validation.",
            "Monitor file integrity changes to authentication-related binaries."
        ],
        "spl_query": "index=security EventCode=4625 OR EventCode=4776 OR EventCode=4768 | stats count by src_ip, user, _time | where count > threshold",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1556",
        "hunt_steps": [
            "Run SIEM queries to detect suspicious authentication modifications.",
            "Correlate failed login attempts with process monitoring and API call logs.",
            "Investigate any unauthorized registry changes related to authentication settings.",
            "Check endpoint logs for injection attempts into authentication-related services.",
            "Validate and escalate if suspicious activity is found."
        ],
        "expected_outcomes": [
            "Unauthorized authentication modifications detected: Incident response initiated.",
            "No malicious activity found: Enhance detection capabilities and refine baselines."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1556 (Modify Authentication Process)", "example": "Malware injecting into LSASS to steal credentials."},
            {"tactic": "Privilege Escalation", "technique": "T1548 (Abuse Elevation Control Mechanism)", "example": "Modifying authentication flow to gain higher privileges."}
        ],
        "watchlist": [
            "Flag unauthorized registry modifications related to authentication.",
            "Monitor authentication logs for anomalous activity.",
            "Detect API calls that attempt to alter authentication mechanisms."
        ],
        "enhancements": [
            "Implement multi-factor authentication (MFA) to mitigate authentication tampering.",
            "Harden registry and file permissions for authentication-related components.",
            "Deploy behavior-based anomaly detection for authentication attempts."
        ],
        "summary": "Detect and respond to authentication process modifications that could be leveraged for credential theft or privilege escalation.",
        "remediation": "Investigate unauthorized authentication modifications, apply security patches, and enforce strict access controls.",
        "improvements": "Enhance behavioral monitoring of authentication-related processes and implement stronger authentication safeguards."
    }
