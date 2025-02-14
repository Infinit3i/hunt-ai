def get_content():
    return {
        "id": "T1074",
        "url_id": "T1074",
        "title": "Sensitive Document Access",
        "tactic": "Collection",
        "data_sources": "File Access Logs, SMB/NFS Logs, Cloud Storage Logs, Endpoint Detection & Response (EDR)",
        "protocol": "SMB, NFS, HTTP, HTTPS",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate unauthorized access to sensitive documents, which may indicate insider threats, compromised credentials, or unauthorized data access attempts.",
        "scope": "Monitor file access activity on network shares, cloud storage, and local systems. Identify document modifications, copies, or deletions occurring outside normal working hours. Detect large-scale document access indicative of exfiltration attempts.",
        "threat_model": "Adversaries may attempt to access or exfiltrate sensitive documents through compromised user credentials, insider threats, or malware scanning for sensitive data.",
        "hypothesis": [
            "Are there users accessing large volumes of sensitive files unexpectedly?",
            "Is document access occurring outside normal working hours?",
            "Are users copying, deleting, or modifying critical files in bulk?"
        ],
        "log_sources": [
            {"type": "File Access Logs", "source": "Windows Security Logs (Event ID 4663), Sysmon (Event ID 11), Linux AuditD"},
            {"type": "SMB/NFS Logs", "source": "Windows File Server Logs, NetApp, Samba Logs"},
            {"type": "Cloud Storage Logs", "source": "AWS S3, Google Drive, OneDrive, Dropbox"},
            {"type": "Endpoint Detection & Response (EDR)", "source": "CrowdStrike, Defender ATP, Carbon Black"}
        ],
        "detection_methods": [
            "Monitor for large-scale access to sensitive files from a single user.",
            "Detect file modifications or deletions occurring outside normal business hours.",
            "Identify access patterns that deviate from established user behavior baselines."
        ],
        "spl_query": "index=file_access sourcetype=windows:file | stats count by user, file_path, _time | where count > 50 AND hour(_time) > 20 | sort - count",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1074",
        "hunt_steps": [
            "Run Queries in SIEM: Detect large-scale file access, modifications, or deletions outside normal hours.",
            "Correlate with User Behavior Analytics (UBA): Determine if the user has a history of accessing these files.",
            "Investigate File Ownership & Permissions: Identify if compromised credentials were used.",
            "Monitor for Exfiltration Attempts: Detect high-volume file transfers to external storage or cloud providers.",
            "Validate & Escalate: If unauthorized access is detected → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Unauthorized File Access Detected: Block access and revoke compromised credentials.",
            "No Malicious Activity Found: Improve baseline monitoring for file access behaviors."
        ],
        "mitre_mapping": [
            {"tactic": "Exfiltration", "technique": "T1048 (Exfiltration Over Alternative Protocol)", "example": "Attackers may transfer stolen files over HTTP/S, FTP, or cloud services."},
            {"tactic": "Impact", "technique": "T1486 (Data Encrypted for Impact)", "example": "Ransomware may encrypt sensitive documents before exfiltration."},
            {"tactic": "Persistence", "technique": "T1098 (Account Manipulation)", "example": "Adversaries may create or modify accounts to maintain long-term access."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Attackers may delete logs to cover their document access trail."},
            {"tactic": "Lateral Movement", "technique": "T1021.001 (Remote Desktop Protocol)", "example": "Attackers may pivot to other machines hosting sensitive data."}
        ],
        "watchlist": [
            "Flag unexpected large-scale file access activity.",
            "Detect unauthorized data transfers to USB or cloud storage.",
            "Monitor login attempts prior to sensitive file access."
        ],
        "enhancements": [
            "Enforce least-privilege access controls on sensitive file shares.",
            "Restrict data transfers and enforce DLP solutions for sensitive files.",
            "Enable logging and monitoring for all critical document access."
        ],
        "summary": "Monitor and investigate unauthorized access to sensitive documents to detect insider threats and exfiltration attempts.",
        "remediation": "Block unauthorized file access, revoke compromised credentials, and improve access control policies.",
        "improvements": "Strengthen detection rules for file access anomalies and insider threats."
    }
