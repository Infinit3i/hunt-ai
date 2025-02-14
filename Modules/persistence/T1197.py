def get_content():
    return {
        "id": "T1197",
        "url_id": "T1197",
        "title": "BITS Jobs",
        "tactic": "Persistence",
        "data_sources": "Windows Event Logs, Process Monitoring, Registry, File System",
        "protocol": "N/A",
        "os": "Windows",
        "objective": "Detect and mitigate the misuse of Background Intelligent Transfer Service (BITS) jobs for persistence or command execution.",
        "scope": "Monitor for unauthorized BITS jobs that may be used for malicious persistence or command execution.",
        "threat_model": "Adversaries may abuse BITS to create malicious jobs that download or execute malicious payloads while blending in with legitimate network activity.",
        "hypothesis": [
            "Are there unauthorized BITS jobs executing commands or downloading suspicious files?",
            "Are BITS jobs executing payloads outside normal software update behavior?",
            "Are attackers leveraging BITS for persistence mechanisms?"
        ],
        "log_sources": [
            {"type": "Windows Event Logs", "source": "Event ID 4688 (Process Creation), Event ID 7045 (New Service Installed)"},
            {"type": "Registry", "source": "BITS Job registry keys"},
            {"type": "File System", "source": "BITS job payloads and execution files"}
        ],
        "detection_methods": [
            "Monitor for BITS jobs creating executable files outside of expected locations.",
            "Detect scheduled BITS tasks that persist beyond normal system behavior.",
            "Correlate BITS job execution with known malware or unauthorized scripts."
        ],
        "spl_query": "index=windows sourcetype=WinEventLog EventCode=4688 CommandLine=*bitsadmin* OR CommandLine=*Add-File*",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1197",
        "hunt_steps": [
            "Identify BITS jobs that persist or execute unauthorized payloads.",
            "Correlate BITS job activities with threat intelligence feeds.",
            "Analyze system persistence mechanisms linked to BITS job executions.",
            "Investigate process execution chains related to suspicious BITS activities.",
            "If unauthorized BITS activity is detected → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "BITS Job Abuse Detected: Block unauthorized BITS jobs and remove associated files.",
            "No Malicious Activity Found: Improve BITS monitoring and implement stricter policies."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1197 (BITS Jobs)", "example": "BITS jobs used for malware download and execution."},
            {"tactic": "Execution", "technique": "T1204.002 (User Execution - Malicious File)", "example": "BITS job executes unauthorized scripts or payloads."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "BITS job logs are deleted to evade detection."}
        ],
        "watchlist": [
            "Monitor new BITS jobs created in Windows Task Scheduler.",
            "Detect suspicious command-line usage of bitsadmin or PowerShell BITS commands.",
            "Alert on unexpected file downloads initiated by BITS jobs."
        ],
        "enhancements": [
            "Restrict BITS job creation to authorized applications.",
            "Enforce logging and alerting on BITS job modifications.",
            "Regularly audit and clean up unauthorized or orphaned BITS jobs."
        ],
        "summary": "BITS job abuse is a stealthy persistence mechanism used by attackers to download or execute malicious payloads.",
        "remediation": "Disable unnecessary BITS services, monitor BITS job creation, and implement security policies for job execution.",
        "improvements": "Enhance SIEM detections for BITS job execution patterns and integrate with behavioral analytics."
    }
