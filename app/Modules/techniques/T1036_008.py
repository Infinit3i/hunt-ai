def get_content():
    return {
        "id": "T1036.008",
        "url_id": "T1036/008",
        "title": "Masquerading: Masquerade File Type",
        "tactic": "Defense Evasion",
        "data_sources": "Process Creation Logs, File System Logs, Endpoint Logs, Security Monitoring Tools",
        "protocol": "File Signature Manipulation, Extension Spoofing, Polyglot File Techniques",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate adversaries who disguise malicious payloads as legitimate files by altering their format, signature, or extension to evade security mechanisms.",
        "scope": "Identify suspicious file modifications, masquerading techniques, and process execution where file types are intentionally altered to deceive users or security tools.",
        "threat_model": "Adversaries modify file headers, extensions, or structure to disguise malware, bypass file validation, or evade security detections. They may rename files, use polyglot formats, or alter magic bytes to mislead users and security tools.",
        "hypothesis": [
            "Are there executables or scripts disguised as benign file formats?",
            "Are adversaries leveraging polyglot files to bypass security validation?",
            "Is there an increase in file format modifications preceding malware execution?"
        ],
        "log_sources": [
            {"type": "Process Creation Logs", "source": "Sysmon (Event ID 1, 11), Windows Security Logs (Event ID 4688)"},
            {"type": "File System Logs", "source": "Windows Event Logs (Event ID 4663), Linux Auditd, macOS Unified Logs"},
            {"type": "Endpoint Logs", "source": "EDR (CrowdStrike, Defender ATP, Carbon Black)"},
            {"type": "Security Monitoring Tools", "source": "SIEM, Host-based IDS Logs"}
        ],
        "detection_methods": [
            "Monitor for execution of files with mismatched extensions and headers.",
            "Detect processes where the binary type does not match expected format.",
            "Identify file modifications involving changes to headers, extensions, or structure."
        ],
        "spl_query": [
            "index=endpoint sourcetype=sysmon \n| search process_name=*.jpg OR process_name=*.txt OR process_name=*.gif \n| where file_header NOT IN (expected_headers) \n| stats count by host, user, process_name, file_path"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify execution of files where the extension does not match the actual format.",
            "Analyze Process Creation Logs: Detect anomalies in how files are being executed.",
            "Monitor for Unexpected File Modifications: Identify tampered headers or polyglot file usage.",
            "Correlate with Threat Intelligence: Compare with known masquerading techniques.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Masquerading via File Type Detected: Block execution of disguised malware and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for file masquerading-based defense evasion techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1036.008 (Masquerade File Type)", "example": "Adversaries modifying JPEG headers to disguise an executable payload."},
            {"tactic": "Execution", "technique": "T1204 (User Execution)", "example": "Malware leveraging fake document extensions to deceive users."}
        ],
        "watchlist": [
            "Flag executions of files with misleading formats or headers.",
            "Monitor for anomalies in file naming and modification activities.",
            "Detect unauthorized renaming of executables using format spoofing."
        ],
        "enhancements": [
            "Deploy file signature validation tools to detect altered headers.",
            "Implement behavioral analytics to detect abnormal file executions.",
            "Improve correlation between file format masquerading activity and known threat actor techniques."
        ],
        "summary": "Document detected malicious masquerading via file format alteration and affected systems.",
        "remediation": "Block execution of disguised file types, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of file masquerading-based defense evasion techniques."
    }