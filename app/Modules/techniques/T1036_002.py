def get_content():
    return {
        "id": "T1036.002",
        "url_id": "T1036/002",
        "title": "Masquerading: Right-to-Left Override",
        "tactic": "Defense Evasion",
        "data_sources": "Process Creation Logs, File System Logs, Endpoint Logs, Security Monitoring Tools",
        "protocol": "Unicode Manipulation, Filename Obfuscation, Text Encoding Tricks",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate adversaries using Right-to-Left Override (RLO) characters to disguise file extensions and execute malicious payloads.",
        "scope": "Identify suspicious filenames and process executions that indicate an attempt to deceive users and security tools.",
        "threat_model": "Adversaries insert special Unicode RLO characters in filenames, causing file extensions to be visually altered (e.g., `evilgpj.exe` instead of `eviljpg.exe`) to trick users into executing malicious files.",
        "hypothesis": [
            "Are there filenames using right-to-left override characters to disguise their true extension?",
            "Are adversaries leveraging Unicode manipulation to mask malicious executables?",
            "Is there an increase in file execution from unusual directories with hidden extensions?"
        ],
        "log_sources": [
            {"type": "Process Creation Logs", "source": "Sysmon (Event ID 1, 11), Windows Security Logs (Event ID 4688)"},
            {"type": "File System Logs", "source": "Windows Event Logs (Event ID 4663), Linux Auditd, macOS Unified Logs"},
            {"type": "Endpoint Logs", "source": "EDR (CrowdStrike, Defender ATP, Carbon Black)"},
            {"type": "Security Monitoring Tools", "source": "SIEM, Host-based IDS Logs"}
        ],
        "detection_methods": [
            "Monitor for execution of files containing RLO characters in their names.",
            "Detect processes running with filenames that visually differ from their true extensions.",
            "Identify files dropped in user directories with obfuscated extensions."
        ],
        "spl_query": [
            "index=endpoint sourcetype=sysmon \n| search process_name=*\u202E* \n| stats count by host, user, process_name, file_path"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify execution of files containing RLO characters.",
            "Analyze Process Creation Logs: Detect anomalies in filename representations.",
            "Monitor for Unexpected File Drops: Identify suspicious files in downloads, temp, or user directories.",
            "Correlate with Threat Intelligence: Compare with known defense evasion techniques.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Right-to-Left Override Detected: Block execution of RLO-masked files and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for RLO-based defense evasion techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1036.002 (Right-to-Left Override)", "example": "Adversaries renaming `evilgpj.exe` to `eviljpg.exe` using Unicode RLO."},
            {"tactic": "Execution", "technique": "T1204 (User Execution)", "example": "Malware masquerading as a benign file to trick users into execution."}
        ],
        "watchlist": [
            "Flag executions of files containing RLO characters in their names.",
            "Monitor for anomalies in file naming conventions.",
            "Detect unauthorized renaming of executables using Unicode manipulation."
        ],
        "enhancements": [
            "Deploy file integrity monitoring to detect filename alterations.",
            "Implement behavioral analytics to detect abnormal process execution.",
            "Improve correlation between RLO manipulation activity and known threat actor techniques."
        ],
        "summary": "Document detected malicious Right-to-Left Override-based defense evasion activity and affected systems.",
        "remediation": "Block execution of RLO-masked files, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of RLO-based defense evasion techniques."
    }
