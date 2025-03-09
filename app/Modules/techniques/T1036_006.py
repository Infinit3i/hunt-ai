def get_content():
    return {
        "id": "T1036.006",
        "url_id": "T1036/006",
        "title": "Masquerading: Space after Filename",
        "tactic": "Defense Evasion",
        "data_sources": "Process Creation Logs, File System Logs, Endpoint Logs, Security Monitoring Tools",
        "protocol": "File Name Manipulation, Whitespace Padding, Execution Path Abuse",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate adversaries who append spaces to filenames to disguise malicious executables and bypass detection.",
        "scope": "Identify suspicious file execution and process creation events where filenames contain trailing spaces to evade security tools.",
        "threat_model": "Adversaries add trailing spaces to filenames (`calc .exe` instead of `calc.exe`) to manipulate how the operating system and security tools interpret and execute the file, bypassing detection mechanisms.",
        "hypothesis": [
            "Are there executables running with trailing spaces in their filenames?",
            "Are adversaries leveraging filename obfuscation to execute malicious payloads?",
            "Is there an increase in process execution where filenames appear legitimate but contain hidden characters?"
        ],
        "log_sources": [
            {"type": "Process Creation Logs", "source": "Sysmon (Event ID 1, 11), Windows Security Logs (Event ID 4688)"},
            {"type": "File System Logs", "source": "Windows Event Logs (Event ID 4663), Linux Auditd, macOS Unified Logs"},
            {"type": "Endpoint Logs", "source": "EDR (CrowdStrike, Defender ATP, Carbon Black)"},
            {"type": "Security Monitoring Tools", "source": "SIEM, Host-based IDS Logs"}
        ],
        "detection_methods": [
            "Monitor for execution of binaries containing trailing spaces in their filenames.",
            "Detect processes where the binary name visually resembles a known file but includes whitespace padding.",
            "Identify execution of files with unexpected or misleading filename structures."
        ],
        "spl_query": [
            "index=endpoint sourcetype=sysmon \n| search process_name=*' ' \n| stats count by host, user, process_name, file_path"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify execution of filenames containing trailing spaces.",
            "Analyze Process Creation Logs: Detect anomalies in how the operating system interprets filenames.",
            "Monitor for Unexpected Binary Execution: Identify executables running with misleading file structures.",
            "Correlate with Threat Intelligence: Compare with known defense evasion techniques.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Masquerading via Filename Spaces Detected: Block execution of obfuscated binaries and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for filename manipulation-based defense evasion techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1036.006 (Space after Filename)", "example": "Adversaries renaming `malware.exe` to `malware .exe` to evade detection."},
            {"tactic": "Execution", "technique": "T1204 (User Execution)", "example": "Malware leveraging misleading filenames to trick users into execution."}
        ],
        "watchlist": [
            "Flag executions of files with trailing spaces in their filenames.",
            "Monitor for anomalies in process execution related to filename structure.",
            "Detect unauthorized renaming of executables using whitespace padding."
        ],
        "enhancements": [
            "Deploy file integrity monitoring to detect filename manipulations.",
            "Implement behavioral analytics to detect abnormal process execution.",
            "Improve correlation between filename obfuscation activity and known threat actor techniques."
        ],
        "summary": "Document detected malicious masquerading via filename manipulation-based defense evasion activity and affected systems.",
        "remediation": "Block execution of obfuscated filenames, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of filename-based masquerading techniques."
    }
